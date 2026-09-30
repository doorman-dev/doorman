use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::TryStreamExt;
use mongodb::{
    Client, Database, IndexModel,
    bson::{Document, doc},
    options::IndexOptions,
};
use redis::{AsyncCommands, aio::ConnectionManager};
use serde_json::Value;
use thiserror::Error;

use crate::{
    config::SharedStorageConfig,
    storage::{memory::MemoryStorage, models::PolicyDocuments},
};

#[derive(Clone)]
pub struct SharedStorage {
    mongo: Option<Database>,
    redis: Option<ConnectionManager>,
    memory: Option<MemoryStorage>,
    policy_cache: Arc<tokio::sync::RwLock<Option<CachedPolicyDocuments>>>,
    policy_cache_ttl: Duration,
    tls_mutation_mutex: Arc<tokio::sync::Mutex<()>>,
    tls_mutation_key: String,
}

pub struct TlsMutationGuard {
    _local: tokio::sync::OwnedMutexGuard<()>,
    redis: Option<(ConnectionManager, String, String)>,
    renewal: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TlsMutationGuard {
    fn drop(&mut self) {
        if let Some(renewal) = self.renewal.take() {
            renewal.abort();
        }
        if let Some((mut redis, key, token)) = self.redis.take() {
            tokio::spawn(async move {
                let _: redis::RedisResult<i64> = redis::cmd("EVAL")
                    .arg("if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end")
                    .arg(1).arg(key).arg(token).query_async(&mut redis).await;
            });
        }
    }
}

#[derive(Clone)]
struct CachedPolicyDocuments {
    loaded_at: Instant,
    revision: u64,
    documents: PolicyDocuments,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("MongoDB operation failed: {0}")]
    Mongo(#[from] mongodb::error::Error),
    #[error("Redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("MongoDB document conversion failed: {0}")]
    Bson(#[from] mongodb::bson::ser::Error),
    #[error("stored document cannot be represented as JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid stored document: {0}")]
    InvalidDocument(String),
}
impl StorageError {
    pub fn is_duplicate_key(&self) -> bool {
        matches!(self, Self::Mongo(error) if error.to_string().contains("E11000"))
    }
}

fn restored_document(value: &Value) -> Result<Document, StorageError> {
    let object = value
        .as_object()
        .cloned()
        .ok_or_else(|| StorageError::InvalidDocument("expected stored object".to_owned()))?;
    Document::try_from(object).map_err(|error| StorageError::InvalidDocument(error.to_string()))
}

pub struct GatewayMetric<'a> {
    pub minute_start: u64,
    pub status: u16,
    pub duration_micros: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub api_key: Option<&'a str>,
    pub username: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    pub is_test: bool,
}

impl SharedStorage {
    pub async fn connect(config: &SharedStorageConfig) -> Result<Self, StorageError> {
        if config.storage_mode.eq_ignore_ascii_case("MEM") {
            return Ok(Self {
                mongo: None,
                redis: None,
                memory: Some(MemoryStorage::new()),
                policy_cache: Arc::new(tokio::sync::RwLock::new(None)),
                policy_cache_ttl: Duration::from_secs(config.policy_cache_ttl_seconds),
                tls_mutation_mutex: Arc::new(tokio::sync::Mutex::new(())),
                tls_mutation_key: String::new(),
            });
        }
        // Bound server selection so a MongoDB outage fails requests quickly
        // (fail closed) instead of stalling them for the 30s driver default.
        let mut mongo_options = mongodb::options::ClientOptions::parse(config.mongo_uri()).await?;
        mongo_options.server_selection_timeout = Some(Duration::from_secs(5));
        mongo_options.connect_timeout = Some(Duration::from_secs(5));
        let client = Client::with_options(mongo_options)?;
        let mongo = client.database(&config.mongo_database);
        mongo.run_command(doc! { "ping": 1 }).await?;

        // Without timeouts a Redis outage would hang every request, and an
        // unbounded backoff would delay recovery after Redis returns.
        let redis_client = redis::Client::open(config.redis_url())?;
        let redis_config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_secs(1))
            .set_response_timeout(Duration::from_secs(2))
            .set_number_of_retries(1)
            .set_factor(100)
            .set_max_delay(500);
        let mut redis = ConnectionManager::new_with_config(redis_client, redis_config).await?;
        let _: String = redis::cmd("PING").query_async(&mut redis).await?;
        Self::ensure_indexes(&mongo).await?;
        Ok(Self {
            mongo: Some(mongo),
            redis: Some(redis),
            memory: None,
            policy_cache: Arc::new(tokio::sync::RwLock::new(None)),
            policy_cache_ttl: Duration::from_secs(config.policy_cache_ttl_seconds),
            tls_mutation_mutex: Arc::new(tokio::sync::Mutex::new(())),
            tls_mutation_key: format!("doorman:tls-mutation:{}", config.mongo_database),
        })
    }

    pub async fn tls_mutation_lock(&self) -> Result<TlsMutationGuard, StorageError> {
        let local = self.tls_mutation_mutex.clone().lock_owned().await;
        let Some(mut redis) = self.redis.clone() else {
            return Ok(TlsMutationGuard {
                _local: local,
                redis: None,
                renewal: None,
            });
        };
        let key = self.tls_mutation_key.clone();
        let token = uuid::Uuid::new_v4().to_string();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let acquired: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg(&token)
                .arg("NX")
                .arg("PX")
                .arg(30_000)
                .query_async(&mut redis)
                .await?;
            if acquired.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(StorageError::InvalidDocument(
                    "TLS mutation lock timed out".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut renewal_redis = redis.clone();
        let renewal_key = key.clone();
        let renewal_token = token.clone();
        let renewal = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let renewed: redis::RedisResult<i64> = redis::cmd("EVAL")
                    .arg("if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], 30000) else return 0 end")
                    .arg(1).arg(&renewal_key).arg(&renewal_token)
                    .query_async(&mut renewal_redis).await;
                if !matches!(renewed, Ok(1)) {
                    break;
                }
            }
        });
        Ok(TlsMutationGuard {
            _local: local,
            redis: Some((redis, key, token)),
            renewal: Some(renewal),
        })
    }

    async fn ensure_indexes(database: &Database) -> Result<(), StorageError> {
        let indexes = [
            ("users", doc! {"username": 1}, true),
            ("users", doc! {"email": 1}, true),
            ("roles", doc! {"role_name": 1}, true),
            ("groups", doc! {"group_name": 1}, true),
            ("apis", doc! {"api_id": 1}, true),
            ("apis", doc! {"api_name": 1, "api_version": 1}, false),
            (
                "endpoints",
                doc! {
                    "api_name": 1,
                    "api_version": 1,
                    "endpoint_method": 1,
                    "endpoint_uri": 1
                },
                true,
            ),
            ("subscriptions", doc! {"username": 1}, true),
            ("routings", doc! {"client_key": 1}, true),
            ("credit_defs", doc! {"api_credit_group": 1}, true),
            ("user_credits", doc! {"username": 1}, true),
            ("endpoint_validations", doc! {"endpoint_id": 1}, true),
            ("tiers", doc! {"tier_id": 1}, true),
            ("tiers", doc! {"name": 1}, false),
            ("user_tier_assignments", doc! {"user_id": 1}, true),
            ("user_tier_assignments", doc! {"tier_id": 1}, false),
            ("vault_entries", doc! {"username": 1, "key_name": 1}, true),
            ("vault_entries", doc! {"username": 1}, false),
            ("config_snapshots", doc! {"snapshot_id": 1}, true),
            ("tls_profiles", doc! {"id": 1}, true),
            (
                "revocations",
                doc! {"type": 1, "username": 1, "jti": 1},
                true,
            ),
        ];
        for (collection, keys, unique) in indexes {
            database
                .collection::<Document>(collection)
                .create_index(
                    IndexModel::builder()
                        .keys(keys)
                        .options(IndexOptions::builder().unique(unique).build())
                        .build(),
                )
                .await?;
        }
        Ok(())
    }
    pub async fn initialize_core(&self) -> Result<(), StorageError> {
        let admin_role = serde_json::json!({
            "role_name": "admin", "role_description": "Administrator role",
            "manage_users": true, "manage_apis": true, "manage_endpoints": true,
            "manage_groups": true, "manage_roles": true, "manage_routings": true,
            "manage_gateway": true, "manage_subscriptions": true, "manage_credits": true,
            "manage_auth": true, "manage_security": true, "manage_tiers": true,
            "manage_rate_limits": true, "view_analytics": true, "view_logs": true,
            "export_logs": true, "ui_access": true
        });
        if self
            .find_one("roles", &serde_json::json!({"role_name": "admin"}))
            .await?
            .is_none()
        {
            self.insert_one("roles", admin_role).await?;
        }
        for (name, description) in [
            ("admin", "Administrator group with full access"),
            ("ALL", "Default group with access to all APIs"),
        ] {
            if self
                .find_one("groups", &serde_json::json!({"group_name": name}))
                .await?
                .is_none()
            {
                self.insert_one(
                    "groups",
                    serde_json::json!({
                        "group_name": name, "group_description": description, "api_access": []
                    }),
                )
                .await?;
            }
        }
        let existing_admin = self
            .find_one("users", &serde_json::json!({"username": "admin"}))
            .await?;
        let admin_credentials = || -> Result<(String, String), StorageError> {
            let password = std::env::var("DOORMAN_ADMIN_PASSWORD")
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    StorageError::InvalidDocument(
                        "DOORMAN_ADMIN_PASSWORD is required for admin initialization".to_owned(),
                    )
                })?;
            let password = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|error| {
                StorageError::InvalidDocument(format!("failed to hash admin password: {error}"))
            })?;
            let email = std::env::var("DOORMAN_ADMIN_EMAIL")
                .ok()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "admin@doorman.dev".to_owned());
            Ok((email, password))
        };
        match existing_admin {
            None => {
                let (email, password) = admin_credentials()?;
                self.insert_one(
                    "users",
                    serde_json::json!({
                        "username": "admin", "email": email, "password": password,
                        "role": "admin", "groups": ["ALL", "admin"], "ui_access": true,
                        "rate_limit_duration": 1, "rate_limit_duration_type": "second",
                        "throttle_duration": 1, "throttle_duration_type": "second",
                        "throttle_wait_duration": 0, "throttle_wait_duration_type": "second",
                        "throttle_queue_limit": 1, "throttle_enabled": null,
                        "custom_attributes": {"custom_key": "custom_value"}, "active": true
                    }),
                )
                .await?;
            }
            Some(admin) => {
                // Mongo-mode repair: restore only missing bootstrap fields.
                let mut repairs = serde_json::Map::new();
                if admin.get("ui_access") != Some(&Value::Bool(true)) {
                    repairs.insert("ui_access".to_owned(), Value::Bool(true));
                }
                let missing = |field: &str| {
                    admin
                        .get(field)
                        .is_none_or(|v| v.is_null() || v.as_str() == Some(""))
                };
                if missing("email") {
                    let email = std::env::var("DOORMAN_ADMIN_EMAIL")
                        .ok()
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "admin@doorman.dev".to_owned());
                    repairs.insert("email".to_owned(), Value::String(email));
                }
                if missing("password") {
                    repairs.insert("password".to_owned(), Value::String(admin_credentials()?.1));
                }
                if !repairs.is_empty() {
                    self.update_one(
                        "users",
                        &serde_json::json!({"username": "admin"}),
                        &Value::Object(repairs),
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn dump_memory_data(
        &self,
    ) -> Result<std::collections::HashMap<String, Vec<Value>>, StorageError> {
        let Some(memory) = &self.memory else {
            return Err(StorageError::InvalidDocument(
                "Memory dump is available only in memory mode".to_owned(),
            ));
        };
        Ok(memory.collections.read().await.clone())
    }

    pub async fn restore_memory_data(
        &self,
        collections: std::collections::HashMap<String, Vec<Value>>,
    ) -> Result<(), StorageError> {
        let Some(memory) = &self.memory else {
            return Err(StorageError::InvalidDocument(
                "Memory restore is available only in memory mode".to_owned(),
            ));
        };
        *memory.collections.write().await = collections;
        memory.clear_runtime().await;
        self.invalidate_policy_cache().await;
        Ok(())
    }

    /// Python's InMemoryCollection raises while the chaos Mongo outage flag is set.
    fn chaos_mongo_guard(&self) -> Result<(), StorageError> {
        if self.memory.is_some() {
            Self::chaos_guard("mongo")?;
        }
        Ok(())
    }

    fn chaos_guard(backend: &str) -> Result<(), StorageError> {
        use crate::middleware::chaos::{
            CHAOS_ERROR_BUDGET_BURN, CHAOS_MONGO_OUTAGE, CHAOS_REDIS_OUTAGE,
        };
        use std::sync::atomic::Ordering;
        let flag = if backend == "redis" {
            &CHAOS_REDIS_OUTAGE
        } else {
            &CHAOS_MONGO_OUTAGE
        };
        if flag.load(Ordering::Relaxed) {
            CHAOS_ERROR_BUDGET_BURN.fetch_add(1, Ordering::Relaxed);
            return Err(StorageError::InvalidDocument(format!(
                "chaos: simulated {backend} outage"
            )));
        }
        Ok(())
    }

    pub fn is_memory(&self) -> bool {
        self.memory.is_some()
    }

    pub async fn set_ephemeral(
        &self,
        key: &str,
        value: Value,
        ttl_seconds: u64,
    ) -> Result<(), StorageError> {
        Self::chaos_guard("redis")?;
        if let Some(memory) = &self.memory {
            memory.set_value(key, value, ttl_seconds).await;
            return Ok(());
        }
        let encoded = serde_json::to_string(&value)?;
        let mut redis = self.redis()?;
        let _: () = redis.set_ex(key, encoded, ttl_seconds.max(1)).await?;
        Ok(())
    }

    pub async fn get_ephemeral(&self, key: &str) -> Result<Option<Value>, StorageError> {
        Self::chaos_guard("redis")?;
        if let Some(memory) = &self.memory {
            return Ok(memory.get_value(key).await);
        }
        let mut redis = self.redis()?;
        let encoded: Option<String> = redis.get(key).await?;
        encoded
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(StorageError::from)
    }

    fn mongo(&self) -> Result<&Database, StorageError> {
        self.mongo.as_ref().ok_or_else(|| {
            StorageError::InvalidDocument("MongoDB unavailable in memory mode".to_owned())
        })
    }

    fn redis(&self) -> Result<ConnectionManager, StorageError> {
        self.redis.clone().ok_or_else(|| {
            StorageError::InvalidDocument("Redis unavailable in memory mode".to_owned())
        })
    }

    pub async fn load_policy_documents(&self) -> Result<PolicyDocuments, StorageError> {
        let revision = self.policy_revision().await?;
        if let Some(memory) = &self.memory {
            return Ok(memory.load_policy_documents().await);
        }
        if let Some(cached) = self.policy_cache.read().await.as_ref()
            && cached.revision == revision
            && cached.loaded_at.elapsed() < self.policy_cache_ttl
        {
            return Ok(cached.documents.clone());
        }

        let (
            apis,
            endpoints,
            endpoint_validations,
            users,
            roles,
            subscriptions,
            routings,
            credit_defs,
            user_credits,
            settings,
            revocations,
            tiers,
            tier_assignments,
        ) = tokio::try_join!(
            self.load_collection("apis"),
            self.load_collection("endpoints"),
            self.load_collection("endpoint_validations"),
            self.load_collection("users"),
            self.load_collection("roles"),
            self.load_collection("subscriptions"),
            self.load_collection("routings"),
            self.load_collection("credit_defs"),
            self.load_collection("user_credits"),
            self.load_collection("settings"),
            self.load_collection("revocations"),
            self.load_collection("tiers"),
            self.load_collection("user_tier_assignments"),
        )?;
        let documents = PolicyDocuments {
            apis,
            endpoints,
            endpoint_validations,
            users,
            roles,
            subscriptions,
            routings,
            credit_defs,
            user_credits,
            settings,
            revocations,
            tiers,
            tier_assignments,
        };
        *self.policy_cache.write().await = Some(CachedPolicyDocuments {
            loaded_at: Instant::now(),
            revision,
            documents: documents.clone(),
        });
        Ok(documents)
    }

    pub async fn invalidate_policy_cache(&self) {
        *self.policy_cache.write().await = None;
    }

    async fn policy_revision(&self) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            return Ok(memory.revision());
        }
        let mut redis = self.redis()?;
        Ok(redis
            .get::<_, Option<u64>>("gateway:policy_revision")
            .await?
            .unwrap_or(0))
    }

    pub async fn bump_policy_revision(&self) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            return Ok(memory.bump_revision());
        }
        let mut redis = self.redis()?;
        Ok(redis.incr("gateway:policy_revision", 1_u64).await?)
    }

    async fn load_collection(&self, name: &str) -> Result<Vec<Value>, StorageError> {
        let mut cursor = self
            .mongo()?
            .collection::<Document>(name)
            .find(doc! {})
            .await?;
        let mut values = Vec::new();
        while let Some(mut document) = cursor.try_next().await? {
            document.remove("_id");
            values.push(serde_json::to_value(document)?);
        }
        Ok(values)
    }

    pub async fn increment_window(&self, key: &str, ttl_seconds: u64) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            return Ok(memory.increment(key, 1, ttl_seconds).await);
        }
        let mut redis = self.redis()?;
        Ok(redis::Script::new(
            r#"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
            return count
            "#,
        )
        .key(key)
        .arg(ttl_seconds.max(1))
        .invoke_async(&mut redis)
        .await?)
    }

    pub async fn check_tier_window(
        &self,
        key: &str,
        limit: u64,
        ttl_seconds: u64,
    ) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            let current = memory
                .get_value(key)
                .await
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            if current >= limit {
                return Ok(current + 1);
            }
            return Ok(memory.increment(key, 1, ttl_seconds).await);
        }
        let mut redis = self.redis()?;
        Ok(redis::Script::new(
            r#"
            local current = tonumber(redis.call('GET', KEYS[1]) or '0')
            if current >= tonumber(ARGV[1]) then
                return current + 1
            end
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
            return count
            "#,
        )
        .key(key)
        .arg(limit)
        .arg(ttl_seconds.max(1))
        .invoke_async(&mut redis)
        .await?)
    }

    pub async fn add_bandwidth(
        &self,
        key: &str,
        bytes: u64,
        ttl_seconds: u64,
    ) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            return Ok(memory.increment(key, bytes, ttl_seconds).await);
        }
        let mut redis = self.redis()?;
        Ok(redis::Script::new(
            r#"
            local total = redis.call('INCRBY', KEYS[1], ARGV[1])
            if redis.call('TTL', KEYS[1]) < 0 then
                redis.call('EXPIRE', KEYS[1], ARGV[2])
            end
            return total
            "#,
        )
        .key(key)
        .arg(bytes)
        .arg(ttl_seconds.max(1))
        .invoke_async(&mut redis)
        .await?)
    }

    pub async fn next_routing_index(
        &self,
        key: &str,
        server_count: usize,
    ) -> Result<usize, StorageError> {
        if let Some(memory) = &self.memory {
            let current = memory
                .get_value(key)
                .await
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            memory
                .set_value(
                    key,
                    serde_json::json!((current + 1) % server_count.max(1) as u64),
                    86400,
                )
                .await;
            return Ok(current as usize);
        }
        let mut redis = self.redis()?;
        let index: u64 = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then current = 0 else current = tonumber(current) end
            local next = (current + 1) % tonumber(ARGV[1])
            redis.call('SET', KEYS[1], next, 'EX', ARGV[2])
            return current
            "#,
        )
        .key(key)
        .arg(server_count.max(1))
        .arg(86400_u64)
        .invoke_async(&mut redis)
        .await?;
        Ok(index as usize)
    }

    pub async fn current_routing_index(&self, key: &str) -> Result<usize, StorageError> {
        Ok(self.current_counter(key).await? as usize)
    }

    pub async fn next_client_routing_index(
        &self,
        key: &str,
        initial: &Value,
        server_count: usize,
    ) -> Result<usize, StorageError> {
        if let Some(memory) = &self.memory {
            let mut value = memory
                .get_value(key)
                .await
                .unwrap_or_else(|| initial.clone());
            let current = value
                .get("server_index")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            value["server_index"] = serde_json::json!((current + 1) % server_count.max(1) as u64);
            memory.set_value(key, value, 86400).await;
            return Ok(current as usize);
        }
        let mut redis = self.redis()?;
        let initial = serde_json::to_string(initial)?;
        let index: u64 = redis::Script::new(
            r#"
            local raw = redis.call('GET', KEYS[1])
            if not raw then raw = ARGV[1] end
            local ok, routing = pcall(cjson.decode, raw)
            if not ok or type(routing) ~= 'table' then
                return redis.error_reply('invalid client routing cache value')
            end
            local current = tonumber(routing.server_index) or 0
            routing.server_index = (current + 1) % tonumber(ARGV[2])
            redis.call('SET', KEYS[1], cjson.encode(routing), 'EX', ARGV[3])
            return current
            "#,
        )
        .key(key)
        .arg(initial)
        .arg(server_count.max(1))
        .arg(86400_u64)
        .invoke_async(&mut redis)
        .await?;
        Ok(index as usize)
    }

    pub async fn current_client_routing_index(
        &self,
        key: &str,
        initial: &Value,
    ) -> Result<usize, StorageError> {
        if let Some(memory) = &self.memory {
            let value = memory
                .get_value(key)
                .await
                .unwrap_or_else(|| initial.clone());
            return Ok(value
                .get("server_index")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize);
        }
        let mut redis = self.redis()?;
        let raw: Option<String> = redis.get(key).await?;
        let value = match raw {
            Some(raw) => serde_json::from_str::<Value>(&raw)?,
            None => initial.clone(),
        };
        Ok(value
            .get("server_index")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize)
    }

    pub async fn current_counter(&self, key: &str) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            return Ok(memory
                .get_value(key)
                .await
                .and_then(|value| value.as_u64())
                .unwrap_or(0));
        }
        let mut redis = self.redis()?;
        Ok(redis.get::<_, Option<u64>>(key).await?.unwrap_or(0))
    }

    pub async fn deduct_credit(&self, username: &str, group: &str) -> Result<bool, StorageError> {
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let documents = collections.entry("user_credits".to_owned()).or_default();
            let Some(document) = documents
                .iter_mut()
                .find(|doc| doc.get("username").and_then(Value::as_str) == Some(username))
            else {
                return Ok(false);
            };
            let Some(available) =
                document.pointer_mut(&format!("/users_credits/{group}/available_credits"))
            else {
                return Ok(false);
            };
            let current = available.as_i64().unwrap_or(0);
            if current <= 0 {
                return Ok(false);
            }
            *available = serde_json::json!(current - 1);
            memory.bump_revision();
            return Ok(true);
        }
        let path = format!("users_credits.{group}.available_credits");
        let mut filter = doc! { "username": username };
        filter.insert(path.clone(), doc! { "$gt": 0 });
        let mut increment = Document::new();
        increment.insert(path, -1_i32);
        let result = self
            .mongo()?
            .collection::<Document>("user_credits")
            .update_one(filter, doc! { "$inc": increment })
            .await?;
        Ok(result.modified_count == 1)
    }

    pub async fn find_many(
        &self,
        collection: &str,
        filter: &Value,
    ) -> Result<Vec<Value>, StorageError> {
        self.chaos_mongo_guard()?;
        if let Some(memory) = &self.memory {
            let collections = memory.collections.read().await;
            return Ok(collections
                .get(collection)
                .into_iter()
                .flatten()
                .filter(|item| value_matches(item, filter))
                .cloned()
                .collect());
        }
        let filter = restored_document(filter)?;
        let mut cursor = self
            .mongo()?
            .collection::<Document>(collection)
            .find(filter)
            .await?;
        let mut values = Vec::new();
        while let Some(document) = cursor.try_next().await? {
            values.push(serde_json::to_value(document)?);
        }
        Ok(values)
    }

    pub async fn find_one(
        &self,
        collection: &str,
        filter: &Value,
    ) -> Result<Option<Value>, StorageError> {
        self.chaos_mongo_guard()?;
        if let Some(memory) = &self.memory {
            let collections = memory.collections.read().await;
            return Ok(collections
                .get(collection)
                .and_then(|items| items.iter().find(|item| value_matches(item, filter)))
                .cloned());
        }
        let filter = restored_document(filter)?;
        self.mongo()?
            .collection::<Document>(collection)
            .find_one(filter)
            .await?
            .map(serde_json::to_value)
            .transpose()
            .map_err(Into::into)
    }

    pub async fn insert_one(
        &self,
        collection: &str,
        mut value: Value,
    ) -> Result<Value, StorageError> {
        self.chaos_mongo_guard()?;
        if value.get("_id").is_none() {
            value["_id"] = Value::String(uuid::Uuid::new_v4().to_string());
        }
        if let Some(memory) = &self.memory {
            memory
                .collections
                .write()
                .await
                .entry(collection.to_owned())
                .or_default()
                .push(value.clone());
            memory.bump_revision();
            self.invalidate_policy_cache().await;
            return Ok(value);
        }
        self.mongo()?
            .collection::<Document>(collection)
            .insert_one(mongodb::bson::to_document(&value)?)
            .await?;
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        Ok(value)
    }

    pub async fn update_one(
        &self,
        collection: &str,
        filter: &Value,
        updates: &Value,
    ) -> Result<Option<Value>, StorageError> {
        self.chaos_mongo_guard()?;
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let Some(item) = collections
                .entry(collection.to_owned())
                .or_default()
                .iter_mut()
                .find(|item| value_matches(item, filter))
            else {
                return Ok(None);
            };
            merge_object(item, updates);
            let result = item.clone();
            memory.bump_revision();
            self.invalidate_policy_cache().await;
            return Ok(Some(result));
        }
        let filter_document = restored_document(filter)?;
        let mut update_document = mongodb::bson::to_document(updates)?;
        update_document.remove("_id");
        let result = self
            .mongo()?
            .collection::<Document>(collection)
            .update_one(filter_document.clone(), doc! { "$set": update_document })
            .await?;
        if result.matched_count == 0 {
            return Ok(None);
        }
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        self.mongo()?
            .collection::<Document>(collection)
            .find_one(filter_document)
            .await?
            .map(serde_json::to_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Replace a matching document while preserving its storage identity.
    ///
    /// Most platform mutations use `$set`-like merge semantics, but selected
    /// Python services intentionally call MongoDB's `replace_one`; omitted
    /// nullable fields must therefore be removed rather than retained.
    pub async fn replace_one(
        &self,
        collection: &str,
        filter: &Value,
        mut replacement: Value,
    ) -> Result<Option<Value>, StorageError> {
        self.chaos_mongo_guard()?;
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let Some(item) = collections
                .entry(collection.to_owned())
                .or_default()
                .iter_mut()
                .find(|item| value_matches(item, filter))
            else {
                return Ok(None);
            };
            if replacement.get("_id").is_none() {
                replacement["_id"] = item.get("_id").cloned().unwrap_or(Value::Null);
            }
            *item = replacement;
            let result = item.clone();
            memory.bump_revision();
            self.invalidate_policy_cache().await;
            return Ok(Some(result));
        }
        let filter_document = restored_document(filter)?;
        let mut replacement_document = mongodb::bson::to_document(&replacement)?;
        replacement_document.remove("_id");
        let result = self
            .mongo()?
            .collection::<Document>(collection)
            .replace_one(filter_document.clone(), replacement_document)
            .await?;
        if result.matched_count == 0 {
            return Ok(None);
        }
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        self.mongo()?
            .collection::<Document>(collection)
            .find_one(filter_document)
            .await?
            .map(serde_json::to_value)
            .transpose()
            .map_err(Into::into)
    }

    pub async fn delete_one(&self, collection: &str, filter: &Value) -> Result<bool, StorageError> {
        self.chaos_mongo_guard()?;
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let items = collections.entry(collection.to_owned()).or_default();
            let before = items.len();
            items.retain(|item| !value_matches(item, filter));
            let deleted = before != items.len();
            if deleted {
                memory.bump_revision();
                self.invalidate_policy_cache().await;
            }
            return Ok(deleted);
        }
        let result = self
            .mongo()?
            .collection::<Document>(collection)
            .delete_one(restored_document(filter)?)
            .await?;
        if result.deleted_count > 0 {
            self.bump_policy_revision().await?;
            self.invalidate_policy_cache().await;
        }
        Ok(result.deleted_count > 0)
    }

    /// Remove expired per-token revocations while retaining non-expiring
    /// revoke-all records.  This deliberately lives in the storage layer so
    /// the memory and MongoDB backends have identical cleanup semantics.
    pub async fn purge_expired_revocations(&self, now_seconds: u64) -> Result<u64, StorageError> {
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let records = collections.entry("revocations".to_owned()).or_default();
            let before = records.len();
            records.retain(|record| {
                // Python's purge_expired_tokens treats a missing/malformed expires_at
                // as 0 and deletes it, which would silently un-revoke a token on data
                // corruption. Rust deliberately keeps such rows instead (approved
                // security-safe divergence) and relies on the request-time check to
                // keep ignoring them safely.
                let expired_jti = record.get("type").and_then(Value::as_str) == Some("jti")
                    && record
                        .get("expires_at")
                        .and_then(Value::as_u64)
                        .is_some_and(|expires_at| expires_at <= now_seconds);
                !expired_jti
            });
            let removed = (before - records.len()) as u64;
            if removed > 0 {
                memory.bump_revision();
                self.invalidate_policy_cache().await;
            }
            return Ok(removed);
        }

        let result = self
            .mongo()?
            .collection::<Document>("revocations")
            .delete_many(doc! {
                "type": "jti",
                "expires_at": { "$lte": now_seconds as i64 },
            })
            .await?;
        if result.deleted_count > 0 {
            self.bump_policy_revision().await?;
            self.invalidate_policy_cache().await;
        }
        Ok(result.deleted_count)
    }

    pub async fn replace_collection(
        &self,
        collection: &str,
        values: Vec<Value>,
    ) -> Result<(), StorageError> {
        if let Some(memory) = &self.memory {
            memory
                .collections
                .write()
                .await
                .insert(collection.to_owned(), values);
            memory.bump_revision();
            self.invalidate_policy_cache().await;
            return Ok(());
        }
        let target = self.mongo()?.collection::<Document>(collection);
        target.delete_many(doc! {}).await?;
        if !values.is_empty() {
            let documents = values
                .iter()
                .map(restored_document)
                .collect::<Result<Vec<_>, _>>()?;
            target.insert_many(documents).await?;
        }
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        Ok(())
    }

    /// Replace a related set of collections as one configuration change.
    ///
    /// MongoDB deployments must provide transaction support (a replica set or
    /// sharded cluster).  Failing that precondition is safer than partially
    /// applying a configuration import or rollback.
    pub async fn replace_collections_atomically(
        &self,
        replacements: &[(String, Vec<Value>)],
        snapshot: Option<Value>,
    ) -> Result<(), StorageError> {
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            if let Some(snapshot) = snapshot {
                collections
                    .entry("config_snapshots".to_owned())
                    .or_default()
                    .push(snapshot);
            }
            for (collection, values) in replacements {
                collections.insert(collection.clone(), values.clone());
            }
            memory.bump_revision();
            self.invalidate_policy_cache().await;
            return Ok(());
        }

        let database = self.mongo()?;
        let documents = replacements
            .iter()
            .map(|(collection, values)| {
                values
                    .iter()
                    .map(restored_document)
                    .collect::<Result<Vec<_>, _>>()
                    .map(|documents| (collection.as_str(), documents))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = snapshot
            .map(|value| restored_document(&value))
            .transpose()?;
        let mut session = database.client().start_session().await?;
        session.start_transaction().await?;

        let result: Result<(), StorageError> = async {
            if let Some(snapshot) = snapshot.as_ref() {
                database
                    .collection::<Document>("config_snapshots")
                    .insert_one(snapshot)
                    .session(&mut session)
                    .await?;
            }
            for (collection, values) in &documents {
                let target = database.collection::<Document>(collection);
                target.delete_many(doc! {}).session(&mut session).await?;
                if !values.is_empty() {
                    target.insert_many(values).session(&mut session).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            let _ = session.abort_transaction().await;
            return Err(error);
        }
        session.commit_transaction().await?;
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        Ok(())
    }

    /// Capture the rollback snapshot and merge the import under one memory
    /// lock or MongoDB transaction, including reads of the current documents.
    pub async fn import_configuration_atomically(
        &self,
        payload: &Value,
        mut snapshot: Value,
    ) -> Result<Value, StorageError> {
        use super::configuration::{COLLECTIONS, merge_import};
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let mut current = COLLECTIONS
                .into_iter()
                .map(|name| {
                    (
                        name.to_owned(),
                        collections.get(name).cloned().unwrap_or_default(),
                    )
                })
                .collect::<std::collections::HashMap<_, _>>();
            snapshot["data"] = serde_json::to_value(&current)?;
            let counts = merge_import(&mut current, payload)?;
            collections.extend(current);
            collections
                .entry("config_snapshots".to_owned())
                .or_default()
                .push(snapshot);
            memory.bump_revision();
            drop(collections);
            self.invalidate_policy_cache().await;
            return Ok(counts);
        }

        let database = self.mongo()?;
        let mut session = database.client().start_session().await?;
        session.start_transaction().await?;
        let result: Result<Value, StorageError> = async {
            let mut current = std::collections::HashMap::new();
            for name in COLLECTIONS {
                let mut cursor = database
                    .collection::<Document>(name)
                    .find(doc! {})
                    .session(&mut session)
                    .await?;
                let mut documents = Vec::new();
                while let Some(document) = cursor.stream(&mut session).try_next().await? {
                    documents.push(serde_json::to_value(document)?);
                }
                current.insert(name.to_owned(), documents);
            }
            snapshot["data"] = serde_json::to_value(&current)?;
            let counts = merge_import(&mut current, payload)?;
            database
                .collection::<Document>("config_snapshots")
                .insert_one(restored_document(&snapshot)?)
                .session(&mut session)
                .await?;
            for name in COLLECTIONS {
                let target = database.collection::<Document>(name);
                let documents = current[name]
                    .iter()
                    .map(restored_document)
                    .collect::<Result<Vec<_>, _>>()?;
                target.delete_many(doc! {}).session(&mut session).await?;
                if !documents.is_empty() {
                    target.insert_many(documents).session(&mut session).await?;
                }
            }
            Ok(counts)
        }
        .await;
        let counts = match result {
            Ok(counts) => counts,
            Err(error) => {
                let _ = session.abort_transaction().await;
                return Err(error);
            }
        };
        session.commit_transaction().await?;
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        Ok(counts)
    }

    pub async fn crud_find_one(
        &self,
        collection: &str,
        resource_id: &str,
    ) -> Result<Option<Value>, StorageError> {
        if let Some(memory) = &self.memory {
            let collections = memory.collections.read().await;
            return Ok(collections
                .get(collection)
                .and_then(|items| {
                    items
                        .iter()
                        .find(|item| item.get("_id").and_then(Value::as_str) == Some(resource_id))
                })
                .cloned());
        }
        let document = self
            .mongo()?
            .collection::<Document>(collection)
            .find_one(doc! { "_id": resource_id })
            .await?;
        document
            .map(serde_json::to_value)
            .transpose()
            .map_err(Into::into)
    }

    pub async fn crud_list(&self, collection: &str) -> Result<Vec<Value>, StorageError> {
        if let Some(memory) = &self.memory {
            return Ok(memory
                .collections
                .read()
                .await
                .get(collection)
                .cloned()
                .unwrap_or_default());
        }
        let mut cursor = self
            .mongo()?
            .collection::<Document>(collection)
            .find(doc! {})
            .await?;
        let mut values = Vec::new();
        while let Some(document) = cursor.try_next().await? {
            values.push(serde_json::to_value(document)?);
        }
        Ok(values)
    }

    pub async fn crud_insert(&self, collection: &str, value: &Value) -> Result<(), StorageError> {
        if let Some(memory) = &self.memory {
            memory
                .collections
                .write()
                .await
                .entry(collection.to_owned())
                .or_default()
                .push(value.clone());
            memory.bump_revision();
            return Ok(());
        }
        let document = mongodb::bson::to_document(value)?;
        self.mongo()?
            .collection::<Document>(collection)
            .insert_one(document)
            .await?;
        Ok(())
    }

    pub async fn crud_update(
        &self,
        collection: &str,
        resource_id: &str,
        value: &Value,
    ) -> Result<Option<Value>, StorageError> {
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let Some(item) = collections
                .entry(collection.to_owned())
                .or_default()
                .iter_mut()
                .find(|item| item.get("_id").and_then(Value::as_str) == Some(resource_id))
            else {
                return Ok(None);
            };
            if let (Some(target), Some(update)) = (item.as_object_mut(), value.as_object()) {
                for (key, value) in update {
                    if key != "_id" {
                        target.insert(key.clone(), value.clone());
                    }
                }
            }
            let result = item.clone();
            memory.bump_revision();
            return Ok(Some(result));
        }
        let mut update = mongodb::bson::to_document(value)?;
        update.remove("_id");
        let result = self
            .mongo()?
            .collection::<Document>(collection)
            .update_one(doc! { "_id": resource_id }, doc! { "$set": update })
            .await?;
        if result.matched_count == 0 {
            return Ok(None);
        }
        self.crud_find_one(collection, resource_id).await
    }

    pub async fn crud_delete(
        &self,
        collection: &str,
        resource_id: &str,
    ) -> Result<bool, StorageError> {
        if let Some(memory) = &self.memory {
            let mut collections = memory.collections.write().await;
            let items = collections.entry(collection.to_owned()).or_default();
            let before = items.len();
            items.retain(|item| item.get("_id").and_then(Value::as_str) != Some(resource_id));
            let deleted = before != items.len();
            if deleted {
                memory.bump_revision();
            }
            return Ok(deleted);
        }
        let result = self
            .mongo()?
            .collection::<Document>(collection)
            .delete_one(doc! { "_id": resource_id })
            .await?;
        Ok(result.deleted_count > 0)
    }

    pub async fn record_gateway_metric(
        &self,
        metric: GatewayMetric<'_>,
    ) -> Result<(), StorageError> {
        let key = format!("gateway_metrics:{}", metric.minute_start);
        if let Some(memory) = &self.memory {
            let _ = memory.increment(&format!("{key}:count"), 1, 2678400).await;
            let _ = memory
                .increment(
                    &format!("{key}:total_micros"),
                    metric.duration_micros,
                    2678400,
                )
                .await;
            return Ok(());
        }
        let mut redis = self.redis()?;
        let script = redis::Script::new(
            r#"
            redis.call('HINCRBY', KEYS[1], 'count', 1)
            redis.call('HINCRBY', KEYS[1], 'test_count', ARGV[1])
            redis.call('HINCRBY', KEYS[1], 'error_count', ARGV[2])
            redis.call('HINCRBY', KEYS[1], 'total_micros', ARGV[3])
            redis.call('HINCRBY', KEYS[1], 'bytes_in', ARGV[4])
            redis.call('HINCRBY', KEYS[1], 'bytes_out', ARGV[5])
            redis.call('HINCRBY', KEYS[1], 'status:' .. ARGV[6], 1)
            if ARGV[7] ~= '' and ARGV[1] == '0' then
                redis.call('HINCRBY', KEYS[1], 'api:' .. ARGV[7], 1)
            end
            if ARGV[8] ~= '' and ARGV[1] == '0' then
                redis.call('HINCRBY', KEYS[1], 'user:' .. ARGV[8], 1)
            end
            if ARGV[9] ~= '' and ARGV[1] == '0' then
                redis.call('HINCRBY', KEYS[1], 'endpoint:' .. ARGV[9], 1)
            end
            redis.call('EXPIRE', KEYS[1], 2678400)
            return 1
            "#,
        );
        let _: u64 = script
            .key(key)
            .arg(u8::from(metric.is_test))
            .arg(u8::from(metric.status >= 400))
            .arg(metric.duration_micros)
            .arg(metric.bytes_in)
            .arg(metric.bytes_out)
            .arg(metric.status)
            .arg(metric.api_key.unwrap_or_default())
            .arg(metric.username.unwrap_or_default())
            .arg(metric.endpoint.unwrap_or_default())
            .invoke_async(&mut redis)
            .await?;
        Ok(())
    }

    pub async fn mongo_healthy(&self) -> bool {
        if self.is_memory() {
            return true;
        }
        match self.mongo() {
            Ok(mongo) => mongo.run_command(doc! { "ping": 1 }).await.is_ok(),
            Err(_) => false,
        }
    }

    pub async fn redis_healthy(&self) -> bool {
        if self.is_memory() {
            return true;
        }
        let Ok(mut redis) = self.redis() else {
            return false;
        };
        redis::cmd("PING")
            .query_async::<String>(&mut redis)
            .await
            .is_ok()
    }

    pub async fn clear_gateway_state(&self) -> Result<(), StorageError> {
        if let Some(memory) = &self.memory {
            memory.clear_runtime().await;
            self.invalidate_policy_cache().await;
            return Ok(());
        }
        const PATTERNS: &[&str] = &[
            "api_cache:*",
            "api_endpoint_cache:*",
            "api_id_cache:*",
            "endpoint_cache:*",
            "endpoint_validation_cache:*",
            "graphql_schema_cache:*",
            "group_cache:*",
            "openapi_cache:*",
            "role_cache:*",
            "user_subscription_cache:*",
            "user_cache:*",
            "user_group_cache:*",
            "user_role_cache:*",
            "endpoint_load_balancer:*",
            "endpoint_server_cache:*",
            "client_routing_cache:*",
            "token_def_cache:*",
            "credit_def_cache:*",
            "csrf_token_map:*",
            "wsdl_cache:*",
            "rate_limit:*",
            "throttle_limit:*",
            "bandwidth_usage:*",
            "ip_rate_limit:*",
            "tier_rate_limit:*",
            "gateway_metrics:*",
        ];
        let mut redis = self.redis()?;
        for pattern in PATTERNS {
            let mut cursor = 0_u64;
            loop {
                let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(pattern)
                    .arg("COUNT")
                    .arg(500_u64)
                    .query_async(&mut redis)
                    .await?;
                if !keys.is_empty() {
                    let _: usize = redis::cmd("DEL").arg(keys).query_async(&mut redis).await?;
                }
                cursor = next;
                if cursor == 0 {
                    break;
                }
            }
        }
        self.bump_policy_revision().await?;
        self.invalidate_policy_cache().await;
        Ok(())
    }
}

fn value_matches(item: &Value, filter: &Value) -> bool {
    let Some(filter) = filter.as_object() else {
        return true;
    };
    filter.iter().all(|(key, expected)| {
        if key == "$or" {
            return expected.as_array().is_none_or(|alternatives| {
                alternatives
                    .iter()
                    .any(|alternative| value_matches(item, alternative))
            });
        }
        if let Some(candidates) = expected.get("$in").and_then(Value::as_array) {
            return item
                .get(key)
                .is_some_and(|actual| candidates.contains(actual));
        }
        item.get(key) == Some(expected)
    })
}

fn merge_object(target: &mut Value, updates: &Value) {
    if let (Some(target), Some(updates)) = (target.as_object_mut(), updates.as_object()) {
        for (key, value) in updates {
            if key == "_id" {
                continue;
            }
            let parts = key.split('.').collect::<Vec<_>>();
            let mut current = &mut *target;
            for part in &parts[..parts.len().saturating_sub(1)] {
                let entry = current
                    .entry((*part).to_owned())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if !entry.is_object() {
                    *entry = Value::Object(serde_json::Map::new());
                }
                current = entry.as_object_mut().expect("object inserted above");
            }
            let leaf = parts.last().copied().unwrap_or(key.as_str());
            current.insert(leaf.to_owned(), value.clone());
        }
    }
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn tls_mutation_lock_serializes_cloned_memory_storage() {
        let storage = SharedStorage::connect(&crate::config::SharedStorageConfig::default())
            .await
            .unwrap();
        let first = storage.tls_mutation_lock().await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                storage.clone().tls_mutation_lock()
            )
            .await
            .is_err()
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), storage.tls_mutation_lock())
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn memory_filters_match_python_or_and_in_contracts() {
        let item = json!({"name": "alice", "role": "admin"});
        assert!(value_matches(
            &item,
            &json!({"$or": [{"name": "missing"}, {"role": "admin"}]})
        ));
        assert!(value_matches(
            &item,
            &json!({"name": {"$in": ["alice", "bob"]}})
        ));
        assert!(!value_matches(&item, &json!({"name": {"$in": ["bob"]}})));
    }

    #[tokio::test]
    async fn purge_expired_revocations_preserves_malformed_and_missing_expiry() {
        // Deliberate divergence from Python's purge_expired_tokens, which treats a
        // missing/malformed expires_at as 0 and deletes it -- that would silently
        // un-revoke a token on data corruption. Rust keeps these rows; the
        // request-time revocation check already ignores them safely.
        let config = crate::config::SharedStorageConfig::default();
        let storage = SharedStorage::connect(&config).await.unwrap();
        storage
            .insert_one(
                "revocations",
                json!({"type": "jti", "username": "u", "jti": "no-expiry"}),
            )
            .await
            .unwrap();
        storage
            .insert_one(
                "revocations",
                json!({"type": "jti", "username": "u", "jti": "bad-expiry", "expires_at": "nope"}),
            )
            .await
            .unwrap();
        storage
            .insert_one(
                "revocations",
                json!({"type": "jti", "username": "u", "jti": "expired", "expires_at": 1u64}),
            )
            .await
            .unwrap();
        let removed = storage.purge_expired_revocations(1_000).await.unwrap();
        assert_eq!(removed, 1);
        let remaining = storage.find_many("revocations", &json!({})).await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().any(|record| record["jti"] == "no-expiry"));
        assert!(remaining.iter().any(|record| record["jti"] == "bad-expiry"));
    }

    #[test]
    fn memory_updates_set_null_and_dotted_fields_like_python() {
        let mut item = json!({"profile": "old", "keep": true});
        merge_object(
            &mut item,
            &json!({"profile.email": "a@example.com", "keep": null}),
        );
        assert_eq!(
            item,
            json!({"profile": {"email": "a@example.com"}, "keep": null})
        );
    }
}
