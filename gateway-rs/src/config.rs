use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub connect_timeout: Duration,
    pub https_only: bool,
    pub content_security_policy: Option<String>,
    pub compression_enabled: bool,
    pub compression_level: i32,
    pub compression_minimum_size: u16,
    pub strict_response_envelope: bool,
    pub websockets_enabled: bool,
    pub logs_dir: Option<PathBuf>,
    pub security_settings_file: Option<PathBuf>,
    pub shared_storage: SharedStorageConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedStorageConfig {
    pub storage_mode: String,
    pub mongo_uri_override: Option<String>,
    pub mongo_hosts: String,
    pub mongo_replica_set: Option<String>,
    pub mongo_user: Option<String>,
    pub mongo_password: Option<String>,
    pub mongo_database: String,
    pub mongo_auth_source: Option<String>,
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_db: u32,
    pub redis_password: Option<String>,
    pub jwt_keys_json: Option<String>,
    pub jwt_secret: Option<String>,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub token_encryption_key: Option<String>,
    pub trust_x_forwarded_for: bool,
    pub local_host_ip_bypass: bool,
    pub local_host_ip_bypass_locked: bool,
    pub policy_cache_ttl_seconds: u64,
    pub skip_tier_rate_limit: bool,
}

impl SharedStorageConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            storage_mode: env::var("MEM_OR_EXTERNAL")
                .or_else(|_| env::var("MEM_OR_REDIS"))
                .unwrap_or_else(|_| "MEM".to_owned()),
            mongo_uri_override: env_non_empty("MONGO_DB_URI"),
            mongo_hosts: env::var("MONGO_DB_HOSTS")
                .unwrap_or_else(|_| "localhost:27017".to_owned()),
            mongo_replica_set: env_non_empty("MONGO_REPLICA_SET_NAME"),
            mongo_user: env_non_empty("MONGO_DB_USER"),
            mongo_password: env_non_empty("MONGO_DB_PASSWORD"),
            mongo_database: env::var("MONGO_DB_NAME").unwrap_or_else(|_| "doorman".to_owned()),
            mongo_auth_source: env_non_empty("MONGO_DB_AUTH_SOURCE"),
            redis_host: env::var("REDIS_HOST").unwrap_or_else(|_| "localhost".to_owned()),
            redis_port: env_parse("REDIS_PORT", 6379)?,
            redis_db: env_parse("REDIS_DB", 0)?,
            redis_password: env_non_empty("REDIS_PASSWORD"),
            jwt_keys_json: env_non_empty("JWT_KEYS"),
            jwt_secret: env_non_empty("JWT_SECRET_KEY"),
            jwt_issuer: env_non_empty("JWT_ISSUER").unwrap_or_else(|| "doorman-gateway".to_owned()),
            jwt_audience: env_non_empty("JWT_AUDIENCE")
                .unwrap_or_else(|| "doorman-gateway".to_owned()),
            token_encryption_key: env_non_empty("TOKEN_ENCRYPTION_KEY")
                .or_else(|| env_non_empty("MEM_ENCRYPTION_KEY")),
            trust_x_forwarded_for: env_bool("TRUST_X_FORWARDED_FOR", false),
            local_host_ip_bypass: env_bool("LOCAL_HOST_IP_BYPASS", false),
            local_host_ip_bypass_locked: env_non_empty("LOCAL_HOST_IP_BYPASS").is_some(),
            policy_cache_ttl_seconds: env_parse("GATEWAY_POLICY_CACHE_TTL_SECONDS", 1)?,
            skip_tier_rate_limit: env_bool("SKIP_TIER_RATE_LIMIT", false),
        })
    }

    pub fn mongo_uri(&self) -> String {
        if let Some(uri) = self.mongo_uri_override.as_ref() {
            return uri.clone();
        }
        let auth = match (&self.mongo_user, &self.mongo_password) {
            (Some(user), Some(password)) => format!("{user}:{password}@"),
            _ => String::new(),
        };
        let mut options = Vec::new();
        if self.mongo_hosts.contains(',')
            && let Some(value) = self
                .mongo_replica_set
                .as_deref()
                .filter(|value| !value.is_empty())
        {
            options.push(format!("replicaSet={value}"));
        }
        if let Some(value) = self
            .mongo_auth_source
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            options.push(format!("authSource={value}"));
        }
        let query = if options.is_empty() {
            String::new()
        } else {
            format!("?{}", options.join("&"))
        };
        format!(
            "mongodb://{auth}{}/{database}{query}",
            self.mongo_hosts,
            database = self.mongo_database
        )
    }

    pub fn redis_url(&self) -> String {
        match &self.redis_password {
            Some(password) => format!(
                "redis://:{}@{}:{}/{}",
                password, self.redis_host, self.redis_port, self.redis_db
            ),
            None => format!(
                "redis://{}:{}/{}",
                self.redis_host, self.redis_port, self.redis_db
            ),
        }
    }

    fn validate_required(&self) -> Result<(), ConfigError> {
        if self.storage_mode.eq_ignore_ascii_case("MEM") {
            if self.jwt_keys_json.is_none() && self.jwt_secret.is_none() {
                return Err(ConfigError::MissingEnv("JWT_SECRET_KEY or JWT_KEYS"));
            }
            return Ok(());
        }
        if self.mongo_user.is_none() {
            return Err(ConfigError::MissingEnv("MONGO_DB_USER"));
        }
        if self.mongo_password.is_none() {
            return Err(ConfigError::MissingEnv("MONGO_DB_PASSWORD"));
        }
        if self.jwt_keys_json.is_none() && self.jwt_secret.is_none() {
            return Err(ConfigError::MissingEnv("JWT_SECRET_KEY or JWT_KEYS"));
        }
        Ok(())
    }
}

impl Default for SharedStorageConfig {
    fn default() -> Self {
        Self {
            storage_mode: "MEM".to_owned(),
            mongo_uri_override: None,
            mongo_hosts: "localhost:27017".to_owned(),
            mongo_replica_set: Some("rs0".to_owned()),
            mongo_user: Some("doorman_admin".to_owned()),
            mongo_password: Some("changeme".to_owned()),
            mongo_database: "doorman".to_owned(),
            mongo_auth_source: Some("admin".to_owned()),
            redis_host: "localhost".to_owned(),
            redis_port: 6379,
            redis_db: 0,
            redis_password: None,
            jwt_keys_json: None,
            jwt_secret: Some("insecure-test-key".to_owned()),
            jwt_issuer: "doorman-gateway".to_owned(),
            jwt_audience: "doorman-gateway".to_owned(),
            token_encryption_key: None,
            trust_x_forwarded_for: false,
            local_host_ip_bypass: false,
            local_host_ip_bypass_locked: false,
            policy_cache_ttl_seconds: 1,
            skip_tier_rate_limit: false,
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        crate::python_scalar::integer_digit_limit()
            .map_err(|message| ConfigError::InvalidConfiguration(message.to_owned()))?;
        let shared_storage = SharedStorageConfig::from_env()?;
        shared_storage.validate_required()?;
        validate_runtime_environment(&shared_storage)?;

        let configured_compression_level = env_parse("COMPRESSION_LEVEL", 6_i32)?;
        let compression_level = if (1..=9).contains(&configured_compression_level) {
            configured_compression_level
        } else {
            tracing::warn!(
                value = configured_compression_level,
                "invalid COMPRESSION_LEVEL; using 1"
            );
            1
        };
        let compression_minimum_size =
            env_parse::<u64>("COMPRESSION_MINIMUM_SIZE", 500)?.min(u64::from(u16::MAX)) as u16;

        Ok(Self {
            host: env::var("HOST")
                .or_else(|_| env::var("GATEWAY_RUST_HOST"))
                .unwrap_or_else(|_| "0.0.0.0".to_owned()),
            port: env_parse("PORT", 3001)?,
            connect_timeout: python_http_connect_timeout()?,
            https_only: env_bool("HTTPS_ONLY", false),
            content_security_policy: env::var("CONTENT_SECURITY_POLICY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            compression_enabled: env_bool("COMPRESSION_ENABLED", true),
            compression_level,
            compression_minimum_size,
            strict_response_envelope: env_bool("STRICT_RESPONSE_ENVELOPE", false),
            websockets_enabled: env_bool("WEBSOCKETS_ENABLED", false),
            logs_dir: env_non_empty("LOGS_DIR").map(PathBuf::from).or_else(|| {
                let path = PathBuf::from("/app/logs");
                path.exists().then_some(path)
            }),
            shared_storage,
            security_settings_file: Some(
                env::var("SECURITY_SETTINGS_FILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("generated/security_settings.json")),
            ),
        })
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.bind_addr()
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(self.bind_addr()))
    }

    pub fn for_test(_removed_backend_url: String) -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 0,
            connect_timeout: Duration::from_secs(1),
            https_only: false,
            content_security_policy: None,
            compression_enabled: true,
            compression_level: 6,
            compression_minimum_size: 500,
            strict_response_envelope: false,
            websockets_enabled: false,
            logs_dir: None,
            // Tests opt into an isolated path when exercising file persistence.
            security_settings_file: None,
            shared_storage: SharedStorageConfig::default(),
        }
    }
}

fn validate_runtime_environment(storage: &SharedStorageConfig) -> Result<(), ConfigError> {
    let admin_password = env::var("DOORMAN_ADMIN_PASSWORD")
        .map_err(|_| ConfigError::MissingEnv("DOORMAN_ADMIN_PASSWORD"))?;
    if admin_password.len() < 16 {
        return Err(ConfigError::InvalidConfiguration(
            "DOORMAN_ADMIN_PASSWORD must be at least 16 characters".to_owned(),
        ));
    }
    if ["please-change-me", "changeme", "admin", "password"].contains(&admin_password.as_str()) {
        return Err(ConfigError::InvalidConfiguration(
            "DOORMAN_ADMIN_PASSWORD must not use a default value".to_owned(),
        ));
    }
    if let Some(secret) = storage.jwt_secret.as_deref()
        && secret.len() < 32
    {
        return Err(ConfigError::InvalidConfiguration(
            "JWT_SECRET_KEY must be at least 32 characters".to_owned(),
        ));
    }
    let environment = env_non_empty("ENV").ok_or_else(|| {
        ConfigError::InvalidConfiguration(
            "ENV must be explicitly set to development or production".to_owned(),
        )
    })?;
    if !matches!(
        environment.to_ascii_lowercase().as_str(),
        "development" | "dev" | "production" | "prod"
    ) {
        return Err(ConfigError::InvalidConfiguration(
            "ENV must be development or production".to_owned(),
        ));
    }
    let workers = env_parse::<u64>("THREADS", 1)?;
    if storage.storage_mode.eq_ignore_ascii_case("MEM") && workers > 1 {
        return Err(ConfigError::InvalidConfiguration(
            "MEM_OR_EXTERNAL=MEM requires THREADS=1; use shared storage for multiple workers"
                .to_owned(),
        ));
    }
    if let Some(keys) = storage.jwt_keys_json.as_deref() {
        if !has_strong_jwt_key(keys) {
            return Err(ConfigError::InvalidConfiguration(
                "JWT_KEYS must contain an active HS256 key of at least 32 characters or a non-empty RS256 key".to_owned(),
            ));
        }
    }
    if matches!(
        environment.to_ascii_lowercase().as_str(),
        "production" | "prod"
    ) {
        validate_production_secrets(storage)?;
        if !env_bool("HTTPS_ONLY", false) {
            return Err(ConfigError::InvalidConfiguration(
                "production requires HTTPS_ONLY=true".to_owned(),
            ));
        }
        let origins = env_non_empty("ALLOWED_ORIGINS").ok_or_else(|| {
            ConfigError::InvalidConfiguration(
                "production requires explicit ALLOWED_ORIGINS".to_owned(),
            )
        })?;
        if origins
            .split(',')
            .map(str::trim)
            .any(|origin| origin.is_empty() || origin == "*")
        {
            return Err(ConfigError::InvalidConfiguration(
                "production ALLOWED_ORIGINS must not contain wildcard or empty origins".to_owned(),
            ));
        }
        if !env_bool("CORS_STRICT", false) {
            return Err(ConfigError::InvalidConfiguration(
                "production requires CORS_STRICT=true".to_owned(),
            ));
        }
        if storage.local_host_ip_bypass {
            return Err(ConfigError::InvalidConfiguration(
                "production requires LOCAL_HOST_IP_BYPASS=false".to_owned(),
            ));
        }
        if env_non_empty("DISCOVERY_ALLOWED_HOSTS").is_none() {
            return Err(ConfigError::InvalidConfiguration(
                "production requires DISCOVERY_ALLOWED_HOSTS".to_owned(),
            ));
        }
        if let Some(secret) = storage.jwt_secret.as_deref()
            && [
                "please-change-me",
                "test-secret-key",
                "test-secret-key-please-change",
                "insecure-test-key",
            ]
            .contains(&secret)
        {
            return Err(ConfigError::InvalidConfiguration(
                "production JWT_SECRET_KEY must not use a default value".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_production_secrets(storage: &SharedStorageConfig) -> Result<(), ConfigError> {
    for (name, value) in [
        ("JWT_ISSUER", &storage.jwt_issuer),
        ("JWT_AUDIENCE", &storage.jwt_audience),
    ] {
        if value.trim().is_empty() || value == "doorman-gateway" {
            return Err(ConfigError::InvalidConfiguration(format!(
                "production requires an explicit, unique {name}"
            )));
        }
    }
    if storage.storage_mode.eq_ignore_ascii_case("MEM") {
        let key = env_non_empty("MEM_ENCRYPTION_KEY").ok_or_else(|| {
            ConfigError::InvalidConfiguration(
                "production MEM mode requires MEM_ENCRYPTION_KEY".to_owned(),
            )
        })?;
        if key.len() < 32
            || ["change-me-in-prod", "please-change-me", "changeme"].contains(&key.as_str())
        {
            return Err(ConfigError::InvalidConfiguration(
                "MEM_ENCRYPTION_KEY must be a unique 32+ character secret in production".to_owned(),
            ));
        }
    } else {
        let mongo_password = storage.mongo_password.as_deref().unwrap_or_default();
        if mongo_password.len() < 16
            || ["changeme", "password", "please-change-me"].contains(&mongo_password)
        {
            return Err(ConfigError::InvalidConfiguration(
                "production external storage requires a unique MongoDB password of at least 16 characters".to_owned(),
            ));
        }
        let redis_password = storage.redis_password.as_deref().unwrap_or_default();
        if redis_password.len() < 16
            || ["changeme", "password", "please-change-me"].contains(&redis_password)
        {
            return Err(ConfigError::InvalidConfiguration(
                "production external storage requires a unique Redis password of at least 16 characters".to_owned(),
            ));
        }
    }
    Ok(())
}

fn has_strong_jwt_key(raw: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    let entries = value
        .get("keys")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| value.as_array().cloned())
        .unwrap_or_else(|| vec![value]);
    entries
        .into_iter()
        .filter(|entry| entry.get("active").and_then(Value::as_bool) != Some(false))
        .any(|entry| {
            let algorithm = entry
                .get("algorithm")
                .and_then(Value::as_str)
                .unwrap_or("HS256");
            if algorithm.eq_ignore_ascii_case("RS256") {
                entry
                    .get("private_key")
                    .or_else(|| entry.get("public_key"))
                    .or_else(|| entry.get("verification_key"))
                    .and_then(Value::as_str)
                    .is_some_and(|key| key.len() >= 128)
            } else {
                entry
                    .get("secret")
                    .or_else(|| entry.get("key"))
                    .or_else(|| entry.get("verification_key"))
                    .and_then(Value::as_str)
                    .is_some_and(|key| key.len() >= 32)
            }
        })
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn env_non_empty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn python_http_connect_timeout() -> Result<Duration, ConfigError> {
    let (name, value) = match env::var("HTTP_CONNECT_TIMEOUT") {
        Ok(value) => ("HTTP_CONNECT_TIMEOUT", value),
        Err(_) => match env::var("GATEWAY_CONNECT_TIMEOUT_SECONDS") {
            Ok(value) => ("GATEWAY_CONNECT_TIMEOUT_SECONDS", value),
            Err(_) => return Ok(Duration::from_secs_f64(5.0)),
        },
    };
    let seconds = value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| ConfigError::InvalidValue(name.to_owned(), value.clone()))?;
    Ok(Duration::from_secs_f64(seconds))
}

fn env_parse<T>(name: &str, default: T) -> Result<T, ConfigError>
where
    T: FromStr + Copy,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| ConfigError::InvalidValue(name.to_owned(), value)),
        Err(_) => Ok(default),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid value for {0}: {1}")]
    InvalidValue(String, String),
    #[error("invalid gateway bind address: {0}")]
    InvalidAddress(String),
    #[error("missing required environment variable for Rust gateway: {0}")]
    MissingEnv(&'static str),
    #[error("invalid runtime configuration: {0}")]
    InvalidConfiguration(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct EnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvRestore {
        fn set(values: &[(&'static str, &str)]) -> Self {
            let previous = values
                .iter()
                .map(|(name, _)| (*name, std::env::var_os(name)))
                .collect();
            unsafe {
                for (name, value) in values {
                    std::env::set_var(name, value);
                }
            }
            Self(previous)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            unsafe {
                for (name, value) in self.0.drain(..) {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    #[test]
    fn compression_defaults_match_python() {
        let config = Config::for_test("http://127.0.0.1:9".to_owned());
        assert!(config.compression_enabled);
        assert_eq!(config.compression_level, 6);
        assert_eq!(config.compression_minimum_size, 500);
    }

    #[test]
    fn builds_python_compatible_storage_urls() {
        let storage = SharedStorageConfig {
            storage_mode: "REDIS".to_owned(),
            mongo_uri_override: None,
            mongo_hosts: "mongo-a:27017,mongo-b:27017".to_owned(),
            mongo_replica_set: Some("rs0".to_owned()),
            mongo_user: Some("doorman".to_owned()),
            mongo_password: Some("secret".to_owned()),
            mongo_database: "doorman".to_owned(),
            mongo_auth_source: Some("admin".to_owned()),
            redis_host: "redis".to_owned(),
            redis_port: 6380,
            redis_db: 2,
            redis_password: Some("redis-secret".to_owned()),
            jwt_keys_json: None,
            jwt_secret: Some("jwt".to_owned()),
            jwt_issuer: "doorman-test".to_owned(),
            jwt_audience: "doorman-test-api".to_owned(),
            token_encryption_key: None,
            trust_x_forwarded_for: false,
            local_host_ip_bypass: false,
            local_host_ip_bypass_locked: false,
            policy_cache_ttl_seconds: 1,
            skip_tier_rate_limit: false,
        };

        assert_eq!(
            storage.mongo_uri(),
            "mongodb://doorman:secret@mongo-a:27017,mongo-b:27017/doorman?replicaSet=rs0&authSource=admin"
        );
        assert_eq!(storage.redis_url(), "redis://:redis-secret@redis:6380/2");
    }

    #[test]
    fn jwt_configuration_presence_matches_python() {
        let mut storage = SharedStorageConfig {
            storage_mode: "MEM".to_owned(),
            mongo_uri_override: None,
            mongo_hosts: "localhost:27017".to_owned(),
            mongo_replica_set: None,
            mongo_user: None,
            mongo_password: None,
            mongo_database: "doorman".to_owned(),
            mongo_auth_source: None,
            redis_host: "localhost".to_owned(),
            redis_port: 6379,
            redis_db: 0,
            redis_password: None,
            jwt_keys_json: None,
            jwt_secret: Some("abc123".to_owned()),
            jwt_issuer: "doorman-test".to_owned(),
            jwt_audience: "doorman-test-api".to_owned(),
            token_encryption_key: None,
            trust_x_forwarded_for: false,
            local_host_ip_bypass: false,
            local_host_ip_bypass_locked: false,
            policy_cache_ttl_seconds: 1,
            skip_tier_rate_limit: false,
        };

        assert!(storage.validate_required().is_ok());
        storage.jwt_secret = None;
        assert!(matches!(
            storage.validate_required(),
            Err(ConfigError::MissingEnv("JWT_SECRET_KEY or JWT_KEYS"))
        ));
    }

    #[test]
    fn worker_safety_matches_python_for_memory_and_shared_storage() {
        let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _environment = EnvRestore::set(&[
            ("MEM_OR_EXTERNAL", "MEM"),
            ("THREADS", "2"),
            ("ENV", "development"),
            ("DOORMAN_ADMIN_PASSWORD", "WorkerSafetyPassword123!"),
        ]);

        let memory = SharedStorageConfig::from_env().unwrap();
        let error = validate_runtime_environment(&memory).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("MEM_OR_EXTERNAL=MEM requires THREADS=1")
        );

        unsafe { std::env::set_var("THREADS", "1") };
        let single_memory = SharedStorageConfig::from_env().unwrap();
        assert!(validate_runtime_environment(&single_memory).is_ok());

        unsafe {
            std::env::set_var("MEM_OR_EXTERNAL", "REDIS");
            std::env::set_var("THREADS", "4");
        }
        let shared = SharedStorageConfig::from_env().unwrap();
        assert!(validate_runtime_environment(&shared).is_ok());
    }

    #[test]
    fn production_https_guard_rejects_insecure_and_accepts_complete_secure_config() {
        let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _environment = EnvRestore::set(&[
            ("ENV", "production"),
            ("HTTPS_ONLY", "false"),
            ("MEM_OR_EXTERNAL", "MEM"),
            ("THREADS", "1"),
            ("DOORMAN_ADMIN_PASSWORD", "ProductionAdminPassword123!"),
            (
                "MEM_ENCRYPTION_KEY",
                "production-memory-key-with-at-least-32-characters",
            ),
            ("JWT_ISSUER", "doorman-production"),
            ("JWT_AUDIENCE", "doorman-production-api"),
            ("ALLOWED_ORIGINS", "https://console.example.test"),
            ("CORS_STRICT", "true"),
            ("LOCAL_HOST_IP_BYPASS", "false"),
            ("DISCOVERY_ALLOWED_HOSTS", "api.example.test"),
        ]);
        let storage = SharedStorageConfig::from_env().unwrap();
        let error = validate_runtime_environment(&storage).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("production requires HTTPS_ONLY=true")
        );

        unsafe { std::env::set_var("HTTPS_ONLY", "true") };
        let storage = SharedStorageConfig::from_env().unwrap();
        assert!(validate_runtime_environment(&storage).is_ok());
    }
}
