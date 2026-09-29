use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Instant,
};

use reqwest::{Client, redirect::Policy};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::watch;
use tokio_rustls::rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate as GrpcCertificate, Channel, ClientTlsConfig, Endpoint, Identity as GrpcIdentity};

use crate::{
    config::Config,
    gateway::circuit_breaker::CircuitEntry,
    hot_reload::HotReloadConfig,
    storage::{
        models::PolicyDocuments,
        runtime::{SharedStorage, StorageError},
    },
    tls::{TlsReloadHandle, profiles::{TlsProfileError, TlsProfiles}, secrets::TlsSecretError, server_config_from_pem_with_roots},
    validation::json::ValidatorRegistry,
};

#[derive(Debug, Error)]
pub enum StateError {
    #[error("failed to construct gateway HTTP client: {0}")]
    Http(#[from] reqwest::Error),
    #[error("required shared storage is unavailable: {0}")]
    Storage(#[from] StorageError),
    #[error("TLS profiles could not be loaded: {0}")]
    TlsProfiles(#[from] TlsProfileError),
    #[error("TLS material could not be read: {0}")]
    TlsIo(#[from] std::io::Error),
    #[error("TLS secret could not be decrypted: {0}")]
    TlsSecret(#[from] TlsSecretError),
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub proxy_client: Client,
    tls_snapshot: Arc<std::sync::RwLock<Arc<TlsSnapshot>>>,
    tls_listener_handle: Arc<Mutex<Option<TlsReloadHandle>>>,
    tls_listener_hash: Arc<Mutex<Option<[u8; 32]>>>,
    tls_listener_from_admin: Arc<AtomicBool>,
    tls_reload_lock: Arc<tokio::sync::Mutex<()>>,
    grpc_channels: Arc<Mutex<HashMap<(u64, String, String, u64), Channel>>>,
    pub policy_documents: Option<Arc<Mutex<PolicyDocuments>>>,
    pub storage: Option<Arc<SharedStorage>>,
    pub runtime: Arc<GatewayRuntime>,
    pub hot_reload: Arc<HotReloadConfig>,
    pub validators: Arc<ValidatorRegistry>,
}

pub struct TlsSnapshot {
    pub revision: u64,
    pub profiles: Arc<TlsProfiles>,
    fingerprint: [u8; 32],
    http_clients: HashMap<String, Client>,
}

pub struct GatewayRuntime {
    pub started_at: Instant,
    pub active_requests: AtomicU64,
    pub request_total: AtomicU64,
    pub request_duration_micros: AtomicU64,
    pub request_duration_buckets: [AtomicU64; 11],
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    pub responses_by_status: Mutex<BTreeMap<u16, u64>>,
    pub circuits: Mutex<HashMap<String, CircuitEntry>>,
    pub retries_total: AtomicU64,
    pub upstream_timeouts_total: AtomicU64,
    pub memory_snapshot_healthy: AtomicBool,
    pub metrics_persistence_healthy: AtomicBool,
    pub revocation_purge_healthy: AtomicBool,
    pub activity_log_healthy: AtomicBool,
    pub security_audit_log_healthy: AtomicBool,
    pub tls_reload_success_total: AtomicU64,
    pub tls_reload_failure_total: AtomicU64,
    pub tls_certificate_expiries: Mutex<BTreeMap<String, i64>>,
    memory_autosave_updates: watch::Sender<MemoryAutosaveConfig>,
}

#[derive(Clone, Debug)]
pub struct MemoryAutosaveConfig {
    pub enabled: bool,
    pub frequency_seconds: u64,
    pub dump_path: Option<String>,
}

impl MemoryAutosaveConfig {
    pub fn from_settings(settings: Option<&Value>) -> Self {
        let mut config = Self::default();
        let Some(settings) = settings else {
            return config;
        };
        if let Some(enabled) = settings.get("enable_auto_save").and_then(Value::as_bool) {
            config.enabled = enabled;
        }
        if let Some(frequency_seconds) = settings
            .get("auto_save_frequency_seconds")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
        {
            config.frequency_seconds = frequency_seconds;
        }
        if let Some(path) = settings
            .get("dump_path")
            .and_then(Value::as_str)
            .filter(|path| !path.trim().is_empty())
        {
            config.dump_path = Some(path.to_owned());
        }
        config
    }
}

impl Default for MemoryAutosaveConfig {
    fn default() -> Self {
        let enabled = std::env::var("MEM_AUTO_SAVE_ENABLED")
            .ok()
            .is_some_and(|value| {
                matches!(
                    crate::python_scalar::strip(&value)
                        .to_ascii_lowercase()
                        .as_str(),
                    "1" | "true" | "yes" | "on"
                )
            });
        let frequency_seconds = std::env::var("MEM_AUTO_SAVE_FREQ")
            .ok()
            .and_then(|value| {
                crate::python_scalar::parse_integer(crate::python_scalar::strip(&value))
            })
            .and_then(|value| u64::try_from(value).ok())
            // Python preserves positive environment intervals; the worker
            // applies the 60-second scheduling minimum independently.
            .filter(|value| *value > 0)
            .unwrap_or(900);
        let dump_path = std::env::var("MEM_DUMP_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        Self {
            enabled,
            frequency_seconds,
            dump_path,
        }
    }
}

impl Default for GatewayRuntime {
    fn default() -> Self {
        let (memory_autosave_updates, _) = watch::channel(MemoryAutosaveConfig::default());
        Self {
            started_at: Instant::now(),
            active_requests: AtomicU64::new(0),
            request_total: AtomicU64::new(0),
            request_duration_micros: AtomicU64::new(0),
            request_duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            responses_by_status: Mutex::new(BTreeMap::new()),
            circuits: Mutex::new(HashMap::new()),
            retries_total: AtomicU64::new(0),
            upstream_timeouts_total: AtomicU64::new(0),
            memory_snapshot_healthy: AtomicBool::new(true),
            metrics_persistence_healthy: AtomicBool::new(true),
            revocation_purge_healthy: AtomicBool::new(true),
            activity_log_healthy: AtomicBool::new(true),
            security_audit_log_healthy: AtomicBool::new(true),
            tls_reload_success_total: AtomicU64::new(0),
            tls_reload_failure_total: AtomicU64::new(0),
            tls_certificate_expiries: Mutex::new(BTreeMap::new()),
            memory_autosave_updates,
        }
    }
}

impl GatewayRuntime {
    pub fn memory_autosave_config(&self) -> watch::Receiver<MemoryAutosaveConfig> {
        self.memory_autosave_updates.subscribe()
    }

    pub fn update_memory_autosave_config(&self, config: MemoryAutosaveConfig) {
        self.memory_autosave_updates.send_replace(config);
    }
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, reqwest::Error> {
        let proxy_client = Client::builder()
            .user_agent("doorman-gateway/2.0.0 (compatible; httpx/0.27)")
            .connect_timeout(config.connect_timeout)
            .redirect(Policy::none())
            .pool_max_idle_per_host(32)
            .tcp_keepalive(std::time::Duration::from_secs(60))
            .build()?;
        Ok(Self {
            config,
            proxy_client,
            tls_snapshot: Arc::new(std::sync::RwLock::new(Arc::new(TlsSnapshot {
                revision: 0,
                profiles: Arc::new(TlsProfiles::default()),
                fingerprint: [0; 32],
                http_clients: HashMap::new(),
            }))),
            tls_listener_handle: Arc::new(Mutex::new(None)),
            tls_listener_hash: Arc::new(Mutex::new(None)),
            tls_listener_from_admin: Arc::new(AtomicBool::new(false)),
            tls_reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            grpc_channels: Arc::new(Mutex::new(HashMap::new())),
            policy_documents: None,
            storage: None,
            runtime: Arc::new(GatewayRuntime::default()),
            hot_reload: Arc::new(HotReloadConfig::from_env()),
            validators: Arc::new(ValidatorRegistry::default()),
        })
    }

    pub async fn from_config(config: Config) -> Result<Self, StateError> {
        let mut state = Self::new(config)?;
        state.publish_tls_profiles(TlsProfiles::load_file(state.config.tls_profiles_file.as_deref())?)?;
        let storage = SharedStorage::connect(&state.config.shared_storage).await?;
        storage.initialize_core().await?;
        state.storage = Some(Arc::new(storage));
        Ok(state)
    }

    pub fn tls_snapshot(&self) -> Arc<TlsSnapshot> {
        self.tls_snapshot.read().expect("TLS snapshot lock poisoned").clone()
    }

    pub fn publish_tls_profiles(&self, profiles: TlsProfiles) -> Result<(), StateError> {
        let fingerprint = profiles.fingerprint();
        if self.tls_snapshot().fingerprint == fingerprint {
            return Ok(());
        }
        let expiries = profiles.certificate_expiries();
        let mut http_clients = HashMap::new();
        for (id, profile) in &profiles.upstreams {
            let mut builder = Client::builder()
                .user_agent("doorman-gateway/2.0.0 (compatible; httpx/0.27)")
                .connect_timeout(self.config.connect_timeout)
                .redirect(Policy::none())
                .pool_max_idle_per_host(32)
                .tcp_keepalive(std::time::Duration::from_secs(60));
            if !profile.ca_pem.is_empty() {
                for cert in reqwest::Certificate::from_pem_bundle(&profile.ca_pem)? {
                    builder = builder.add_root_certificate(cert);
                }
            }
            if let (Some(cert), Some(key)) = (&profile.client_cert_pem, &profile.client_key_pem) {
                let mut identity = cert.clone();
                identity.push(b'\n');
                identity.extend_from_slice(key);
                builder = builder.identity(reqwest::Identity::from_pem(&identity)?);
            }
            http_clients.insert(id.clone(), builder.build()?);
        }
        let revision = self.tls_snapshot().revision.saturating_add(1);
        let snapshot = Arc::new(TlsSnapshot { revision, profiles: Arc::new(profiles), fingerprint, http_clients });
        *self.tls_snapshot.write().expect("TLS snapshot lock poisoned") = snapshot;
        self.grpc_channels.lock().expect("gRPC cache lock poisoned").clear();
        let mut active_expiries = self.runtime.tls_certificate_expiries.lock().expect("TLS expiry lock poisoned");
        active_expiries.retain(|name, _| name == "listener");
        active_expiries.extend(expiries);
        self.runtime.tls_reload_success_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub fn set_tls_listener_handle(&self, handle: TlsReloadHandle) {
        *self.tls_listener_handle.lock().expect("TLS listener handle lock poisoned") = Some(handle);
    }

    pub fn tls_listener_from_admin(&self) -> bool {
        self.tls_listener_from_admin.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn reload_tls_from_storage(&self) -> Result<Option<ServerConfig>, StateError> {
        let result = self.reload_tls_from_storage_inner().await;
        if result.is_err() {
            self.runtime.tls_reload_failure_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    async fn reload_tls_from_storage_inner(&self) -> Result<Option<ServerConfig>, StateError> {
        let _guard = self.tls_reload_lock.lock().await;
        let mut profiles = TlsProfiles::load_file(self.config.tls_profiles_file.as_deref())?;
        let documents = match &self.storage {
            Some(storage) => storage.find_many("tls_profiles", &serde_json::json!({})).await?,
            None => Vec::new(),
        };
        profiles.merge_admin_documents(&documents)?;
        let listener = if self.config.downstream_tls_mode == crate::config::DownstreamTlsMode::Native {
            let admin_listener = documents.iter().find(|document| document.get("kind").and_then(Value::as_str) == Some("listener"));
            let roots = profiles.combined_client_roots();
            let admin_material = admin_listener.map(|document| -> Result<_, StateError> {
                let id = document.get("id").and_then(Value::as_str).unwrap_or("listener");
                let cert = document.get("cert_pem").and_then(Value::as_str).ok_or(TlsProfileError::Invalid("listener certificate missing".to_owned()))?;
                let key = document.get("key_pem").and_then(Value::as_str).ok_or(TlsProfileError::Invalid("listener key missing".to_owned()))?;
                let cert = crate::tls::secrets::open(id, "cert_pem", cert)?;
                let key = crate::tls::secrets::open(id, "key_pem", key)?;
                let config = server_config_from_pem_with_roots(&cert, &key, Some(roots.clone()))?;
                Ok((cert, key, config, true))
            });
            let (cert, key, config, from_admin) = match admin_material {
                Some(Ok(material)) => material,
                Some(Err(error)) => {
                    tracing::warn!(%error, "admin TLS listener certificate rejected; using mounted certificate");
                    let cert = std::fs::read(self.config.downstream_tls_cert_file.as_deref().expect("validated TLS certificate path"))?;
                    let key = std::fs::read(self.config.downstream_tls_key_file.as_deref().expect("validated TLS key path"))?;
                    let config = server_config_from_pem_with_roots(&cert, &key, Some(roots))?;
                    (cert, key, config, false)
                }
                None => {
                    let cert = std::fs::read(self.config.downstream_tls_cert_file.as_deref().expect("validated TLS certificate path"))?;
                    let key = std::fs::read(self.config.downstream_tls_key_file.as_deref().expect("validated TLS key path"))?;
                    let config = server_config_from_pem_with_roots(&cert, &key, Some(roots))?;
                    (cert, key, config, false)
                }
            };
            let mut hasher = Sha256::new();
            hasher.update(&cert);
            hasher.update(&key);
            hasher.update(profiles.fingerprint());
            let hash: [u8; 32] = hasher.finalize().into();
            let expiry = crate::tls::certificate_expiry_timestamp(&cert)?;
            Some((config, hash, expiry, from_admin))
        } else {
            None
        };
        self.publish_tls_profiles(profiles)?;
        if let Some((config, hash, expiry, from_admin)) = &listener {
            let mut active = self.tls_listener_hash.lock().expect("TLS listener hash lock poisoned");
            if active.as_ref() != Some(hash) {
                if let Some(handle) = self.tls_listener_handle.lock().expect("TLS listener handle lock poisoned").as_ref() {
                    handle.publish(config.clone());
                }
                *active = Some(*hash);
                self.runtime.tls_reload_success_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.runtime.tls_certificate_expiries.lock().expect("TLS expiry lock poisoned").insert("listener".to_owned(), *expiry);
            self.tls_listener_from_admin.store(*from_admin, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(listener.map(|(config, _, _, _)| config))
    }

    pub fn proxy_client_for(&self, profile_id: Option<&str>) -> Option<Client> {
        match profile_id {
            Some(id) => self.tls_snapshot().http_clients.get(id).cloned(),
            None => Some(self.proxy_client.clone()),
        }
    }

    pub async fn grpc_channel(
        &self,
        endpoint: &str,
        profile_id: Option<&str>,
        timeout_ms: u64,
    ) -> Result<Channel, String> {
        let snapshot = self.tls_snapshot();
        let key = (snapshot.revision, endpoint.to_owned(), profile_id.unwrap_or_default().to_owned(), timeout_ms);
        if let Some(channel) = self.grpc_channels.lock().map_err(|_| "gRPC channel cache unavailable")?.get(&key).cloned() {
            return Ok(channel);
        }
        let mut target = Endpoint::from_shared(endpoint.to_owned()).map_err(|error| error.to_string())?
            .connect_timeout(std::time::Duration::from_millis(timeout_ms.max(1)))
            .timeout(std::time::Duration::from_millis(timeout_ms.max(1)));
        if let Some(id) = profile_id {
            let profile = snapshot.profiles.upstreams.get(id).ok_or("gRPC TLS profile is unavailable")?;
            let mut tls = ClientTlsConfig::new();
            if !profile.ca_pem.is_empty() {
                tls = tls.ca_certificate(GrpcCertificate::from_pem(profile.ca_pem.clone()));
            }
            if let (Some(cert), Some(key)) = (&profile.client_cert_pem, &profile.client_key_pem) {
                tls = tls.identity(GrpcIdentity::from_pem(cert.clone(), key.clone()));
            }
            if let Some(server_name) = &profile.server_name {
                tls = tls.domain_name(server_name.clone());
            }
            target = target.tls_config(tls).map_err(|error| error.to_string())?;
        }
        let channel = target.connect().await.map_err(|error| error.to_string())?;
        let mut cache = self.grpc_channels.lock().map_err(|_| "gRPC channel cache unavailable")?;
        if cache.len() >= 128 {
            if let Some(oldest) = cache.keys().next().cloned() {
                cache.remove(&oldest);
            }
        }
        cache.insert(key, channel.clone());
        Ok(channel)
    }

    pub fn with_policy_documents(mut self, documents: PolicyDocuments) -> Self {
        self.policy_documents = Some(Arc::new(Mutex::new(documents)));
        self
    }

    pub fn with_validator(
        mut self,
        name: impl Into<String>,
        validator: impl Fn(&serde_json::Value, &serde_json::Value) -> Result<(), String>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Arc::make_mut(&mut self.validators).register(name, validator);
        self
    }
}
