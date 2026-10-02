use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::storage::models::PolicyDocuments;

#[derive(Clone, Default)]
pub struct MemoryStorage {
    pub collections: Arc<RwLock<HashMap<String, Vec<Value>>>>,
    pub counters: Arc<RwLock<HashMap<String, ExpiringValue>>>,
    pub policy_revision: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct ExpiringValue {
    pub value: Value,
    pub expires_at: Option<Instant>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        let mut collections = HashMap::new();
        for name in [
            "users",
            "apis",
            "endpoints",
            "groups",
            "roles",
            "subscriptions",
            "routings",
            "credit_defs",
            "user_credits",
            "endpoint_validations",
            "settings",
            "revocations",
            "vault_entries",
            "tiers",
            "user_tier_assignments",
            "rate_limit_rules",
            "config_snapshots",
            "tls_profiles",
        ] {
            collections.insert(name.to_owned(), Vec::new());
        }
        Self {
            collections: Arc::new(RwLock::new(collections)),
            counters: Arc::new(RwLock::new(HashMap::new())),
            policy_revision: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn load_policy_documents(&self) -> PolicyDocuments {
        let collections = self.collections.read().await;
        let get = |name: &str| collections.get(name).cloned().unwrap_or_default();
        PolicyDocuments {
            apis: get("apis"),
            endpoints: get("endpoints"),
            endpoint_validations: get("endpoint_validations"),
            users: get("users"),
            roles: get("roles"),
            subscriptions: get("subscriptions"),
            routings: get("routings"),
            credit_defs: get("credit_defs"),
            user_credits: get("user_credits"),
            settings: get("settings"),
            revocations: get("revocations"),
            tiers: get("tiers"),
            tier_assignments: get("user_tier_assignments"),
        }
    }

    pub fn revision(&self) -> u64 {
        self.policy_revision.load(Ordering::SeqCst)
    }

    pub fn bump_revision(&self) -> u64 {
        self.policy_revision.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub async fn increment(&self, key: &str, amount: u64, ttl_seconds: u64) -> u64 {
        let mut counters = self.counters.write().await;
        let now = Instant::now();
        if counters
            .get(key)
            .and_then(|entry| entry.expires_at)
            .is_some_and(|expiry| expiry <= now)
        {
            counters.remove(key);
        }
        let entry = counters
            .entry(key.to_owned())
            .or_insert_with(|| ExpiringValue {
                value: json!(0),
                expires_at: Some(now + Duration::from_secs(ttl_seconds.max(1))),
            });
        let next = entry.value.as_u64().unwrap_or(0).saturating_add(amount);
        entry.value = json!(next);
        if entry.expires_at.is_none() {
            entry.expires_at = Some(now + Duration::from_secs(ttl_seconds.max(1)));
        }
        next
    }

    pub async fn get_value(&self, key: &str) -> Option<Value> {
        let mut counters = self.counters.write().await;
        if counters
            .get(key)
            .and_then(|entry| entry.expires_at)
            .is_some_and(|expiry| expiry <= Instant::now())
        {
            counters.remove(key);
        }
        counters.get(key).map(|entry| entry.value.clone())
    }

    pub async fn set_value(&self, key: &str, value: Value, ttl_seconds: u64) {
        self.counters.write().await.insert(
            key.to_owned(),
            ExpiringValue {
                value,
                expires_at: Some(Instant::now() + Duration::from_secs(ttl_seconds.max(1))),
            },
        );
    }

    pub async fn clear_runtime(&self) {
        self.counters.write().await.clear();
        self.bump_revision();
    }
}
