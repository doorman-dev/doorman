use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CacheName {
    Api,
    ApiEndpoint,
    ApiId,
    Endpoint,
    EndpointValidation,
    GraphqlSchema,
    Group,
    Openapi,
    Role,
    UserSubscription,
    User,
    UserGroup,
    UserRole,
    EndpointLoadBalancer,
    EndpointServer,
    ClientRouting,
    TokenDef,
    CreditDef,
    CsrfTokenMap,
    Wsdl,
}

impl CacheName {
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Api => "api_cache:",
            Self::ApiEndpoint => "api_endpoint_cache:",
            Self::ApiId => "api_id_cache:",
            Self::Endpoint => "endpoint_cache:",
            Self::EndpointValidation => "endpoint_validation_cache:",
            Self::GraphqlSchema => "graphql_schema_cache:",
            Self::Group => "group_cache:",
            Self::Openapi => "openapi_cache:",
            Self::Role => "role_cache:",
            Self::UserSubscription => "user_subscription_cache:",
            Self::User => "user_cache:",
            Self::UserGroup => "user_group_cache:",
            Self::UserRole => "user_role_cache:",
            Self::EndpointLoadBalancer => "endpoint_load_balancer:",
            Self::EndpointServer => "endpoint_server_cache:",
            Self::ClientRouting => "client_routing_cache:",
            Self::TokenDef => "token_def_cache:",
            Self::CreditDef => "credit_def_cache:",
            Self::CsrfTokenMap => "csrf_token_map:",
            Self::Wsdl => "wsdl_cache:",
        }
    }

    pub fn default_ttl_seconds(self) -> u64 {
        match self {
            Self::GraphqlSchema | Self::Openapi | Self::Wsdl => 3600,
            Self::CsrfTokenMap => 1800,
            _ => 86400,
        }
    }

    pub fn key(self, key: &str) -> String {
        format!("{}{key}", self.prefix())
    }
}

#[derive(Clone, Debug, Default)]
pub struct WindowCounter {
    inner: Arc<Mutex<HashMap<String, CounterEntry>>>,
}

#[derive(Clone, Debug, Default)]
pub struct TokenBucketCounter {
    inner: Arc<Mutex<HashMap<String, TokenBucketEntry>>>,
}

#[derive(Clone, Debug)]
struct TokenBucketEntry {
    tokens: f64,
    last_millis: u64,
}

impl TokenBucketCounter {
    /// Consume one token, refilling continuously over `window_millis`.
    pub fn take(&self, key: &str, capacity: u64, window_millis: u64, now_millis: u64) -> bool {
        if capacity == 0 || window_millis == 0 {
            return false;
        }
        let mut inner = self.inner.lock().expect("token bucket mutex poisoned");
        let entry = inner.entry(key.to_owned()).or_insert(TokenBucketEntry {
            tokens: capacity as f64,
            last_millis: now_millis,
        });
        let elapsed = now_millis.saturating_sub(entry.last_millis);
        let refill = elapsed as f64 * capacity as f64 / window_millis as f64;
        entry.tokens = (entry.tokens + refill).min(capacity as f64);
        entry.last_millis = now_millis;
        if entry.tokens < 1.0 {
            return false;
        }
        entry.tokens -= 1.0;
        true
    }
}

#[derive(Clone, Debug)]
struct CounterEntry {
    count: u64,
    expires_at: u64,
}

impl WindowCounter {
    pub fn incr(&self, key: &str, ttl_seconds: u64, now_seconds: u64) -> u64 {
        self.incr_by(key, 1, ttl_seconds, now_seconds)
    }

    pub fn incr_by(&self, key: &str, amount: u64, ttl_seconds: u64, now_seconds: u64) -> u64 {
        let mut inner = self.inner.lock().expect("counter mutex poisoned");
        let entry = inner.entry(key.to_owned()).or_insert(CounterEntry {
            count: 0,
            expires_at: now_seconds + ttl_seconds,
        });
        if entry.expires_at <= now_seconds {
            entry.count = 0;
            entry.expires_at = now_seconds + ttl_seconds;
        }
        entry.count = entry.count.saturating_add(amount);
        entry.count
    }

    pub fn get(&self, key: &str, now_seconds: u64) -> u64 {
        let inner = self.inner.lock().expect("counter mutex poisoned");
        inner
            .get(key)
            .filter(|entry| entry.expires_at > now_seconds)
            .map(|entry| entry.count)
            .unwrap_or(0)
    }

    pub fn reset(&self) {
        self.inner.lock().expect("counter mutex poisoned").clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_python_cache_prefixes() {
        assert_eq!(CacheName::Api.key("demo/v1"), "api_cache:demo/v1");
        assert_eq!(CacheName::CsrfTokenMap.default_ttl_seconds(), 1800);
    }

    #[test]
    fn expires_window_counters() {
        let counter = WindowCounter::default();
        assert_eq!(counter.incr("rate:a:1", 60, 100), 1);
        assert_eq!(counter.incr("rate:a:1", 60, 101), 2);
        assert_eq!(counter.get("rate:a:1", 102), 2);
        assert_eq!(counter.get("rate:a:1", 161), 0);
    }
    #[test]
    fn python_test_inmemory_counter_increments_and_expires() {
        let counter = WindowCounter::default();
        assert_eq!(counter.incr("k1", 1, 0), 1);
        assert_eq!(counter.incr("k1", 1, 0), 2);
        assert_eq!(counter.incr("k1", 1, 0), 3);
        assert_eq!(counter.incr("k1", 1, 2), 1);
        assert_eq!(counter.incr("k1", 1, 2), 2);
    }

    #[test]
    fn token_bucket_allows_burst_then_refills() {
        let bucket = TokenBucketCounter::default();
        assert!(bucket.take("alice", 2, 1_000, 0));
        assert!(bucket.take("alice", 2, 1_000, 0));
        assert!(!bucket.take("alice", 2, 1_000, 0));
        assert!(bucket.take("alice", 2, 1_000, 500));
    }
}
