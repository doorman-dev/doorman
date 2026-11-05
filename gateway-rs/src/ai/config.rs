//! Per-API AI configuration stored in `apis.api_ai_config` (plan §5.2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialOverride {
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub credential_group: String,
}

/// A backup upstream for failover and load balancing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiTarget {
    /// `credit_defs.api_credit_group` with this target's key. Empty = the API's own key.
    #[serde(default)]
    pub credential_group: String,
    /// Base URL. None = the API's upstream server (another key, same endpoint).
    #[serde(default)]
    pub server: Option<String>,
    /// Share of traffic when `load_balance` is on. The primary counts as 1.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

pub const MAX_FALLBACK_TARGETS: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiApiConfig {
    /// `credit_defs.api_credit_group` holding the provider key (C1). Required.
    #[serde(default)]
    pub credential_group: String,
    #[serde(default)]
    pub credential_overrides: Vec<CredentialOverride>,
    /// Exact IDs or trailing-`*` prefixes. Required, non-empty.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub model_aliases: BTreeMap<String, String>,
    /// None = provider default operation set.
    #[serde(default)]
    pub allowed_operations: Option<Vec<String>>,
    #[serde(default)]
    pub max_output_tokens: Option<u64>,
    #[serde(default = "default_true")]
    pub stream_allowed: bool,
    #[serde(default = "default_true")]
    pub inject_stream_usage: bool,
    #[serde(default = "default_true")]
    pub forward_user_id: bool,
    /// false = members of `api_allowed_groups` can use the API without an
    /// individual subscription (company-wide rollout). Default true.
    #[serde(default = "default_true")]
    pub require_subscription: bool,
    /// None = global setting; "none" | "metadata" | "full".
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub guardrail_ids: Vec<String>,
    #[serde(default = "default_first_byte_timeout_ms")]
    pub first_byte_timeout_ms: u64,
    #[serde(default = "default_stream_idle_timeout_ms")]
    pub stream_idle_timeout_ms: u64,
    /// Backups tried in order when the primary returns 502-504, times out
    /// before the first byte, or cannot be reached. Never on 429 (C3).
    #[serde(default)]
    pub fallback_targets: Vec<AiTarget>,
    /// Spread requests by weight across the primary and the backups that use a
    /// different server. Never across keys on the same server (C3).
    #[serde(default)]
    pub load_balance: bool,
}

impl Default for AiApiConfig {
    fn default() -> Self {
        Self {
            credential_group: String::new(),
            credential_overrides: Vec::new(),
            allowed_models: Vec::new(),
            default_model: None,
            model_aliases: BTreeMap::new(),
            allowed_operations: None,
            max_output_tokens: None,
            stream_allowed: true,
            inject_stream_usage: true,
            forward_user_id: true,
            require_subscription: true,
            log_level: None,
            guardrail_ids: Vec::new(),
            first_byte_timeout_ms: default_first_byte_timeout_ms(),
            stream_idle_timeout_ms: default_stream_idle_timeout_ms(),
            fallback_targets: Vec::new(),
            load_balance: false,
        }
    }
}

impl AiApiConfig {
    pub fn from_value(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        Self::deserialize(value)
    }
}

/// Exact model ID or trailing-`*` prefix match against the allowlist.
pub fn model_allowed(model: &str, allowed_models: &[String]) -> bool {
    allowed_models
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => model.starts_with(prefix),
            None => pattern == model,
        })
}

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_first_byte_timeout_ms() -> u64 {
    60_000
}

fn default_stream_idle_timeout_ms() -> u64 {
    120_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ai_config_applies_contract_defaults() {
        let config = AiApiConfig::from_value(&json!({
            "credential_group": "openai-prod",
            "allowed_models": ["gpt-x"]
        }))
        .unwrap();
        assert_eq!(
            config,
            AiApiConfig {
                credential_group: "openai-prod".to_owned(),
                allowed_models: vec!["gpt-x".to_owned()],
                ..AiApiConfig::default()
            }
        );
        assert!(config.stream_allowed && config.inject_stream_usage && config.forward_user_id);
        assert_eq!(config.first_byte_timeout_ms, 60_000);
        assert_eq!(config.stream_idle_timeout_ms, 120_000);
    }
}
