//! Global AI gateway settings (`settings` document `type: "ai_settings"`).
//! Follows `security_settings.rs`: defaults merged under the stored document.

use serde_json::{Value, json};

use super::runtime::{SharedStorage, StorageError};

pub const SETTINGS_TYPE: &str = "ai_settings";

/// Prompt-log levels, least to most content.
pub const LOG_LEVELS: [&str; 3] = ["none", "metadata", "full"];

pub fn defaults() -> Value {
    json!({"type": SETTINGS_TYPE, "log_level": "metadata", "retention_days": 30, "notice_text": null})
}

/// The stored settings over the defaults (C8: default level is `metadata`).
pub fn merge(current: Option<&Value>) -> Value {
    let mut settings = defaults();
    if let (Some(fields), Some(current)) =
        (settings.as_object_mut(), current.and_then(Value::as_object))
    {
        for key in ["log_level", "retention_days", "notice_text"] {
            if let Some(value) = current.get(key).filter(|value| !value.is_null()) {
                fields.insert(key.to_owned(), value.clone());
            }
        }
    }
    settings
}

/// Settings from already-loaded policy documents (no extra storage read).
pub fn from_documents(settings: &[Value]) -> Value {
    merge(
        settings
            .iter()
            .find(|doc| doc.get("type").and_then(Value::as_str) == Some(SETTINGS_TYPE)),
    )
}

pub async fn load(storage: &SharedStorage) -> Result<Value, StorageError> {
    let current = storage
        .find_one("settings", &json!({"type": SETTINGS_TYPE}))
        .await?;
    Ok(merge(current.as_ref()))
}

pub async fn save(storage: &SharedStorage, settings: &Value) -> Result<(), StorageError> {
    let filter = json!({"type": SETTINGS_TYPE});
    if storage.find_one("settings", &filter).await?.is_some() {
        storage.update_one("settings", &filter, settings).await?;
    } else {
        storage.insert_one("settings", settings.clone()).await?;
    }
    storage.bump_policy_revision().await?;
    Ok(())
}

/// The more restrictive of the global and per-API levels (USER-approved §5.2
/// semantics): a per-API value can lower logging but never raise it.
pub fn effective_log_level<'a>(global: &'a str, per_api: Option<&'a str>) -> &'a str {
    let rank = |level: &str| {
        LOG_LEVELS
            .iter()
            .position(|item| *item == level)
            .unwrap_or(1)
    };
    match per_api {
        Some(level) if rank(level) < rank(global) => level,
        _ => global,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_api_level_can_only_lower_logging() {
        assert_eq!(effective_log_level("metadata", Some("full")), "metadata");
        assert_eq!(effective_log_level("full", Some("none")), "none");
        assert_eq!(effective_log_level("full", None), "full");
        assert_eq!(effective_log_level("none", Some("full")), "none");
        assert_eq!(merge(None)["log_level"], "metadata");
    }
}
