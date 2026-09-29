use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::RwLock,
};

use serde_json::{Map, Number, Value};

pub const RELOADABLE_KEYS: [&str; 22] = [
    "LOG_LEVEL",
    "LOG_FORMAT",
    "LOG_FILE",
    "GATEWAY_TIMEOUT",
    "UPSTREAM_TIMEOUT",
    "CONNECTION_TIMEOUT",
    "RATE_LIMIT_ENABLED",
    "RATE_LIMIT_REQUESTS",
    "RATE_LIMIT_WINDOW",
    "CACHE_TTL",
    "CACHE_MAX_SIZE",
    "CIRCUIT_BREAKER_ENABLED",
    "CIRCUIT_BREAKER_THRESHOLD",
    "CIRCUIT_BREAKER_TIMEOUT",
    "RETRY_ENABLED",
    "RETRY_MAX_ATTEMPTS",
    "RETRY_BACKOFF",
    "METRICS_ENABLED",
    "METRICS_INTERVAL",
    "FEATURE_REQUEST_REPLAY",
    "FEATURE_AB_TESTING",
    "FEATURE_COST_ANALYTICS",
];

#[derive(Debug)]
pub struct HotReloadConfig {
    config_file: Option<PathBuf>,
    values: RwLock<BTreeMap<String, Value>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HttpRuntimeSettings {
    pub timeout_seconds: Option<u64>,
    pub retry_count: Option<u32>,
}

impl HotReloadConfig {
    pub fn from_env() -> Self {
        Self::new(env::var_os("DOORMAN_CONFIG_FILE").map(PathBuf::from))
    }

    pub fn new(config_file: Option<PathBuf>) -> Self {
        let manager = Self {
            config_file,
            values: RwLock::new(BTreeMap::new()),
        };
        if let Err(error) = manager.reload() {
            tracing::warn!(error = %error, "initial hot-reload configuration could not be loaded");
        }
        manager
    }

    /// Validate and atomically publish the next configuration. HTTP gateway
    /// timeout and retry settings apply on subsequent requests; other values
    /// remain inspection-only until restart.
    pub fn reload(&self) -> Result<(), String> {
        let mut loaded = BTreeMap::new();
        if let Some(path) = self.config_file.as_deref()
            && path.exists()
        {
            let file_values = load_file(path)?;
            loaded.extend(file_values);
        }
        for key in RELOADABLE_KEYS {
            if let Ok(value) = env::var(key) {
                let value = if matches!(key, "GATEWAY_TIMEOUT" | "RETRY_MAX_ATTEMPTS") {
                    Value::String(value)
                } else {
                    parse_env_value(&value)
                };
                loaded.insert(key.to_owned(), value);
            }
        }
        for key in ["GATEWAY_TIMEOUT", "RETRY_MAX_ATTEMPTS"] {
            if let Some(value) = loaded.get(key) {
                let number = value
                    .as_u64()
                    .or_else(|| value.as_str()?.trim().parse().ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| format!("{key} must be a positive integer"))?;
                loaded.insert(key.to_owned(), Value::from(number));
            }
        }
        if let Some(value) = loaded.get("RETRY_ENABLED") {
            let enabled = value
                .as_bool()
                .or_else(|| {
                    value.as_str().and_then(|value| {
                        match value.trim().to_ascii_lowercase().as_str() {
                            "1" | "true" | "yes" | "on" => Some(true),
                            "0" | "false" | "no" | "off" => Some(false),
                            _ => None,
                        }
                    })
                })
                .ok_or_else(|| "RETRY_ENABLED must be a boolean".to_owned())?;
            loaded.insert("RETRY_ENABLED".to_owned(), Value::Bool(enabled));
        }
        let mut values = self
            .values
            .write()
            .map_err(|_| "hot-reload configuration lock is poisoned".to_owned())?;
        // Python applies LOG_LEVEL immediately via a registered callback
        // (`logging.getLogger().setLevel(new_value)`); apply it to the live
        // tracing subscriber here instead of only recording it as reloaded.
        if let Some(Value::String(level)) = loaded.get("LOG_LEVEL")
            && values.get("LOG_LEVEL") != loaded.get("LOG_LEVEL")
        {
            crate::observability::logging::set_log_level(level);
        }
        *values = loaded;
        Ok(())
    }

    pub fn dump(&self) -> Value {
        let values = self
            .values
            .read()
            .map(|values| values.clone())
            .unwrap_or_default();
        Value::Object(values.into_iter().collect::<Map<_, _>>())
    }

    pub fn http_settings(&self) -> HttpRuntimeSettings {
        let Ok(values) = self.values.read() else {
            return HttpRuntimeSettings::default();
        };
        HttpRuntimeSettings {
            timeout_seconds: values.get("GATEWAY_TIMEOUT").and_then(Value::as_u64),
            retry_count: if values.get("RETRY_ENABLED").and_then(Value::as_bool) == Some(false) {
                Some(0)
            } else {
                values
                    .get("RETRY_MAX_ATTEMPTS")
                    .and_then(Value::as_u64)
                    .map(|attempts| attempts.saturating_sub(1).min(u64::from(u32::MAX)) as u32)
            },
        }
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.values
            .read()
            .ok()
            .and_then(|values| values.get(key).cloned())
            .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.values.read().ok().and_then(|values| {
            values.get(key).and_then(|value| {
                value.as_bool().or_else(|| {
                    value
                        .as_str()
                        .and_then(|value| match value.to_ascii_lowercase().as_str() {
                            "1" | "true" | "yes" | "on" => Some(true),
                            "0" | "false" | "no" | "off" => Some(false),
                            _ => None,
                        })
                })
            })
        })
    }
}

fn load_file(path: &Path) -> Result<BTreeMap<String, Value>, String> {
    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let value = match path.extension().and_then(|extension| extension.to_str()) {
        Some("yaml" | "yml") => {
            serde_yaml::from_str::<Value>(&contents).map_err(|error| error.to_string())?
        }
        Some("json") => serde_json::from_str(&contents).map_err(|error| error.to_string())?,
        Some(extension) => return Err(format!("Unsupported config file format: .{extension}")),
        None => return Err("Unsupported config file format".to_owned()),
    };
    let mut flattened = BTreeMap::new();
    flatten(&value, None, &mut flattened);
    Ok(flattened)
}

fn flatten(value: &Value, parent: Option<&str>, output: &mut BTreeMap<String, Value>) {
    let Value::Object(values) = value else {
        return;
    };
    for (key, value) in values {
        let key = parent.map_or_else(
            || key.to_ascii_uppercase(),
            |parent| format!("{parent}_{}", key.to_ascii_uppercase()),
        );
        if value.is_object() {
            flatten(value, Some(&key), output);
        } else {
            output.insert(key, value.clone());
        }
    }
}

fn parse_env_value(value: &str) -> Value {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => return Value::Bool(true),
        "false" | "no" | "0" => return Value::Bool(false),
        _ => {}
    }
    if let Ok(value) = value.parse::<i64>() {
        return Value::Number(Number::from(value));
    }
    if let Ok(value) = value.parse::<f64>()
        && let Some(value) = Number::from_f64(value)
    {
        return Value::Number(value);
    }
    Value::String(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_changes_are_applied_without_erroring_the_reload() {
        // The dynamic-apply path runs even when no tracing subscriber has been
        // initialized in this test binary (`set_log_level` then safely no-ops);
        // what this guards is that reload() itself never fails because of it,
        // and that the new value is recorded either way.
        // SAFETY: test-only; no other test in this crate reads LOG_LEVEL.
        unsafe {
            env::set_var("LOG_LEVEL", "debug");
        }
        let config = HotReloadConfig::new(None);
        assert_eq!(
            config.dump().get("LOG_LEVEL").and_then(Value::as_str),
            Some("debug")
        );
        // SAFETY: test-only; no other test in this crate reads LOG_LEVEL.
        unsafe {
            env::set_var("LOG_LEVEL", "warn");
        }
        assert!(config.reload().is_ok());
        assert_eq!(
            config.dump().get("LOG_LEVEL").and_then(Value::as_str),
            Some("warn")
        );
        // SAFETY: test-only.
        unsafe {
            env::remove_var("LOG_LEVEL");
        }
    }

    #[test]
    fn rejected_reload_retains_last_valid_runtime_settings() {
        let directory =
            std::env::temp_dir().join(format!("doorman-hot-config-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.json");
        fs::write(
            &path,
            r#"{"gateway":{"timeout":"1"},"retry":{"enabled":true,"max_attempts":"1"}}"#,
        )
        .unwrap();
        let config = HotReloadConfig::new(Some(path.clone()));
        assert_eq!(config.get_u64("GATEWAY_TIMEOUT"), Some(1));
        assert_eq!(config.get_u64("RETRY_MAX_ATTEMPTS"), Some(1));
        let previous = config.dump();
        for invalid in [
            r#"{"gateway":{"timeout":0}}"#,
            r#"{"gateway":{"timeout":-1}}"#,
            r#"{"retry":{"max_attempts":"bad"}}"#,
            r#"{"retry":{"enabled":"maybe"}}"#,
            "invalid json",
        ] {
            fs::write(&path, invalid).unwrap();
            assert!(config.reload().is_err());
            assert_eq!(config.dump(), previous);
        }
        fs::write(&path, r#"{"retry":{"enabled":false}}"#).unwrap();
        config.reload().unwrap();
        assert_eq!(config.get_bool("RETRY_ENABLED"), Some(false));
        assert_eq!(config.get_u64("GATEWAY_TIMEOUT"), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn flattens_json_configuration_like_the_python_manager() {
        let directory =
            std::env::temp_dir().join(format!("doorman-hot-config-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config.json");
        fs::write(
            &path,
            r#"{"gateway":{"timeout":45},"retry":{"enabled":true}}"#,
        )
        .unwrap();

        let config = HotReloadConfig::new(Some(path));
        let values = config.dump();
        assert_eq!(values["GATEWAY_TIMEOUT"], 45);
        assert_eq!(values["RETRY_ENABLED"], true);

        fs::remove_dir_all(directory).unwrap();
    }
}
