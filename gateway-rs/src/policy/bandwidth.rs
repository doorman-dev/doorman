use http::StatusCode;
use serde_json::Value;

use super::{PolicyFailure, PolicyStage};
use crate::storage::{
    cache::WindowCounter,
    models::{bool_field, string_field, u64_field},
    redis::bandwidth_key,
};

/// Python `_window_to_seconds`: strips every trailing `s`; unknown or empty windows are one day.
pub fn window_seconds(window: &str) -> u64 {
    match window.to_ascii_lowercase().trim_end_matches('s') {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        "week" => 604800,
        "month" => 2592000,
        _ => 86400,
    }
}

pub fn enforce_pre_request_limit(
    username: &str,
    user: &Value,
    counter: &WindowCounter,
    now_seconds: u64,
    content_length: u64,
) -> Result<(), PolicyFailure> {
    if bool_field(user, "bandwidth_limit_enabled") == Some(false) {
        return Ok(());
    }
    let Some(limit) = u64_field(user, "bandwidth_limit_bytes") else {
        return Ok(());
    };
    if limit == 0 {
        return Ok(());
    }
    let window = string_field(user, "bandwidth_limit_window").unwrap_or("day");
    let seconds = window_seconds(window);
    let bucket = (now_seconds / seconds) * seconds;
    let used = counter.get(&bandwidth_key(username, seconds, bucket), now_seconds);
    if used >= limit || used + content_length > limit {
        Err(PolicyFailure::new(
            PolicyStage::Bandwidth,
            StatusCode::TOO_MANY_REQUESTS,
            "Bandwidth limit exceeded",
            "Bandwidth limit exceeded",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn window_mapping_matches_python_defaults() {
        for (window, seconds) in [
            ("second", 1),
            ("Minutes", 60),
            ("hourss", 3600),
            ("week", 604800),
            ("month", 2592000),
            ("year", 86400),
            ("fortnight", 86400),
            ("", 86400),
        ] {
            assert_eq!(window_seconds(window), seconds, "{window}");
        }
    }

    #[test]
    fn rejects_over_limit_request_body() {
        let user = json!({
            "bandwidth_limit_bytes": 100,
            "bandwidth_limit_window": "day",
        });
        let counter = WindowCounter::default();
        assert!(enforce_pre_request_limit("alice", &user, &counter, 1, 101).is_err());
    }

    #[test]
    fn python_bandwidth_limit_blocks_after_usage_reaches_limit() {
        let user = json!({
            "bandwidth_limit_enabled": true,
            "bandwidth_limit_bytes": 1,
            "bandwidth_limit_window": "second",
        });
        let counter = WindowCounter::default();
        assert!(enforce_pre_request_limit("admin", &user, &counter, 100, 0).is_ok());
        let key = bandwidth_key("admin", 1, 100);
        assert_eq!(counter.incr(&key, 1, 100), 1);

        let failure = enforce_pre_request_limit("admin", &user, &counter, 100, 0).unwrap_err();
        assert_eq!(failure.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(failure.error_message, "Bandwidth limit exceeded");
    }

    #[test]
    fn python_bandwidth_limit_resets_in_the_next_window() {
        let user = json!({
            "bandwidth_limit_enabled": true,
            "bandwidth_limit_bytes": 1,
            "bandwidth_limit_window": "second",
        });
        let counter = WindowCounter::default();
        let key = bandwidth_key("admin", 1, 100);
        assert_eq!(counter.incr(&key, 1, 100), 1);
        assert!(enforce_pre_request_limit("admin", &user, &counter, 100, 0).is_err());

        assert!(enforce_pre_request_limit("admin", &user, &counter, 101, 0).is_ok());
    }
}
