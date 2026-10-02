use http::StatusCode;
use serde_json::Value;

use super::{PolicyFailure, PolicyStage};
use crate::storage::{
    cache::{TokenBucketCounter, WindowCounter},
    models::{bool_field_default, string_field, u64_field},
    redis::rate_limit_key,
};

pub fn duration_to_seconds(duration: &str) -> u64 {
    let duration = duration.trim().trim_end_matches('s').to_ascii_lowercase();
    match duration.as_str() {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        "week" => 604800,
        "month" => 2592000,
        "year" => 31536000,
        _ => 60,
    }
}

/// Python truthiness for a numeric limit field: `bool(x)` / `int(x or default)`.
pub fn truthy_count(value: &Value, field: &str) -> Option<u64> {
    match value.get(field) {
        Some(Value::Number(number)) => number
            .as_u64()
            .or_else(|| number.as_f64().map(|float| float as u64))
            .filter(|count| *count != 0),
        Some(Value::String(raw)) if !raw.is_empty() => raw.parse().ok(),
        Some(Value::Bool(true)) => Some(1),
        _ => None,
    }
}

pub fn enforce_rate_limit(
    username: &str,
    user: &Value,
    counter: &WindowCounter,
    bucket_counter: &TokenBucketCounter,
    now_millis: u64,
) -> Result<(), PolicyFailure> {
    let rate_enabled = bool_field_default(user, "rate_limit_enabled", false)
        || truthy_count(user, "rate_limit_duration").is_some();
    if !rate_enabled {
        return Ok(());
    }
    let limit = truthy_count(user, "rate_limit_duration").unwrap_or(60);
    let duration = string_field(user, "rate_limit_duration_type").unwrap_or("minute");
    let window = duration_to_seconds(duration);
    let window_millis = window * 1000;
    let window_index = now_millis / window_millis;
    let now_seconds = now_millis / 1000;
    let algorithm = string_field(user, "rate_limit_algorithm").unwrap_or("fixed_window");

    if algorithm.eq_ignore_ascii_case("token_bucket") {
        let burst = u64_field(user, "rate_limit_burst_allowance").unwrap_or(0);
        let allowed = bucket_counter.take(
            &format!("rate_bucket:{username}"),
            limit.saturating_add(burst),
            window_millis,
            now_millis,
        );
        return allowed.then_some(()).ok_or_else(|| {
            PolicyFailure::new(
                PolicyStage::RateLimit,
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                "Rate limit exceeded",
            )
        });
    }

    let count = counter.incr(
        &rate_limit_key(username, window_index),
        window * 2,
        now_seconds,
    );

    let effective_count = if algorithm.eq_ignore_ascii_case("sliding_window") && window_index > 0 {
        let prev_index = window_index - 1;
        let prev_key = rate_limit_key(username, prev_index);
        let prev_count = counter.get(&prev_key, now_seconds);
        let time_into_current_window = (now_millis % window_millis) as f64 / window_millis as f64;
        let weight = (1.0 - time_into_current_window).max(0.0);
        (prev_count as f64 * weight + count as f64).ceil() as u64
    } else {
        count
    };

    if effective_count > limit {
        Err(PolicyFailure::new(
            PolicyStage::RateLimit,
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
            "Rate limit exceeded",
        ))
    } else {
        if algorithm.eq_ignore_ascii_case("hybrid") {
            let burst = u64_field(user, "rate_limit_burst_allowance").unwrap_or(0);
            if burst > 0
                && !bucket_counter.take(
                    &format!("rate_hybrid_bucket:{username}"),
                    limit,
                    window_millis,
                    now_millis,
                )
            {
                let window_start = window_index.saturating_mul(window);
                let burst_key = format!("burst:user:{username}:{window_start}");
                if counter.get(&burst_key, now_seconds) >= burst {
                    return Err(PolicyFailure::new(
                        PolicyStage::RateLimit,
                        StatusCode::TOO_MANY_REQUESTS,
                        "Rate limit exceeded",
                        "Rate limit exceeded",
                    ));
                }
                counter.incr(&burst_key, window * 2, now_seconds);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread, time::Instant};

    use super::*;
    use serde_json::json;

    #[test]
    fn enforces_user_rate_window() {
        let user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 1,
            "rate_limit_duration_type": "minute",
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        assert!(enforce_rate_limit("alice", &user, &counter, &buckets, 60_000).is_ok());
        assert!(enforce_rate_limit("alice", &user, &counter, &buckets, 61_000).is_err());
    }

    #[test]
    fn zero_limit_falls_back_to_python_default_instead_of_denying() {
        let user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 0,
            "rate_limit_duration_type": "minute"
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        // Python: `int(user.get('rate_limit_duration') or 60)` treats 0 as unset.
        assert!(enforce_rate_limit("invalid", &user, &counter, &buckets, 60_000).is_ok());
        let disabled = json!({"rate_limit_duration": 0});
        for _ in 0..100 {
            assert!(enforce_rate_limit("off", &disabled, &counter, &buckets, 60_000).is_ok());
        }
    }

    #[test]
    fn enforces_sliding_window() {
        let user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 5,
            "rate_limit_duration_type": "minute",
            "rate_limit_algorithm": "sliding_window"
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        for _ in 0..5 {
            counter.incr(&rate_limit_key("bob", 0), 120, 0);
        }
        assert!(enforce_rate_limit("bob", &user, &counter, &buckets, 60_001).is_err());
    }

    #[test]
    fn token_bucket_allows_configured_burst_then_blocks_and_refills() {
        let user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 2,
            "rate_limit_duration_type": "second",
            "rate_limit_algorithm": "token_bucket",
            "rate_limit_burst_allowance": 1,
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        for _ in 0..3 {
            assert!(enforce_rate_limit("carol", &user, &counter, &buckets, 0).is_ok());
        }
        assert!(enforce_rate_limit("carol", &user, &counter, &buckets, 0).is_err());
        assert!(enforce_rate_limit("carol", &user, &counter, &buckets, 1_000).is_ok());
    }

    #[test]
    fn hybrid_mode_enforces_window_and_bucket_together() {
        let user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 2,
            "rate_limit_duration_type": "second",
            "rate_limit_algorithm": "hybrid",
            "rate_limit_burst_allowance": 1,
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        assert!(enforce_rate_limit("dana", &user, &counter, &buckets, 0).is_ok());
        assert!(enforce_rate_limit("dana", &user, &counter, &buckets, 0).is_ok());
        assert!(enforce_rate_limit("dana", &user, &counter, &buckets, 0).is_err());
    }

    #[test]
    fn hybrid_mode_uses_a_separate_windowed_burst_counter_like_python() {
        let user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 2,
            "rate_limit_duration_type": "second",
            "rate_limit_algorithm": "hybrid",
            "rate_limit_burst_allowance": 1,
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        assert!(buckets.take("rate_hybrid_bucket:erin", 2, 1_000, 0));
        assert!(buckets.take("rate_hybrid_bucket:erin", 2, 1_000, 0));

        assert!(enforce_rate_limit("erin", &user, &counter, &buckets, 0).is_ok());
        assert_eq!(counter.get("burst:user:erin:0", 0), 1);
        assert!(enforce_rate_limit("erin", &user, &counter, &buckets, 0).is_err());
    }

    #[test]
    fn concurrent_requests_share_one_atomic_rate_window() {
        let user = Arc::new(json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 1,
            "rate_limit_duration_type": "minute",
        }));
        let counter = Arc::new(WindowCounter::default());
        let buckets = Arc::new(TokenBucketCounter::default());
        let workers = (0..16)
            .map(|_| {
                let user = user.clone();
                let counter = counter.clone();
                let buckets = buckets.clone();
                thread::spawn(move || {
                    enforce_rate_limit("shared", &user, &counter, &buckets, 60_000).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let allowed = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(allowed, 1, "only one request may consume the shared limit");
    }

    #[test]
    fn hybrid_limiter_handles_high_volume_and_consistent_shared_user_rules() {
        let high_volume_user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 1_000,
            "rate_limit_duration_type": "minute",
            "rate_limit_algorithm": "hybrid",
            "rate_limit_burst_allowance": 0,
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        let started = Instant::now();
        for request in 0..1_000 {
            assert!(
                enforce_rate_limit(
                    &format!("user_{}", request % 100),
                    &high_volume_user,
                    &counter,
                    &buckets,
                    60_000,
                )
                .is_ok()
            );
        }
        assert!(started.elapsed().as_secs_f64() < 1.0);

        let shared_user = json!({
            "rate_limit_enabled": true,
            "rate_limit_duration": 100,
            "rate_limit_duration_type": "minute",
            "rate_limit_algorithm": "hybrid",
            "rate_limit_burst_allowance": 0,
        });
        let counter = WindowCounter::default();
        let buckets = TokenBucketCounter::default();
        for _rule in 0..5 {
            assert!(
                enforce_rate_limit("distributed-user", &shared_user, &counter, &buckets, 60_000)
                    .is_ok()
            );
        }
    }
}
