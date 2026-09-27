//! Quota policy enforcement module.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::cache::WindowCounter;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuotaPolicy {
    pub quota_id: String,
    pub name: String,
    pub period_seconds: u64,
    pub max_requests: u64,
    pub max_bandwidth_bytes: u64,
}

/// Derived usage state used by the quota API and enforcement callers.
/// Thresholds deliberately match the Python tracker: warning begins at 80%
/// and critical at 95%, including the exhausted boundary.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct QuotaUsageStatus {
    pub allowed: bool,
    pub current_usage: u64,
    pub limit: u64,
    pub remaining: u64,
    pub percentage_used: f64,
    pub is_warning: bool,
    pub is_critical: bool,
    pub is_exhausted: bool,
}

pub fn quota_usage_status(current_usage: u64, limit: u64) -> QuotaUsageStatus {
    let remaining = limit.saturating_sub(current_usage);
    let percentage_used = if limit == 0 {
        0.0
    } else {
        current_usage as f64 / limit as f64 * 100.0
    };
    let is_exhausted = limit == 0 || current_usage >= limit;
    QuotaUsageStatus {
        allowed: !is_exhausted,
        current_usage,
        limit,
        remaining,
        percentage_used,
        is_warning: percentage_used >= 80.0,
        is_critical: percentage_used >= 95.0,
        is_exhausted,
    }
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            quota_id: "default_quota".to_owned(),
            name: "Default Quota".to_owned(),
            period_seconds: 86400, // 24 hours
            max_requests: 100_000,
            max_bandwidth_bytes: 10_000_000_000, // 10 GB
        }
    }
}

pub fn current_window_index(period_seconds: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if period_seconds == 0 {
        0
    } else {
        now / period_seconds
    }
}

pub fn quota_counter_key(user_id: &str, quota_id: &str, window_index: u64) -> String {
    format!("quota:{quota_id}:{user_id}:{window_index}")
}

/// Atomically records quota use for the current period and returns the new
/// usage. The counter is shared by all in-process gateway requests.
pub fn increment_quota(
    counter: &WindowCounter,
    user_id: &str,
    quota_id: &str,
    period_seconds: u64,
    now_seconds: u64,
) -> u64 {
    increment_quota_by(counter, user_id, quota_id, 1, period_seconds, now_seconds)
}

/// Records an arbitrary positive usage amount, matching the Python tracker's
/// `increment_quota(..., amount=...)` contract.
pub fn increment_quota_by(
    counter: &WindowCounter,
    user_id: &str,
    quota_id: &str,
    amount: u64,
    period_seconds: u64,
    now_seconds: u64,
) -> u64 {
    let period = period_seconds.max(1);
    let window_index = now_seconds / period;
    counter.incr_by(
        &quota_counter_key(user_id, quota_id, window_index),
        amount,
        period.saturating_mul(2),
        now_seconds,
    )
}

pub fn check_quota(
    current_usage: u64,
    request_increment: u64,
    policy: &QuotaPolicy,
) -> Result<(), String> {
    if current_usage + request_increment > policy.max_requests {
        return Err(format!(
            "Quota limit exceeded for {}: max {} requests per {}s",
            policy.name, policy.max_requests, policy.period_seconds
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_quota_thresholds() {
        let policy = QuotaPolicy::default();
        assert!(check_quota(99_999, 1, &policy).is_ok());
        assert!(check_quota(100_000, 1, &policy).is_err());
    }

    #[test]
    fn quota_usage_thresholds_match_python_tracker() {
        let within = quota_usage_status(5_000, 10_000);
        assert!(within.allowed);
        assert_eq!(within.remaining, 5_000);
        assert!(!within.is_warning);

        let warning = quota_usage_status(8_500, 10_000);
        assert!(warning.is_warning);
        assert!(!warning.is_critical);

        let critical = quota_usage_status(9_600, 10_000);
        assert!(critical.is_critical);
        assert!(!critical.is_exhausted);

        let exhausted = quota_usage_status(10_000, 10_000);
        assert!(exhausted.is_exhausted);
        assert!(!exhausted.allowed);
        assert_eq!(exhausted.remaining, 0);

        let fractional = quota_usage_status(1, 3);
        assert!((fractional.percentage_used - 33.333_333_333_333_33).abs() < f64::EPSILON);
    }

    #[test]
    fn quota_increment_is_atomic_and_scoped_to_its_period() {
        let counter = WindowCounter::default();
        assert_eq!(increment_quota(&counter, "alice", "requests", 60, 60), 1);
        assert_eq!(increment_quota(&counter, "alice", "requests", 60, 61), 2);
        assert_eq!(increment_quota(&counter, "alice", "requests", 60, 120), 1);
        assert_eq!(
            increment_quota_by(&counter, "alice", "requests", 4, 60, 121),
            5
        );
    }
}
