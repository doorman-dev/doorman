use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        pub enum $name {
            $(#[serde(rename = $value)] $variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(format!("{value:?} is not a valid {}", stringify!($name))),
                }
            }
        }
    };
}

string_enum!(RuleType {
    PerUser => "per_user",
    PerApi => "per_api",
    PerEndpoint => "per_endpoint",
    PerIp => "per_ip",
    PerUserApi => "per_user_api",
    PerUserEndpoint => "per_user_endpoint",
    Global => "global",
});

string_enum!(TimeWindow {
    Second => "second",
    Minute => "minute",
    Hour => "hour",
    Day => "day",
    Month => "month",
});

string_enum!(TierName {
    Free => "free",
    Pro => "pro",
    Enterprise => "enterprise",
    Custom => "custom",
});

string_enum!(QuotaType {
    Requests => "requests",
    Bandwidth => "bandwidth",
    ComputeTime => "compute_time",
});

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RateLimitRule {
    pub rule_id: String,
    pub rule_type: RuleType,
    pub time_window: TimeWindow,
    pub limit: i64,
    #[serde(default)]
    pub target_identifier: Option<String>,
    #[serde(default)]
    pub burst_allowance: i64,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl RateLimitRule {
    pub fn to_dict(&self) -> Value {
        serde_json::to_value(self).expect("rate-limit rule is JSON representable")
    }

    pub fn from_dict(value: Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TierLimits {
    pub requests_per_second: Option<i64>,
    pub requests_per_minute: Option<i64>,
    pub requests_per_hour: Option<i64>,
    pub requests_per_day: Option<i64>,
    pub requests_per_month: Option<i64>,
    pub burst_per_second: i64,
    pub burst_per_minute: i64,
    pub burst_per_hour: i64,
    pub monthly_request_quota: Option<i64>,
    pub daily_request_quota: Option<i64>,
    pub monthly_bandwidth_quota: Option<i64>,
    pub enable_throttling: bool,
    pub max_queue_time_ms: i64,
}

impl Default for TierLimits {
    fn default() -> Self {
        Self {
            requests_per_second: None,
            requests_per_minute: None,
            requests_per_hour: None,
            requests_per_day: None,
            requests_per_month: None,
            burst_per_second: 0,
            burst_per_minute: 0,
            burst_per_hour: 0,
            monthly_request_quota: None,
            daily_request_quota: None,
            monthly_bandwidth_quota: None,
            enable_throttling: false,
            max_queue_time_ms: 5_000,
        }
    }
}

impl TierLimits {
    pub fn to_dict(&self) -> Value {
        serde_json::to_value(self).expect("tier limits are JSON representable")
    }

    pub fn from_dict(value: Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Tier {
    pub tier_id: String,
    pub name: TierName,
    pub display_name: String,
    pub limits: TierLimits,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub price_monthly: Option<f64>,
    #[serde(default)]
    pub price_yearly: Option<f64>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl Tier {
    pub fn to_dict(&self) -> Value {
        serde_json::to_value(self).expect("tier is JSON representable")
    }

    pub fn from_dict(value: Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserTierAssignment {
    pub user_id: String,
    pub tier_id: String,
    #[serde(default)]
    pub override_limits: Option<TierLimits>,
    #[serde(default)]
    pub effective_from: Option<String>,
    #[serde(default)]
    pub effective_until: Option<String>,
    #[serde(default)]
    pub assigned_at: Option<String>,
    #[serde(default)]
    pub assigned_by: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl UserTierAssignment {
    pub fn to_dict(&self) -> Value {
        serde_json::to_value(self).expect("tier assignment is JSON representable")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct QuotaUsage {
    pub key: String,
    pub quota_type: QuotaType,
    pub current_usage: i64,
    pub limit: i64,
    pub reset_at: String,
    pub burst_usage: i64,
    pub burst_limit: i64,
}

impl QuotaUsage {
    pub fn remaining(&self) -> i64 {
        0.max(self.limit - self.current_usage)
    }

    pub fn percentage_used(&self) -> f64 {
        if self.limit == 0 {
            0.0
        } else {
            self.current_usage as f64 / self.limit as f64 * 100.0
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.current_usage >= self.limit
    }

    pub fn to_dict(&self) -> Value {
        json!({
            "key": self.key,
            "quota_type": self.quota_type,
            "current_usage": self.current_usage,
            "limit": self.limit,
            "remaining": self.remaining(),
            "percentage_used": self.percentage_used(),
            "reset_at": self.reset_at,
            "burst_usage": self.burst_usage,
            "burst_limit": self.burst_limit,
            "is_exhausted": self.is_exhausted(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitCounter {
    pub key: String,
    pub window_start: i64,
    pub window_size: i64,
    pub count: i64,
    pub limit: i64,
    pub burst_count: i64,
    pub burst_limit: i64,
}

impl RateLimitCounter {
    pub fn remaining(&self) -> i64 {
        0.max(self.limit - self.count)
    }

    pub fn is_limited(&self) -> bool {
        self.count >= self.limit
    }

    pub fn reset_at(&self) -> i64 {
        self.window_start + self.window_size
    }

    pub fn to_dict(&self) -> Value {
        json!({
            "key": self.key,
            "window_start": self.window_start,
            "window_size": self.window_size,
            "count": self.count,
            "limit": self.limit,
            "remaining": self.remaining(),
            "reset_at": self.reset_at(),
            "burst_count": self.burst_count,
            "burst_limit": self.burst_limit,
            "is_limited": self.is_limited(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UsageHistoryRecord {
    pub timestamp: String,
    pub user_id: Option<String>,
    pub api_name: Option<String>,
    pub endpoint_uri: Option<String>,
    pub ip_address: Option<String>,
    pub request_count: i64,
    pub blocked_count: i64,
    pub burst_used: i64,
    pub period: String,
}

impl UsageHistoryRecord {
    pub fn to_dict(&self) -> Value {
        json!({
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "api_name": self.api_name,
            "endpoint_uri": self.endpoint_uri,
            "ip_address": self.ip_address,
            "request_count": self.request_count,
            "blocked_count": self.blocked_count,
            "burst_used": self.burst_used,
            "period": self.period,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitInfo {
    pub limit: i64,
    pub remaining: i64,
    pub reset_at: i64,
    pub retry_after: Option<i64>,
    pub burst_limit: i64,
    pub burst_remaining: i64,
    pub tier: Option<String>,
}

impl RateLimitInfo {
    pub fn to_headers(&self) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::from([
            ("X-RateLimit-Limit".to_owned(), self.limit.to_string()),
            (
                "X-RateLimit-Remaining".to_owned(),
                self.remaining.to_string(),
            ),
            ("X-RateLimit-Reset".to_owned(), self.reset_at.to_string()),
        ]);
        if let Some(retry_after) = self.retry_after {
            headers.insert(
                "X-RateLimit-Retry-After".to_owned(),
                retry_after.to_string(),
            );
            headers.insert("Retry-After".to_owned(), retry_after.to_string());
        }
        if self.burst_limit > 0 {
            headers.insert(
                "X-RateLimit-Burst-Limit".to_owned(),
                self.burst_limit.to_string(),
            );
            headers.insert(
                "X-RateLimit-Burst-Remaining".to_owned(),
                self.burst_remaining.to_string(),
            );
        }
        headers
    }

    pub fn to_dict(&self) -> Value {
        json!({
            "limit": self.limit,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
            "retry_after": self.retry_after,
            "burst_limit": self.burst_limit,
            "burst_remaining": self.burst_remaining,
            "tier": self.tier,
        })
    }
}

pub const fn get_time_window_seconds(window: TimeWindow) -> i64 {
    match window {
        TimeWindow::Second => 1,
        TimeWindow::Minute => 60,
        TimeWindow::Hour => 3_600,
        TimeWindow::Day => 86_400,
        TimeWindow::Month => 2_592_000,
    }
}

pub fn generate_redis_key(
    rule_type: RuleType,
    identifier: &str,
    window: TimeWindow,
    window_start: i64,
) -> String {
    let type_prefix = rule_type.as_str().replace("per_", "");
    format!(
        "ratelimit:{type_prefix}:{identifier}:{}:{window_start}",
        window.as_str()
    )
}

pub fn generate_quota_key(user_id: &str, quota_type: QuotaType, period: &str) -> String {
    format!(
        "quota:user:{user_id}:{}:month:{period}",
        quota_type.as_str()
    )
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_and_tier_round_trips_preserve_python_defaults_and_wire_values() {
        let rule = RateLimitRule::from_dict(json!({
            "rule_id": "rule_001", "rule_type": "per_user", "time_window": "minute",
            "limit": 100, "created_at": "2025-12-01T10:20:30"
        }))
        .unwrap();
        assert_eq!(rule.burst_allowance, 0);
        assert!(rule.enabled);
        assert_eq!(rule.to_dict()["created_at"], "2025-12-01T10:20:30");
        assert!(
            RateLimitRule::from_dict(
                json!({"rule_id":"bad", "rule_type":"unknown", "time_window":"minute", "limit":1})
            )
            .is_err()
        );

        let tier = Tier::from_dict(json!({
            "tier_id": "tier_free", "name": "free", "display_name": "Free Plan",
            "limits": {"requests_per_minute": 60}
        }))
        .unwrap();
        assert_eq!(tier.limits.max_queue_time_ms, 5_000);
        assert!(tier.enabled);
        assert_eq!(tier.to_dict()["features"], json!([]));
        assert!(TierLimits::from_dict(json!({"unknown": 1})).is_err());
    }

    #[test]
    fn computed_usage_counter_and_history_shapes_match_python() {
        let usage = QuotaUsage {
            key: "quota:user:alice:requests:month:2025-12".to_owned(),
            quota_type: QuotaType::Requests,
            current_usage: 25,
            limit: 100,
            reset_at: "2026-01-01T00:00:00".to_owned(),
            burst_usage: 2,
            burst_limit: 5,
        };
        assert_eq!(usage.remaining(), 75);
        assert_eq!(usage.percentage_used(), 25.0);
        assert!(!usage.is_exhausted());
        assert_eq!(usage.to_dict()["quota_type"], "requests");

        let counter = RateLimitCounter {
            key: "k".to_owned(),
            window_start: 100,
            window_size: 60,
            count: 11,
            limit: 10,
            burst_count: 1,
            burst_limit: 2,
        };
        assert_eq!(counter.remaining(), 0);
        assert!(counter.is_limited());
        assert_eq!(counter.reset_at(), 160);
        assert_eq!(counter.to_dict()["is_limited"], true);

        let history = UsageHistoryRecord {
            timestamp: "2025-12-01T00:00:00".to_owned(),
            user_id: Some("alice".to_owned()),
            api_name: None,
            endpoint_uri: None,
            ip_address: None,
            request_count: 3,
            blocked_count: 1,
            burst_used: 1,
            period: "minute".to_owned(),
        };
        assert_eq!(history.to_dict()["period"], "minute");
    }

    #[test]
    fn response_headers_windows_and_storage_keys_match_python() {
        let info = RateLimitInfo {
            limit: 100,
            remaining: 4,
            reset_at: 1_701_504_000,
            retry_after: Some(7),
            burst_limit: 20,
            burst_remaining: 3,
            tier: Some("pro".to_owned()),
        };
        let headers = info.to_headers();
        assert_eq!(headers["X-RateLimit-Limit"], "100");
        assert_eq!(headers["Retry-After"], "7");
        assert_eq!(headers["X-RateLimit-Burst-Remaining"], "3");
        assert_eq!(info.to_dict()["tier"], "pro");
        assert_eq!(get_time_window_seconds(TimeWindow::Month), 2_592_000);
        assert_eq!(
            generate_redis_key(
                RuleType::PerUser,
                "john_doe",
                TimeWindow::Minute,
                1_701_504_000
            ),
            "ratelimit:user:john_doe:minute:1701504000"
        );
        assert_eq!(
            generate_redis_key(RuleType::Global, "all", TimeWindow::Second, 10),
            "ratelimit:global:all:second:10"
        );
        assert_eq!(
            generate_quota_key("john_doe", QuotaType::Requests, "2025-12"),
            "quota:user:john_doe:requests:month:2025-12"
        );
    }
}
