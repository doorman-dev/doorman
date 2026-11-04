use http::StatusCode;
use serde::Serialize;
use serde_json::Value;

use crate::{
    policy::{PolicyFailure, PolicyStage},
    storage::{
        models::{PolicyDocuments, bool_field_default, string_field, u64_field},
        runtime::SharedStorage,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TierLimitStatus {
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: u64,
    pub retry_after: Option<u64>,
    pub burst_remaining: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TierLimitBody {
    pub error: &'static str,
    pub error_code: &'static str,
    pub message: String,
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: u64,
    pub retry_after: u64,
}

impl TierLimitStatus {
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("x-ratelimit-limit", self.limit.to_string()),
            ("x-ratelimit-remaining", self.remaining.to_string()),
            ("x-ratelimit-reset", self.reset_at.to_string()),
        ];
        if let Some(retry_after) = self.retry_after {
            headers.push(("x-ratelimit-retry-after", retry_after.to_string()));
            headers.push(("retry-after", retry_after.to_string()));
        }
        headers
    }
}

pub async fn enforce(
    documents: &PolicyDocuments,
    storage: &SharedStorage,
    username: &str,
    now_seconds: u64,
    mutate: bool,
) -> Result<Option<TierLimitStatus>, PolicyFailure> {
    let Some(limits) = effective_limits(documents, username, now_seconds) else {
        return Ok(None);
    };
    let windows = [
        ("minute", 60_u64, "requests_per_minute", "burst_per_minute"),
        ("hour", 3_600, "requests_per_hour", "burst_per_hour"),
        ("day", 86_400, "requests_per_day", ""),
    ];
    let mut smallest = None;
    for (period, seconds, limit_field, burst_field) in windows {
        let Some(limit) =
            u64_field(&limits, limit_field).filter(|limit| *limit > 0 && *limit < 999_999)
        else {
            continue;
        };
        let burst = if burst_field.is_empty() {
            0
        } else {
            u64_field(&limits, burst_field).unwrap_or(0)
        };
        let window_start = now_seconds / seconds * seconds;
        let reset_at = window_start + seconds;
        let key = format!("ratelimit:user:{username}:{period}:{window_start}");
        let count = if mutate {
            storage
                .check_tier_window(&key, limit, seconds.saturating_mul(2))
                .await
                .map_err(storage_failure)?
        } else {
            storage
                .current_counter(&key)
                .await
                .map_err(storage_failure)?
        };
        let allowed = if mutate {
            count <= limit
        } else {
            count < limit
        };
        let status = TierLimitStatus {
            limit,
            remaining: if mutate {
                // Python reports remaining from the pre-increment count.
                limit.saturating_sub(count.saturating_sub(1))
            } else {
                limit.saturating_sub(count)
            },
            reset_at,
            retry_after: (!allowed).then_some(reset_at.saturating_sub(now_seconds)),
            burst_remaining: burst,
        };
        if !allowed {
            let retry_after = status.retry_after.unwrap_or_default();
            return Err(PolicyFailure::tier_limit(
                TierLimitBody {
                    error: "Rate limit exceeded",
                    error_code: "RATE_LIMIT_EXCEEDED",
                    message: format!("Rate limit exceeded: quota {limit} per {period}"),
                    limit,
                    remaining: 0,
                    reset_at,
                    retry_after,
                },
                status,
            ));
        }
        if smallest.is_none() {
            smallest = Some(status);
        }
    }
    Ok(smallest)
}

/// The user's effective `limits.ai_monthly_token_allowance` (override limits,
/// then the assigned tier, then the default tier) as `(tier_id, tokens)`.
pub fn ai_monthly_token_allowance(
    documents: &PolicyDocuments,
    username: &str,
    now_seconds: u64,
) -> Option<(String, u64)> {
    let limits = effective_limits(documents, username, now_seconds)?;
    let allowance = limits
        .get("ai_monthly_token_allowance")
        .and_then(Value::as_u64)
        .filter(|tokens| *tokens > 0)?;
    let tier = documents
        .tier_assignments
        .iter()
        .find(|value| string_field(value, "user_id") == Some(username))
        .and_then(|value| string_field(value, "tier_id"))
        .or_else(|| {
            documents
                .tiers
                .iter()
                .find(|value| bool_field_default(value, "is_default", false))
                .and_then(|value| string_field(value, "tier_id"))
        })
        .unwrap_or("override")
        .to_owned();
    Some((tier, allowance))
}

/// The user's assigned tier, or the default tier when they have none.
pub fn user_tier_id(documents: &PolicyDocuments, username: &str) -> Option<String> {
    documents
        .tier_assignments
        .iter()
        .find(|value| string_field(value, "user_id") == Some(username))
        .and_then(|value| string_field(value, "tier_id"))
        .or_else(|| {
            documents
                .tiers
                .iter()
                .find(|value| bool_field_default(value, "is_default", false))
                .and_then(|value| string_field(value, "tier_id"))
        })
        .map(str::to_owned)
}

fn effective_limits(
    documents: &PolicyDocuments,
    username: &str,
    now_seconds: u64,
) -> Option<Value> {
    let assignment = documents
        .tier_assignments
        .iter()
        .find(|value| string_field(value, "user_id") == Some(username));
    if let Some(overrides) = assignment
        .and_then(|value| value.get("override_limits"))
        .filter(|value| value.is_object())
    {
        return Some(overrides.clone());
    }

    let assigned_tier = assignment
        .filter(|value| assignment_is_effective(value, now_seconds))
        .and_then(|value| string_field(value, "tier_id"));
    let tier = assigned_tier
        .and_then(|tier_id| {
            documents
                .tiers
                .iter()
                .find(|value| string_field(value, "tier_id") == Some(tier_id))
        })
        .or_else(|| {
            documents
                .tiers
                .iter()
                .find(|value| bool_field_default(value, "is_default", false))
        })?;
    tier.get("limits")
        .filter(|value| value.is_object())
        .cloned()
}

pub fn assignment_is_effective(assignment: &Value, now_seconds: u64) -> bool {
    let starts = timestamp_field(assignment.get("effective_from"));
    let ends = timestamp_field(assignment.get("effective_until"));
    starts.is_none_or(|start| now_seconds >= start) && ends.is_none_or(|end| now_seconds <= end)
}

fn timestamp_field(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if value.is_null() {
        return None;
    }
    if let Some(value) = value.as_u64() {
        return Some(value / if value > 10_000_000_000 { 1_000 } else { 1 });
    }
    if let Some(value) = value.as_str() {
        let rfc3339 =
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .or_else(|_| {
                    // TierService stores datetime.now().isoformat(), which is a
                    // timezone-naive timestamp. The Python process compares it to
                    // its local naive now; the gateway standardizes that persisted
                    // representation as UTC for effective-assignment evaluation.
                    time::OffsetDateTime::parse(
                        &format!("{value}Z"),
                        &time::format_description::well_known::Rfc3339,
                    )
                });
        return rfc3339
            .ok()
            .and_then(|value| u64::try_from(value.unix_timestamp()).ok());
    }
    value
        .pointer("/$date/$numberLong")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value / 1_000)
}

fn storage_failure(error: crate::storage::runtime::StorageError) -> PolicyFailure {
    tracing::error!(error = %error, "tier rate-limit state unavailable");
    PolicyFailure::new(
        PolicyStage::Resolution,
        StatusCode::SERVICE_UNAVAILABLE,
        "GTW006",
        "Gateway state store unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_overrides_assignment_and_default_tiers() {
        let documents = PolicyDocuments {
            tiers: vec![
                json!({"tier_id": "free", "is_default": true, "limits": {"requests_per_minute": 10}}),
                json!({"tier_id": "pro", "limits": {"requests_per_minute": 100}}),
            ],
            tier_assignments: vec![
                json!({"user_id": "assigned", "tier_id": "pro"}),
                json!({"user_id": "override", "tier_id": "free", "override_limits": {"requests_per_minute": 7}}),
            ],
            ..Default::default()
        };
        assert_eq!(
            effective_limits(&documents, "assigned", 1_700_000_000).unwrap()["requests_per_minute"],
            100
        );
        assert_eq!(
            effective_limits(&documents, "override", 1_700_000_000).unwrap()["requests_per_minute"],
            7
        );
        assert_eq!(
            effective_limits(&documents, "unassigned", 1_700_000_000).unwrap()["requests_per_minute"],
            10
        );
    }
}
