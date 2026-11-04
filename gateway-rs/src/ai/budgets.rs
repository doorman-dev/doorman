//! AI budgets: resolution, pre-check and charge (plan P3.1, decision D6).
//!
//! Budgets are soft limits: concurrent in-flight requests can each overshoot
//! by at most one request. Counters live in shared storage (Redis or memory)
//! under `ai_budget:{budget_id}:{period_key}`. A storage error never blocks a
//! request; it is logged and the budget is skipped.
//!
//! A budget can be limited to one `provider`, and a global, group or API
//! budget can be `per_user`: each member then gets their own allowance under
//! `ai_budget:{budget_id}:{period_key}:u:{username}`, while the shared key
//! keeps the total across members for reporting only.

use serde_json::{Value, json};
use time::{Date, Duration, Month, OffsetDateTime, Time, format_description::well_known::Rfc3339};

use crate::{
    ai::usage::AiUsage,
    storage::{models::PolicyDocuments, runtime::SharedStorage},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetSpec {
    pub budget_id: String,
    pub name: String,
    pub scope: String,
    pub target: String,
    pub period: String,
    pub limit_type: String,
    pub limit_value: u64,
    pub action: String,
    pub downgrade_model: Option<String>,
    pub warn_at_percent: u64,
    pub enabled: bool,
    /// Only requests to this provider (`openai`, `anthropic`, ...) count.
    pub provider: Option<String>,
    /// Each member gets their own allowance (global, group and api scopes).
    pub per_user: bool,
    /// The member whose allowance this resolved spec tracks (set by
    /// [`applicable`] for `per_user` budgets).
    pub member: Option<String>,
}

impl BudgetSpec {
    pub fn from_value(value: &Value) -> Option<Self> {
        let text = |field: &str| value.get(field).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            budget_id: text("budget_id")?,
            name: text("name").unwrap_or_default(),
            scope: text("scope")?,
            target: text("target").unwrap_or_default(),
            period: text("period")?,
            limit_type: text("limit_type")?,
            limit_value: value.get("limit_value").and_then(Value::as_u64)?,
            action: text("action")?,
            downgrade_model: text("downgrade_model").filter(|model| !model.is_empty()),
            warn_at_percent: value
                .get("warn_at_percent")
                .and_then(Value::as_u64)
                .unwrap_or(80),
            enabled: value
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            provider: text("provider").filter(|provider| !provider.is_empty()),
            per_user: value
                .get("per_user")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            member: None,
        })
    }

    /// The shared counter: the whole budget, or for `per_user` budgets the
    /// reporting total across members.
    pub fn total_key(&self, now: OffsetDateTime) -> String {
        format!(
            "ai_budget:{}:{}",
            self.budget_id,
            period_key(now, &self.period)
        )
    }

    /// The counter the limit is enforced against.
    pub fn counter_key(&self, now: OffsetDateTime) -> String {
        match &self.member {
            Some(member) => format!("{}:u:{member}", self.total_key(now)),
            None => self.total_key(now),
        }
    }
}

/// `d2026-10-18`, `w2026-42` (ISO week) or `m2026-10`, all UTC.
pub fn period_key(now: OffsetDateTime, period: &str) -> String {
    let now = now.to_offset(time::UtcOffset::UTC);
    match period {
        "day" => format!("d{}", now.date()),
        "week" => {
            let (year, week, _) = now.date().to_iso_week_date();
            format!("w{year}-{week:02}")
        }
        _ => format!("m{}-{:02}", now.year(), u8::from(now.month())),
    }
}

/// Start of the next period (UTC).
pub fn resets_at(now: OffsetDateTime, period: &str) -> OffsetDateTime {
    let today = now.to_offset(time::UtcOffset::UTC).date();
    let next: Date = match period {
        "day" => today + Duration::days(1),
        "week" => today + Duration::days(7 - i64::from(today.weekday().number_days_from_monday())),
        _ => {
            let (year, month) = match today.month() {
                Month::December => (today.year() + 1, Month::January),
                month => (today.year(), month.next()),
            };
            Date::from_calendar_date(year, month, 1).unwrap_or(today)
        }
    };
    next.with_time(Time::MIDNIGHT).assume_utc()
}

/// Counter TTL per §5.4: day 2 days, week 15 days, month 40 days.
pub fn ttl_seconds(period: &str) -> u64 {
    match period {
        "day" => 2 * 86_400,
        "week" => 15 * 86_400,
        _ => 40 * 86_400,
    }
}

/// Enabled budgets for a request, plus the user's tier token allowance as an
/// implicit monthly blocking user budget. Sorted by `budget_id`.
///
/// `api` and `provider` describe the request; `None` means "any" (used for a
/// user's status view), which lists provider budgets and per-user API
/// budgets but not shared API pools.
pub fn applicable(
    documents: &PolicyDocuments,
    username: &str,
    groups: &[String],
    api: Option<&str>,
    provider: Option<&str>,
    now: OffsetDateTime,
) -> Vec<BudgetSpec> {
    let tier = crate::policy::tier::user_tier_id(documents, username);
    let mut specs: Vec<BudgetSpec> = documents
        .ai_budgets
        .iter()
        .filter_map(BudgetSpec::from_value)
        .filter(|spec| spec.enabled)
        .filter(|spec| match spec.scope.as_str() {
            "global" => true,
            "user" => spec.target == username,
            "group" => groups.iter().any(|group| group == &spec.target),
            "tier" => tier.as_deref() == Some(spec.target.as_str()),
            "api" => api.map_or(spec.per_user, |api| spec.target == api),
            _ => false,
        })
        .filter(|spec| match (&spec.provider, provider) {
            (Some(wanted), Some(actual)) => wanted == actual,
            _ => true,
        })
        .map(|mut spec| {
            if spec.per_user && spec.scope != "user" {
                spec.member = Some(username.to_owned());
            }
            spec
        })
        .collect();
    if let Some((tier, allowance)) = crate::policy::tier::ai_monthly_token_allowance(
        documents,
        username,
        now.unix_timestamp().max(0) as u64,
    ) {
        specs.push(BudgetSpec {
            budget_id: format!("tier-{tier}-{username}"),
            name: format!("Tier {tier} AI token allowance"),
            scope: "user".to_owned(),
            target: username.to_owned(),
            period: "month".to_owned(),
            limit_type: "tokens".to_owned(),
            limit_value: allowance,
            action: "block".to_owned(),
            downgrade_model: None,
            warn_at_percent: 80,
            enabled: true,
            provider: None,
            per_user: false,
            member: None,
        });
    }
    specs.sort_by(|a, b| a.budget_id.cmp(&b.budget_id));
    specs
}

pub async fn used(storage: &SharedStorage, spec: &BudgetSpec, now: OffsetDateTime) -> u64 {
    storage
        .current_counter(&spec.counter_key(now))
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, budget = %spec.budget_id, "failed to read AI budget counter");
            0
        })
}

pub fn percent(used: u64, limit: u64) -> u64 {
    if limit == 0 {
        return 0;
    }
    (u128::from(used) * 100 / u128::from(limit)) as u64
}

/// `BudgetStatus` (plan §5.9).
pub fn status_json(spec: &BudgetSpec, used: u64, now: OffsetDateTime) -> Value {
    json!({
        "budget_id": spec.budget_id,
        "name": spec.name,
        "scope": spec.scope,
        "target": spec.target,
        "period": spec.period,
        "limit_type": spec.limit_type,
        "limit_value": spec.limit_value,
        "used": used,
        "percent": percent(used, spec.limit_value),
        "action": spec.action,
        "provider": spec.provider,
        "per_user": spec.per_user,
        "period_key": period_key(now, &spec.period),
        "resets_at": resets_at(now, &spec.period).format(&Rfc3339).unwrap_or_default(),
    })
}

/// A counter to charge once the request's usage is known.
#[derive(Clone, Debug)]
pub struct BudgetCharge {
    pub key: String,
    pub ttl_seconds: u64,
    pub tokens: bool,
}

#[derive(Debug, Default)]
pub struct Precheck {
    pub charges: Vec<BudgetCharge>,
    /// (budget name, model to switch to)
    pub downgrade: Option<(String, String)>,
    /// (budget name, percent used) for the highest budget over its warning threshold.
    pub warning: Option<(String, u64)>,
}

#[derive(Debug)]
pub struct BudgetBlock {
    pub budget: String,
    pub resets_at: OffsetDateTime,
    pub retry_after_seconds: u64,
}

pub async fn precheck(
    storage: &SharedStorage,
    specs: &[BudgetSpec],
    allowed_models: &[String],
    now: OffsetDateTime,
) -> Result<Precheck, BudgetBlock> {
    let mut outcome = Precheck::default();
    let mut warning: Option<(String, u64)> = None;
    for spec in specs {
        let used = used(storage, spec, now).await;
        let exceeded = used >= spec.limit_value;
        if exceeded && spec.action == "block" {
            let resets = resets_at(now, &spec.period);
            return Err(BudgetBlock {
                budget: spec.name.clone(),
                resets_at: resets,
                retry_after_seconds: (resets - now).whole_seconds().max(1) as u64,
            });
        }
        if exceeded && spec.action == "downgrade" && outcome.downgrade.is_none() {
            match spec.downgrade_model.as_deref() {
                Some(model) if crate::ai::config::model_allowed(model, allowed_models) => {
                    outcome.downgrade = Some((spec.name.clone(), model.to_owned()));
                }
                _ => tracing::warn!(
                    budget = %spec.budget_id,
                    "AI budget downgrade model is not allowed on this API; not downgrading"
                ),
            }
        }
        let used_percent = percent(used, spec.limit_value);
        if used_percent >= spec.warn_at_percent
            && warning
                .as_ref()
                .is_none_or(|(_, best)| used_percent > *best)
        {
            warning = Some((spec.name.clone(), used_percent));
        }
        outcome.charges.push(BudgetCharge {
            key: spec.counter_key(now),
            ttl_seconds: ttl_seconds(&spec.period),
            tokens: spec.limit_type == "tokens",
        });
        if spec.member.is_some() {
            outcome.charges.push(BudgetCharge {
                key: spec.total_key(now),
                ttl_seconds: ttl_seconds(&spec.period),
                tokens: spec.limit_type == "tokens",
            });
        }
    }
    outcome.warning = warning;
    Ok(outcome)
}

/// Adds the request's cost (nanos) or tokens (input + output + cache writes;
/// cache reads are excluded) to each applicable budget counter.
pub async fn charge(
    storage: &SharedStorage,
    charges: &[BudgetCharge],
    usage: &AiUsage,
    cost_nanos: u64,
) {
    let tokens = usage
        .input_tokens
        .saturating_add(usage.output_tokens)
        .saturating_add(usage.cache_write_tokens);
    for charge in charges {
        let amount = if charge.tokens { tokens } else { cost_nanos };
        if amount == 0 {
            continue;
        }
        if let Err(error) = storage
            .incr_by(&charge.key, amount, charge.ttl_seconds)
            .await
        {
            tracing::error!(%error, key = %charge.key, "failed to charge AI budget");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn iso_week_period_key() {
        // 2026-10-18 is a Sunday in ISO week 42.
        let now = datetime!(2026-10-18 23:59:59 UTC);
        assert_eq!(period_key(now, "day"), "d2026-10-18");
        assert_eq!(period_key(now, "week"), "w2026-42");
        assert_eq!(period_key(now, "month"), "m2026-10");
        assert_eq!(resets_at(now, "day"), datetime!(2026-10-19 00:00 UTC));
        assert_eq!(resets_at(now, "week"), datetime!(2026-10-19 00:00 UTC));
        assert_eq!(resets_at(now, "month"), datetime!(2026-11-01 00:00 UTC));
        // ISO year boundary: 2027-01-01 (Friday) belongs to 2026-W53.
        let new_year = datetime!(2027-01-01 08:00 UTC);
        assert_eq!(period_key(new_year, "week"), "w2026-53");
        assert_eq!(
            resets_at(datetime!(2026-12-31 08:00 UTC), "month"),
            datetime!(2027-01-01 00:00 UTC)
        );
        assert_eq!(
            resets_at(datetime!(2026-10-19 00:00 UTC), "week"),
            datetime!(2026-10-26 00:00 UTC)
        );
        assert_eq!(ttl_seconds("week"), 15 * 86_400);
    }

    #[test]
    fn applicable_budgets_match_scope_and_target() {
        let budget = |id: &str, scope: &str, target: &str| {
            json!({"budget_id": id, "name": id, "scope": scope, "target": target, "period": "month",
                "limit_type": "cost", "limit_value": 10, "action": "block", "enabled": true})
        };
        let mut disabled = budget("z", "global", "");
        disabled["enabled"] = json!(false);
        let documents = PolicyDocuments {
            ai_budgets: vec![
                budget("g", "group", "eng"),
                budget("a", "global", ""),
                budget("u", "user", "alice"),
                budget("o", "user", "bob"),
                budget("p", "api", "corp/v1"),
                budget("q", "api", "other/v1"),
                disabled,
            ],
            ..Default::default()
        };
        let now = datetime!(2026-10-18 12:00 UTC);
        let ids: Vec<String> = applicable(
            &documents,
            "alice",
            &["eng".to_owned()],
            Some("corp/v1"),
            Some("openai"),
            now,
        )
        .into_iter()
        .map(|spec| spec.budget_id)
        .collect();
        assert_eq!(ids, vec!["a", "g", "p", "u"]);
        let ids: Vec<String> =
            applicable(&documents, "carol", &[], Some("x/v1"), Some("openai"), now)
                .into_iter()
                .map(|spec| spec.budget_id)
                .collect();
        assert_eq!(ids, vec!["a"]);
    }

    #[test]
    fn provider_and_per_user_budgets_resolve_per_member() {
        let budget = |id: &str, scope: &str, target: &str, provider: &str| {
            json!({"budget_id": id, "name": id, "scope": scope, "target": target, "period": "month",
                "limit_type": "cost", "limit_value": 10, "action": "block", "enabled": true,
                "provider": provider, "per_user": true})
        };
        let documents = PolicyDocuments {
            ai_budgets: vec![
                budget("eng-openai", "group", "eng", "openai"),
                budget("eng-claude", "group", "eng", "anthropic"),
                budget("api-each", "api", "corp/v1", ""),
            ],
            ..Default::default()
        };
        let now = datetime!(2026-10-18 12:00 UTC);
        let eng = ["eng".to_owned()];
        let specs = applicable(
            &documents,
            "alice",
            &eng,
            Some("corp/v1"),
            Some("openai"),
            now,
        );
        let ids: Vec<&str> = specs.iter().map(|spec| spec.budget_id.as_str()).collect();
        assert_eq!(ids, vec!["api-each", "eng-openai"]);
        let openai = &specs[1];
        assert_eq!(openai.member.as_deref(), Some("alice"));
        assert_eq!(
            openai.counter_key(now),
            "ai_budget:eng-openai:m2026-10:u:alice"
        );
        assert_eq!(openai.total_key(now), "ai_budget:eng-openai:m2026-10");
        // A status view (any API, any provider) lists every per-user allowance.
        let all = applicable(&documents, "alice", &eng, None, None, now);
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn per_user_budget_blocks_one_member_and_keeps_a_total() {
        let storage = SharedStorage::connect(&crate::config::SharedStorageConfig::default())
            .await
            .unwrap();
        let doc = json!({"budget_id": "each", "name": "each", "scope": "global", "target": "",
            "period": "month", "limit_type": "tokens", "limit_value": 10, "action": "block",
            "enabled": true, "per_user": true});
        let documents = PolicyDocuments {
            ai_budgets: vec![doc],
            ..Default::default()
        };
        let now = OffsetDateTime::now_utc();
        let usage = AiUsage {
            input_tokens: 6,
            output_tokens: 6,
            ..Default::default()
        };
        let alice = applicable(&documents, "alice", &[], Some("a/v1"), Some("openai"), now);
        let charges = precheck(&storage, &alice, &[], now).await.unwrap().charges;
        assert_eq!(charges.len(), 2);
        charge(&storage, &charges, &usage, 0).await;
        assert!(precheck(&storage, &alice, &[], now).await.is_err());
        let bob = applicable(&documents, "bob", &[], Some("a/v1"), Some("openai"), now);
        assert!(precheck(&storage, &bob, &[], now).await.is_ok());
        assert_eq!(
            used(
                &storage,
                &BudgetSpec::from_value(&documents.ai_budgets[0]).unwrap(),
                now
            )
            .await,
            12
        );
    }
}
