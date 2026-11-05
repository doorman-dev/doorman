//! `/platform/ai/*` and `/platform/analytics/ai/*` handlers (plan §5.7, §5.9).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axum::{body::Body, response::Response};
use http::{HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    ai::{
        adapter::PRESETS,
        budgets::{self, BudgetSpec},
        keys,
        pricing::{builtin_prices, builtin_prices_enabled, format_usd, validate_pricing_doc},
        usage::{AiUsage, invalidate_price_table, price_table},
    },
    error_codes::ErrorCode,
    observability::audit,
    routes::platform::{error, has_permission, success, unexpected},
    state::AppState,
};

const MAX_ACTIVE_KEYS_PER_USER: usize = 20;

pub(crate) async fn dispatch(
    state: &AppState,
    method: &Method,
    path: &str,
    query: &HashMap<String, String>,
    payload: Value,
    username: &str,
    request_id: &str,
) -> Response {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method.clone(), segments.as_slice()) {
        (Method::GET, ["ai", "providers"]) => {
            success(StatusCode::OK, json!({"providers": PRESETS}), request_id)
        }
        (Method::GET, ["ai", "keys"]) => list_keys(state, username, request_id).await,
        (Method::POST, ["ai", "keys"]) => create_key(state, username, &payload, request_id).await,
        (Method::DELETE, ["ai", "keys", key_id]) => {
            revoke_key(state, username, key_id, request_id).await
        }
        (Method::GET, ["ai", "keys", "user", target]) => {
            if !has_permission(state, username, "manage_users").await {
                return forbidden(
                    "You do not have permission to view other users' AI keys",
                    request_id,
                );
            }
            list_keys(state, target, request_id).await
        }
        (Method::GET, ["ai", "pricing"]) => {
            if !has_permission(state, username, "view_analytics").await {
                return forbidden("You do not have permission to view AI pricing", request_id);
            }
            get_pricing(state, request_id).await
        }
        (Method::GET, ["ai", "pricing", "builtin"]) => {
            if !has_permission(state, username, "view_analytics").await {
                return forbidden("You do not have permission to view AI pricing", request_id);
            }
            let document = builtin_prices();
            success(
                StatusCode::OK,
                json!({
                    "enabled": builtin_prices_enabled(),
                    "source": document.get("source"),
                    "license": document.get("license"),
                    "generated_at": document.get("generated_at"),
                    "prices": document.get("prices").cloned().unwrap_or_else(|| json!([])),
                }),
                request_id,
            )
        }
        (Method::POST, ["ai", "pricing", "recalculate"]) => {
            if !has_permission(state, username, "manage_ai").await {
                return forbidden(
                    "You do not have permission to manage AI pricing",
                    request_id,
                );
            }
            recalculate_pricing(state, &payload, request_id).await
        }
        (Method::PUT, ["ai", "pricing"]) => {
            if !has_permission(state, username, "manage_ai").await {
                return forbidden(
                    "You do not have permission to manage AI pricing",
                    request_id,
                );
            }
            put_pricing(state, username, &payload, request_id).await
        }
        (Method::GET, ["ai", "usage", "me"]) => usage_me(state, username, request_id).await,
        (Method::GET, ["ai", "settings"]) => get_settings(state, request_id).await,
        (Method::PUT, ["ai", "settings"]) => {
            if !has_permission(state, username, "manage_ai").await {
                return forbidden(
                    "You do not have permission to manage AI settings",
                    request_id,
                );
            }
            put_settings(state, username, &payload, request_id).await
        }
        (_, ["ai", "guardrails", ..]) => {
            if !has_permission(state, username, "manage_security").await {
                return forbidden(
                    "You do not have permission to manage AI guardrails",
                    request_id,
                );
            }
            match (method.clone(), &segments[2..]) {
                (Method::GET, []) => list_guardrails(state, request_id).await,
                (Method::POST, ["test"]) => test_guardrail(state, &payload, request_id).await,
                (Method::POST, []) => {
                    save_guardrail(state, username, None, &payload, request_id).await
                }
                (Method::PUT, [id]) => {
                    save_guardrail(state, username, Some(id), &payload, request_id).await
                }
                (Method::DELETE, [id]) => delete_guardrail(state, username, id, request_id).await,
                _ => error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::AI_OPERATION_NOT_ALLOWED,
                    "AI platform route does not exist",
                    request_id,
                ),
            }
        }
        (Method::GET, ["ai", "prompt-logs"]) => {
            if !has_permission(state, username, "view_logs").await {
                return forbidden(
                    "You do not have permission to view AI prompt logs",
                    request_id,
                );
            }
            list_prompt_logs(state, query, request_id).await
        }
        (Method::GET, ["ai", "prompt-logs", id]) => {
            if !has_permission(state, username, "view_logs").await {
                return forbidden(
                    "You do not have permission to view AI prompt logs",
                    request_id,
                );
            }
            get_prompt_log(state, id, request_id).await
        }
        (Method::DELETE, ["ai", "prompt-logs", id]) => {
            if !has_permission(state, username, "manage_security").await {
                return forbidden(
                    "You do not have permission to delete AI prompt logs",
                    request_id,
                );
            }
            delete_prompt_log(state, username, id, request_id).await
        }
        (Method::GET, ["ai", "budgets", "status"]) => {
            budget_status(state, username, query, request_id).await
        }
        (_, ["ai", "budgets", ..]) => {
            if !has_permission(state, username, "manage_ai").await {
                return forbidden(
                    "You do not have permission to manage AI budgets",
                    request_id,
                );
            }
            match (method.clone(), &segments[2..]) {
                (Method::GET, []) => list_budgets(state, request_id).await,
                (Method::POST, []) => {
                    save_budget(state, username, None, &payload, request_id).await
                }
                (Method::PUT, [id]) => {
                    save_budget(state, username, Some(id), &payload, request_id).await
                }
                (Method::DELETE, [id]) => delete_budget(state, username, id, request_id).await,
                _ => error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::AI_OPERATION_NOT_ALLOWED,
                    "AI platform route does not exist",
                    request_id,
                ),
            }
        }
        (Method::GET, ["analytics", "ai", report]) => {
            if !has_permission(state, username, "view_analytics").await {
                return forbidden(
                    "You do not have permission to view AI analytics",
                    request_id,
                );
            }
            if *report == "export.csv" && !has_permission(state, username, "export_logs").await {
                return forbidden("You do not have permission to export AI usage", request_id);
            }
            analytics(state, report, query, request_id).await
        }
        _ => error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "AI platform route does not exist",
            request_id,
        ),
    }
}

// ── Pricing ─────────────────────────────────────────────────────────────────

const PRICING_FIELDS: [&str; 9] = [
    "pricing_id",
    "provider",
    "model_pattern",
    "input_usd_per_mtok",
    "output_usd_per_mtok",
    "cache_read_usd_per_mtok",
    "cache_write_usd_per_mtok",
    "effective_from",
    "note",
];

fn pricing_row(doc: &Value) -> Value {
    Value::Object(
        PRICING_FIELDS
            .iter()
            .map(|field| {
                (
                    (*field).to_owned(),
                    doc.get(*field).cloned().unwrap_or(Value::Null),
                )
            })
            .collect(),
    )
}

/// Re-prices past daily rollups that were recorded with no price, using the
/// current prices (admin and built-in). Rows that were partly priced are left
/// alone, because their tokens can't be split. Budget counters are not changed.
async fn recalculate_pricing(state: &AppState, payload: &Value, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let days = payload
        .get("days")
        .and_then(Value::as_u64)
        .unwrap_or(90)
        .clamp(1, 3650);
    let since = (OffsetDateTime::now_utc() - Duration::days(days as i64))
        .date()
        .to_string();
    let rows = match storage.find_many("ai_usage_daily", &json!({})).await {
        Ok(rows) => rows,
        Err(_) => return unexpected(request_id),
    };
    invalidate_price_table();
    let table = price_table(Some(storage)).await;
    let number = |row: &Value, field: &str| row.get(field).and_then(Value::as_u64).unwrap_or(0);
    let (mut repriced, mut requests, mut skipped, mut still_unpriced) =
        (0_u64, 0_u64, 0_u64, 0_u64);
    let mut added_nanos = 0_u64;
    for row in rows {
        let unpriced = number(&row, "unpriced_requests");
        let day = row.get("day").and_then(Value::as_str).unwrap_or_default();
        if unpriced == 0 || day < since.as_str() {
            continue;
        }
        if unpriced < number(&row, "requests").saturating_sub(number(&row, "errors")) {
            skipped += 1;
            continue;
        }
        let at = time::Date::parse(
            day,
            time::macros::format_description!("[year]-[month]-[day]"),
        )
        .map(|date| date.midnight().assume_utc())
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let usage = AiUsage {
            input_tokens: number(&row, "input_tokens"),
            output_tokens: number(&row, "output_tokens"),
            cache_read_tokens: number(&row, "cache_read_tokens"),
            cache_write_tokens: number(&row, "cache_write_tokens"),
            ..AiUsage::default()
        };
        let provider = row
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let model = row.get("model").and_then(Value::as_str).unwrap_or_default();
        let cost = table.cost(provider, model, &usage, at);
        if cost.unpriced {
            still_unpriced += 1;
            continue;
        }
        let Some(id) = row.get("_id").cloned() else {
            continue;
        };
        let total = number(&row, "cost_nanos").saturating_add(cost.cost_nanos);
        let update = json!({
            "cost_nanos": i64::try_from(total).unwrap_or(i64::MAX),
            "unpriced_requests": 0,
        });
        match storage
            .update_one("ai_usage_daily", &json!({"_id": id}), &update)
            .await
        {
            Ok(Some(_)) => {
                repriced += 1;
                requests += unpriced;
                added_nanos = added_nanos.saturating_add(cost.cost_nanos);
            }
            Ok(None) => {}
            Err(_) => return unexpected(request_id),
        }
    }
    success(
        StatusCode::OK,
        json!({
            "days": days,
            "repriced_rows": repriced,
            "repriced_requests": requests,
            "added_cost_usd": format_usd(added_nanos),
            "skipped_partly_priced_rows": skipped,
            "still_unpriced_rows": still_unpriced,
        }),
        request_id,
    )
}

async fn get_pricing(state: &AppState, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage.find_many("ai_pricing", &json!({})).await {
        Ok(docs) => {
            let updated_at = docs
                .iter()
                .filter_map(|doc| doc.get("updated_at").and_then(Value::as_str))
                .max()
                .map(str::to_owned);
            let pricing: Vec<Value> = docs.iter().map(pricing_row).collect();
            success(
                StatusCode::OK,
                json!({"pricing": pricing, "updated_at": updated_at}),
                request_id,
            )
        }
        Err(_) => unexpected(request_id),
    }
}

/// Replaces the whole pricing table after validating every row.
async fn put_pricing(
    state: &AppState,
    username: &str,
    payload: &Value,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let Some(rows) = payload.get("pricing").and_then(Value::as_array) else {
        return invalid("pricing: must be a list", request_id);
    };
    let mut errors = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if let Err(message) = validate_pricing_doc(row) {
            errors.push(format!("pricing[{index}]: {message}"));
        }
    }
    if !errors.is_empty() {
        return invalid(&errors.join("; "), request_id);
    }
    let updated_at = rfc3339(now());
    let docs: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut doc = pricing_row(row);
            if doc["pricing_id"].as_str().is_none_or(str::is_empty) {
                doc["pricing_id"] = json!(uuid::Uuid::new_v4().to_string());
            }
            doc["updated_at"] = json!(updated_at);
            doc
        })
        .collect();
    let existing = match storage.find_many("ai_pricing", &json!({})).await {
        Ok(existing) => existing,
        Err(_) => return unexpected(request_id),
    };
    for doc in &existing {
        if let Some(id) = doc.get("pricing_id") {
            if storage
                .delete_one("ai_pricing", &json!({"pricing_id": id}))
                .await
                .is_err()
            {
                return unexpected(request_id);
            }
        }
    }
    for doc in &docs {
        if storage.insert_one("ai_pricing", doc.clone()).await.is_err() {
            return unexpected(request_id);
        }
    }
    invalidate_price_table();
    audit::management_mutation(username, "ai_pricing.replace", "ai_pricing", "success");
    let pricing: Vec<Value> = docs.iter().map(pricing_row).collect();
    success(
        StatusCode::OK,
        json!({"pricing": pricing, "updated_at": updated_at}),
        request_id,
    )
}

// ── Analytics ───────────────────────────────────────────────────────────────

const MAX_RANGE_DAYS: i64 = 400;

#[derive(Clone, Default)]
struct Totals {
    requests: u64,
    errors: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    cost_nanos: u64,
    estimated_requests: u64,
    unpriced_requests: u64,
}

impl Totals {
    fn add(&mut self, row: &Value) {
        let field = |name: &str| row.get(name).and_then(Value::as_u64).unwrap_or(0);
        self.requests += field("requests");
        self.errors += field("errors");
        self.input_tokens += field("input_tokens");
        self.output_tokens += field("output_tokens");
        self.cache_read_tokens += field("cache_read_tokens");
        self.cache_write_tokens += field("cache_write_tokens");
        self.cost_nanos += field("cost_nanos");
        self.estimated_requests += field("estimated_requests");
        self.unpriced_requests += field("unpriced_requests");
    }

    fn json(&self) -> serde_json::Map<String, Value> {
        let value = json!({
            "requests": self.requests,
            "errors": self.errors,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "cost_nanos": self.cost_nanos,
            "cost_usd": format_usd(self.cost_nanos),
            "estimated_requests": self.estimated_requests,
            "unpriced_requests": self.unpriced_requests,
        });
        value.as_object().cloned().unwrap_or_default()
    }
}

fn parse_day(value: &str) -> Option<time::Date> {
    time::Date::parse(
        value,
        time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()
}

/// Inclusive UTC `start`/`end` (`YYYY-MM-DD`); defaults to the last 30 days.
fn day_range(query: &HashMap<String, String>) -> Result<(String, String), String> {
    let today = now().date();
    let parse = |name: &str, default: time::Date| match query.get(name).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(raw) => parse_day(raw).ok_or_else(|| format!("{name}: must be a YYYY-MM-DD date")),
    };
    let end = parse("end", today)?;
    let start = parse("start", end - Duration::days(29))?;
    if start > end {
        return Err("start: must not be after end".to_owned());
    }
    if (end - start).whole_days() >= MAX_RANGE_DAYS {
        return Err(format!("start: range is limited to {MAX_RANGE_DAYS} days"));
    }
    Ok((start.to_string(), end.to_string()))
}

async fn usage_rows(state: &AppState, start: &str, end: &str) -> Option<Vec<Value>> {
    state
        .storage
        .as_ref()?
        .find_many(
            "ai_usage_daily",
            &json!({"day": {"$gte": start, "$lte": end}}),
        )
        .await
        .ok()
}

fn sorted_by_cost(groups: BTreeMap<String, Totals>) -> Vec<(String, Totals)> {
    let mut rows: Vec<(String, Totals)> = groups.into_iter().collect();
    rows.sort_by(|(a_key, a), (b_key, b)| {
        b.cost_nanos
            .cmp(&a.cost_nanos)
            .then(b.requests.cmp(&a.requests))
            .then(a_key.cmp(b_key))
    });
    rows
}

fn row_string(row: &Value, field: &str) -> String {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn row_groups(row: &Value) -> Vec<String> {
    row.get("groups")
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Breakdown key for usage with no role or tier.
const NO_VALUE: &str = "(none)";

/// username → (current role, current tier).
async fn people_lookup(state: &AppState) -> HashMap<String, (Option<String>, Option<String>)> {
    let Some(documents) = policy_documents(state).await else {
        return HashMap::new();
    };
    documents
        .users
        .iter()
        .filter_map(|user| {
            let username = user.get("username").and_then(Value::as_str)?;
            let role = user.get("role").and_then(Value::as_str).map(str::to_owned);
            let tier = crate::policy::tier::user_tier_id(&documents, username);
            Some((username.to_owned(), (role, tier)))
        })
        .collect()
}

/// Role and tier come from each row's snapshot (taken at request time); rows
/// recorded before snapshots existed use the user's current values.
async fn fill_role_and_tier(state: &AppState, rows: &mut [Value]) {
    let people = people_lookup(state).await;
    for row in rows.iter_mut() {
        let username = row_string(row, "username");
        let current = people.get(&username);
        for (field, fallback) in [
            ("role", current.and_then(|(role, _)| role.clone())),
            ("tier", current.and_then(|(_, tier)| tier.clone())),
        ] {
            if row_string(row, field).is_empty() {
                row[field] = json!(fallback.unwrap_or_else(|| NO_VALUE.to_owned()));
            }
        }
    }
}

async fn analytics(
    state: &AppState,
    report: &str,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    if report == "export.csv" {
        return export_csv(state, query, request_id).await;
    }
    let (start, end) = match day_range(query) {
        Ok(range) => range,
        Err(message) => return invalid(&message, request_id),
    };
    let Some(mut rows) = usage_rows(state, &start, &end).await else {
        return unexpected(request_id);
    };
    // Optional filters (USER-approved §5.9 extension), ANDed before aggregation.
    let filter = |name: &str| {
        query
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    };
    let (model, group, user) = (filter("model"), filter("group"), filter("username"));
    let (role, tier, provider) = (filter("role"), filter("tier"), filter("provider"));
    fill_role_and_tier(state, &mut rows).await;
    rows.retain(|row| {
        model.is_none_or(|model| row_string(row, "model") == model)
            && user.is_none_or(|user| row_string(row, "username") == user)
            && group.is_none_or(|group| row_groups(row).iter().any(|g| g == group))
            && role.is_none_or(|role| row_string(row, "role") == role)
            && tier.is_none_or(|tier| row_string(row, "tier") == tier)
            && provider.is_none_or(|provider| row_string(row, "provider") == provider)
    });
    match report {
        "overview" => {
            let mut totals = Totals::default();
            let mut users = BTreeSet::new();
            let mut models: BTreeMap<String, Totals> = BTreeMap::new();
            for row in &rows {
                totals.add(row);
                if row.get("requests").and_then(Value::as_u64).unwrap_or(0) > 0 {
                    users.insert(row_string(row, "username"));
                }
                let key = format!(
                    "{}\u{0}{}",
                    row_string(row, "provider"),
                    row_string(row, "model")
                );
                models.entry(key).or_default().add(row);
            }
            let top_models: Vec<Value> = sorted_by_cost(models)
                .into_iter()
                .take(10)
                .map(|(key, totals)| {
                    let (provider, model) = key.split_once('\u{0}').unwrap_or_default();
                    json!({
                        "provider": provider,
                        "model": model,
                        "requests": totals.requests,
                        "input_tokens": totals.input_tokens,
                        "output_tokens": totals.output_tokens,
                        "cost_nanos": totals.cost_nanos,
                        "cost_usd": format_usd(totals.cost_nanos),
                    })
                })
                .collect();
            let mut body = totals.json();
            body.insert("start".to_owned(), json!(start));
            body.insert("end".to_owned(), json!(end));
            body.insert("active_users".to_owned(), json!(users.len()));
            body.insert("top_models".to_owned(), json!(top_models));
            success(StatusCode::OK, Value::Object(body), request_id)
        }
        "timeseries" => {
            let group_by = query.get("group_by").map(String::as_str).unwrap_or("none");
            if !matches!(group_by, "model" | "api" | "none") {
                return invalid("group_by: must be model, api or none", request_id);
            }
            let mut points: BTreeMap<(String, Option<String>), Totals> = BTreeMap::new();
            for row in &rows {
                let key = (group_by != "none").then(|| row_string(row, group_by));
                points
                    .entry((row_string(row, "day"), key))
                    .or_default()
                    .add(row);
            }
            let points: Vec<Value> = points
                .into_iter()
                .map(|((day, key), totals)| {
                    json!({
                        "day": day,
                        "key": key,
                        "requests": totals.requests,
                        "input_tokens": totals.input_tokens,
                        "output_tokens": totals.output_tokens,
                        "cost_nanos": totals.cost_nanos,
                        "cost_usd": format_usd(totals.cost_nanos),
                    })
                })
                .collect();
            success(
                StatusCode::OK,
                json!({"start": start, "end": end, "group_by": group_by, "points": points}),
                request_id,
            )
        }
        "breakdown" => {
            let dimension = query.get("dimension").map(String::as_str).unwrap_or("user");
            if !matches!(
                dimension,
                "user" | "group" | "role" | "tier" | "provider" | "model" | "api"
            ) {
                return invalid(
                    "dimension: must be user, group, role, tier, provider, model or api",
                    request_id,
                );
            }
            let limit = match query.get("limit") {
                None => 50,
                Some(raw) => match raw.parse::<usize>() {
                    Ok(limit) if (1..=500).contains(&limit) => limit,
                    _ => return invalid("limit: must be an integer from 1 to 500", request_id),
                },
            };
            let mut groups: BTreeMap<String, Totals> = BTreeMap::new();
            let mut user_groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            // username → (day, role, tier) of the newest row.
            let mut user_meta: BTreeMap<String, (String, String, String)> = BTreeMap::new();
            for row in &rows {
                match dimension {
                    // A user in several groups counts once per group (snapshot at first write).
                    "group" => {
                        for group in row_groups(row) {
                            groups.entry(group).or_default().add(row);
                        }
                    }
                    "user" => {
                        let user = row_string(row, "username");
                        user_groups
                            .entry(user.clone())
                            .or_default()
                            .extend(row_groups(row));
                        let day = row_string(row, "day");
                        let meta = user_meta.entry(user.clone()).or_default();
                        if day >= meta.0 {
                            *meta = (day, row_string(row, "role"), row_string(row, "tier"));
                        }
                        groups.entry(user).or_default().add(row);
                    }
                    other => groups.entry(row_string(row, other)).or_default().add(row),
                }
            }
            let rows: Vec<Value> = sorted_by_cost(groups)
                .into_iter()
                .take(limit)
                .map(|(key, totals)| {
                    let mut row = totals.json();
                    if dimension == "user" {
                        let groups: Vec<&String> = user_groups
                            .get(&key)
                            .map(|set| set.iter().collect())
                            .unwrap_or_default();
                        row.insert("groups".to_owned(), json!(groups));
                        if let Some((_, role, tier)) = user_meta.get(&key) {
                            row.insert("role".to_owned(), json!(role));
                            row.insert("tier".to_owned(), json!(tier));
                        }
                    }
                    row.insert("key".to_owned(), json!(key));
                    Value::Object(row)
                })
                .collect();
            success(
                StatusCode::OK,
                json!({"dimension": dimension, "start": start, "end": end, "rows": rows}),
                request_id,
            )
        }
        _ => error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "AI platform route does not exist",
            request_id,
        ),
    }
}

/// RFC 4180 quoting, plus a leading `'` for cells a spreadsheet would run as a formula.
fn csv_cell(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

/// Monthly chargeback CSV (metadata only, C6).
async fn export_csv(
    state: &AppState,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    let dimension = query
        .get("dimension")
        .map(String::as_str)
        .unwrap_or("group");
    if !matches!(dimension, "group" | "user") {
        return invalid("dimension: must be group or user", request_id);
    }
    let month = match query.get("month") {
        Some(month) => month.clone(),
        None => now().date().to_string()[..7].to_owned(),
    };
    let Some(first) = parse_day(&format!("{month}-01")).filter(|_| month.len() == 7) else {
        return invalid("month: must be YYYY-MM", request_id);
    };
    let last = first
        .replace_day(time::util::days_in_month(first.month(), first.year()))
        .unwrap_or(first);
    let Some(mut rows) = usage_rows(state, &first.to_string(), &last.to_string()).await else {
        return unexpected(request_id);
    };
    fill_role_and_tier(state, &mut rows).await;
    // (group, username, model, role, tier, provider) → totals; for `user`,
    // group is the joined group list.
    type Cell = (String, String, String, String, String, String);
    let mut cells: BTreeMap<Cell, Totals> = BTreeMap::new();
    for row in &rows {
        let rest = (
            row_string(row, "username"),
            row_string(row, "model"),
            row_string(row, "role"),
            row_string(row, "tier"),
            row_string(row, "provider"),
        );
        let groups = row_groups(row);
        let keys = if dimension == "group" {
            groups
        } else {
            vec![groups.join(";")]
        };
        for group in keys {
            let (username, model, role, tier, provider) = rest.clone();
            cells
                .entry((group, username, model, role, tier, provider))
                .or_default()
                .add(row);
        }
    }
    let mut csv = String::from(
        "# AI usage chargeback (metadata only). Group totals can double-count users who belong to several groups.\n\
         month,group,username,model,requests,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,cost_usd,estimated_requests,unpriced_requests,role,tier,provider\n",
    );
    for ((group, username, model, role, tier, provider), totals) in cells {
        let line = [
            csv_cell(&month),
            csv_cell(&group),
            csv_cell(&username),
            csv_cell(&model),
            totals.requests.to_string(),
            totals.input_tokens.to_string(),
            totals.output_tokens.to_string(),
            totals.cache_read_tokens.to_string(),
            totals.cache_write_tokens.to_string(),
            format_usd(totals.cost_nanos),
            totals.estimated_requests.to_string(),
            totals.unpriced_requests.to_string(),
            csv_cell(&role),
            csv_cell(&tier),
            csv_cell(&provider),
        ]
        .join(",");
        csv.push_str(&line);
        csv.push('\n');
    }
    let mut response = Response::new(Body::from(csv));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename=\"ai-chargeback-{dimension}-{month}.csv\""
    )) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert("x-request-id", value);
    }
    response
}

/// Signed-in user's month-to-date usage; budgets are filled in by C10.
async fn usage_me(state: &AppState, username: &str, request_id: &str) -> Response {
    let today = now().date();
    let month = today.to_string()[..7].to_owned();
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let rows = match storage
        .find_many(
            "ai_usage_daily",
            &json!({"username": username, "day": {"$gte": format!("{month}-01"), "$lte": today.to_string()}}),
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return unexpected(request_id),
    };
    let mut totals = Totals::default();
    rows.iter().for_each(|row| totals.add(row));
    success(
        StatusCode::OK,
        json!({
            "username": username,
            "period": "month",
            "period_key": format!("m{month}"),
            "usage": {
                "requests": totals.requests,
                "input_tokens": totals.input_tokens,
                "output_tokens": totals.output_tokens,
                "cost_nanos": totals.cost_nanos,
                "cost_usd": format_usd(totals.cost_nanos),
            },
            "budgets": own_budget_statuses(state, username).await,
            "apis": my_ai_apis(state, username).await,
        }),
        request_id,
    )
}

/// The active AI APIs `username` may call, with what an SDK needs to connect
/// (same subscription and group checks as the data plane).
async fn my_ai_apis(state: &AppState, username: &str) -> Vec<Value> {
    let Some(documents) = policy_documents(state).await else {
        return Vec::new();
    };
    let Some(user) = documents
        .users
        .iter()
        .find(|user| user.get("username").and_then(Value::as_str) == Some(username))
    else {
        return Vec::new();
    };
    let mut apis: Vec<Value> = documents
        .apis
        .iter()
        .filter(|api| crate::platform_contract::is_ai_api(api))
        .filter(|api| api.get("active").and_then(Value::as_bool) != Some(false))
        .filter(|api| crate::policy::groups::enforce_group_access(api, user).is_ok())
        .filter_map(|api| {
            let name = api.get("api_name").and_then(Value::as_str)?;
            let version = api.get("api_version").and_then(Value::as_str)?;
            let provider = api
                .get("api_ai_provider")
                .and_then(Value::as_str)
                .and_then(crate::ai::adapter::AiProvider::parse)?;
            let config = api
                .get("api_ai_config")
                .and_then(|config| crate::ai::config::AiApiConfig::from_value(config).ok())?;
            if config.require_subscription
                && crate::policy::subscription::enforce_subscription(
                    &format!("{name}/{version}"),
                    user,
                    &documents.roles,
                    &documents.subscriptions,
                    false,
                )
                .is_err()
            {
                return None;
            }
            let mut models: Vec<String> = config
                .allowed_models
                .iter()
                .filter(|model| !model.ends_with('*'))
                .cloned()
                .collect();
            models.extend(config.model_aliases.keys().cloned());
            Some(json!({
                "api_name": name,
                "api_version": version,
                "provider": provider.as_str(),
                "sdk_base_url_suffix": crate::ai::adapter::preset(provider).sdk_base_url_suffix,
                "default_model": config.default_model,
                "models": models,
                "model_patterns": config.allowed_models,
            }))
        })
        .collect();
    apis.sort_by(|a, b| {
        (a["api_name"].as_str(), a["api_version"].as_str())
            .cmp(&(b["api_name"].as_str(), b["api_version"].as_str()))
    });
    apis
}

// ── Budgets ─────────────────────────────────────────────────────────────────

const BUDGET_FIELDS: [&str; 13] = [
    "budget_id",
    "name",
    "scope",
    "target",
    "period",
    "limit_type",
    "limit_value",
    "action",
    "downgrade_model",
    "warn_at_percent",
    "enabled",
    "provider",
    "per_user",
];

fn budget_doc(value: &Value) -> Value {
    Value::Object(
        BUDGET_FIELDS
            .iter()
            .map(|field| {
                (
                    (*field).to_owned(),
                    value.get(*field).cloned().unwrap_or(Value::Null),
                )
            })
            .collect(),
    )
}

async fn policy_documents(state: &AppState) -> Option<crate::storage::models::PolicyDocuments> {
    state.storage.as_ref()?.load_policy_documents().await.ok()
}

/// Statuses of the budgets that apply to `username` on any API (user, group,
/// global and tier allowance).
async fn own_budget_statuses(state: &AppState, username: &str) -> Vec<Value> {
    let (Some(storage), Some(documents)) = (state.storage.as_ref(), policy_documents(state).await)
    else {
        return Vec::new();
    };
    let groups: Vec<String> = documents
        .users
        .iter()
        .find(|user| user.get("username").and_then(Value::as_str) == Some(username))
        .and_then(|user| user.get("groups"))
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let at = now();
    let mut statuses = Vec::new();
    for spec in budgets::applicable(&documents, username, &groups, None, None, at) {
        let used = budgets::used(storage, &spec, at).await;
        statuses.push(budgets::status_json(&spec, used, at));
    }
    statuses
}

async fn list_budgets(state: &AppState, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let docs = match storage.find_many("ai_budgets", &json!({})).await {
        Ok(docs) => docs,
        Err(_) => return unexpected(request_id),
    };
    let at = now();
    let mut rows = Vec::new();
    for doc in &docs {
        let mut row = budget_doc(doc);
        if let Some(spec) = BudgetSpec::from_value(doc) {
            // For per-user budgets this is the total across members; the
            // limit applies to each member, so there is no single percent.
            let used = budgets::used(storage, &spec, at).await;
            row["used"] = json!(used);
            row["percent"] = if spec.per_user && spec.scope != "user" {
                Value::Null
            } else {
                json!(budgets::percent(used, spec.limit_value))
            };
            row["per_user"] = json!(spec.per_user);
            row["resets_at"] = json!(rfc3339(budgets::resets_at(at, &spec.period)));
        }
        rows.push(row);
    }
    rows.sort_by(|a, b| a["budget_id"].as_str().cmp(&b["budget_id"].as_str()));
    success(StatusCode::OK, json!({"budgets": rows}), request_id)
}

/// Validates a budget against §5.3 / P3.2 and returns the normalized document.
async fn validate_budget(state: &AppState, input: &Value) -> Result<Value, String> {
    let documents = policy_documents(state)
        .await
        .ok_or_else(|| "storage: unavailable".to_owned())?;
    let mut errors = Vec::new();
    let text = |field: &str| {
        input
            .get(field)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default()
    };
    let name = text("name");
    if name.is_empty() || name.chars().count() > 100 {
        errors.push("name: must be 1-100 characters".to_owned());
    }
    let scope = text("scope");
    let mut target = text("target").to_owned();
    match scope {
        "global" => target.clear(),
        "user" => {
            if !documents
                .users
                .iter()
                .any(|user| user.get("username").and_then(Value::as_str) == Some(target.as_str()))
            {
                errors.push("target: user does not exist".to_owned());
            }
        }
        "group" => {
            let filter = json!({"group_name": target});
            let exists = match state.storage.as_ref() {
                Some(storage) => storage
                    .find_one("groups", &filter)
                    .await
                    .ok()
                    .flatten()
                    .is_some(),
                None => false,
            };
            if !exists {
                errors.push("target: group does not exist".to_owned());
            }
        }
        "tier" => {
            if !documents
                .tiers
                .iter()
                .any(|tier| tier.get("tier_id").and_then(Value::as_str) == Some(target.as_str()))
            {
                errors.push("target: tier does not exist".to_owned());
            }
        }
        "api" => {
            let exists = target.split_once('/').is_some_and(|(name, version)| {
                documents.apis.iter().any(|api| {
                    api.get("api_name").and_then(Value::as_str) == Some(name)
                        && api.get("api_version").and_then(Value::as_str) == Some(version)
                        && crate::platform_contract::is_ai_api(api)
                })
            });
            if !exists {
                errors.push("target: AI API {api_name}/{api_version} does not exist".to_owned());
            }
        }
        _ => errors.push("scope: must be user, group, tier, api or global".to_owned()),
    }
    let period = text("period");
    if !matches!(period, "minute" | "hour" | "day" | "week" | "month") {
        errors.push("period: must be minute, hour, day, week or month".to_owned());
    }
    let limit_type = text("limit_type");
    if !matches!(limit_type, "cost" | "tokens" | "requests") {
        errors.push("limit_type: must be cost, tokens or requests".to_owned());
    }
    let limit_value = input
        .get("limit_value")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    if limit_value.is_none() {
        errors.push("limit_value: must be an integer greater than 0".to_owned());
    }
    let action = text("action");
    if !matches!(action, "warn" | "downgrade" | "block") {
        errors.push("action: must be warn, downgrade or block".to_owned());
    } else if matches!(period, "minute" | "hour") && action != "block" {
        errors.push("action: per-minute and per-hour limits always block".to_owned());
    }
    let downgrade_model = text("downgrade_model");
    if action == "downgrade" {
        let allowed_somewhere = documents.apis.iter().any(|api| {
            crate::platform_contract::is_ai_api(api)
                && api
                    .get("api_ai_config")
                    .and_then(|config| crate::ai::config::AiApiConfig::from_value(config).ok())
                    .is_some_and(|config| {
                        crate::ai::config::model_allowed(downgrade_model, &config.allowed_models)
                    })
        });
        if downgrade_model.is_empty() {
            errors.push("downgrade_model: required for the downgrade action".to_owned());
        } else if !allowed_somewhere {
            errors.push("downgrade_model: not allowed on any AI API".to_owned());
        }
    }
    let warn_at_percent = match input.get("warn_at_percent") {
        None | Some(Value::Null) => Some(80),
        Some(value) => value.as_u64().filter(|percent| (1..=99).contains(percent)),
    };
    if warn_at_percent.is_none() {
        errors.push("warn_at_percent: must be an integer from 1 to 99".to_owned());
    }
    let enabled = match input.get("enabled") {
        None | Some(Value::Null) => Some(true),
        Some(value) => value.as_bool(),
    };
    if enabled.is_none() {
        errors.push("enabled: must be a boolean".to_owned());
    }
    let provider = match input.get("provider") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.trim().is_empty() => None,
        Some(value) => {
            let parsed = value
                .as_str()
                .and_then(|value| crate::ai::adapter::AiProvider::parse(value.trim()));
            if parsed.is_none() {
                errors.push(
                    "provider: must be openai, anthropic, gemini, azure_openai or openai_compatible"
                        .to_owned(),
                );
            }
            parsed.map(|provider| provider.as_str())
        }
    };
    let per_user = match input.get("per_user") {
        None | Some(Value::Null) => Some(false),
        Some(value) => value.as_bool(),
    };
    match per_user {
        None => errors.push("per_user: must be a boolean".to_owned()),
        Some(true) if scope == "user" => {
            errors.push("per_user: not used with user scope (it is already one user)".to_owned())
        }
        _ => {}
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(json!({
        "name": name,
        "scope": scope,
        "target": target,
        "period": period,
        "limit_type": limit_type,
        "limit_value": limit_value,
        "action": action,
        "downgrade_model": (action == "downgrade").then_some(downgrade_model),
        "warn_at_percent": warn_at_percent,
        "enabled": enabled,
        "provider": provider,
        "per_user": per_user,
    }))
}

async fn save_budget(
    state: &AppState,
    username: &str,
    budget_id: Option<&str>,
    payload: &Value,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let input = match budget_id {
        None => payload.clone(),
        Some(id) => match storage
            .find_one("ai_budgets", &json!({"budget_id": id}))
            .await
        {
            Ok(Some(mut existing)) => {
                if let (Some(existing), Some(updates)) =
                    (existing.as_object_mut(), payload.as_object())
                {
                    for (key, value) in updates {
                        existing.insert(key.clone(), value.clone());
                    }
                }
                existing
            }
            Ok(None) => {
                return error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::AI_INVALID_CONFIG,
                    "AI budget not found",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        },
    };
    let mut doc = match validate_budget(state, &input).await {
        Ok(doc) => doc,
        Err(message) => return invalid(&message, request_id),
    };
    let id = budget_id
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    doc["budget_id"] = json!(id);
    let saved = match budget_id {
        None => storage
            .insert_one("ai_budgets", doc.clone())
            .await
            .map(|_| ()),
        Some(_) => storage
            .update_one("ai_budgets", &json!({"budget_id": id}), &doc)
            .await
            .map(|_| ()),
    };
    if saved.is_err() {
        return unexpected(request_id);
    }
    let _ = storage.bump_policy_revision().await;
    let action = if budget_id.is_some() {
        "ai_budget.update"
    } else {
        "ai_budget.create"
    };
    audit::management_mutation(username, action, &id, "success");
    success(
        if budget_id.is_some() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        budget_doc(&doc),
        request_id,
    )
}

async fn delete_budget(state: &AppState, username: &str, id: &str, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage
        .delete_one("ai_budgets", &json!({"budget_id": id}))
        .await
    {
        Ok(true) => {
            let _ = storage.bump_policy_revision().await;
            audit::management_mutation(username, "ai_budget.delete", id, "success");
            success(
                StatusCode::OK,
                json!({"message": "AI budget deleted", "budget_id": id}),
                request_id,
            )
        }
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_INVALID_CONFIG,
            "AI budget not found",
            request_id,
        ),
        Err(_) => unexpected(request_id),
    }
}

/// `?scope=&target=`: own budgets for anyone; others' need `view_analytics`.
async fn budget_status(
    state: &AppState,
    username: &str,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    let scope = query
        .get("scope")
        .map(String::as_str)
        .filter(|v| !v.is_empty());
    let target = query
        .get("target")
        .map(String::as_str)
        .filter(|v| !v.is_empty());
    let own = scope.is_none() || (scope == Some("user") && target == Some(username));
    if !own && !has_permission(state, username, "view_analytics").await {
        return forbidden(
            "You do not have permission to view these AI budgets",
            request_id,
        );
    }
    // A user's status lists every budget that applies to them (user, group,
    // global and tier allowance), the same view as their own default query.
    if scope.is_none() || (scope == Some("user") && target.is_some()) {
        let subject = if scope.is_none() {
            username
        } else {
            target.unwrap_or(username)
        };
        let budgets = own_budget_statuses(state, subject).await;
        return success(StatusCode::OK, json!({"budgets": budgets}), request_id);
    }
    let (Some(storage), Some(documents)) = (state.storage.as_ref(), policy_documents(state).await)
    else {
        return unexpected(request_id);
    };
    let at = now();
    let mut statuses = Vec::new();
    for spec in documents
        .ai_budgets
        .iter()
        .filter_map(BudgetSpec::from_value)
    {
        if Some(spec.scope.as_str()) != scope || target.is_some_and(|target| spec.target != target)
        {
            continue;
        }
        let used = budgets::used(storage, &spec, at).await;
        statuses.push(budgets::status_json(&spec, used, at));
    }
    success(StatusCode::OK, json!({"budgets": statuses}), request_id)
}

fn forbidden(message: &str, request_id: &str) -> Response {
    error(
        StatusCode::FORBIDDEN,
        ErrorCode::USR_PERMISSION_DENIED,
        message,
        request_id,
    )
}

fn invalid(message: &str, request_id: &str) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        ErrorCode::AI_INVALID_CONFIG,
        message,
        request_id,
    )
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

fn key_is_active(record: &Value, at: OffsetDateTime) -> bool {
    record.get("revoked").and_then(Value::as_bool) != Some(true)
        && record
            .get("expires_at")
            .and_then(Value::as_str)
            .is_none_or(|expires| {
                OffsetDateTime::parse(expires, &Rfc3339).is_ok_and(|expires| expires > at)
            })
}

/// The public view of a key record: never the hash.
fn public_key(record: &Value) -> Value {
    json!({
        "key_id": record.get("key_id").cloned().unwrap_or(Value::Null),
        "name": record.get("name").cloned().unwrap_or(Value::Null),
        "key_prefix": record.get("key_prefix").cloned().unwrap_or(Value::Null),
        "created_at": record.get("created_at").cloned().unwrap_or(Value::Null),
        "expires_at": record.get("expires_at").cloned().unwrap_or(Value::Null),
        "last_used_at": record.get("last_used_at").cloned().unwrap_or(Value::Null),
        "revoked": record.get("revoked").and_then(Value::as_bool).unwrap_or(false),
        "api_scope": record.get("api_scope").cloned().unwrap_or(Value::Null),
    })
}

async fn list_keys(state: &AppState, owner: &str, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage
        .find_many("ai_access_keys", &json!({"username": owner}))
        .await
    {
        Ok(mut records) => {
            records.sort_by(|a, b| {
                b.get("created_at")
                    .and_then(Value::as_str)
                    .cmp(&a.get("created_at").and_then(Value::as_str))
            });
            let keys: Vec<Value> = records.iter().map(public_key).collect();
            success(StatusCode::OK, json!({"keys": keys}), request_id)
        }
        Err(_) => unexpected(request_id),
    }
}

async fn create_key(
    state: &AppState,
    username: &str,
    payload: &Value,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if name.is_empty() || name.chars().count() > 100 {
        return invalid("name: must be 1-100 characters", request_id);
    }
    let expires_in_days = match payload.get("expires_in_days") {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_u64().filter(|days| (1..=365).contains(days)) {
            Some(days) => Some(days),
            None => {
                return invalid(
                    "expires_in_days: must be an integer from 1 to 365",
                    request_id,
                );
            }
        },
    };
    let api_scope = match payload.get("api_scope") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => {
            let scope: Option<Vec<String>> = items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::trim)
                        .filter(|item| {
                            let mut parts = item.split('/');
                            matches!(
                                (parts.next(), parts.next(), parts.next()),
                                (Some(name), Some(version), None)
                                    if !name.is_empty() && !version.is_empty()
                            )
                        })
                        .map(str::to_owned)
                })
                .collect();
            match scope {
                Some(scope) => Some(scope),
                None => {
                    return invalid(
                        "api_scope: entries must be \"{api_name}/{api_version}\"",
                        request_id,
                    );
                }
            }
        }
        Some(_) => return invalid("api_scope: must be a list", request_id),
    };
    let at = now();
    let active = match storage
        .find_many("ai_access_keys", &json!({"username": username}))
        .await
    {
        Ok(records) => records
            .iter()
            .filter(|record| key_is_active(record, at))
            .count(),
        Err(_) => return unexpected(request_id),
    };
    if active >= MAX_ACTIVE_KEYS_PER_USER {
        return invalid(
            &format!("A user can have at most {MAX_ACTIVE_KEYS_PER_USER} active AI keys"),
            request_id,
        );
    }
    let key = keys::generate_key();
    let key_id = uuid::Uuid::new_v4().to_string();
    let key_prefix = keys::key_prefix(&key);
    let expires_at = expires_in_days.map(|days| rfc3339(at + Duration::days(days as i64)));
    let record = json!({
        "key_id": key_id,
        "username": username,
        "name": name,
        "key_prefix": key_prefix,
        "key_hash": keys::hash_key(&key),
        "created_at": rfc3339(at),
        "expires_at": expires_at,
        "last_used_at": null,
        "revoked": false,
        "api_scope": api_scope,
    });
    if storage.insert_one("ai_access_keys", record).await.is_err() {
        return unexpected(request_id);
    }
    let _ = storage.bump_policy_revision().await;
    audit::management_mutation(username, "ai_key.create", &key_id, "success");
    success(
        StatusCode::CREATED,
        json!({
            "key_id": key_id,
            "name": name,
            "key": key,
            "key_prefix": key_prefix,
            "expires_at": expires_at,
        }),
        request_id,
    )
}

async fn revoke_key(state: &AppState, username: &str, key_id: &str, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let filter = json!({"key_id": key_id});
    let record = match storage.find_one("ai_access_keys", &filter).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                ErrorCode::AI_ACCESS_KEY_INVALID,
                "AI access key not found",
                request_id,
            );
        }
        Err(_) => return unexpected(request_id),
    };
    let owner = record
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if owner != username && !has_permission(state, username, "manage_users").await {
        audit::management_mutation(username, "ai_key.revoke", key_id, "denied");
        return forbidden(
            "You do not have permission to revoke this AI key",
            request_id,
        );
    }
    match storage
        .update_one("ai_access_keys", &filter, &json!({"revoked": true}))
        .await
    {
        Ok(Some(_)) => {
            let _ = storage.bump_policy_revision().await;
            audit::management_mutation(username, "ai_key.revoke", key_id, "success");
            success(
                StatusCode::OK,
                json!({"message": "AI key revoked", "key_id": key_id}),
                request_id,
            )
        }
        _ => unexpected(request_id),
    }
}

// ── AI settings ─────────────────────────────────────────────────────────────

/// Read-only egress IPs for provider-side allowlists (`DOORMAN_EGRESS_IPS`).
fn egress_ips() -> Vec<String> {
    std::env::var("DOORMAN_EGRESS_IPS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .map(str::to_owned)
        .collect()
}

fn settings_body(settings: &Value) -> Value {
    json!({
        "log_level": settings["log_level"],
        "retention_days": settings["retention_days"],
        "notice_text": settings["notice_text"],
        "egress_ips": egress_ips(),
        "user_id_salt_set": crate::ai::user_id_salt_set(),
    })
}

async fn get_settings(state: &AppState, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match crate::storage::ai_settings::load(storage).await {
        Ok(settings) => success(StatusCode::OK, settings_body(&settings), request_id),
        Err(_) => unexpected(request_id),
    }
}

async fn put_settings(
    state: &AppState,
    username: &str,
    payload: &Value,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let mut settings = match crate::storage::ai_settings::load(storage).await {
        Ok(settings) => settings,
        Err(_) => return unexpected(request_id),
    };
    let mut errors = Vec::new();
    if let Some(level) = payload.get("log_level").filter(|value| !value.is_null()) {
        match level.as_str() {
            Some(level) if crate::storage::ai_settings::LOG_LEVELS.contains(&level) => {
                settings["log_level"] = json!(level);
            }
            _ => errors.push("log_level: must be none, metadata or full".to_owned()),
        }
    }
    if let Some(days) = payload
        .get("retention_days")
        .filter(|value| !value.is_null())
    {
        match days.as_u64().filter(|days| (1..=3650).contains(days)) {
            Some(days) => settings["retention_days"] = json!(days),
            None => errors.push("retention_days: must be an integer from 1 to 3650".to_owned()),
        }
    }
    if let Some(notice) = payload.get("notice_text") {
        match notice {
            Value::Null => settings["notice_text"] = Value::Null,
            Value::String(text) if text.chars().count() <= 2000 => {
                let text = text.trim();
                settings["notice_text"] = if text.is_empty() {
                    Value::Null
                } else {
                    json!(text)
                };
            }
            _ => errors.push("notice_text: must be a string of at most 2000 characters".to_owned()),
        }
    }
    if payload.get("egress_ips").is_some() {
        errors.push("egress_ips: read-only (set DOORMAN_EGRESS_IPS)".to_owned());
    }
    // Employee notice (C8): full prompt logging requires notice text.
    if settings["log_level"] == "full" && settings["notice_text"].is_null() {
        errors.push("notice_text: required when log_level is full".to_owned());
    }
    if !errors.is_empty() {
        return invalid(&errors.join("; "), request_id);
    }
    if crate::storage::ai_settings::save(storage, &settings)
        .await
        .is_err()
    {
        return unexpected(request_id);
    }
    audit::management_mutation(username, "ai_settings.update", "ai_settings", "success");
    success(StatusCode::OK, settings_body(&settings), request_id)
}

// ── Guardrails ──────────────────────────────────────────────────────────────

const GUARDRAIL_FIELDS: [&str; 8] = [
    "guardrail_id",
    "name",
    "enabled",
    "applies_to",
    "direction",
    "detectors",
    "action",
    "mode",
];

fn guardrail_doc(value: &Value) -> Value {
    Value::Object(
        GUARDRAIL_FIELDS
            .iter()
            .filter_map(|field| value.get(*field).map(|v| ((*field).to_owned(), v.clone())))
            .collect(),
    )
}

async fn list_guardrails(state: &AppState, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage.find_many("ai_guardrails", &json!({})).await {
        Ok(mut docs) => {
            docs.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            let guardrails: Vec<Value> = docs.iter().map(guardrail_doc).collect();
            success(
                StatusCode::OK,
                json!({"guardrails": guardrails}),
                request_id,
            )
        }
        Err(_) => unexpected(request_id),
    }
}

async fn save_guardrail(
    state: &AppState,
    username: &str,
    guardrail_id: Option<&str>,
    payload: &Value,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let mut doc = match guardrail_id {
        None => guardrail_doc(payload),
        Some(id) => match storage
            .find_one("ai_guardrails", &json!({"guardrail_id": id}))
            .await
        {
            Ok(Some(existing)) => {
                let mut doc = guardrail_doc(&existing);
                if let (Some(doc), Some(updates)) =
                    (doc.as_object_mut(), guardrail_doc(payload).as_object())
                {
                    doc.extend(
                        updates
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone())),
                    );
                }
                doc
            }
            Ok(None) => {
                return error(
                    StatusCode::NOT_FOUND,
                    ErrorCode::AI_INVALID_CONFIG,
                    "AI guardrail not found",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        },
    };
    let id = guardrail_id
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    doc["guardrail_id"] = json!(id);
    if let Err(errors) = crate::ai::guardrails::validate_guardrail_doc(&doc) {
        return invalid(&errors.join("; "), request_id);
    }
    let saved = match guardrail_id {
        None => storage
            .insert_one("ai_guardrails", doc.clone())
            .await
            .map(|_| ()),
        Some(_) => storage
            .update_one("ai_guardrails", &json!({"guardrail_id": id}), &doc)
            .await
            .map(|_| ()),
    };
    if saved.is_err() {
        return unexpected(request_id);
    }
    let _ = storage.bump_policy_revision().await;
    let action = if guardrail_id.is_some() {
        "ai_guardrail.update"
    } else {
        "ai_guardrail.create"
    };
    audit::management_mutation(username, action, &id, "success");
    success(
        if guardrail_id.is_some() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        doc,
        request_id,
    )
}

async fn delete_guardrail(
    state: &AppState,
    username: &str,
    id: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage
        .delete_one("ai_guardrails", &json!({"guardrail_id": id}))
        .await
    {
        Ok(true) => {
            let _ = storage.bump_policy_revision().await;
            audit::management_mutation(username, "ai_guardrail.delete", id, "success");
            success(
                StatusCode::OK,
                json!({"message": "AI guardrail deleted", "guardrail_id": id}),
                request_id,
            )
        }
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_INVALID_CONFIG,
            "AI guardrail not found",
            request_id,
        ),
        Err(_) => unexpected(request_id),
    }
}

/// Dry run (P4.3): `text` returns spans and the redacted preview (the admin
/// supplied the text); `sample_last_n` returns per-detector counts only.
async fn test_guardrail(state: &AppState, payload: &Value, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let mut rail = payload.get("guardrail").cloned().unwrap_or(Value::Null);
    if !rail.is_object() {
        return invalid("guardrail: must be a guardrail document", request_id);
    }
    if rail.get("guardrail_id").is_none() {
        rail["guardrail_id"] = json!("test");
    }
    if let Some(text) = payload.get("text").and_then(Value::as_str) {
        return match crate::ai::guardrails::test_text(&rail, text) {
            Ok(result) => success(StatusCode::OK, result, request_id),
            Err(errors) => invalid(&errors.join("; "), request_id),
        };
    }
    let Some(sample) = payload
        .get("sample_last_n")
        .and_then(Value::as_u64)
        .filter(|n| (1..=500).contains(n))
    else {
        return invalid("text or sample_last_n (1-500) is required", request_id);
    };
    if let Err(errors) = crate::ai::guardrails::validate_guardrail_doc(&rail) {
        return invalid(&errors.join("; "), request_id);
    }
    let mut logs = match storage.find_many("ai_prompt_logs", &json!({})).await {
        Ok(logs) => logs,
        Err(_) => return unexpected(request_id),
    };
    logs.sort_by(|a, b| b["at"].as_str().cmp(&a["at"].as_str()));
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut sampled = 0_u64;
    for log in logs.iter().take(sample as usize) {
        let Some(prompt) =
            crate::storage::field_encryption::decrypt_value(log["prompt_enc"].as_str())
        else {
            continue;
        };
        sampled += 1;
        if let Ok(result) = crate::ai::guardrails::test_text(&rail, &prompt) {
            for hit in result["matches"].as_array().into_iter().flatten() {
                if let Some(detector) = hit["detector"].as_str() {
                    *counts.entry(detector.to_owned()).or_default() += 1;
                }
            }
        }
    }
    success(
        StatusCode::OK,
        json!({"sampled": sampled, "counts": counts}),
        request_id,
    )
}

// ── Prompt logs ─────────────────────────────────────────────────────────────

fn prompt_log_summary(log: &Value) -> Value {
    json!({
        "log_id": log["log_id"],
        "request_id": log["request_id"],
        "at": log["at"],
        "username": log["username"],
        "api": log["api"],
        "model": log["model"],
        "redactions": log.get("redactions").cloned().unwrap_or_else(|| json!([])),
    })
}

async fn list_prompt_logs(
    state: &AppState,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let limit = query
        .get("limit")
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    match storage.find_many("ai_prompt_logs", &json!({})).await {
        Ok(mut logs) => {
            logs.sort_by(|a, b| b["at"].as_str().cmp(&a["at"].as_str()));
            let logs: Vec<Value> = logs.iter().take(limit).map(prompt_log_summary).collect();
            success(StatusCode::OK, json!({"logs": logs}), request_id)
        }
        Err(_) => unexpected(request_id),
    }
}

async fn get_prompt_log(state: &AppState, id: &str, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage
        .find_one("ai_prompt_logs", &json!({"log_id": id}))
        .await
    {
        Ok(Some(log)) => {
            use crate::storage::field_encryption::decrypt_value;
            let mut body = prompt_log_summary(&log);
            body["prompt"] = json!(decrypt_value(log["prompt_enc"].as_str()));
            body["completion"] = json!(decrypt_value(log["completion_enc"].as_str()));
            success(StatusCode::OK, body, request_id)
        }
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_INVALID_CONFIG,
            "AI prompt log not found",
            request_id,
        ),
        Err(_) => unexpected(request_id),
    }
}

async fn delete_prompt_log(
    state: &AppState,
    username: &str,
    id: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    match storage
        .delete_one("ai_prompt_logs", &json!({"log_id": id}))
        .await
    {
        Ok(true) => {
            audit::management_mutation(username, "ai_prompt_log.delete", id, "success");
            success(
                StatusCode::OK,
                json!({"message": "AI prompt log deleted", "log_id": id}),
                request_id,
            )
        }
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_INVALID_CONFIG,
            "AI prompt log not found",
            request_id,
        ),
        Err(_) => unexpected(request_id),
    }
}
