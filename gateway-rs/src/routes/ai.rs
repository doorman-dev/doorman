//! AI data plane: `/api/ai/{api_name}/{api_version}/{provider path}`.
//!
//! Requests run through the shared REST policy pipeline (as SOAP and GraphQL
//! do) with `DataPlaneProtocol::Ai`, then branch here to `execute_ai`, which
//! streams provider responses without buffering, envelopes or transforms.

use std::{
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, OnceLock, atomic::Ordering},
    time::Instant,
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{OriginalUri, Request, State},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use serde_json::Value;

use crate::{
    ai::{
        adapter::{AiProvider, INBOUND_CREDENTIAL_HEADERS, INBOUND_CREDENTIAL_QUERY},
        budgets,
        config::{AiApiConfig, model_allowed},
        failover,
        guardrails::{self, CompiledGuardrails, Direction},
        keys::{InboundAuth, record_last_used, resolve_inbound},
        providers::adapter_for,
        usage::{
            AiUsage, FinalizeCtx, PromptLog, UsageTap, activity_block, cost_for, estimate_usage,
            record_usage,
        },
    },
    error::GatewayError,
    error_codes::ErrorCode,
    gateway::circuit_breaker::{check as circuit_allows, record_failure, record_success},
    middleware::body_limit::{BodyLimits, NoCompression},
    policy::{
        PolicyDecision, PolicyErrorBody, PolicyFailure, credits::credit_header_values,
        evaluator::PolicyRequest,
    },
    routes::rest::{
        DataPlaneProtocol, PolicyPath, is_hop_by_hop, rest_policy_then_proxy, retry_backoff,
    },
    state::AppState,
    storage::models::PolicyDocuments,
};

/// The `/api/ai/{name}/{version}/{rest}` parts of the request path.
#[derive(Clone, Debug)]
pub(crate) struct AiRoute {
    pub name: String,
    pub version: String,
    pub rest_path: String,
}

/// The AI operation, recorded as the activity-log endpoint.
#[derive(Clone, Debug)]
pub(crate) struct AiOperation(pub &'static str);

/// The `ai` block for a non-stream request's activity-log line.
#[derive(Clone, Debug)]
pub(crate) struct AiActivity(pub Value);

/// Upstream rate-limit and request-id headers always reach the client (§5.5).
/// One place an AI request can be sent: the primary or a backup.
struct UpstreamTarget {
    /// Position in config: 0 = primary, 1.. = `fallback_targets`.
    index: usize,
    credential: Option<(String, String)>,
    server: String,
    weight: u32,
}

fn is_passthrough_response_header(name: &str) -> bool {
    matches!(name, "retry-after" | "request-id" | "x-request-id")
        || name.starts_with("x-ratelimit-")
        || name.starts_with("anthropic-ratelimit-")
}

pub async fn ai_policy_then_proxy(
    State(state): State<AppState>,
    mut request: Request,
) -> Result<Response, GatewayError> {
    if !matches!(
        *request.method(),
        Method::GET | Method::POST | Method::OPTIONS
    ) {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.0.path().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    let tail = path.strip_prefix("/api/ai/").unwrap_or_default();
    let mut segments = tail.splitn(3, '/');
    let name = segments.next().unwrap_or_default().to_owned();
    let version = segments.next().unwrap_or_default().to_owned();
    let rest_path = segments.next().unwrap_or_default().to_owned();
    if name.is_empty() || version.is_empty() {
        return Ok(ai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "AI route must be /api/ai/{api_name}/{api_version}/{provider path}",
        ));
    }
    request.extensions_mut().insert(PolicyPath(format!(
        "/api/rest/{name}/{version}/{rest_path}"
    )));
    request.extensions_mut().insert(DataPlaneProtocol::Ai);
    request.extensions_mut().insert(AiRoute {
        name,
        version,
        rest_path,
    });
    rest_policy_then_proxy(State(state), request).await
}

/// Resolves the AI caller before policy evaluation: a `dk_` key becomes the
/// request principal, anything else is normalised for JWT verification.
pub(crate) fn authenticate(
    state: &AppState,
    policy_request: &mut PolicyRequest,
    documents: &PolicyDocuments,
    route: Option<&AiRoute>,
    query: Option<&str>,
) -> Result<(), PolicyFailure> {
    let api = route
        .map(|route| format!("{}/{}", route.name, route.version))
        .unwrap_or_default();
    let query = parse_query(query);
    match resolve_inbound(&mut policy_request.headers, &query, documents, &api)? {
        InboundAuth::Key(principal) => {
            if let Some(storage) = &state.storage {
                record_last_used(storage.clone(), &principal.key_id);
            }
            policy_request.ai_principal = Some(principal);
        }
        InboundAuth::Jwt => {}
    }
    Ok(())
}

fn parse_query(query: Option<&str>) -> Vec<(String, String)> {
    query
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn ai_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(PolicyErrorBody {
            error_code: code.to_owned(),
            error_message: message.to_owned(),
        }),
    )
        .into_response()
}

type GuardrailCache = Mutex<Option<(u64, Arc<CompiledGuardrails>)>>;

/// Guardrails compiled once per distinct `ai_guardrails` document set.
fn compiled_guardrails(docs: &[Value]) -> Arc<CompiledGuardrails> {
    static CACHE: OnceLock<GuardrailCache> = OnceLock::new();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(docs)
        .unwrap_or_default()
        .hash(&mut hasher);
    let fingerprint = hasher.finish();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(cache) = cache.lock()
        && let Some((cached, compiled)) = cache.as_ref()
        && *cached == fingerprint
    {
        return compiled.clone();
    }
    let (compiled, errors) = CompiledGuardrails::compile(docs);
    for error in errors {
        tracing::warn!(%error, "skipping invalid AI guardrail");
    }
    let compiled = Arc::new(compiled);
    if let Ok(mut cache) = cache.lock() {
        *cache = Some((fingerprint, compiled.clone()));
    }
    compiled
}

/// Logs detector IDs and counts only, never matched text.
fn log_guardrail_hits(api: &str, direction: &str, outcome: &guardrails::GuardrailOutcome) {
    for (kind, hits) in [
        ("redacted", &outcome.redactions),
        ("dry_run", &outcome.dry_run_hits),
        ("log_only", &outcome.log_only_hits),
    ] {
        for (detector, count) in hits {
            tracing::info!(api, direction, kind, detector = %detector, count, "AI guardrail hit");
        }
    }
    if let Some(guardrail) = &outcome.blocked_by {
        tracing::info!(api, direction, guardrail = %guardrail, "AI guardrail blocked request");
    }
}

/// 400 `AI005` naming the guardrail, never the matched text.
fn guardrail_block_response(guardrail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error_code": ErrorCode::AI_GUARDRAIL_BLOCKED,
            "error_message": "Blocked by guardrail",
            "guardrail": guardrail,
        })),
    )
        .into_response()
}

/// 429 `AI004` with the budget name, reset time and `Retry-After` (plan P3.1).
fn budget_block_response(block: budgets::BudgetBlock) -> Response {
    let resets_at = block
        .resets_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error_code": ErrorCode::AI_BUDGET_EXCEEDED,
            "error_message": "AI budget exceeded",
            "budget": block.budget,
            "period_resets_at": resets_at,
        })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&block.retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn now_rfc3339() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

pub(crate) async fn execute_ai(
    state: &AppState,
    request: Request,
    decision: PolicyDecision,
    documents: Option<&PolicyDocuments>,
) -> Result<Response, GatewayError> {
    let started = Instant::now();
    let Some(route) = request.extensions().get::<AiRoute>().cloned() else {
        return Ok(ai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "Not an AI route",
        ));
    };
    let Some(documents) = documents else {
        return Ok(ai_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "GTW006",
            "Gateway state store unavailable",
        ));
    };
    let api = documents
        .apis
        .iter()
        .find(|api| {
            decision.api_id.is_some()
                && api.get("api_id").and_then(Value::as_str) == decision.api_id.as_deref()
        })
        .cloned()
        .unwrap_or(Value::Null);
    let provider = api
        .get("api_ai_provider")
        .and_then(Value::as_str)
        .and_then(AiProvider::parse);
    let config = api
        .get("api_ai_config")
        .filter(|value| value.is_object())
        .and_then(|value| AiApiConfig::from_value(value).ok());
    let (Some(provider), Some(config), true) =
        (provider, config, crate::platform_contract::is_ai_api(&api))
    else {
        return Ok(ai_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::AI_INVALID_CONFIG,
            "This API is not a valid AI API",
        ));
    };
    let adapter = adapter_for(provider);
    let api_label = format!("{}/{}", route.name, route.version);

    if let Some(delay_ms) = decision.throttle_delay_ms.filter(|delay| *delay > 0) {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let method = request.method().clone();
    let query = parse_query(request.uri().query());
    let request_path = request.uri().path().to_owned();
    let (parts, body) = request.into_parts();
    let body_limit = BodyLimits::from_env().ai;
    let raw_body = match to_bytes(body, BodyLimits::for_path(&request_path, body_limit)).await {
        Ok(body) => body,
        Err(_) => {
            return Ok(ai_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "REQ001",
                &format!("Request entity too large (max: {body_limit} bytes)"),
            ));
        }
    };
    let mut body = if method == Method::POST {
        match serde_json::from_slice::<Value>(&raw_body) {
            Ok(body) if body.is_object() => body,
            _ => {
                return Ok(ai_error(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::AI_INVALID_REQUEST,
                    "Request body must be a JSON object",
                ));
            }
        }
    } else {
        Value::Null
    };

    let Some(info) = adapter.classify(&method, &route.rest_path, &query, &body) else {
        return Ok(ai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "Operation not allowed for this AI API",
        ));
    };
    if config
        .allowed_operations
        .as_ref()
        .is_some_and(|operations| !operations.iter().any(|op| op == info.operation))
    {
        return Ok(ai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "Operation not allowed for this AI API",
        ));
    }

    if info.local {
        // Only concrete IDs are listed; `prefix*` patterns are not model names.
        let models: Vec<String> = config
            .allowed_models
            .iter()
            .filter(|model| !model.ends_with('*'))
            .cloned()
            .collect();
        let response = adapter.local_response(&info, &models);
        let Some((status, payload)) = response else {
            return Ok(ai_error(
                StatusCode::NOT_FOUND,
                ErrorCode::AI_OPERATION_NOT_ALLOWED,
                "Operation not allowed for this AI API",
            ));
        };
        let mut response = (status, Json(payload)).into_response();
        response
            .extensions_mut()
            .insert(AiOperation(info.operation));
        return Ok(response);
    }

    let requested = info
        .model
        .clone()
        .filter(|model| !model.trim().is_empty())
        .or_else(|| config.default_model.clone());
    let Some(requested) = requested else {
        return Ok(ai_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::AI_INVALID_REQUEST,
            "Request has no model",
        ));
    };
    let mut model = config
        .model_aliases
        .get(&requested)
        .cloned()
        .unwrap_or_else(|| requested.clone());
    if !model_allowed(&model, &config.allowed_models) {
        return Ok(ai_error(
            StatusCode::FORBIDDEN,
            ErrorCode::AI_MODEL_NOT_ALLOWED,
            "Model not allowed for this AI API",
        ));
    }
    if info.stream && !config.stream_allowed {
        return Ok(ai_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::AI_STREAM_NOT_ALLOWED,
            "Streaming not allowed for this AI API",
        ));
    }

    let username = decision
        .username
        .clone()
        .or_else(|| decision.tier_username.clone());
    let user_groups: Vec<String> = username
        .as_deref()
        .and_then(|username| {
            documents
                .users
                .iter()
                .find(|user| user.get("username").and_then(Value::as_str) == Some(username))
        })
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

    // Input guardrails (P4): redact in place or block; never rewrite otherwise (C5).
    let rails = compiled_guardrails(&documents.ai_guardrails);
    let mut redactions: Vec<(String, u32)> = Vec::new();
    if info.generation {
        let input_rails = rails.applicable(&api_label, &user_groups, Direction::Input);
        if !input_rails.is_empty() {
            let outcome = guardrails::apply(provider, Direction::Input, &mut body, &input_rails);
            log_guardrail_hits(&api_label, "input", &outcome);
            if let Some(guardrail) = outcome.blocked_by {
                return Ok(guardrail_block_response(&guardrail));
            }
            redactions = outcome.redactions;
        }
    }
    let settings = crate::storage::ai_settings::from_documents(&documents.settings);
    let log_level = crate::storage::ai_settings::effective_log_level(
        settings["log_level"].as_str().unwrap_or("metadata"),
        config.log_level.as_deref(),
    );
    let prompt_log = (log_level == "full" && info.generation).then(|| PromptLog {
        prompt: adapter.prompt_text(&info, &body),
        completion: None,
        rails: rails.clone(),
        groups: user_groups.clone(),
        retention_days: settings["retention_days"].as_u64().unwrap_or(30),
        redactions: redactions.clone(),
    });

    // Budgets (P3): block, downgrade or warn before anything is sent upstream.
    let mut budget_charges = Vec::new();
    let mut budget_warning = None;
    let mut downgraded = None;
    if info.metered
        && let Some(storage) = &state.storage
    {
        let now = time::OffsetDateTime::now_utc();
        let specs = budgets::applicable(
            documents,
            username.as_deref().unwrap_or_default(),
            &user_groups,
            Some(&api_label),
            Some(provider.as_str()),
            now,
        );
        if !specs.is_empty() {
            match budgets::precheck(storage, &specs, &config.allowed_models, now).await {
                Err(block) => return Ok(budget_block_response(block)),
                Ok(outcome) => {
                    if let Some((_, to)) = outcome.downgrade
                        && to != model
                    {
                        downgraded = Some(format!("{model}->{to}"));
                        model = to;
                    }
                    budget_warning = outcome
                        .warning
                        .map(|(name, percent)| format!("{name};{percent}"));
                    budget_charges = outcome.charges;
                }
            }
        }
    }

    let mut rest_path = route.rest_path.clone();
    if info.model.as_deref() != Some(model.as_str()) {
        rest_path = adapter.set_model(&info, &rest_path, &mut body, &model);
    }
    if info.generation {
        if let Some(cap) = config.max_output_tokens {
            adapter.clamp_max_output(&info, &mut body, cap);
        }
        if config.forward_user_id
            && let Some(username) = username.as_deref()
        {
            adapter.inject_user_id(&info, &mut body, &crate::ai::hashed_user_id(username));
        }
    }
    if info.stream && config.inject_stream_usage {
        adapter.ensure_stream_usage(&info, &mut body);
    }

    // Provider credential (C1): the tenant's own credit definition, never a default.
    let credential_group = config
        .credential_overrides
        .iter()
        .find(|entry| user_groups.iter().any(|group| group == &entry.group))
        .map(|entry| entry.credential_group.clone())
        .unwrap_or_else(|| config.credential_group.clone());
    // Some(None) = no key needed; None = configured key missing or undecryptable.
    let resolve_credential = |group: &str| -> Option<Option<(String, String)>> {
        if group == "none" && provider == AiProvider::OpenaiCompatible {
            return Some(None);
        }
        documents
            .credit_defs
            .iter()
            .find(|def| def.get("api_credit_group").and_then(Value::as_str) == Some(group))
            .and_then(|def| credit_header_values(def, now_rfc3339()))
            .and_then(|(header, mut values)| values.pop().map(|key| (header, key)))
            .filter(|(_, key)| !key.trim().is_empty() && !key.starts_with("enc:"))
            .map(Some)
    };
    let Some(primary_server) = decision.upstream.clone() else {
        return Ok(ai_error(
            StatusCode::NOT_FOUND,
            "GTW001",
            "No upstream servers configured",
        ));
    };
    // Index 0 is the primary; backups follow in configured order (failover).
    let mut targets: Vec<UpstreamTarget> = Vec::with_capacity(1 + config.fallback_targets.len());
    for (index, (group, server, weight)) in std::iter::once((credential_group.as_str(), None, 1))
        .chain(config.fallback_targets.iter().map(|target| {
            (
                if target.credential_group.trim().is_empty() {
                    credential_group.as_str()
                } else {
                    target.credential_group.as_str()
                },
                target.server.as_deref(),
                target.weight,
            )
        }))
        .enumerate()
    {
        match resolve_credential(group) {
            Some(credential) => targets.push(UpstreamTarget {
                index,
                credential,
                server: server.unwrap_or(&primary_server).to_owned(),
                weight,
            }),
            None => tracing::error!(
                api = %api_label,
                credential_group = %group,
                target = index,
                "AI credential not configured or undecryptable"
            ),
        }
    }
    if targets.is_empty() {
        return Ok(ai_error(
            StatusCode::BAD_GATEWAY,
            ErrorCode::AI_CREDENTIAL_UNAVAILABLE,
            "AI credential not configured",
        ));
    }

    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        let lower = name.as_str();
        if is_hop_by_hop(name)
            || INBOUND_CREDENTIAL_HEADERS.contains(&lower)
            || matches!(
                lower,
                "host"
                    | "content-length"
                    | "accept-encoding"
                    | "proxy-authorization"
                    | "x-csrf-token"
                    | "csrf-token"
                    | "x-user-email"
            )
            || lower.starts_with("x-doorman-")
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    adapter.default_headers(&mut headers);
    if method == Method::POST {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", value);
    }

    let query = adapter
        .upstream_query(&info, query)
        .into_iter()
        .filter(|(name, _)| !INBOUND_CREDENTIAL_QUERY.contains(&name.as_str()))
        .collect::<Vec<_>>();
    let query = if query.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&query)
                .finish()
        )
    };
    let outbound_body = if method == Method::POST {
        serde_json::to_vec(&body).unwrap_or_default()
    } else {
        Vec::new()
    };
    let request_bytes = outbound_body.len() as u64;

    let circuit_key = format!("ai:{api_label}");
    if !circuit_allows(&state.runtime.circuits, &circuit_key) {
        return Ok(ai_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "GTW999",
            "Upstream circuit open",
        ));
    }
    let Some(client) = state.proxy_client_for(decision.upstream_tls_profile_id.as_deref()) else {
        return Ok(ai_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "TLS004",
            "Upstream TLS profile is unavailable",
        ));
    };
    let first_byte_timeout = std::time::Duration::from_millis(config.first_byte_timeout_ms.max(1));
    let attempts = decision.retry_count.saturating_add(1);
    let weights: Vec<u32> = targets.iter().map(|target| target.weight).collect();
    let bench_keys: Vec<String> = targets
        .iter()
        .map(|target| failover::target_key(&api_label, target.index))
        .collect();
    let order = failover::attempt_order(
        &weights,
        config.load_balance,
        rand::random::<u64>(),
        |i| targets[i].server != primary_server,
        |i| failover::is_benched(&bench_keys[i]),
    );
    let mut fallbacks = 0_u32;
    let mut chosen = None;
    // Per target, retries happen only before anything reaches the client, and
    // only for connection errors and 502/503/504; never 429 (C3) or 500 (costs
    // tokens). With backups configured, a timeout, a connection error or a
    // 502-504 after retries moves on to the next target; a 429 never does (C3).
    'targets: for (position, &slot) in order.iter().enumerate() {
        let target = &targets[slot];
        let has_next = position + 1 < order.len();
        let mut target_headers = headers.clone();
        if let Some((header_name, key)) = &target.credential {
            let header_override =
                (provider == AiProvider::OpenaiCompatible).then_some(header_name.as_str());
            adapter.apply_credential(&mut target_headers, key, header_override);
        }
        let url = format!(
            "{}/{}{}",
            target.server.trim_end_matches('/'),
            rest_path.trim_start_matches('/'),
            query
        );
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            let send = client
                .request(method.clone(), url.clone())
                .headers(target_headers.clone())
                .body(outbound_body.clone())
                .send();
            let move_on = |reason: &str, cool_down: std::time::Duration| {
                failover::bench_target(&bench_keys[slot], cool_down);
                tracing::warn!(api = %api_label, target = target.index, reason, "AI upstream failed; trying the next target");
            };
            match tokio::time::timeout(first_byte_timeout, send).await {
                Err(_) => {
                    record_failure(&state.runtime.circuits, &circuit_key);
                    state
                        .runtime
                        .upstream_timeouts_total
                        .fetch_add(1, Ordering::Relaxed);
                    if has_next {
                        move_on("first-byte timeout", failover::ERROR_COOL_DOWN);
                        fallbacks += 1;
                        continue 'targets;
                    }
                    return Ok(ai_error(
                        StatusCode::GATEWAY_TIMEOUT,
                        ErrorCode::AI_FIRST_BYTE_TIMEOUT,
                        "Upstream first-byte timeout",
                    ));
                }
                Ok(Ok(response))
                    if matches!(response.status().as_u16(), 502..=504) && attempt < attempts =>
                {
                    record_failure(&state.runtime.circuits, &circuit_key);
                    state.runtime.retries_total.fetch_add(1, Ordering::Relaxed);
                    retry_backoff(attempt).await;
                }
                Ok(Ok(response)) if has_next && matches!(response.status().as_u16(), 502..=504) => {
                    record_failure(&state.runtime.circuits, &circuit_key);
                    move_on("server error", failover::ERROR_COOL_DOWN);
                    fallbacks += 1;
                    continue 'targets;
                }
                Ok(Ok(response)) => {
                    chosen = Some(response);
                    break 'targets;
                }
                Ok(Err(error)) if error.is_connect() && attempt < attempts => {
                    record_failure(&state.runtime.circuits, &circuit_key);
                    state.runtime.retries_total.fetch_add(1, Ordering::Relaxed);
                    retry_backoff(attempt).await;
                }
                Ok(Err(_)) if has_next => {
                    record_failure(&state.runtime.circuits, &circuit_key);
                    move_on("connection error", failover::ERROR_COOL_DOWN);
                    fallbacks += 1;
                    continue 'targets;
                }
                Ok(Err(error)) => {
                    record_failure(&state.runtime.circuits, &circuit_key);
                    return Err(error.into());
                }
            }
        }
    }
    let Some(upstream) = chosen else {
        return Ok(ai_error(
            StatusCode::BAD_GATEWAY,
            "GTW999",
            "No AI upstream target responded",
        ));
    };
    let status = upstream.status();
    if status.is_server_error() {
        record_failure(&state.runtime.circuits, &circuit_key);
    } else {
        record_success(&state.runtime.circuits, &circuit_key);
    }
    let upstream_headers = upstream.headers().clone();
    let is_stream = upstream_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/event-stream"));

    let allowed = decision
        .allowed_headers
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut response_headers = HeaderMap::new();
    for (name, value) in &upstream_headers {
        let lower = name.as_str();
        if (is_passthrough_response_header(lower) || allowed.iter().any(|item| item == lower))
            && !is_hop_by_hop(name)
            && !matches!(lower, "set-cookie" | "content-length" | "content-encoding")
        {
            response_headers.append(name.clone(), value.clone());
        }
    }
    if let Ok(value) = HeaderValue::from_str(&model) {
        response_headers.insert(HeaderName::from_static("x-doorman-ai-model"), value);
    }
    let redaction_count: u32 = redactions.iter().map(|(_, count)| *count).sum();
    let redaction_header = (redaction_count > 0).then(|| redaction_count.to_string());
    let fallback_header = (fallbacks > 0).then(|| fallbacks.to_string());
    for (name, value) in [
        ("x-doorman-ai-model-downgraded", downgraded.as_deref()),
        ("x-doorman-ai-budget-warning", budget_warning.as_deref()),
        ("x-doorman-ai-redactions", redaction_header.as_deref()),
        ("x-doorman-ai-fallbacks", fallback_header.as_deref()),
    ] {
        if let Some(value) = value.and_then(|value| HeaderValue::from_str(value).ok()) {
            response_headers.insert(HeaderName::from_static(name), value);
        }
    }
    let bandwidth = decision
        .bandwidth_key
        .clone()
        .zip(decision.bandwidth_ttl_seconds);
    let user_role = username.as_deref().and_then(|username| {
        documents
            .users
            .iter()
            .find(|user| user.get("username").and_then(Value::as_str) == Some(username))
            .and_then(|user| user.get("role"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let user_tier = username
        .as_deref()
        .and_then(|username| crate::policy::tier::user_tier_id(documents, username));
    let mut ctx = FinalizeCtx {
        storage: state.storage.clone(),
        request_id,
        provider,
        api: api_label,
        model,
        username,
        operation: info.operation,
        metered: info.metered,
        stream: is_stream,
        status: status.as_u16(),
        started,
        ttft_ms: None,
        request_bytes,
        response_bytes: 0,
        bandwidth,
        redactions: redaction_count,
        fallbacks,
        prompt_log,
        groups: user_groups.clone(),
        role: user_role,
        tier: user_tier,
        budget_charges,
        log_dir: state
            .config
            .logs_enabled
            .then(|| state.config.logs_dir.clone())
            .flatten(),
    };

    if is_stream {
        let idle = std::time::Duration::from_millis(config.stream_idle_timeout_ms.max(1));
        let tap = UsageTap::new(
            upstream.bytes_stream().boxed(),
            adapter.stream_usage(&info),
            ctx,
            idle,
        );
        let mut response = Response::new(Body::from_stream(tap));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        response.extensions_mut().insert(NoCompression);
        response
            .extensions_mut()
            .insert(AiOperation(info.operation));
        return Ok(response);
    }

    // Non-stream (including Gemini's chunked JSON array): buffer with the idle
    // timeout applied per chunk, never a whole-response timeout.
    let idle = std::time::Duration::from_millis(config.stream_idle_timeout_ms.max(1));
    let mut chunks = upstream.bytes_stream();
    let mut buffered: Vec<u8> = Vec::new();
    loop {
        match tokio::time::timeout(idle, chunks.next()).await {
            Ok(Some(Ok(chunk))) => {
                if ctx.ttft_ms.is_none() {
                    ctx.ttft_ms = Some(started.elapsed().as_millis() as u64);
                }
                buffered.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Ok(Some(Err(error))) => return Err(error.into()),
            Err(_) => {
                return Ok(ai_error(
                    StatusCode::GATEWAY_TIMEOUT,
                    ErrorCode::AI_FIRST_BYTE_TIMEOUT,
                    "Upstream stopped responding",
                ));
            }
        }
    }
    ctx.response_bytes = buffered.len() as u64;
    if let (Some(storage), Some((key, ttl))) = (state.storage.as_ref(), ctx.bandwidth.as_ref()) {
        let accounted = request_bytes.saturating_add(ctx.response_bytes);
        if let Err(error) = storage.add_bandwidth(key, accounted, *ttl).await {
            tracing::error!(error = %error, "AI bandwidth accounting failed");
        }
    }
    let mut parsed = serde_json::from_slice::<Value>(&buffered).ok();
    // Output guardrails apply to non-stream responses only (v1); streaming
    // output guardrails would need buffering, so streams are never altered.
    if info.generation
        && status.is_success()
        && let Some(json) = parsed.as_mut()
    {
        let output_rails = rails.applicable(&ctx.api, &user_groups, Direction::Output);
        if !output_rails.is_empty() {
            let outcome = guardrails::apply(provider, Direction::Output, json, &output_rails);
            log_guardrail_hits(&ctx.api, "output", &outcome);
            if let Some(guardrail) = outcome.blocked_by {
                let usage = adapter
                    .extract_usage(&info, json)
                    .unwrap_or_else(|| estimate_usage(request_bytes, ctx.response_bytes));
                ctx.prompt_log = None;
                tokio::spawn(record_usage(ctx, usage, None));
                return Ok(guardrail_block_response(&guardrail));
            }
            if !outcome.redactions.is_empty() {
                ctx.redactions += outcome
                    .redactions
                    .iter()
                    .map(|(_, count)| *count)
                    .sum::<u32>();
                buffered = serde_json::to_vec(json).unwrap_or(buffered);
            }
        }
    }
    if let (Some(log), Some(json)) = (ctx.prompt_log.as_mut(), parsed.as_ref()) {
        log.completion = adapter.response_text(&info, json);
    }
    let usage: AiUsage = if status.is_success() {
        parsed
            .as_ref()
            .and_then(|json| adapter.extract_usage(&info, json))
            .unwrap_or_else(|| estimate_usage(request_bytes, ctx.response_bytes))
    } else {
        AiUsage::default()
    };
    let content_type = upstream_headers
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    let mut response = Response::new(Body::from(buffered));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
        .extensions_mut()
        .insert(AiOperation(info.operation));
    if info.metered {
        let cost = if status.is_success() {
            let cost = cost_for(&ctx, &usage).await;
            response
                .extensions_mut()
                .insert(AiActivity(activity_block(&ctx, &usage, cost)));
            cost
        } else {
            Default::default()
        };
        tokio::spawn(record_usage(ctx, usage, Some(cost)));
    }
    Ok(response)
}
