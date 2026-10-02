use std::{
    collections::HashMap,
    env,
    fmt::Write as _,
    fs,
    io::Read,
    net::SocketAddr,
    process::{Command, Stdio},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, OriginalUri, Request, State},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const PYTHON_OPENAPI_GZIP_BASE64: &str =
    include_str!("../../../parity/openapi/python-openapi.json.gz.b64");
static PYTHON_OPENAPI: OnceLock<Value> = OnceLock::new();

use crate::{
    middleware::{
        body_limit::BodyLimits,
        chaos::{CHAOS_ERROR_BUDGET_BURN, CHAOS_MONGO_OUTAGE, CHAOS_REDIS_OUTAGE},
        response_compat::MessageEnvelope,
    },
    observability::{
        analytics_aggregator::{
            AggregatedPoint, EndpointEntity, EntityCounter, global_analytics, pooled_percentiles,
        },
        audit::{self, global_ip_deny},
    },
    platform_contract::{normalize_create_api, normalize_update_api},
    policy::{
        auth::{AuthClaims, verify_request_token},
        groups::enforce_group_access,
        ip::{effective_client_ip_for_settings, enforce_configured_api_ip_policy},
        rate_limit::duration_to_seconds,
    },
    state::{AppState, MemoryAutosaveConfig},
    storage::{
        models::{bool_field_default, strip_mongo_id},
        redis::bandwidth_key,
        runtime::SharedStorage,
    },
};

#[derive(Debug, Default)]
pub struct DescriptorBackfill {
    pub scanned: u64,
    pub updated: u64,
    pub skipped: u64,
    pub errors: Vec<Value>,
}

impl DescriptorBackfill {
    pub fn missing(&self) -> usize {
        self.errors.len()
    }
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[derive(Serialize)]
struct AccessClaims {
    sub: String,
    role: String,
    jti: String,
    iat: usize,
    exp: usize,
    iss: String,
    aud: String,
}

#[derive(Clone, Copy)]
struct EntitySpec {
    collection: &'static str,
    key: &'static str,
    list_key: Option<&'static str>,
    permission: &'static str,
    permission_code: &'static str,
    id_field: Option<&'static str>,
    created: &'static str,
    updated: &'static str,
    deleted: &'static str,
    duplicate_code: &'static str,
    not_found_code: &'static str,
}

struct TierAssignmentInput {
    effective_from: Value,
    effective_until: Value,
    override_limits: Value,
    assigned_by: Value,
    notes: Value,
}

/// Removes the per-request protoc work directory on every return path.
struct ProtoCompileDirectory(std::path::PathBuf);

impl Drop for ProtoCompileDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Percent-decode a request path as UTF-8, leaving invalid escapes intact.
fn percent_decode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes
                    .get(index + 1)
                    .and_then(|byte| (*byte as char).to_digit(16)),
                bytes
                    .get(index + 2)
                    .and_then(|byte| (*byte as char).to_digit(16)),
            )
        {
            decoded.push((high * 16 + low) as u8);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded).unwrap_or_else(|_| path.to_owned())
}

pub async fn platform_dispatch(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let direct_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    let method = request.method().clone();
    let headers = request.headers().clone();
    let request_id = request_id_from(&headers);
    let query = parse_query(uri.query());
    // Starlette routes on the percent-decoded path (e.g. `%40` in an email).
    let decoded_path = percent_decode_path(uri.path());
    let path = decoded_path
        .strip_prefix("/platform")
        .unwrap_or(decoded_path.as_str());
    if path != "/security/settings"
        && let Some(response) = platform_ip_filter(&state, &headers, direct_addr, &request_id).await
    {
        return response;
    }
    let body_limit = BodyLimits::for_path(uri.path(), BodyLimits::from_env().default);
    let body = match to_bytes(request.into_body(), body_limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "REQ001",
                &format!("Request entity too large (max: {body_limit} bytes)"),
                &request_id,
            );
        }
    };
    // Body-size middleware runs first; then Starlette resolves the route before
    // any handler runs: an unknown path is
    // a bare 404 and a known path with another method is a 405 naming the
    // first registered route's method.
    match python_route_match(path, &method) {
        RouteMatch::Found => {}
        RouteMatch::NotFound => {
            // Starlette's redirect_slashes: when the path with its trailing
            // slash toggled resolves (for any method), answer 307 to it.
            let toggled = match uri.path().strip_suffix('/') {
                Some(stripped) => stripped.to_owned(),
                None => format!("{}/", uri.path()),
            };
            let toggled_decoded = percent_decode_path(&toggled);
            let toggled_path = toggled_decoded
                .strip_prefix("/platform")
                .unwrap_or(toggled_decoded.as_str());
            if !matches!(
                python_route_match(toggled_path, &method),
                RouteMatch::NotFound
            ) {
                // A relative Location stays correct behind TLS termination.
                let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
                if let Ok(value) = HeaderValue::from_str(&format!("{toggled}{query}")) {
                    response.headers_mut().insert(header::LOCATION, value);
                }
                return response;
            }
            return json_response(
                StatusCode::NOT_FOUND,
                json!({"detail": "Not Found"}),
                &request_id,
            );
        }
        RouteMatch::MethodNotAllowed(allow) => {
            let mut response = json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({"detail": "Method Not Allowed"}),
                &request_id,
            );
            if let Ok(value) = HeaderValue::from_str(&allow) {
                response.headers_mut().insert(header::ALLOW, value);
            }
            return response;
        }
    }
    if rejects_non_json_body(path, &method, &headers, &body) {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    let parsed_payload = if body.is_empty() {
        Ok(Value::Object(Map::new()))
    } else {
        serde_json::from_slice(&body)
    };
    // Python rate-limits login/registration by IP before parsing the body, so
    // the invalid-payload response is deferred until after that check.
    let invalid_auth_payload = matches!(path, "/authorization" | "/authorization/register")
        && method == Method::POST
        && (parsed_payload.is_err() || body.is_empty());
    let invalid_auth_response = || {
        error(
            StatusCode::BAD_REQUEST,
            "AUTH004",
            "Invalid JSON payload",
            &request_id,
        )
    };
    // FastAPI validates a typed JSON body before entering the route handler.
    // The shared entity routes model those typed Python endpoints, so malformed
    // JSON must produce the global validation envelope before authentication or
    // permission checks run.  Limit this to JSON mutating requests so raw proto
    // and WSDL uploads retain their content-specific parsing behavior.
    if parsed_payload.is_err()
        && content_type_is_json(&headers)
        && declares_json_body(path, &method)
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    let mut payload = parsed_payload.unwrap_or(Value::Null);
    // FastAPI validates the declared body model before the handler runs.
    if !body.is_empty()
        && content_type_is_json(&headers)
        && body_fails_declared_model(path, &method, &payload)
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    // SubscribeModel requires all three fields.  Keep this lightweight
    // compatibility check at dispatch time until the remaining typed model is
    // ported, so a missing field reaches FastAPI's global validation envelope
    // instead of becoming a later SUB003/SUB005 lookup error.
    if content_type_is_json(&headers)
        && is_subscription_mutation(path, &method)
        && !subscription_payload_has_required_fields(&payload)
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    if method == Method::PUT
        && is_update_password_path(path)
        && normalize_update_password_model(&mut payload).is_err()
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    if (content_type_is_json(&headers) || body.is_empty())
        && is_tier_typed_mutation(path, &method)
        && normalize_tier_request(path, &method, &mut payload).is_err()
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    // Endpoint validation models are FastAPI body parameters, so an invalid
    // body is rejected before the handler authenticates the caller.
    let validation_create = method == Method::POST
        && matches!(
            path,
            "/endpoint/validation" | "/endpoint/endpoint/validation"
        );
    let validation_update = method == Method::PUT
        && ["/endpoint/validation/", "/endpoint/endpoint/validation/"]
            .iter()
            .any(|prefix| {
                path.strip_prefix(prefix)
                    .is_some_and(|id| !id.is_empty() && !id.contains('/'))
            });
    if (validation_create || validation_update)
        && normalize_endpoint_validation_model(&mut payload.clone(), validation_create).is_err()
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    // A request with no body at all is a 422 for every route whose Python
    // counterpart declares a required typed body parameter, regardless of
    // Content-Type (see requires_nonempty_json_body).
    if body.is_empty() && requires_nonempty_json_body(path, &method) {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }
    // Python's body: dict[str, Any] parameter has no default, so a request
    // with no body at all is a 422 even though an explicit `{}` is valid.
    if path == "/config/import"
        && method == Method::POST
        && (body.is_empty() || !payload.is_object())
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            &request_id,
        );
    }

    // FastAPI validates `limit: int = Query(ge=1, le=1000)` and
    // `offset: int = Query(ge=0)` before the handler authenticates.
    if path == "/logging/logs" && method == Method::GET {
        let out_of_range = |field: &str, min: i64, max: i64| {
            query
                .get(field)
                .is_some_and(|value| !value.parse::<i64>().is_ok_and(|n| (min..=max).contains(&n)))
        };
        if out_of_range("limit", 1, 1_000) || out_of_range("offset", 0, i64::MAX) {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                &request_id,
            );
        }
    }
    if path == "/authorization" && method == Method::POST {
        if let Some(response) = auth_ip_rate_limit(
            &state,
            &headers,
            direct_addr,
            "LOGIN_IP_RATE_LIMIT",
            5,
            "LOGIN_IP_RATE_WINDOW",
            300,
            &request_id,
        )
        .await
        {
            return response;
        }
        if invalid_auth_payload {
            return invalid_auth_response();
        }
        if let Some(response) = auth_account_rate_limit(
            &state,
            &payload,
            "LOGIN_ACCOUNT_RATE_LIMIT",
            10,
            "LOGIN_ACCOUNT_RATE_WINDOW",
            900,
            &request_id,
        )
        .await
        {
            return response;
        }
        return login(&state, &headers, payload, &request_id).await;
    }
    if path == "/authorization/register" && method == Method::POST {
        if let Some(response) = auth_ip_rate_limit(
            &state,
            &headers,
            direct_addr,
            "REGISTER_IP_RATE_LIMIT",
            5,
            "REGISTER_IP_RATE_WINDOW",
            3600,
            &request_id,
        )
        .await
        {
            return response;
        }
        if invalid_auth_payload {
            return invalid_auth_response();
        }
        if let Some(response) = auth_account_rate_limit(
            &state,
            &payload,
            "REGISTER_ACCOUNT_RATE_LIMIT",
            5,
            "REGISTER_ACCOUNT_RATE_WINDOW",
            3600,
            &request_id,
        )
        .await
        {
            return response;
        }
        return register(&state, payload, &request_id).await;
    }
    if path == "/monitor/liveness" && method == Method::GET {
        return success(StatusCode::OK, json!({"status": "alive"}), &request_id);
    }
    if path == "/monitor/readiness" && method == Method::GET {
        let privileged = match authorize(&state, &headers, &method, path, &request_id).await {
            Ok(claims) => {
                let username = claims.sub.as_deref().unwrap_or_default();
                has_permission(&state, username, "manage_gateway").await
            }
            Err(_) => false,
        };
        return readiness(&state, privileged, &request_id).await;
    }

    // The pinned tier and rate-limit-rule routers have no authentication at
    // all, so anyone could create, delete or assign tiers and limits.  The
    // candidate requires an authenticated caller with the management
    // permission instead (approved divergence MIG-123).
    let claims = match authorize(&state, &headers, &method, path, &request_id).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let username = claims.sub.clone().unwrap_or_default();

    if path == "/tls" || path.starts_with("/tls/") {
        let response = if has_permission(&state, &username, "manage_security").await {
            crate::routes::tls_admin::dispatch(&state, path, &method, payload, &request_id).await
        } else {
            error(
                StatusCode::FORBIDDEN,
                "TLSA001",
                "manage_security is required",
                &request_id,
            )
        };
        audit_management_request(&username, &method, path, &response);
        return with_platform_activity_context(response, &username, path);
    }

    if path.starts_with("/authorization") {
        let response = authorization_routes(
            &state,
            &headers,
            path,
            method.clone(),
            payload,
            &claims,
            &request_id,
        )
        .await;
        audit_management_request(&username, &method, path, &response);
        return with_platform_activity_context(response, &username, path);
    }

    if let Some(response) = dispatch_core_entities(
        &state,
        path,
        &method,
        payload.clone(),
        &query,
        &username,
        &request_id,
    )
    .await
    {
        audit_management_request(&username, &method, path, &response);
        return with_platform_activity_context(response, &username, path);
    }

    let response = match (method.clone(), path) {
        (Method::GET, "/openapi.json") => {
            if !has_permission(&state, &username, "manage_apis").await {
                error(
                    StatusCode::FORBIDDEN,
                    "API008",
                    "You do not have permission to view API documentation",
                    &request_id,
                )
            } else {
                platform_openapi(&request_id)
            }
        }
        (Method::GET, "/docs") | (Method::GET, "/redoc") => {
            if !has_permission(&state, &username, "manage_apis").await {
                error(
                    StatusCode::FORBIDDEN,
                    "API008",
                    "You do not have permission to view API documentation",
                    &request_id,
                )
            } else {
                platform_docs(path, &request_id)
            }
        }
        (Method::POST, "/memory/dump") => {
            memory_dump(&state, payload, &username, &request_id).await
        }
        (Method::POST, "/memory/restore") => {
            memory_restore(&state, payload, &username, &request_id).await
        }
        // The pinned dashboard only requires authentication.
        (Method::GET, "/dashboard") => dashboard(&state, &request_id).await,
        (Method::GET, "/monitor/metrics") => {
            if !has_permission(&state, &username, "manage_gateway").await {
                error(
                    StatusCode::FORBIDDEN,
                    "MON001",
                    "You do not have permission to view monitor metrics",
                    &request_id,
                )
            } else {
                monitor_metrics(&state, &query, &request_id).await
            }
        }
        (Method::GET, "/monitor/report") => {
            if !has_permission(&state, &username, "manage_gateway").await {
                error(
                    StatusCode::FORBIDDEN,
                    "MON002",
                    "You do not have permission to generate reports",
                    &request_id,
                )
            } else {
                monitor_report(&state, &query, &request_id).await
            }
        }
        (Method::GET, "/analytics/overview") => {
            if let Some(response) = analytics_query_error(&query, false, &request_id) {
                response
            } else {
                analytics_overview(&state, &username, &query, &request_id).await
            }
        }
        (Method::GET, "/analytics/timeseries") => {
            if let Some(response) = analytics_query_error(&query, false, &request_id) {
                response
            } else if !has_permission(&state, &username, "view_analytics").await {
                analytics_denied(&request_id)
            } else {
                analytics_timeseries(&query, &request_id)
            }
        }
        (Method::GET, "/analytics/top-apis") => {
            if let Some(response) = analytics_query_error(&query, true, &request_id) {
                response
            } else if !has_permission(&state, &username, "view_analytics").await {
                analytics_denied(&request_id)
            } else {
                analytics_top("api", &query, &request_id)
            }
        }
        (Method::GET, "/analytics/top-users") => {
            if let Some(response) = analytics_query_error(&query, true, &request_id) {
                response
            } else if !has_permission(&state, &username, "view_analytics").await {
                analytics_denied(&request_id)
            } else {
                analytics_top("user", &query, &request_id)
            }
        }
        (Method::GET, "/analytics/top-endpoints") => {
            if let Some(response) = analytics_query_error(&query, true, &request_id) {
                response
            } else if !has_permission(&state, &username, "view_analytics").await {
                analytics_denied(&request_id)
            } else {
                analytics_top("endpoint", &query, &request_id)
            }
        }
        (Method::GET, detail) if detail.starts_with("/analytics/api/") => {
            if let Some(response) = analytics_query_error(&query, false, &request_id) {
                response
            } else {
                analytics_detail(
                    &state,
                    &username,
                    "api",
                    detail.trim_start_matches("/analytics/api/"),
                    &query,
                    &request_id,
                )
                .await
            }
        }
        (Method::GET, detail) if detail.starts_with("/analytics/user/") => {
            if let Some(response) = analytics_query_error(&query, false, &request_id) {
                response
            } else {
                analytics_detail(
                    &state,
                    &username,
                    "user",
                    detail.trim_start_matches("/analytics/user/"),
                    &query,
                    &request_id,
                )
                .await
            }
        }
        (Method::GET, "/security/settings") => {
            if !has_permission(&state, &username, "manage_security").await {
                error(
                    StatusCode::FORBIDDEN,
                    "SEC001",
                    "You do not have permission to view security settings",
                    &request_id,
                )
            } else {
                get_security_settings(&state, &headers, direct_addr, &request_id).await
            }
        }
        (Method::PUT, "/security/settings") => {
            if !has_permission(&state, &username, "manage_security").await {
                error(
                    StatusCode::FORBIDDEN,
                    "SEC002",
                    "You do not have permission to update security settings",
                    &request_id,
                )
            } else {
                upsert_security_settings(&state, &username, payload, &request_id).await
            }
        }
        (Method::POST, "/security/restart") => {
            if !has_permission(&state, &username, "manage_security").await {
                error(
                    StatusCode::FORBIDDEN,
                    "SEC003",
                    "You do not have permission to restart the gateway",
                    &request_id,
                )
            } else {
                match schedule_restart() {
                    Ok(()) => message(StatusCode::ACCEPTED, "Restart scheduled", &request_id),
                    Err(("SEC004", message_text)) => {
                        error(StatusCode::CONFLICT, "SEC004", message_text, &request_id)
                    }
                    Err((code, message_text)) => error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        code,
                        message_text,
                        &request_id,
                    ),
                }
            }
        }
        (Method::GET, "/config/export/all") => {
            config_export(&state, &username, None, &query, &request_id).await
        }
        (Method::GET, "/config/export/apis") => {
            config_export(&state, &username, Some("apis"), &query, &request_id).await
        }
        (Method::GET, "/config/export/roles") => {
            config_export(&state, &username, Some("roles"), &query, &request_id).await
        }
        (Method::GET, "/config/export/groups") => {
            config_export(&state, &username, Some("groups"), &query, &request_id).await
        }
        (Method::GET, "/config/export/routings") => {
            config_export(&state, &username, Some("routings"), &query, &request_id).await
        }
        (Method::GET, "/config/export/endpoints") => {
            config_export(&state, &username, Some("endpoints"), &query, &request_id).await
        }
        (Method::POST, "/config/import") => {
            config_import(&state, &username, payload, &request_id).await
        }
        (Method::POST, "/config/rollback") => {
            config_rollback(&state, &username, payload, &request_id).await
        }
        (Method::GET, "/config/current") => {
            if !has_permission(&state, &username, "manage_gateway").await {
                http_detail(
                    StatusCode::FORBIDDEN,
                    "Insufficient permissions: manage_gateway required",
                    &request_id,
                )
            } else {
                config_current(&state, &request_id)
            }
        }
        (Method::GET, "/config/reloadable-keys") => {
            // The pinned route only requires authentication (no role check).
            success(
                StatusCode::OK,
                json!({
                    "reloadable_keys": active_reloadable_keys(),
                    "total": 3,
                    "restart_required_keys": restart_required_keys(),
                    "notes": [
                        "Environment variables always override config file values",
                        "GATEWAY_TIMEOUT, RETRY_ENABLED, and RETRY_MAX_ATTEMPTS apply to the next REST, GraphQL, or SOAP request",
                        "All other listed settings require a controlled restart or rolling deployment"
                    ]
                }),
                &request_id,
            )
        }
        (Method::POST, "/config/reload") => {
            if !has_permission(&state, &username, "manage_gateway").await {
                http_detail(
                    StatusCode::FORBIDDEN,
                    "Insufficient permissions: manage_gateway required",
                    &request_id,
                )
            } else {
                match state.hot_reload.reload() {
                    Ok(()) => success(
                        StatusCode::OK,
                        json!({
                            "message": "Configuration reloaded; supported HTTP gateway settings apply to subsequent requests",
                            "config": state.hot_reload.dump(),
                            "applied": ["GATEWAY_TIMEOUT", "RETRY_ENABLED", "RETRY_MAX_ATTEMPTS"],
                            "restart_required": true
                        }),
                        &request_id,
                    ),
                    Err(error_value) => {
                        tracing::warn!(error = %error_value, "configuration inspection reload failed");
                        error(
                            StatusCode::BAD_REQUEST,
                            "CFG001",
                            "Configuration reload failed",
                            &request_id,
                        )
                    }
                }
            }
        }
        (Method::POST, "/demo/seed") => demo_seed(&state, &username, &query, &request_id).await,
        (Method::POST, "/tools/cors/check") => {
            if !has_permission(&state, &username, "manage_security").await {
                error(
                    StatusCode::FORBIDDEN,
                    "TLS001",
                    "You do not have permission to use tools",
                    &request_id,
                )
            } else {
                cors_check(payload, &request_id)
            }
        }
        (Method::GET, "/tools/grpc/check") => {
            if !has_permission(&state, &username, "manage_security").await {
                error(
                    StatusCode::FORBIDDEN,
                    "TLS001",
                    "You do not have permission to use tools",
                    &request_id,
                )
            } else {
                let reflection_enabled = env_bool("DOORMAN_ENABLE_GRPC_REFLECTION", false);
                let notes = if reflection_enabled {
                    Vec::<&str>::new()
                } else {
                    vec![
                        "Reflection is disabled by default. Enable with DOORMAN_ENABLE_GRPC_REFLECTION=true",
                    ]
                };
                success(
                    StatusCode::OK,
                    json!({
                        "available": {
                            "grpc": true,
                            "grpc_tools_protoc": true
                        },
                        "reflection_enabled": reflection_enabled,
                        "notes": notes,
                        "details": {}
                    }),
                    &request_id,
                )
            }
        }
        (Method::POST, "/tools/chaos/toggle") => {
            if !has_permission(&state, &username, "manage_gateway").await {
                error(
                    StatusCode::FORBIDDEN,
                    "TLS001",
                    "You do not have permission to use tools",
                    &request_id,
                )
            } else {
                let (backend, enabled, duration_ms) = match normalize_chaos_toggle(&payload) {
                    Ok(values) => values,
                    Err(errors) => return validation_errors(errors, &request_id),
                };
                let backend = backend.trim().to_ascii_lowercase();
                let target = match backend.as_str() {
                    "redis" => &CHAOS_REDIS_OUTAGE,
                    "mongo" => &CHAOS_MONGO_OUTAGE,
                    _ => {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "TLS002",
                            "backend must be redis or mongo",
                            &request_id,
                        );
                    }
                };
                if duration_ms > 0 {
                    target.store(true, std::sync::atomic::Ordering::Relaxed);
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(duration_ms as u64))
                            .await;
                        target.store(false, std::sync::atomic::Ordering::Relaxed);
                    });
                } else {
                    target.store(enabled, std::sync::atomic::Ordering::Relaxed);
                }
                success(
                    StatusCode::OK,
                    json!({
                        "backend": backend,
                        "enabled": target.load(std::sync::atomic::Ordering::Relaxed)
                    }),
                    &request_id,
                )
            }
        }
        (Method::GET, "/tools/chaos/stats") => {
            if !has_permission(&state, &username, "manage_gateway").await {
                error(
                    StatusCode::FORBIDDEN,
                    "TLS001",
                    "You do not have permission to use tools",
                    &request_id,
                )
            } else {
                success(
                    StatusCode::OK,
                    json!({
                        "redis_outage": CHAOS_REDIS_OUTAGE.load(std::sync::atomic::Ordering::Relaxed),
                        "mongo_outage": CHAOS_MONGO_OUTAGE.load(std::sync::atomic::Ordering::Relaxed),
                        "error_budget_burn": CHAOS_ERROR_BUDGET_BURN.load(std::sync::atomic::Ordering::Relaxed)
                    }),
                    &request_id,
                )
            }
        }
        (Method::POST, "/tools/rate-limit-simulator") => {
            if !has_permission(&state, &username, "manage_rate_limits").await {
                return error(
                    StatusCode::FORBIDDEN,
                    "RATE001",
                    "You do not have permission to use the rate limit simulator",
                    &request_id,
                );
            }
            let max_requests = payload
                .get("max_requests")
                .and_then(Value::as_u64)
                .unwrap_or(100);
            let duration_seconds = payload
                .get("duration_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(60);
            let simulated_requests = payload
                .get("simulated_requests")
                .and_then(Value::as_u64)
                .unwrap_or(120);

            let allowed = simulated_requests.min(max_requests);
            let blocked = simulated_requests.saturating_sub(max_requests);

            success(
                StatusCode::OK,
                json!({
                    "max_requests": max_requests,
                    "duration_seconds": duration_seconds,
                    "simulated_requests": simulated_requests,
                    "allowed_requests": allowed,
                    "blocked_requests": blocked,
                    "would_exceed": blocked > 0
                }),
                &request_id,
            )
        }
        _ => {
            if path.starts_with("/subscription") {
                subscription_routes(&state, path, &method, payload, &username, &request_id).await
            } else if path.starts_with("/credit") {
                credit_routes(
                    &state,
                    path,
                    &method,
                    payload,
                    &query,
                    &username,
                    &request_id,
                )
                .await
            } else if path.starts_with("/vault") {
                vault_routes(&state, path, &method, payload, &username, &request_id).await
            } else if path.starts_with("/quota") {
                quota_routes(&state, path, &method, &query, &username, &request_id).await
            } else if path.starts_with("/proto") {
                proto_routes(
                    &state,
                    path,
                    &method,
                    &headers,
                    &body,
                    &username,
                    &request_id,
                )
                .await
            } else if path.starts_with("/logging") {
                logging_routes(&state, path, &method, &query, &username, &request_id).await
            } else if path.starts_with("/openapi") || path.starts_with("/wsdl") {
                discovery_parse(
                    &state,
                    path,
                    &method,
                    payload,
                    &body,
                    &username,
                    &request_id,
                )
                .await
            } else {
                error(
                    StatusCode::NOT_FOUND,
                    "GTW003",
                    "Platform route does not exist",
                    &request_id,
                )
            }
        }
    };
    audit_management_request(&username, &method, path, &response);
    with_platform_activity_context(response, &username, path)
}

/// Preserve the authenticated actor and route family for the outer activity
/// middleware without exposing credentials or request payloads to a log sink.
fn with_platform_activity_context(mut response: Response, username: &str, path: &str) -> Response {
    response
        .extensions_mut()
        .insert(crate::middleware::activity::ActivityContext {
            username: Some(username.to_owned()),
            endpoint: Some(path.to_owned()),
            ..Default::default()
        });
    response
}

/// Emit one payload-free audit record for every authenticated platform mutation.
/// The target is only the route family: user-controlled identifiers and request
/// bodies may contain credentials and must never be placed in the audit event.
fn audit_management_request(actor: &str, method: &Method, path: &str, response: &Response) {
    if method != Method::POST
        && method != Method::PUT
        && method != Method::PATCH
        && method != Method::DELETE
    {
        return;
    }
    let target = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .filter(|target| !target.is_empty())
        .unwrap_or("unknown");
    let status = if response.status().is_success() {
        "success"
    } else {
        "failure"
    };
    audit::management_mutation(
        actor,
        &format!("platform.{}", method.as_str().to_ascii_lowercase()),
        target,
        status,
    );
}

async fn dispatch_core_entities(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Option<Response> {
    if path == "/tiers" || path == "/tiers/" || path.starts_with("/tiers/") {
        if !has_permission(state, username, "manage_tiers").await {
            return Some(error(
                StatusCode::FORBIDDEN,
                "TIER001",
                "You do not have permission to manage tiers",
                request_id,
            ));
        }
        let suffix = path.trim_start_matches("/tiers").trim_matches('/');
        let basic = suffix.is_empty()
            || (!suffix.contains('/')
                && (method == Method::GET
                    || !matches!(
                        suffix,
                        "upgrade" | "downgrade" | "temporary-upgrade" | "compare" | "assignments"
                    )));
        if basic {
            return Some(
                tier_crud_routes(state, path, method, payload, query, username, request_id).await,
            );
        }
        return Some(
            tier_management_routes(state, path, method, payload, query, username, request_id).await,
        );
    }
    if path == "/rate-limits" || path == "/rate-limits/" || path.starts_with("/rate-limits/") {
        let suffix = path.trim_start_matches("/rate-limits").trim_matches('/');
        // A caller may always read their own limit status.
        if suffix != "status" && !has_permission(state, username, "manage_rate_limits").await {
            return Some(error(
                StatusCode::FORBIDDEN,
                "RATE002",
                "You do not have permission to manage rate limits",
                request_id,
            ));
        }
        let basic =
            suffix.is_empty() || (!suffix.contains('/') && !matches!(suffix, "search" | "status"));
        if basic {
            return Some(
                rate_limit_crud_routes(state, path, method, payload, query, username, request_id)
                    .await,
            );
        }
        return Some(
            rate_limit_management_routes(state, path, method, payload, query, username, request_id)
                .await,
        );
    }

    let specs = [
        (
            "/group",
            EntitySpec {
                collection: "groups",
                key: "group_name",
                list_key: Some("groups"),
                permission: "manage_groups",
                permission_code: "GRP008",
                id_field: None,
                created: "Group created successfully",
                updated: "Group updated successfully",
                deleted: "Group deleted successfully",
                duplicate_code: "GRP001",
                not_found_code: "GRP003",
            },
        ),
        (
            "/role",
            EntitySpec {
                collection: "roles",
                key: "role_name",
                list_key: Some("roles"),
                permission: "manage_roles",
                permission_code: "ROLE009",
                id_field: None,
                created: "Role created successfully",
                updated: "Role updated successfully",
                deleted: "Role deleted successfully",
                duplicate_code: "ROLE001",
                not_found_code: "ROLE004",
            },
        ),
        (
            "/routing",
            EntitySpec {
                collection: "routings",
                key: "client_key",
                list_key: None,
                permission: "manage_routings",
                permission_code: "RTG012",
                id_field: None,
                created: "Routing created successfully",
                updated: "Routing updated successfully",
                deleted: "Routing deleted successfully",
                duplicate_code: "RTG001",
                not_found_code: "RTG004",
            },
        ),
    ];
    for (prefix, spec) in specs {
        if path == prefix || path == format!("{prefix}/") || path.starts_with(&format!("{prefix}/"))
        {
            return Some(
                entity_routes(
                    state, prefix, spec, path, method, payload, query, username, request_id,
                )
                .await,
            );
        }
    }
    if path == "/api" || path.starts_with("/api/") || path == "/apis" || path.starts_with("/apis/")
    {
        return Some(
            api_routes(
                state,
                path.trim_start_matches('s'),
                method,
                payload,
                query,
                username,
                request_id,
            )
            .await,
        );
    }
    if path == "/user"
        || path.starts_with("/user/")
        || path == "/users"
        || path.starts_with("/users/")
    {
        return Some(user_routes(state, path, method, payload, query, username, request_id).await);
    }
    if path == "/endpoint"
        || path.starts_with("/endpoint/")
        || path == "/endpoints"
        || path.starts_with("/endpoints/")
    {
        return Some(
            endpoint_routes(state, path, method, payload, query, username, request_id).await,
        );
    }
    None
}

async fn tier_delete_route(
    state: &AppState,
    tier_id: &str,
    _username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let assigned = match storage
        .find_many("user_tier_assignments", &json!({"tier_id": tier_id}))
        .await
    {
        Ok(assignments) => assignments.len(),
        Err(_) => return tier_detail_failure("delete", request_id),
    };
    if assigned > 0 {
        return http_detail(
            StatusCode::BAD_REQUEST,
            &format!("Cannot delete tier {tier_id}: {assigned} users are assigned to it"),
            request_id,
        );
    }
    match storage
        .delete_one("tiers", &json!({"tier_id": tier_id}))
        .await
    {
        Ok(true) => response_model_envelope("Tier deleted", request_id),
        Ok(false) => http_detail(
            StatusCode::NOT_FOUND,
            &format!("Tier {tier_id} not found"),
            request_id,
        ),
        Err(_) => tier_detail_failure("delete", request_id),
    }
}

async fn tier_crud_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let suffix = path.trim_start_matches("/tiers").trim_matches('/');
    if suffix.is_empty()
        && method == Method::GET
        && !has_permission(state, username, "manage_tiers").await
    {
        return error(
            StatusCode::FORBIDDEN,
            "TIER001",
            "You do not have permission to manage tiers",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if suffix.is_empty() && method == Method::GET {
        let skip = match tier_pagination(query, "skip", 0, 0, usize::MAX) {
            Ok(value) => value,
            Err(()) => return tier_pagination_error("skip", request_id),
        };
        let limit = match tier_pagination(query, "limit", 100, 1, 1_000) {
            Ok(value) => value,
            Err(()) => return tier_pagination_error("limit", request_id),
        };
        let enabled_only = match query.get("enabled_only") {
            Some(value) => match pydantic_bool_string(value) {
                Some(value) => value,
                None => return tier_pagination_error("enabled_only", request_id),
            },
            None => false,
        };
        let search = query
            .get("search")
            .map(|value| value.to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        let mut tiers = match storage.find_many("tiers", &json!({})).await {
            Ok(tiers) => tiers,
            Err(_) => return unexpected(request_id),
        };
        // Oracle: TierService.list_tiers calls `.lower()` directly on the
        // TierName enum when a search term is supplied. Any stored tier makes
        // that request fail and the route converts it to TIER999. Preserve
        // this pinned wire behavior rather than silently repairing it here.
        if search.is_some() && !tiers.is_empty() {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "TIER999",
                "Failed to list tiers",
                request_id,
            );
        }
        tiers.retain(|tier| {
            (!enabled_only || tier.get("enabled").and_then(Value::as_bool) == Some(true))
                && search.is_none()
        });
        let total = tiers.len();
        let tier_list = tiers
            .into_iter()
            .skip(skip)
            .take(limit)
            .map(tier_response)
            .collect::<Vec<_>>();
        return success(
            StatusCode::OK,
            json!({
                "tiers": tier_list,
                "skip": skip,
                "limit": limit,
                "page": skip / limit + 1,
                "page_size": limit,
                "has_next": skip.saturating_add(limit) < total,
                "total": total,
            }),
            request_id,
        );
    }
    if suffix.is_empty() && method == Method::POST {
        let Some(tier_id) = payload
            .get("tier_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return validation_errors(
                vec![
                    json!({"loc": ["body", "tier_id"], "msg": "field required", "type": "value_error.missing"}),
                ],
                request_id,
            );
        };
        let Some(name) = payload.get("name").and_then(Value::as_str) else {
            return validation_errors(
                vec![
                    json!({"loc": ["body", "name"], "msg": "field required", "type": "value_error.missing"}),
                ],
                request_id,
            );
        };
        let Some(display_name) = payload.get("display_name").and_then(Value::as_str) else {
            return validation_errors(
                vec![
                    json!({"loc": ["body", "display_name"], "msg": "field required", "type": "value_error.missing"}),
                ],
                request_id,
            );
        };
        let Some(limits) = payload.get("limits").filter(|value| value.is_object()) else {
            return validation_errors(
                vec![
                    json!({"loc": ["body", "limits"], "msg": "field required", "type": "value_error.missing"}),
                ],
                request_id,
            );
        };
        let fallback = || {
            success(
                StatusCode::CREATED,
                tier_response(json!({
                    "tier_id": tier_id, "name": name, "display_name": display_name,
                    "description": payload.get("description").cloned().unwrap_or(Value::Null),
                    "limits": tier_limits_response(limits),
                    "price_monthly": payload.get("price_monthly").cloned().unwrap_or(Value::Null),
                    "price_yearly": payload.get("price_yearly").cloned().unwrap_or(Value::Null),
                    "features": payload.get("features").cloned().unwrap_or_else(|| json!([])),
                    "is_default": payload.get("is_default").cloned().unwrap_or_else(|| json!(false)),
                    "enabled": payload.get("enabled").cloned().unwrap_or_else(|| json!(true)),
                    "created_at": Value::Null, "updated_at": Value::Null,
                })),
                request_id,
            )
        };
        if !matches!(name, "free" | "pro" | "enterprise" | "custom") {
            return fallback();
        }
        let existing = match storage
            .find_one("tiers", &json!({"tier_id": tier_id}))
            .await
        {
            Ok(existing) => existing,
            Err(_) => return fallback(),
        };
        if let Some(existing) = existing {
            return success(StatusCode::CREATED, tier_response(existing), request_id);
        }
        let now = timestamp_now_naive();
        let tier = json!({
            "tier_id": tier_id,
            "name": name,
            "display_name": display_name,
            "description": payload.get("description").cloned().unwrap_or(Value::Null),
            "limits": tier_limits_response(limits),
            "price_monthly": payload.get("price_monthly").cloned().unwrap_or(Value::Null),
            "price_yearly": payload.get("price_yearly").cloned().unwrap_or(Value::Null),
            "features": payload.get("features").cloned().unwrap_or_else(|| json!([])),
            "is_default": payload.get("is_default").cloned().unwrap_or_else(|| json!(false)),
            "enabled": payload.get("enabled").cloned().unwrap_or_else(|| json!(true)),
            "created_at": now,
            "updated_at": now,
        });
        return match storage.insert_one("tiers", tier.clone()).await {
            Ok(_) => success(StatusCode::CREATED, tier_response(tier), request_id),
            Err(_) => fallback(),
        };
    }
    if suffix.is_empty() {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "GTW004",
            "Method not allowed",
            request_id,
        );
    }
    if method == Method::DELETE {
        return tier_delete_route(state, suffix, username, request_id).await;
    }
    if method == Method::GET {
        return match storage.find_one("tiers", &json!({"tier_id": suffix})).await {
            Ok(Some(tier)) => success(StatusCode::OK, tier_response(tier), request_id),
            Ok(None) => http_detail(
                StatusCode::NOT_FOUND,
                &format!("Tier {suffix} not found"),
                request_id,
            ),
            Err(_) => tier_detail_failure("get", request_id),
        };
    }
    if method == Method::PUT {
        let mut updates = Value::Object(Map::new());
        for field in [
            "display_name",
            "description",
            "price_monthly",
            "price_yearly",
            "features",
            "is_default",
            "enabled",
        ] {
            if let Some(value) = payload.get(field) {
                updates[field] = value.clone();
            }
        }
        if let Some(limits) = payload.get("limits").filter(|value| value.is_object()) {
            updates["limits"] = tier_limits_response(limits);
        }
        updates["updated_at"] = json!(timestamp_now_naive());
        return match storage
            .update_one("tiers", &json!({"tier_id": suffix}), &updates)
            .await
        {
            Ok(Some(tier)) => success(StatusCode::OK, tier_response(tier), request_id),
            Ok(None) => http_detail(
                StatusCode::NOT_FOUND,
                &format!("Tier {suffix} not found"),
                request_id,
            ),
            Err(_) => tier_detail_failure("update", request_id),
        };
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "GTW004",
        "Method not allowed",
        request_id,
    )
}

fn tier_pagination(
    query: &HashMap<String, String>,
    field: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ()> {
    let value = query
        .get(field)
        .map_or(Ok(default), |value| value.parse::<usize>());
    match value {
        Ok(value) if value >= minimum && value <= maximum => Ok(value),
        _ => Err(()),
    }
}

fn tier_pagination_error(field: &str, request_id: &str) -> Response {
    validation_errors(
        vec![json!({"loc": ["query", field], "msg": "value is not valid", "type": "value_error"})],
        request_id,
    )
}

fn tier_detail_failure(operation: &str, request_id: &str) -> Response {
    let detail = match operation {
        "get" => "Failed to get tier",
        "update" => "Failed to update tier",
        "delete" => "Failed to delete tier",
        "assign" => "Failed to assign user",
        "get_assignment" => "Failed to get assignment",
        "get_user_tier" => "Failed to get user tier",
        "remove_assignment" => "Failed to remove assignment",
        "list_users" => "Failed to list users",
        "upgrade" => "Failed to upgrade tier",
        "downgrade" => "Failed to downgrade tier",
        "temporary-upgrade" => "Failed to create temporary upgrade",
        "trial/start" => "Failed to start trial",
        "payment/failure" => "Failed to handle payment failure",
        "compare" => "Failed to compare tiers",
        _ => "An unexpected error occurred",
    };
    http_detail(StatusCode::INTERNAL_SERVER_ERROR, detail, request_id)
}

fn tier_statistics_failure(request_id: &str) -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "TIER999",
        "Failed to get statistics",
        request_id,
    )
}

fn pydantic_bool_string(value: &str) -> Option<bool> {
    security_setting_bool(&Value::String(value.to_owned()))
}

fn is_tier_typed_mutation(path: &str, method: &Method) -> bool {
    if method == Method::POST {
        return matches!(
            path,
            "/tiers"
                | "/tiers/"
                | "/tiers/assignments"
                | "/tiers/upgrade"
                | "/tiers/downgrade"
                | "/tiers/temporary-upgrade"
                | "/tiers/trial/start"
                | "/tiers/payment/failure"
                | "/tiers/compare"
        );
    }
    method == Method::PUT
        && path
            .strip_prefix("/tiers/")
            .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains('/'))
}

fn tier_model_string(value: Option<&Value>, required: bool) -> Result<Option<Value>, ()> {
    match value {
        Some(Value::Null) if !required => Ok(None),
        Some(value) => security_setting_string(value)
            .map(|value| Some(Value::String(value)))
            .ok_or(()),
        None if !required => Ok(None),
        None => Err(()),
    }
}

fn tier_model_integer(value: Option<&Value>, default: Option<i64>) -> Result<Option<Value>, ()> {
    match value {
        Some(Value::Null) if default.is_none() => Ok(Some(Value::Null)),
        Some(value) => rate_rule_integer(value)
            .map(|value| Some(json!(value)))
            .ok_or(()),
        None => Ok(default.map(|value| json!(value))),
    }
}

fn tier_model_float(value: Option<&Value>) -> Result<Option<Value>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let parsed = match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse::<f64>().ok(),
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        _ => None,
    }
    .filter(|value| value.is_finite())
    .ok_or(())?;
    serde_json::Number::from_f64(parsed)
        .map(Value::Number)
        .map(Some)
        .ok_or(())
}

fn tier_model_datetime(value: &Value) -> Option<Value> {
    let numeric = match value {
        Value::Number(value) => value.as_f64(),
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        Value::String(value) => value.trim().parse::<f64>().ok(),
        _ => None,
    };
    if let Some(mut seconds) = numeric {
        if seconds.is_nan() {
            return None;
        }
        if seconds > 3e20 {
            return Some(json!("9999-12-31T23:59:59.999999"));
        }
        if seconds < -3e20 {
            return Some(json!("0001-01-01T00:00:00"));
        }
        while seconds.abs() > 2e10 {
            seconds /= 1_000.0;
        }
        let micros = (seconds * 1_000_000.0).round_ties_even() as i128;
        let datetime = time::OffsetDateTime::from_unix_timestamp_nanos(micros * 1_000).ok()?;
        return Some(Value::String(format_tier_datetime(datetime, Some(0))));
    }

    static DATETIME: OnceLock<Regex> = OnceLock::new();
    let value = value.as_str()?;
    let captures = DATETIME
        .get_or_init(|| {
            Regex::new(
                r"^(\d{4})-(\d{1,2})-(\d{1,2})[T ](\d{1,2}):(\d{1,2})(?::(\d{1,2})(?:\.(\d{1,12}))?)?(Z|[+-]\d{2}(?::?\d{2})?)?$",
            )
            .expect("tier datetime regex")
        })
        .captures(value)?;
    let number = |index| captures.get(index)?.as_str().parse::<u8>().ok();
    let year = captures.get(1)?.as_str().parse::<i32>().ok()?;
    let month = time::Month::try_from(number(2)?).ok()?;
    let day = number(3)?;
    let hour = number(4)?;
    let minute = number(5)?;
    let second = captures
        .get(6)
        .map_or(Some(0), |value| value.as_str().parse::<u8>().ok())?;
    let micros = captures.get(7).map_or(Some(0), |value| {
        let digits = value.as_str();
        let padded = format!("{digits:0<6}");
        padded[..6].parse::<u32>().ok()
    })?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let time = time::Time::from_hms_micro(hour, minute, second, micros).ok()?;
    let offset_minutes = match captures.get(8).map(|value| value.as_str()) {
        None => None,
        Some("Z") => Some(0),
        Some(offset) => {
            let sign = if offset.starts_with('-') { -1 } else { 1 };
            let digits = &offset[1..];
            let hours = digits.get(..2)?.parse::<i32>().ok()?;
            let minutes = match digits.len() {
                2 => 0,
                4 => digits.get(2..)?.parse::<i32>().ok()?,
                5 if digits.as_bytes().get(2) == Some(&b':') => {
                    digits.get(3..)?.parse::<i32>().ok()?
                }
                _ => return None,
            };
            if hours >= 24 || minutes >= 60 {
                return None;
            }
            Some(sign * (hours * 60 + minutes))
        }
    };
    let datetime = time::PrimitiveDateTime::new(date, time).assume_utc();
    Some(Value::String(format_tier_datetime(
        datetime,
        offset_minutes,
    )))
}

fn format_tier_datetime(datetime: time::OffsetDateTime, offset_minutes: Option<i32>) -> String {
    let mut value = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
    );
    if datetime.microsecond() != 0 {
        write!(value, ".{:06}", datetime.microsecond()).expect("write to string");
    }
    if let Some(minutes) = offset_minutes {
        let sign = if minutes < 0 { '-' } else { '+' };
        let minutes = minutes.abs();
        write!(value, "{sign}{:02}:{:02}", minutes / 60, minutes % 60).expect("write to string");
    }
    value
}

fn normalize_tier_limits(value: &Value) -> Result<Value, ()> {
    let input = value.as_object().ok_or(())?;
    let mut output = Map::new();
    for field in [
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
        "requests_per_day",
        "requests_per_month",
        "monthly_request_quota",
        "daily_request_quota",
        "monthly_bandwidth_quota",
    ] {
        if let Some(value) = tier_model_integer(input.get(field), None)? {
            output.insert(field.to_owned(), value);
        }
    }
    for (field, default) in [
        ("burst_per_second", 0),
        ("burst_per_minute", 0),
        ("burst_per_hour", 0),
        ("max_queue_time_ms", 5_000),
    ] {
        output.insert(
            field.to_owned(),
            tier_model_integer(input.get(field), Some(default))?.ok_or(())?,
        );
    }
    output.insert(
        "enable_throttling".to_owned(),
        json!(match input.get("enable_throttling") {
            Some(value) => security_setting_bool(value).ok_or(())?,
            None => false,
        }),
    );
    Ok(Value::Object(output))
}

fn tier_model_features(value: Option<&Value>, default: bool) -> Result<Option<Value>, ()> {
    let Some(value) = value else {
        return Ok(default.then(|| json!([])));
    };
    if value.is_null() {
        return Ok(None);
    }
    let values = value.as_array().ok_or(())?;
    let values = values
        .iter()
        .map(|value| security_setting_string(value).map(Value::String).ok_or(()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(Value::Array(values)))
}

fn insert_tier_optional(output: &mut Map<String, Value>, field: &str, value: Option<Value>) {
    if let Some(value) = value {
        output.insert(field.to_owned(), value);
    }
}

fn normalize_tier_create_or_update(payload: &Value, create: bool) -> Result<Value, ()> {
    let input = payload.as_object().ok_or(())?;
    let mut output = Map::new();
    for field in ["tier_id", "name", "display_name"] {
        if create || input.contains_key(field) {
            insert_tier_optional(
                &mut output,
                field,
                tier_model_string(input.get(field), create)?,
            );
        }
    }
    if let Some(value) = tier_model_string(input.get("description"), false)? {
        output.insert("description".to_owned(), value);
    }
    if create || input.contains_key("limits") {
        match input.get("limits") {
            Some(Value::Null) if !create => {}
            Some(value) => {
                output.insert("limits".to_owned(), normalize_tier_limits(value)?);
            }
            None if create => return Err(()),
            None => {}
        }
    }
    for field in ["price_monthly", "price_yearly"] {
        insert_tier_optional(&mut output, field, tier_model_float(input.get(field))?);
    }
    insert_tier_optional(
        &mut output,
        "features",
        tier_model_features(input.get("features"), create)?,
    );
    for (field, default) in [("is_default", false), ("enabled", true)] {
        match input.get(field) {
            Some(Value::Null) if !create => {}
            Some(value) => {
                output.insert(
                    field.to_owned(),
                    json!(security_setting_bool(value).ok_or(())?),
                );
            }
            None if create => {
                output.insert(field.to_owned(), json!(default));
            }
            None => {}
        }
    }
    Ok(Value::Object(output))
}

fn tier_action_string(
    input: &Map<String, Value>,
    output: &mut Map<String, Value>,
    field: &str,
    required: bool,
) -> Result<(), ()> {
    insert_tier_optional(
        output,
        field,
        tier_model_string(input.get(field), required)?,
    );
    Ok(())
}

fn normalize_tier_request(path: &str, method: &Method, payload: &mut Value) -> Result<(), ()> {
    if path == "/tiers/compare" {
        let input = payload.as_array().ok_or(())?;
        *payload = Value::Array(
            input
                .iter()
                .map(|value| security_setting_string(value).map(Value::String).ok_or(()))
                .collect::<Result<Vec<_>, _>>()?,
        );
        return Ok(());
    }
    if matches!(path, "/tiers" | "/tiers/") {
        *payload = normalize_tier_create_or_update(payload, true)?;
        return Ok(());
    }
    if method == Method::PUT {
        *payload = normalize_tier_create_or_update(payload, false)?;
        return Ok(());
    }

    let input = payload.as_object().ok_or(())?;
    let mut output = Map::new();
    tier_action_string(input, &mut output, "user_id", true)?;
    match path {
        "/tiers/assignments" => {
            tier_action_string(input, &mut output, "tier_id", true)?;
            for field in ["effective_from", "effective_until"] {
                if let Some(value) = input.get(field).filter(|value| !value.is_null()) {
                    output.insert(field.to_owned(), tier_model_datetime(value).ok_or(())?);
                }
            }
            if let Some(value) = input
                .get("override_limits")
                .filter(|value| !value.is_null())
            {
                output.insert("override_limits".to_owned(), normalize_tier_limits(value)?);
            }
            tier_action_string(input, &mut output, "notes", false)?;
        }
        "/tiers/upgrade" => {
            tier_action_string(input, &mut output, "new_tier_id", true)?;
            output.insert(
                "immediate".to_owned(),
                json!(match input.get("immediate") {
                    Some(value) => security_setting_bool(value).ok_or(())?,
                    None => true,
                }),
            );
            if let Some(value) = input.get("scheduled_date").filter(|value| !value.is_null()) {
                output.insert(
                    "scheduled_date".to_owned(),
                    tier_model_datetime(value).ok_or(())?,
                );
            }
        }
        "/tiers/downgrade" => {
            tier_action_string(input, &mut output, "new_tier_id", true)?;
            output.insert(
                "grace_period_days".to_owned(),
                tier_model_integer(input.get("grace_period_days"), Some(0))?.ok_or(())?,
            );
        }
        "/tiers/temporary-upgrade" => {
            tier_action_string(input, &mut output, "temp_tier_id", true)?;
            let duration = input
                .get("duration_days")
                .filter(|value| !value.is_null())
                .and_then(rate_rule_integer)
                .ok_or(())?;
            output.insert("duration_days".to_owned(), json!(duration));
        }
        "/tiers/trial/start" => {
            tier_action_string(input, &mut output, "tier_id", true)?;
            output.insert(
                "days".to_owned(),
                tier_model_integer(input.get("days"), Some(14))?.ok_or(())?,
            );
        }
        "/tiers/payment/failure" => {
            tier_action_string(input, &mut output, "reason", false)?;
        }
        _ => return Err(()),
    }
    *payload = Value::Object(output);
    Ok(())
}

fn tier_limits_response(limits: &Value) -> Value {
    let mut response = limits.clone();
    for field in [
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
        "requests_per_day",
        "requests_per_month",
        "monthly_request_quota",
        "daily_request_quota",
        "monthly_bandwidth_quota",
    ] {
        if response.get(field).is_none() {
            response[field] = Value::Null;
        }
    }
    for (field, value) in [
        ("burst_per_second", json!(0)),
        ("burst_per_minute", json!(0)),
        ("burst_per_hour", json!(0)),
        ("enable_throttling", json!(false)),
        ("max_queue_time_ms", json!(5000)),
    ] {
        if response.get(field).is_none() {
            response[field] = value;
        }
    }
    response
}

fn tier_response(tier: Value) -> Value {
    json!({
        "tier_id": tier.get("tier_id").cloned().unwrap_or(Value::Null),
        "name": tier.get("name").cloned().unwrap_or(Value::Null),
        "display_name": tier.get("display_name").cloned().unwrap_or(Value::Null),
        "description": tier.get("description").cloned().unwrap_or(Value::Null),
        "limits": tier_limits_response(tier.get("limits").unwrap_or(&json!({}))),
        "price_monthly": tier.get("price_monthly").cloned().unwrap_or(Value::Null),
        "price_yearly": tier.get("price_yearly").cloned().unwrap_or(Value::Null),
        "features": tier.get("features").cloned().unwrap_or_else(|| json!([])),
        "is_default": tier.get("is_default").cloned().unwrap_or_else(|| json!(false)),
        "enabled": tier.get("enabled").cloned().unwrap_or_else(|| json!(true)),
        "created_at": tier.get("created_at").cloned().unwrap_or(Value::Null),
        "updated_at": tier.get("updated_at").cloned().unwrap_or(Value::Null),
    })
}

fn tier_assignment_response(assignment: Value) -> Value {
    json!({
        "user_id": assignment.get("user_id").cloned().unwrap_or(Value::Null),
        "tier_id": assignment.get("tier_id").cloned().unwrap_or(Value::Null),
        "override_limits": assignment.get("override_limits").cloned().unwrap_or(Value::Null),
        "effective_from": assignment.get("effective_from").cloned().unwrap_or(Value::Null),
        "effective_until": assignment.get("effective_until").cloned().unwrap_or(Value::Null),
        "assigned_at": assignment.get("assigned_at").cloned().unwrap_or(Value::Null),
        "assigned_by": assignment.get("assigned_by").cloned().unwrap_or(Value::Null),
        "notes": assignment.get("notes").cloned().unwrap_or(Value::Null),
    })
}

async fn tier_management_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let suffix = path.trim_start_matches("/tiers/");
    let protected_statistics =
        method == Method::GET && (suffix == "statistics/all" || suffix.ends_with("/statistics"));
    if protected_statistics && !has_permission(state, username, "manage_tiers").await {
        return error(
            StatusCode::FORBIDDEN,
            "TIER001",
            "You do not have permission to manage tiers",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if suffix == "assignments" && method == Method::GET {
        let items = storage
            .find_many("user_tier_assignments", &json!({}))
            .await
            .unwrap_or_default()
            .into_iter()
            .map(strip_internal)
            .collect::<Vec<_>>();
        return success(StatusCode::OK, json!({"response": items}), request_id);
    }
    if suffix == "assignments" && method == Method::POST {
        let user_id = payload
            .get("user_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let tier_id = payload
            .get("tier_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if user_id.is_empty() || tier_id.is_empty() {
            return error(
                StatusCode::BAD_REQUEST,
                "TIER002",
                "user_id and tier_id are required",
                request_id,
            );
        }
        let tier_exists = match storage
            .find_one("tiers", &json!({"tier_id": &tier_id}))
            .await
        {
            Ok(tier) => tier.is_some(),
            Err(_) => return tier_detail_failure("assign", request_id),
        };
        if !tier_exists {
            // Oracle: tier_service.assign_user_to_tier raises ValueError here,
            // which the FastAPI route exposes as a 400 detail response.
            return http_detail(
                StatusCode::BAD_REQUEST,
                &format!("Tier {tier_id} not found"),
                request_id,
            );
        }
        let existing = match storage
            .find_one("user_tier_assignments", &json!({"user_id": &user_id}))
            .await
        {
            Ok(existing) => existing,
            Err(_) => return tier_detail_failure("assign", request_id),
        };
        // Match UserTierAssignment.to_dict(), including explicit nulls.  In
        // particular, this is a replacement on reassignment: fields omitted
        // from the new request must not survive from the previous assignment.
        let assignment = json!({
            "user_id": user_id,
            "tier_id": tier_id,
            "override_limits": payload.get("override_limits").cloned().unwrap_or(Value::Null),
            "effective_from": payload.get("effective_from").cloned().unwrap_or(Value::Null),
            "effective_until": payload.get("effective_until").cloned().unwrap_or(Value::Null),
            "assigned_at": timestamp_now_naive(),
            "assigned_by": Value::Null,
            "notes": payload.get("notes").cloned().unwrap_or(Value::Null),
        });
        let result = if existing.is_some() {
            storage
                .replace_one(
                    "user_tier_assignments",
                    &json!({"user_id": &user_id}),
                    assignment.clone(),
                )
                .await
                .map(|_| ())
        } else {
            storage
                .insert_one("user_tier_assignments", assignment.clone())
                .await
                .map(|_| ())
        };
        return match result {
            Ok(()) => success(StatusCode::CREATED, assignment, request_id),
            Err(_) => tier_detail_failure("assign", request_id),
        };
    }
    if let Some(rest) = suffix.strip_prefix("assignments/") {
        let user_id = rest.trim_end_matches("/tier");
        if method == Method::DELETE {
            return match storage
                .delete_one("user_tier_assignments", &json!({"user_id": user_id}))
                .await
            {
                Ok(true) => response_model_envelope("Assignment removed", request_id),
                Ok(false) => http_detail(
                    StatusCode::NOT_FOUND,
                    &format!("No assignment found for user {user_id}"),
                    request_id,
                ),
                Err(_) => tier_detail_failure("remove_assignment", request_id),
            };
        }
        if method == Method::GET {
            let assignment = match storage
                .find_one("user_tier_assignments", &json!({"user_id": user_id}))
                .await
            {
                Ok(assignment) => assignment,
                Err(_) => {
                    return tier_detail_failure(
                        if rest.ends_with("/tier") {
                            "get_user_tier"
                        } else {
                            "get_assignment"
                        },
                        request_id,
                    );
                }
            };
            if rest.ends_with("/tier") {
                // UserTierAssignment.to_dict serializes datetimes, while the
                // pinned dataclass loader leaves those strings unparsed.
                // TierService.get_user_tier then compares datetime.now() to a
                // string and this route returns its documented 500 detail.
                if assignment.as_ref().is_some_and(|assignment| {
                    assignment
                        .get("effective_from")
                        .is_some_and(|value| !value.is_null())
                        || assignment
                            .get("effective_until")
                            .is_some_and(|value| !value.is_null())
                }) {
                    return http_detail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to get user tier",
                        request_id,
                    );
                }
                // TierService.get_user_tier returns the default for an absent,
                // future, or expired assignment; it only returns the assigned
                // tier while that assignment is effective.
                let tier = if let Some(assignment) = assignment.filter(|assignment| {
                    crate::policy::tier::assignment_is_effective(assignment, unix_seconds())
                }) {
                    storage
                        .find_one("tiers", &json!({"tier_id": assignment.get("tier_id")}))
                        .await
                } else {
                    storage
                        .find_one("tiers", &json!({"is_default": true}))
                        .await
                };
                return match tier {
                    Ok(Some(tier)) => success(StatusCode::OK, tier_response(tier), request_id),
                    Ok(None) => http_detail(
                        StatusCode::NOT_FOUND,
                        &format!("No tier found for user {user_id}"),
                        request_id,
                    ),
                    Err(_) => tier_detail_failure("get_user_tier", request_id),
                };
            }
            return match assignment {
                Some(value) => success(StatusCode::OK, tier_assignment_response(value), request_id),
                None => http_detail(
                    StatusCode::NOT_FOUND,
                    &format!("No assignment found for user {user_id}"),
                    request_id,
                ),
            };
        }
    }
    if suffix.ends_with("/users") && method == Method::GET {
        let tier_id = suffix.trim_end_matches("/users");
        let skip = match tier_pagination(query, "skip", 0, 0, usize::MAX) {
            Ok(value) => value,
            Err(()) => return tier_pagination_error("skip", request_id),
        };
        let limit = match tier_pagination(query, "limit", 100, 1, 1_000) {
            Ok(value) => value,
            Err(()) => return tier_pagination_error("limit", request_id),
        };
        let users = match storage
            .find_many("user_tier_assignments", &json!({"tier_id": tier_id}))
            .await
        {
            Ok(users) => users,
            Err(_) => return tier_detail_failure("list_users", request_id),
        }
        .into_iter()
        .skip(skip)
        .take(limit)
        .map(tier_assignment_response)
        .collect::<Vec<_>>();
        return success(StatusCode::OK, json!(users), request_id);
    }
    if suffix == "statistics/all" && method == Method::GET {
        let tiers = match storage.find_many("tiers", &json!({})).await {
            Ok(tiers) => tiers,
            Err(_) => return tier_statistics_failure(request_id),
        };
        let assignments = match storage.find_many("user_tier_assignments", &json!({})).await {
            Ok(assignments) => assignments,
            Err(_) => return tier_statistics_failure(request_id),
        };
        let result: Vec<Value> = tiers
            .into_iter()
            .map(|tier| {
                let tier_id = tier
                    .get("tier_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let total_users = assignments
                    .iter()
                    .filter(|assignment| {
                        assignment.get("tier_id").and_then(Value::as_str) == Some(tier_id)
                    })
                    .count();
                let active_users = assignments
                    .iter()
                    .filter(|assignment| {
                        assignment.get("tier_id").and_then(Value::as_str) == Some(tier_id)
                            && crate::policy::tier::assignment_is_effective(
                                assignment,
                                unix_seconds(),
                            )
                    })
                    .count();
                json!({
                    "tier_id": tier_id,
                    "total_users": total_users,
                    "active_users": active_users,
                    "inactive_users": total_users - active_users,
                    "tier_name": tier.get("display_name").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        return success(StatusCode::OK, json!(result), request_id);
    }
    if suffix.ends_with("/statistics") && method == Method::GET {
        let tier_id = suffix.trim_end_matches("/statistics");
        let assignments = match storage
            .find_many("user_tier_assignments", &json!({"tier_id": tier_id}))
            .await
        {
            Ok(assignments) => assignments,
            Err(_) => return tier_statistics_failure(request_id),
        };
        let total_users = assignments.len();
        let active_users = assignments
            .iter()
            .filter(|assignment| {
                crate::policy::tier::assignment_is_effective(assignment, unix_seconds())
            })
            .count();
        return success(
            StatusCode::OK,
            json!({
                "tier_id": tier_id,
                "total_users": total_users,
                "active_users": active_users,
                "inactive_users": total_users - active_users,
            }),
            request_id,
        );
    }
    if suffix == "compare" && method == Method::POST {
        let ids = payload.as_array().cloned().unwrap_or_default();
        let stored = match storage.find_many("tiers", &json!({})).await {
            Ok(tiers) => tiers,
            Err(_) => return tier_detail_failure("compare", request_id),
        };
        // TierService loops over the requested identifiers, so input order and
        // duplicates are observable and must not be replaced by collection order.
        let tiers = ids
            .iter()
            .filter_map(|tier_id| {
                stored
                    .iter()
                    .find(|tier| tier.get("tier_id") == Some(tier_id))
            })
            .map(|tier| {
                json!({
                    "tier_id": tier.get("tier_id").cloned().unwrap_or(Value::Null),
                    "name": tier.get("name").cloned().unwrap_or(Value::Null),
                    "display_name": tier.get("display_name").cloned().unwrap_or(Value::Null),
                    "limits": tier.get("limits").cloned().unwrap_or_else(|| json!({})),
                    "price_monthly": tier.get("price_monthly").cloned().unwrap_or(Value::Null),
                    "price_yearly": tier.get("price_yearly").cloned().unwrap_or(Value::Null),
                    "features": tier.get("features").cloned().unwrap_or_else(|| json!([])),
                })
            })
            .collect::<Vec<_>>();
        return success(StatusCode::OK, json!(tiers), request_id);
    }
    if method == Method::POST
        && matches!(
            suffix,
            "upgrade" | "downgrade" | "temporary-upgrade" | "trial/start" | "payment/failure"
        )
    {
        let user_id = payload.get("user_id").and_then(Value::as_str).unwrap_or("");
        if user_id.is_empty() {
            return error(
                StatusCode::BAD_REQUEST,
                "TIER002",
                "user_id is required",
                request_id,
            );
        }
        if matches!(suffix, "upgrade" | "downgrade" | "payment/failure") {
            let serialized_effective_dates =
                match tier_assignment_has_serialized_effective_dates(storage, user_id).await {
                    Ok(value) => value,
                    Err(_) => return tier_detail_failure(suffix, request_id),
                };
            if serialized_effective_dates {
                let detail = match suffix {
                    "upgrade" => "Failed to upgrade tier",
                    "downgrade" => "Failed to downgrade tier",
                    "payment/failure" => "Failed to handle payment failure",
                    _ => unreachable!(),
                };
                return http_detail(StatusCode::INTERNAL_SERVER_ERROR, detail, request_id);
            }
        }
        let current_tier_id = if matches!(suffix, "upgrade" | "downgrade" | "payment/failure") {
            match tier_action_current_tier_id(storage, user_id).await {
                Ok(tier_id) => tier_id.unwrap_or_else(|| "default".to_owned()),
                Err(_) => return tier_detail_failure(suffix, request_id),
            }
        } else {
            "default".to_owned()
        };
        let (tier_id, effective_from, effective_until, notes, assigned_by, missing_status) =
            match suffix {
                "upgrade" => {
                    let Some(tier_id) = payload.get("new_tier_id").and_then(Value::as_str) else {
                        return validation_errors(
                            vec![
                                json!({"loc": ["body", "new_tier_id"], "msg": "field required", "type": "value_error.missing"}),
                            ],
                            request_id,
                        );
                    };
                    let immediate = payload
                        .get("immediate")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let effective_from = if immediate {
                        Value::String(timestamp_now_naive())
                    } else {
                        payload
                            .get("scheduled_date")
                            .cloned()
                            .unwrap_or(Value::Null)
                    };
                    (
                        tier_id.to_owned(),
                        effective_from,
                        Value::Null,
                        format!("Upgraded from {current_tier_id}"),
                        Value::Null,
                        StatusCode::BAD_REQUEST,
                    )
                }
                "downgrade" => {
                    let Some(tier_id) = payload.get("new_tier_id").and_then(Value::as_str) else {
                        return validation_errors(
                            vec![
                                json!({"loc": ["body", "new_tier_id"], "msg": "field required", "type": "value_error.missing"}),
                            ],
                            request_id,
                        );
                    };
                    let grace_days = payload
                        .get("grace_period_days")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let effective_from = timestamp_after_days(grace_days);
                    (
                        tier_id.to_owned(),
                        Value::String(effective_from),
                        Value::Null,
                        format!(
                            "Downgraded from {current_tier_id} with {grace_days} day grace period"
                        ),
                        Value::Null,
                        StatusCode::BAD_REQUEST,
                    )
                }
                "temporary-upgrade" | "trial/start" => {
                    let field = if suffix == "temporary-upgrade" {
                        "temp_tier_id"
                    } else {
                        "tier_id"
                    };
                    let Some(tier_id) = payload.get(field).and_then(Value::as_str) else {
                        return validation_errors(
                            vec![
                                json!({"loc": ["body", field], "msg": "field required", "type": "value_error.missing"}),
                            ],
                            request_id,
                        );
                    };
                    let days = payload
                        .get(if suffix == "temporary-upgrade" {
                            "duration_days"
                        } else {
                            "days"
                        })
                        .and_then(Value::as_i64)
                        .unwrap_or(if suffix == "temporary-upgrade" { 0 } else { 14 });
                    (
                        tier_id.to_owned(),
                        Value::String(timestamp_now_naive()),
                        Value::String(timestamp_after_days(days)),
                        format!("Temporary upgrade for {days} days"),
                        Value::Null,
                        if suffix == "trial/start" {
                            StatusCode::NOT_FOUND
                        } else {
                            StatusCode::BAD_REQUEST
                        },
                    )
                }
                "payment/failure" => {
                    let default_tier = match storage
                        .find_one("tiers", &json!({"is_default": true}))
                        .await
                    {
                        Ok(Some(tier)) => tier,
                        Ok(None) => {
                            return http_detail(
                                StatusCode::BAD_REQUEST,
                                "No default tier configured for fallback",
                                request_id,
                            );
                        }
                        Err(_) => return tier_detail_failure(suffix, request_id),
                    };
                    let Some(tier_id) = default_tier.get("tier_id").and_then(Value::as_str) else {
                        return http_detail(
                            StatusCode::BAD_REQUEST,
                            "No default tier configured for fallback",
                            request_id,
                        );
                    };
                    (
                        tier_id.to_owned(),
                        Value::String(timestamp_after_days(0)),
                        Value::Null,
                        format!("Downgraded from {current_tier_id} with 0 day grace period"),
                        json!("system:payment_failure"),
                        StatusCode::BAD_REQUEST,
                    )
                }
                _ => unreachable!(),
            };
        let tier = match storage
            .find_one("tiers", &json!({"tier_id": &tier_id}))
            .await
        {
            Ok(Some(tier)) => tier,
            Ok(None) => {
                return http_detail(
                    missing_status,
                    &format!("Tier {tier_id} not found"),
                    request_id,
                );
            }
            Err(_) => return tier_detail_failure(suffix, request_id),
        };
        let notification_effective_from = effective_from.clone();
        return match replace_tier_assignment(
            storage,
            user_id,
            &tier_id,
            TierAssignmentInput {
                effective_from,
                effective_until,
                override_limits: Value::Null,
                assigned_by,
                notes: Value::String(notes),
            },
        )
        .await
        {
            Ok(assignment) => {
                send_tier_notification(
                    suffix,
                    user_id,
                    &tier,
                    &notification_effective_from,
                    &payload,
                )
                .await;
                success(StatusCode::OK, assignment, request_id)
            }
            Err(_) => tier_detail_failure(suffix, request_id),
        };
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

async fn send_tier_notification(
    action: &str,
    user_id: &str,
    tier: &Value,
    effective_from: &Value,
    payload: &Value,
) {
    let display_name = tier
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let effective = effective_from.as_str().unwrap_or_default();
    let recipient = format!("{user_id}@example.com");
    let (subject, body) = match action {
        "upgrade" => (
            "Tier Upgrade Notification",
            format!("You have been upgraded to the {display_name} plan.\nEffective: {effective}"),
        ),
        "downgrade" => (
            "Tier Downgrade Notification",
            format!("You have been downgraded to the {display_name} plan.\nEffective: {effective}"),
        ),
        "temporary-upgrade" | "trial/start" => {
            let days = payload
                .get(if action == "temporary-upgrade" {
                    "duration_days"
                } else {
                    "days"
                })
                .and_then(Value::as_i64)
                .unwrap_or(if action == "temporary-upgrade" { 0 } else { 14 });
            (
                "Trial Activated",
                format!("You have been given a temporary trial of {display_name} for {days} days."),
            )
        }
        "payment/failure" => (
            "Tier Downgrade Notification",
            format!("You have been downgraded to the {display_name} plan.\nEffective: {effective}"),
        ),
        _ => return,
    };
    crate::observability::email::send_email(&recipient, subject, &body, None).await;
    if action == "payment/failure" {
        crate::observability::email::send_email(
            &recipient,
            "Payment Failure - Account Downgraded",
            &format!(
                "We could not process your payment. Your account has been downgraded to {display_name}."
            ),
            None,
        )
        .await;
    }
}

async fn tier_action_current_tier_id(
    storage: &SharedStorage,
    user_id: &str,
) -> Result<Option<String>, crate::storage::runtime::StorageError> {
    Ok(quota_tier_and_limits(storage, user_id)
        .await?
        .0
        .and_then(|tier| {
            tier.get("tier_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }))
}

async fn tier_assignment_has_serialized_effective_dates(
    storage: &SharedStorage,
    user_id: &str,
) -> Result<bool, crate::storage::runtime::StorageError> {
    Ok(storage
        .find_one("user_tier_assignments", &json!({"user_id": user_id}))
        .await?
        .is_some_and(|assignment| {
            ["effective_from", "effective_until"]
                .iter()
                .any(|field| assignment.get(*field).is_some_and(|value| !value.is_null()))
        }))
}

async fn replace_tier_assignment(
    storage: &SharedStorage,
    user_id: &str,
    tier_id: &str,
    input: TierAssignmentInput,
) -> Result<Value, crate::storage::runtime::StorageError> {
    let assignment = json!({
        "user_id": user_id,
        "tier_id": tier_id,
        "override_limits": input.override_limits,
        "effective_from": input.effective_from,
        "effective_until": input.effective_until,
        "assigned_at": timestamp_now_naive(),
        "assigned_by": input.assigned_by,
        "notes": input.notes,
    });
    let existing = storage
        .find_one("user_tier_assignments", &json!({"user_id": user_id}))
        .await?;
    if existing.is_some() {
        storage
            .replace_one(
                "user_tier_assignments",
                &json!({"user_id": user_id}),
                assignment.clone(),
            )
            .await?;
    } else {
        storage
            .insert_one("user_tier_assignments", assignment.clone())
            .await?;
    }
    Ok(assignment)
}

async fn rate_limit_management_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    query: &HashMap<String, String>,
    _username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path.trim_start_matches("/rate-limits/");
    if suffix == "status" && method == Method::GET {
        // `/status` is declared after `/{rule_id}` in the Python router, so
        // Starlette resolves it as `get_rule(rule_id="status")`; the later
        // authenticated status handler is unreachable in the pinned app.
        return http_detail(StatusCode::NOT_FOUND, "Rule status not found", request_id);
    }
    if suffix == "search" && method == Method::GET {
        let Some(term) = query.get("q") else {
            return rate_rule_validation("q", "field required", "value_error.missing", request_id);
        };
        // The pinned async in-memory backend does not evaluate the Mongo
        // `$regex` query used by RateLimitRuleService.search_rules, yielding
        // an empty successful array. External Mongo retains the real search.
        if storage.is_memory() {
            return success(StatusCode::OK, json!([]), request_id);
        }
        let pattern = match regex::RegexBuilder::new(term)
            .case_insensitive(true)
            .build()
        {
            Ok(pattern) => pattern,
            Err(_) => return rate_rule_failure("search", request_id),
        };
        let mut rules = match storage.find_many("rate_limit_rules", &json!({})).await {
            Ok(rules) => rules,
            Err(_) => {
                return http_detail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to search rules",
                    request_id,
                );
            }
        };
        // RateLimitRuleService searches only id, description, and target—not
        // every serialized field—and orders the resulting Mongo cursor by
        // priority descending.
        rules.retain(|rule| {
            ["rule_id", "description", "target_identifier"]
                .iter()
                .filter_map(|field| rule.get(*field).and_then(Value::as_str))
                .any(|field| pattern.is_match(field))
        });
        rules.sort_by_key(|rule| {
            std::cmp::Reverse(rule.get("priority").and_then(Value::as_i64).unwrap_or(0))
        });
        let rules = rules
            .into_iter()
            .map(rate_rule_response)
            .collect::<Vec<_>>();
        return success(StatusCode::OK, json!(rules), request_id);
    }
    if suffix == "statistics/summary" && method == Method::GET {
        let rules = match storage.find_many("rate_limit_rules", &json!({})).await {
            Ok(rules) => rules,
            Err(_) => return rate_rule_failure("statistics", request_id),
        };
        let enabled = rules
            .iter()
            .filter(|rule| rule.get("enabled").and_then(Value::as_bool) == Some(true))
            .count();
        let rule_types = [
            "per_user",
            "per_api",
            "per_endpoint",
            "per_ip",
            "per_user_api",
            "per_user_endpoint",
            "global",
        ];
        let rules_by_type = rule_types
            .into_iter()
            .map(|rule_type| {
                (
                    rule_type.to_owned(),
                    json!(
                        rules
                            .iter()
                            .filter(|rule| {
                                rule.get("rule_type").and_then(Value::as_str) == Some(rule_type)
                            })
                            .count()
                    ),
                )
            })
            .collect::<Map<String, Value>>();
        return success(
            StatusCode::OK,
            json!({
                "total_rules": rules.len(),
                "enabled_rules": enabled,
                "disabled_rules": rules.len() - enabled,
                "rules_by_type": rules_by_type,
            }),
            request_id,
        );
    }
    if let Some(operation) = suffix.strip_prefix("bulk/")
        && method == Method::POST
        && matches!(operation, "delete" | "enable" | "disable")
    {
        // The pinned Python app's bulk routes are internally inconsistent:
        // `/bulk/enable` and `/bulk/disable` are shadowed by `{rule_id}`. The
        // in-memory backend lacks delete_many, so non-empty bulk deletes fail;
        // its early empty-list return and external-storage success remain live.
        return if operation == "delete" {
            let Some(rule_ids) = payload.get("rule_ids").and_then(Value::as_array) else {
                return rate_rule_validation(
                    "rule_ids",
                    "field required",
                    "value_error.missing",
                    request_id,
                );
            };
            let rule_ids = match rule_ids
                .iter()
                .map(|value| security_setting_string(value).ok_or(()))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(rule_ids) => rule_ids,
                Err(()) => {
                    return rate_rule_validation(
                        "rule_ids",
                        "str type expected",
                        "type_error.str",
                        request_id,
                    );
                }
            };
            if rule_ids.is_empty() {
                return success(StatusCode::OK, json!({"deleted_count": 0}), request_id);
            }
            if storage.is_memory() {
                return rate_rule_failure("bulk/delete", request_id);
            }
            let mut deleted_count = 0;
            for rule_id in rule_ids {
                match storage
                    .delete_one("rate_limit_rules", &json!({"rule_id": rule_id}))
                    .await
                {
                    Ok(true) => deleted_count += 1,
                    Ok(false) => {}
                    Err(_) => return rate_rule_failure("bulk/delete", request_id),
                }
            }
            success(
                StatusCode::OK,
                json!({"deleted_count": deleted_count}),
                request_id,
            )
        } else {
            http_detail(StatusCode::NOT_FOUND, "Rule bulk not found", request_id)
        };
    }
    let parts = suffix.split('/').collect::<Vec<_>>();
    if parts.len() == 2 && method == Method::POST {
        let id = parts[0];
        if parts[1] == "enable" || parts[1] == "disable" {
            return match storage
                .update_one(
                    "rate_limit_rules",
                    &json!({"rule_id": id}),
                    &json!({
                        "enabled": parts[1] == "enable",
                        "updated_at": timestamp_now_naive(),
                    }),
                )
                .await
            {
                Ok(Some(rule)) => success(StatusCode::OK, rate_rule_response(rule), request_id),
                Ok(None) => http_detail(
                    StatusCode::NOT_FOUND,
                    &format!("Rule {id} not found"),
                    request_id,
                ),
                Err(_) => rate_rule_failure(parts[1], request_id),
            };
        }
        if parts[1] == "duplicate" {
            let mut rule = match storage
                .find_one("rate_limit_rules", &json!({"rule_id": id}))
                .await
            {
                Ok(Some(rule)) => rule,
                Ok(None) => {
                    return http_detail(
                        StatusCode::BAD_REQUEST,
                        &format!("Source rule {id} not found"),
                        request_id,
                    );
                }
                Err(_) => return rate_rule_failure("duplicate", request_id),
            };
            let Some(new_rule_id) = payload.get("new_rule_id").and_then(security_setting_string)
            else {
                return rate_rule_validation(
                    "new_rule_id",
                    "field required",
                    "value_error.missing",
                    request_id,
                );
            };
            match storage
                .find_one("rate_limit_rules", &json!({"rule_id": new_rule_id}))
                .await
            {
                Ok(Some(_)) => {
                    return http_detail(
                        StatusCode::BAD_REQUEST,
                        &format!("Rule with ID {new_rule_id} already exists"),
                        request_id,
                    );
                }
                Ok(None) => {}
                Err(_) => return rate_rule_failure("duplicate", request_id),
            }
            rule["rule_id"] = json!(new_rule_id);
            rule["description"] = json!(format!("Copy of {id}"));
            rule["created_at"] = json!(timestamp_now_naive());
            rule["updated_at"] = json!(timestamp_now_naive());
            if let Some(map) = rule.as_object_mut() {
                map.remove("_id");
            }
            return match storage.insert_one("rate_limit_rules", rule).await {
                Ok(rule) => success(StatusCode::CREATED, rate_rule_response(rule), request_id),
                Err(_) => rate_rule_failure("duplicate", request_id),
            };
        }
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

async fn rate_limit_crud_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    query: &HashMap<String, String>,
    _username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path.trim_start_matches("/rate-limits").trim_matches('/');
    if suffix.is_empty() && method == Method::GET {
        let skip = match tier_pagination(query, "skip", 0, 0, usize::MAX) {
            Ok(value) => value,
            Err(()) => {
                return rate_rule_validation(
                    "skip",
                    "value is not valid",
                    "value_error",
                    request_id,
                );
            }
        };
        let limit = match tier_pagination(query, "limit", 100, 1, 1_000) {
            Ok(value) => value,
            Err(()) => {
                return rate_rule_validation(
                    "limit",
                    "value is not valid",
                    "value_error",
                    request_id,
                );
            }
        };
        let rule_type = query.get("rule_type").map(String::as_str);
        if rule_type.is_some_and(|rule_type| {
            !matches!(
                rule_type,
                "per_user"
                    | "per_api"
                    | "per_endpoint"
                    | "per_ip"
                    | "per_user_api"
                    | "per_user_endpoint"
                    | "global"
            )
        }) {
            return http_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list rules",
                request_id,
            );
        }
        let enabled_only = match query.get("enabled_only") {
            Some(value) => match security_setting_bool(&json!(value)) {
                Some(value) => value,
                None => {
                    return rate_rule_validation(
                        "enabled_only",
                        "value could not be parsed to a boolean",
                        "type_error.bool",
                        request_id,
                    );
                }
            },
            None => false,
        };
        let mut rules = match storage.find_many("rate_limit_rules", &json!({})).await {
            Ok(rules) => rules,
            Err(_) => return rate_rule_failure("list", request_id),
        };
        rules.sort_by_key(|rule| {
            std::cmp::Reverse(rule.get("priority").and_then(Value::as_i64).unwrap_or(0))
        });
        let rules = rules
            .into_iter()
            .filter(|rule| {
                rule_type.is_none_or(|rule_type| {
                    rule.get("rule_type").and_then(Value::as_str) == Some(rule_type)
                }) && (!enabled_only || rule.get("enabled").and_then(Value::as_bool) == Some(true))
            })
            .skip(skip)
            .take(limit)
            .map(rate_rule_response)
            .collect::<Vec<_>>();
        return success(StatusCode::OK, json!(rules), request_id);
    }
    if suffix.is_empty() && method == Method::POST {
        if !payload.is_object() {
            return rate_rule_validation(
                "body",
                "value is not a valid dict",
                "type_error.dict",
                request_id,
            );
        }
        let Some(rule_id) = payload.get("rule_id").and_then(security_setting_string) else {
            return rate_rule_validation(
                "rule_id",
                "field required",
                "value_error.missing",
                request_id,
            );
        };
        let Some(rule_type) = payload.get("rule_type").and_then(security_setting_string) else {
            return rate_rule_validation(
                "rule_type",
                "field required",
                "value_error.missing",
                request_id,
            );
        };
        if !matches!(
            rule_type.as_str(),
            "per_user"
                | "per_api"
                | "per_endpoint"
                | "per_ip"
                | "per_user_api"
                | "per_user_endpoint"
                | "global"
        ) {
            return http_detail(
                StatusCode::BAD_REQUEST,
                &format!("'{rule_type}' is not a valid RuleType"),
                request_id,
            );
        }
        let Some(time_window) = payload.get("time_window").and_then(security_setting_string) else {
            return rate_rule_validation(
                "time_window",
                "field required",
                "value_error.missing",
                request_id,
            );
        };
        if !matches!(
            time_window.as_str(),
            "second" | "minute" | "hour" | "day" | "month"
        ) {
            return http_detail(
                StatusCode::BAD_REQUEST,
                &format!("'{time_window}' is not a valid TimeWindow"),
                request_id,
            );
        }
        let Some(limit) = payload
            .get("limit")
            .and_then(rate_rule_integer)
            .filter(|limit| *limit > 0)
        else {
            return rate_rule_validation(
                "limit",
                "ensure this value is greater than 0",
                "value_error.number.not_gt",
                request_id,
            );
        };
        let burst_allowance = match payload.get("burst_allowance") {
            Some(value) => match rate_rule_integer(value) {
                Some(value) => value,
                None => {
                    return rate_rule_validation(
                        "burst_allowance",
                        "value is not a valid integer",
                        "type_error.integer",
                        request_id,
                    );
                }
            },
            None => 0,
        };
        if burst_allowance < 0 {
            return rate_rule_validation(
                "burst_allowance",
                "ensure this value is greater than or equal to 0",
                "value_error.number.not_ge",
                request_id,
            );
        }
        let priority = match payload.get("priority") {
            Some(value) => match rate_rule_integer(value) {
                Some(value) => value,
                None => {
                    return rate_rule_validation(
                        "priority",
                        "value is not a valid integer",
                        "type_error.integer",
                        request_id,
                    );
                }
            },
            None => 0,
        };
        let enabled = match payload.get("enabled") {
            Some(value) => match security_setting_bool(value) {
                Some(value) => value,
                None => {
                    return rate_rule_validation(
                        "enabled",
                        "value could not be parsed to a boolean",
                        "type_error.bool",
                        request_id,
                    );
                }
            },
            None => true,
        };
        let target_identifier = match payload.get("target_identifier") {
            Some(Value::Null) | None => Value::Null,
            Some(target_identifier) => match security_setting_string(target_identifier) {
                Some(target_identifier) => json!(target_identifier),
                None => {
                    return rate_rule_validation(
                        "target_identifier",
                        "str type expected",
                        "type_error.str",
                        request_id,
                    );
                }
            },
        };
        let description = match payload.get("description") {
            Some(Value::Null) | None => Value::Null,
            Some(description) => match security_setting_string(description) {
                Some(description) => json!(description),
                None => {
                    return rate_rule_validation(
                        "description",
                        "str type expected",
                        "type_error.str",
                        request_id,
                    );
                }
            },
        };
        if matches!(
            rule_type.as_str(),
            "per_user" | "per_api" | "per_endpoint" | "per_ip"
        ) && target_identifier.as_str().is_none_or(str::is_empty)
        {
            // The Python handler raises HTTPException here but catches it in
            // its broad `except Exception`, yielding this 500 defect.
            return http_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create rule",
                request_id,
            );
        }
        match storage
            .find_one("rate_limit_rules", &json!({"rule_id": rule_id}))
            .await
        {
            Ok(Some(_)) => {
                return http_detail(
                    StatusCode::BAD_REQUEST,
                    &format!("Rule with ID {rule_id} already exists"),
                    request_id,
                );
            }
            Ok(None) => {}
            Err(_) => return rate_rule_failure("create", request_id),
        }
        let rule = json!({
            "rule_id": rule_id,
            "rule_type": rule_type,
            "time_window": time_window,
            "limit": limit,
            "target_identifier": target_identifier,
            "burst_allowance": burst_allowance,
            "priority": priority,
            "enabled": enabled,
            "description": description,
            "created_at": timestamp_now_naive(),
            "updated_at": timestamp_now_naive(),
        });
        return match storage.insert_one("rate_limit_rules", rule.clone()).await {
            Ok(_) => success(StatusCode::CREATED, rate_rule_response(rule), request_id),
            Err(_) => rate_rule_failure("create", request_id),
        };
    }
    if suffix.is_empty() {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "GTW004",
            "Method not allowed",
            request_id,
        );
    }
    if method == Method::GET {
        return match storage
            .find_one("rate_limit_rules", &json!({"rule_id": suffix}))
            .await
        {
            Ok(Some(rule)) => success(StatusCode::OK, rate_rule_response(rule), request_id),
            Ok(None) => http_detail(
                StatusCode::NOT_FOUND,
                &format!("Rule {suffix} not found"),
                request_id,
            ),
            Err(_) => rate_rule_failure("get", request_id),
        };
    }
    if method == Method::PUT {
        if !payload.is_object() {
            return rate_rule_validation(
                "body",
                "value is not a valid dict",
                "type_error.dict",
                request_id,
            );
        }
        let mut updates = Value::Object(Map::new());
        if let Some(value) = payload.get("limit").filter(|value| !value.is_null()) {
            let Some(value) = rate_rule_integer(value).filter(|value| *value > 0) else {
                return rate_rule_validation(
                    "limit",
                    "ensure this value is greater than 0",
                    "value_error.number.not_gt",
                    request_id,
                );
            };
            updates["limit"] = json!(value);
        }
        if let Some(value) = payload
            .get("target_identifier")
            .filter(|value| !value.is_null())
        {
            let Some(value) = security_setting_string(value) else {
                return rate_rule_validation(
                    "target_identifier",
                    "str type expected",
                    "type_error.str",
                    request_id,
                );
            };
            updates["target_identifier"] = json!(value);
        }
        if let Some(value) = payload
            .get("burst_allowance")
            .filter(|value| !value.is_null())
        {
            let Some(value) = rate_rule_integer(value).filter(|value| *value >= 0) else {
                return rate_rule_validation(
                    "burst_allowance",
                    "ensure this value is greater than or equal to 0",
                    "value_error.number.not_ge",
                    request_id,
                );
            };
            updates["burst_allowance"] = json!(value);
        }
        if let Some(value) = payload.get("priority").filter(|value| !value.is_null()) {
            let Some(value) = rate_rule_integer(value) else {
                return rate_rule_validation(
                    "priority",
                    "value is not a valid integer",
                    "type_error.integer",
                    request_id,
                );
            };
            updates["priority"] = json!(value);
        }
        if let Some(value) = payload.get("enabled").filter(|value| !value.is_null()) {
            let Some(value) = security_setting_bool(value) else {
                return rate_rule_validation(
                    "enabled",
                    "value could not be parsed to a boolean",
                    "type_error.bool",
                    request_id,
                );
            };
            updates["enabled"] = json!(value);
        }
        if let Some(value) = payload.get("description").filter(|value| !value.is_null()) {
            let Some(value) = security_setting_string(value) else {
                return rate_rule_validation(
                    "description",
                    "str type expected",
                    "type_error.str",
                    request_id,
                );
            };
            updates["description"] = json!(value);
        }
        updates["updated_at"] = json!(timestamp_now_naive());
        return match storage
            .update_one("rate_limit_rules", &json!({"rule_id": suffix}), &updates)
            .await
        {
            Ok(Some(rule)) => success(StatusCode::OK, rate_rule_response(rule), request_id),
            Ok(None) => http_detail(
                StatusCode::NOT_FOUND,
                &format!("Rule {suffix} not found"),
                request_id,
            ),
            Err(_) => rate_rule_failure("update", request_id),
        };
    }
    if method == Method::DELETE {
        return match storage
            .delete_one("rate_limit_rules", &json!({"rule_id": suffix}))
            .await
        {
            Ok(true) => success(
                StatusCode::OK,
                json!({"deleted": true, "rule_id": suffix}),
                request_id,
            ),
            Ok(false) => http_detail(
                StatusCode::NOT_FOUND,
                &format!("Rule {suffix} not found"),
                request_id,
            ),
            Err(_) => rate_rule_failure("delete", request_id),
        };
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "GTW004",
        "Method not allowed",
        request_id,
    )
}

fn rate_rule_validation(
    _field: &str,
    _message_text: &str,
    _kind: &str,
    request_id: &str,
) -> Response {
    // The pinned app's exception middleware replaces Pydantic's normal
    // FastAPI detail list for this model with its project error envelope.
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "VAL001",
        "Validation Error",
        request_id,
    )
}

fn rate_rule_failure(operation: &str, request_id: &str) -> Response {
    let detail = match operation {
        "create" => "Failed to create rule",
        "list" => "Failed to list rules",
        "search" => "Failed to search rules",
        "get" => "Failed to get rule",
        "update" => "Failed to update rule",
        "delete" => "Failed to delete rule",
        "enable" => "Failed to enable rule",
        "disable" => "Failed to disable rule",
        "bulk/delete" => "Failed to delete rules",
        "bulk/enable" => "Failed to enable rules",
        "bulk/disable" => "Failed to disable rules",
        "duplicate" => "Failed to duplicate rule",
        "statistics" => "Failed to get statistics",
        "status" => "Failed to get rate limit status",
        _ => "An unexpected error occurred",
    };
    http_detail(StatusCode::INTERNAL_SERVER_ERROR, detail, request_id)
}

fn rate_rule_integer(value: &Value) -> Option<i64> {
    match value {
        Value::Number(value) => value.as_i64().or_else(|| {
            value
                .as_f64()
                .filter(|value| value.is_finite())
                .map(|value| value as i64)
        }),
        Value::String(value) => crate::python_scalar::parse_model_integer(value)
            .and_then(|value| i64::try_from(value).ok()),
        Value::Bool(value) => Some(i64::from(*value)),
        _ => None,
    }
}

fn rate_rule_response(rule: Value) -> Value {
    json!({
        "rule_id": rule.get("rule_id").cloned().unwrap_or(Value::Null),
        "rule_type": rule.get("rule_type").cloned().unwrap_or(Value::Null),
        "time_window": rule.get("time_window").cloned().unwrap_or(Value::Null),
        "limit": rule.get("limit").cloned().unwrap_or(Value::Null),
        "target_identifier": rule.get("target_identifier").cloned().unwrap_or(Value::Null),
        "burst_allowance": rule.get("burst_allowance").cloned().unwrap_or_else(|| json!(0)),
        "priority": rule.get("priority").cloned().unwrap_or_else(|| json!(0)),
        "enabled": rule.get("enabled").cloned().unwrap_or_else(|| json!(true)),
        "description": rule.get("description").cloned().unwrap_or(Value::Null),
        "created_at": rule.get("created_at").cloned().unwrap_or(Value::Null),
        "updated_at": rule.get("updated_at").cloned().unwrap_or(Value::Null),
    })
}

#[allow(clippy::too_many_arguments)]
async fn entity_routes(
    state: &AppState,
    prefix: &str,
    spec: EntitySpec,
    path: &str,
    method: &Method,
    mut payload: Value,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path.strip_prefix(prefix).unwrap_or("").trim_matches('/');
    if (method == Method::POST && suffix.is_empty()) || method == Method::PUT {
        let normalized = match spec.collection {
            "roles" => normalize_role_model(&mut payload, method == Method::POST),
            "groups" => normalize_group_model(&mut payload, method == Method::POST),
            "routings" => normalize_routing_model(&mut payload, method == Method::POST),
            _ => Ok(()),
        };
        if normalized.is_err() {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
    }
    if method == Method::GET && (suffix.is_empty() || suffix == "all") {
        // The pinned get_groups only authenticates; get_routings requires
        // manage_routings (RTG012).
        if spec.collection == "routings" && !has_permission(state, username, spec.permission).await
        {
            return error(
                StatusCode::FORBIDDEN,
                "RTG012",
                "You do not have permission to get routings",
                request_id,
            );
        }
        if spec.collection != "roles" {
            // Python's `get_groups`/`get_routings` type `page`/`page_size` as
            // typed FastAPI query params (a non-numeric value never reaches the
            // handler and produces FastAPI's own 422), matching roles above.
            if let Some(response) =
                int_query_validation_error(query, &["page", "page_size"], request_id)
            {
                return response;
            }
            if let Err(message_text) = validate_pagination(query) {
                return error(StatusCode::BAD_REQUEST, "PAG001", &message_text, request_id);
            }
        }
        let mut items = match storage.find_many(spec.collection, &json!({})).await {
            Ok(items) => items.into_iter().map(strip_internal).collect::<Vec<_>>(),
            Err(_) => return unexpected(request_id),
        };
        if matches!(spec.collection, "roles" | "groups" | "routings") {
            // Python's `get_roles(page: int = ..., page_size: int = ...)` are
            // typed FastAPI query params: a non-numeric value never reaches the
            // handler and instead produces FastAPI's own 422 validation body.
            // Unlike the other collections above, this branch previously parsed
            // page/page_size with `.unwrap_or(1)`, silently accepting garbage.
            if let Some(response) =
                int_query_validation_error(query, &["page", "page_size"], request_id)
            {
                return response;
            }
            if spec.collection == "roles" {
                items.sort_by_key(|role| {
                    role.get("role_name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                });
            }
            let page = query
                .get("page")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1);
            let page_size = query
                .get("page_size")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(10);
            let maximum = env::var("MAX_PAGE_SIZE")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(200);
            if page == 0 || page_size == 0 {
                return error(
                    StatusCode::BAD_REQUEST,
                    "PAG001",
                    "Invalid page or page size",
                    request_id,
                );
            }
            if page_size > maximum {
                return error(
                    StatusCode::BAD_REQUEST,
                    "PAG001",
                    "Page size exceeds maximum limit",
                    request_id,
                );
            }
            let total = items.len();
            let start = (page - 1).saturating_mul(page_size);
            items = items.into_iter().skip(start).take(page_size).collect();
            if spec.collection == "roles" && !is_admin_user(state, username).await {
                let mut visible = Vec::new();
                for mut role in items {
                    let role_name = role
                        .get("role_name")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if is_admin_role(state, role_name).await {
                        continue;
                    }
                    role.as_object_mut()
                        .map(|role| role.remove("platform_admin"));
                    visible.push(role);
                }
                // The pinned route replaces the page with just the filtered roles.
                return success(StatusCode::OK, json!({"roles": visible}), request_id);
            }
            return success(
                StatusCode::OK,
                json!({spec.collection: items, "page": page, "page_size": page_size,
                    "has_next": total > start.saturating_add(page_size), "total": total}),
                request_id,
            );
        }
        let payload = match spec.list_key {
            Some(list_key) => paginate_named(items, query, list_key),
            None => paginate(items, query),
        };
        return success(StatusCode::OK, payload, request_id);
    }
    if method == Method::POST && suffix.is_empty() {
        if !has_permission(state, username, spec.permission).await {
            return error(
                StatusCode::FORBIDDEN,
                if spec.collection == "routings" {
                    "RTG009"
                } else {
                    spec.permission_code
                },
                if spec.collection == "roles" {
                    "You do not have permission to create roles"
                } else {
                    "Insufficient permissions"
                },
                request_id,
            );
        }
        if spec.collection == "routings" && payload.get("client_key").is_none_or(Value::is_null) {
            payload["client_key"] = json!(Uuid::new_v4().to_string());
        }
        let Some(key) = payload
            .get(spec.key)
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Missing required field",
                request_id,
            );
        };
        if spec.collection == "roles"
            && matches!(
                key.trim().to_ascii_lowercase().as_str(),
                "admin" | "platform admin"
            )
            && !is_admin_user(state, username).await
        {
            return error(
                StatusCode::FORBIDDEN,
                "ROLE013",
                "Only admin may create the admin role",
                request_id,
            );
        }
        if matches!(
            storage
                .find_one(spec.collection, &json!({spec.key: key}))
                .await,
            Ok(Some(_))
        ) {
            return error(
                StatusCode::BAD_REQUEST,
                spec.duplicate_code,
                if spec.collection == "roles" {
                    "Role already exists"
                } else {
                    "Resource already exists"
                },
                request_id,
            );
        }
        if let Some(id_field) = spec.id_field {
            if payload
                .get(id_field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                payload[id_field] = json!(Uuid::new_v4().to_string());
            }
        }
        return match storage.insert_one(spec.collection, payload).await {
            Ok(_) => {
                audit::management_mutation(
                    username,
                    "management.create",
                    &format!("{}:{key}", spec.collection),
                    "success",
                );
                if spec.collection == "routings" {
                    message(
                        StatusCode::CREATED,
                        &format!("Routing created successfully with key: {key}"),
                        request_id,
                    )
                } else {
                    message(StatusCode::CREATED, spec.created, request_id)
                }
            }
            Err(duplicate_error) if duplicate_error.is_duplicate_key() => error(
                StatusCode::BAD_REQUEST,
                spec.duplicate_code,
                if spec.collection == "roles" {
                    "Role already exists"
                } else {
                    "Resource already exists"
                },
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    let key = suffix.split('/').next().unwrap_or("");
    if key.is_empty() {
        return error(
            StatusCode::NOT_FOUND,
            "GTW003",
            "Platform route does not exist",
            request_id,
        );
    }
    let filter = json!({spec.key: key});
    if method == Method::GET {
        // The pinned get_group only authenticates; get_routing needs manage_routings.
        if spec.collection == "routings" && !has_permission(state, username, spec.permission).await
        {
            return error(
                StatusCode::FORBIDDEN,
                "RTG013",
                "You do not have permission to get routings",
                request_id,
            );
        }
        if spec.collection == "roles"
            && is_admin_role(state, key).await
            && !is_admin_user(state, username).await
        {
            return json_response(
                StatusCode::NOT_FOUND,
                json!({"error_message": "Role not found"}),
                request_id,
            );
        }
        return match storage.find_one(spec.collection, &filter).await {
            Ok(Some(mut item)) => {
                if spec.collection == "roles" && !is_admin_user(state, username).await {
                    item.as_object_mut()
                        .map(|role| role.remove("platform_admin"));
                }
                success(StatusCode::OK, strip_internal(item), request_id)
            }
            Ok(None) => error(
                // Python's routing retrieval also returns 400 (RTG004) for a
                // missing client_key, unlike groups/roles which use 404 here.
                if spec.collection == "routings" {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                },
                spec.not_found_code,
                not_found_message(spec.collection),
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if !has_permission(state, username, spec.permission).await {
        return error(
            StatusCode::FORBIDDEN,
            if spec.collection == "routings" {
                if method == Method::PUT {
                    "RTG010"
                } else {
                    "RTG011"
                }
            } else if spec.collection == "roles" {
                if method == Method::PUT {
                    "ROLE010"
                } else {
                    "ROLE011"
                }
            } else if spec.collection == "groups" {
                if method == Method::PUT {
                    "GRP009"
                } else {
                    "GRP010"
                }
            } else {
                "AUTH006"
            },
            match (spec.collection, method == Method::PUT) {
                ("roles", true) => "You do not have permission to update roles",
                ("roles", false) => "You do not have permission to delete roles",
                ("groups", true) => "You do not have permission to update groups",
                ("groups", false) => "You do not have permission to delete groups",
                _ => "Insufficient permissions",
            },
            request_id,
        );
    }
    // Python's update/delete service methods for groups and routings return
    // 400 (not 404) when the target doesn't exist, matching the roles
    // convention below rather than the generic 404 used elsewhere.
    if matches!(spec.collection, "groups" | "routings")
        && matches!(storage.find_one(spec.collection, &filter).await, Ok(None))
    {
        return error(
            StatusCode::BAD_REQUEST,
            spec.not_found_code,
            not_found_message(spec.collection),
            request_id,
        );
    }
    if spec.collection == "roles" {
        match storage.find_one(spec.collection, &filter).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    spec.not_found_code,
                    "Role does not exist",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        }
        if is_admin_role(state, key).await && !is_admin_user(state, username).await {
            return error(
                StatusCode::FORBIDDEN,
                if method == Method::PUT {
                    "ROLE014"
                } else {
                    "ROLE016"
                },
                if method == Method::PUT {
                    "Only admin may modify the admin role"
                } else {
                    "Only admin may delete the admin role"
                },
                request_id,
            );
        }
    }
    // The service rejects an empty update only after its existence check.
    if method == Method::PUT && payload.as_object().is_some_and(|object| object.is_empty()) {
        let (code, message_text) = match spec.collection {
            "roles" => ("ROLE007", "No data to update"),
            "groups" => ("GRP006", "No data to update"),
            "routings" => ("RTG007", "No data to update"),
            _ => ("VAL001", "No data to update"),
        };
        return error(StatusCode::BAD_REQUEST, code, message_text, request_id);
    }
    if method == Method::PUT {
        if spec.collection == "routings" {
            let existing = match storage.find_one(spec.collection, &filter).await {
                Ok(Some(routing)) => routing,
                Ok(None) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "RTG004",
                        "Routing does not exist",
                        request_id,
                    );
                }
                Err(_) => return unexpected(request_id),
            };
            if payload
                .get(spec.key)
                .is_some_and(|value| value.as_str() != Some(key))
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "RTG005",
                    "Routing key cannot be changed",
                    request_id,
                );
            }
            if payload.as_object().is_some_and(|updates| {
                updates
                    .iter()
                    .all(|(field, value)| existing.get(field) == Some(value))
            }) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "RTG006",
                    "Unable to update routing",
                    request_id,
                );
            }
        }
        if payload
            .get(spec.key)
            .is_some_and(|value| value.as_str() != Some(key))
        {
            return error(
                StatusCode::BAD_REQUEST,
                if spec.collection == "roles" {
                    "ROLE005"
                } else {
                    "VAL001"
                },
                if spec.collection == "roles" {
                    "Role name cannot be changed"
                } else {
                    "Resource identifier cannot be updated"
                },
                request_id,
            );
        }
        return match storage.update_one(spec.collection, &filter, &payload).await {
            Ok(Some(_)) => {
                audit::management_mutation(
                    username,
                    "management.update",
                    &format!("{}:{key}", spec.collection),
                    "success",
                );
                if spec.collection == "roles" {
                    match storage.find_one(spec.collection, &filter).await {
                        Ok(Some(role)) => success(StatusCode::OK, strip_internal(role), request_id),
                        Ok(None) => error(
                            StatusCode::NOT_FOUND,
                            spec.not_found_code,
                            "Resource not found",
                            request_id,
                        ),
                        Err(_) => unexpected(request_id),
                    }
                } else {
                    message(StatusCode::OK, spec.updated, request_id)
                }
            }
            Ok(None) => error(
                if spec.collection == "roles" {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                },
                spec.not_found_code,
                not_found_message(spec.collection),
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::DELETE {
        if spec.collection == "groups" && key == "ALL" {
            return error(
                StatusCode::BAD_REQUEST,
                "AUTH900",
                "Protected resource cannot be deleted",
                request_id,
            );
        }
        return match storage.delete_one(spec.collection, &filter).await {
            Ok(true) => {
                audit::management_mutation(
                    username,
                    "management.delete",
                    &format!("{}:{key}", spec.collection),
                    "success",
                );
                message(StatusCode::OK, spec.deleted, request_id)
            }
            Ok(false) => error(
                if spec.collection == "roles" {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                },
                spec.not_found_code,
                not_found_message(spec.collection),
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "GTW004",
        "Method not allowed",
        request_id,
    )
}

/// Mirrors the pinned `sanitize_filename` checks on a proto path segment.
fn proto_file_name_error(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("Empty filename provided");
    }
    if name.contains("..") {
        return Some("Path traversal detected: .. not allowed in filename");
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Some("Absolute paths not allowed in filename");
    }
    if name.as_bytes().get(1) == Some(&b':') {
        return Some("Drive letters not allowed in filename");
    }
    if name.chars().count() > 255 {
        return Some("Filename too long (max 255 characters)");
    }
    None
}

fn merge_proto_metadata(target: &mut Value, source: &Value) {
    for key in [
        "api_grpc_proto_source",
        "api_grpc_descriptor_set",
        "api_grpc_descriptor_sha256",
    ] {
        if let Some(value) = source.get(key) {
            target[key] = value.clone();
        }
    }
    if target.get("api_grpc_package").is_none_or(Value::is_null) {
        if let Some(value) = source.get("api_grpc_package") {
            target["api_grpc_package"] = value.clone();
        }
    }
}

async fn lock_tls_binding_mutation(
    state: &AppState,
    payload: &Value,
    prefix: &str,
) -> Result<Option<crate::storage::runtime::TlsMutationGuard>, ()> {
    let has_binding = [
        "client_tls_policy",
        "upstream_tls_profile",
        "upstream_tls_profiles",
    ]
    .iter()
    .any(|field| {
        payload
            .get(format!("{prefix}_{field}"))
            .is_some_and(|value| !value.is_null())
    });
    if !has_binding {
        return Ok(None);
    }
    let guard = state
        .storage
        .as_ref()
        .ok_or(())?
        .tls_mutation_lock()
        .await
        .map_err(|_| ())?;
    state.reload_tls_from_storage().await.map_err(|_| ())?;
    Ok(Some(guard))
}

async fn api_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    mut payload: Value,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path.strip_prefix("/api").unwrap_or("").trim_matches('/');
    if method == Method::GET && (suffix.is_empty() || suffix == "all") {
        // Python's `get_apis(page: int = ..., page_size: int = ...)` typed
        // FastAPI query params: a non-numeric value produces a 422, not a
        // silently-defaulted page or a custom 400 PAG001 body.
        if let Some(response) =
            int_query_validation_error(query, &["page", "page_size"], request_id)
        {
            return response;
        }
        if let Err(message_text) = validate_pagination(query) {
            return error(StatusCode::BAD_REQUEST, "PAG001", &message_text, request_id);
        }
        return match storage.find_many("apis", &json!({})).await {
            Ok(items) => success(
                StatusCode::OK,
                paginate_apis(items.into_iter().map(strip_internal).collect(), query),
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    let parts = suffix
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() >= 3 {
        return api_discovery_routes(state, &parts, method, username, request_id).await;
    }
    if method == Method::POST && parts.is_empty() {
        if !has_permission(state, username, "manage_apis").await {
            return error(
                StatusCode::FORBIDDEN,
                "API007",
                "You do not have permission to create APIs",
                request_id,
            );
        }
        payload = match normalize_create_api(&payload) {
            Ok(payload) => payload,
            Err(errors) => return validation_errors(errors, request_id),
        };
        let _tls_guard = match lock_tls_binding_mutation(state, &payload, "api").await {
            Ok(guard) => guard,
            Err(()) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TLS004",
                    "TLS profiles are unavailable",
                    request_id,
                );
            }
        };
        if let Some(policy) = payload
            .get("api_client_tls_policy")
            .filter(|value| !value.is_null())
        {
            if crate::tls::policy::ClientTlsPolicy::validate_value(
                policy,
                &state.tls_snapshot().profiles,
                state.config.downstream_tls_mode == crate::config::DownstreamTlsMode::Native,
            )
            .is_err()
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "TLS003",
                    "Invalid client TLS policy",
                    request_id,
                );
            }
        }
        if crate::tls::profiles::validate_upstream_bindings(
            &payload,
            "api",
            &state.tls_snapshot().profiles,
        )
        .is_err()
        {
            return error(
                StatusCode::BAD_REQUEST,
                "TLS004",
                "Invalid upstream TLS binding",
                request_id,
            );
        }
        let name = payload["api_name"]
            .as_str()
            .expect("validated API name")
            .to_owned();
        let version = payload["api_version"]
            .as_str()
            .expect("validated API version")
            .to_owned();
        if payload["api_public"].as_bool().unwrap_or(false)
            && payload["api_credits_enabled"].as_bool().unwrap_or(false)
        {
            return error(
                StatusCode::BAD_REQUEST,
                "API013",
                "Public API cannot have credits enabled",
                request_id,
            );
        }
        let filter = json!({"api_name": name, "api_version": version});
        let existing = storage.find_one("apis", &filter).await.ok().flatten();
        if let Some(existing) = existing {
            let descriptor_only =
                existing.get("api_id").is_none() && existing.get("api_grpc_proto_source").is_some();
            if !descriptor_only {
                return message(StatusCode::OK, "API already exists", request_id);
            }
            merge_proto_metadata(&mut payload, &existing);
            payload["api_id"] = json!(Uuid::new_v4().to_string());
            payload["api_path"] = json!(format!("/{name}/{version}"));
            return match storage.update_one("apis", &filter, &payload).await {
                Ok(Some(api)) => {
                    audit::management_mutation(
                        username,
                        "api.create",
                        &format!("{name}/{version}"),
                        "success",
                    );
                    success(
                        StatusCode::CREATED,
                        json!({"api": strip_internal(api)}),
                        request_id,
                    )
                }
                _ => unexpected(request_id),
            };
        }
        if let Ok(Some(pending)) = storage.find_one("grpc_proto_uploads", &filter).await {
            merge_proto_metadata(&mut payload, &pending);
        }
        payload["api_id"] = json!(Uuid::new_v4().to_string());
        payload["api_path"] = json!(format!("/{name}/{version}"));
        return match storage.insert_one("apis", payload).await {
            Ok(api) => {
                let _ = storage.delete_one("grpc_proto_uploads", &filter).await;
                audit::management_mutation(
                    username,
                    "api.create",
                    &format!("{name}/{version}"),
                    "success",
                );
                success(
                    StatusCode::CREATED,
                    json!({"api": strip_internal(api)}),
                    request_id,
                )
            }
            Err(error) if error.is_duplicate_key() => {
                message(StatusCode::OK, "API already exists", request_id)
            }
            Err(_) => unexpected(request_id),
        };
    }
    if parts.len() != 2 {
        return error(
            StatusCode::NOT_FOUND,
            "GTW003",
            "Platform route does not exist",
            request_id,
        );
    }
    let filter = json!({"api_name": parts[0], "api_version": parts[1]});
    if method == Method::GET {
        return match storage.find_one("apis", &filter).await {
            Ok(Some(api)) => success(StatusCode::OK, strip_internal(api), request_id),
            Ok(None) => error(
                StatusCode::BAD_REQUEST,
                "API003",
                "API does not exist for the requested name and version",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::PUT {
        if !has_permission(state, username, "manage_apis").await {
            return error(
                StatusCode::FORBIDDEN,
                "API008",
                "You do not have permission to update APIs",
                request_id,
            );
        }
        payload = match normalize_update_api(&payload) {
            Ok(payload) => payload,
            Err(errors) => return validation_errors(errors, request_id),
        };
        let _tls_guard = match lock_tls_binding_mutation(state, &payload, "api").await {
            Ok(guard) => guard,
            Err(()) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TLS004",
                    "TLS profiles are unavailable",
                    request_id,
                );
            }
        };
        if let Some(policy) = payload
            .get("api_client_tls_policy")
            .filter(|value| !value.is_null())
        {
            if crate::tls::policy::ClientTlsPolicy::validate_value(
                policy,
                &state.tls_snapshot().profiles,
                state.config.downstream_tls_mode == crate::config::DownstreamTlsMode::Native,
            )
            .is_err()
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "TLS003",
                    "Invalid client TLS policy",
                    request_id,
                );
            }
        }
        if crate::tls::profiles::validate_upstream_bindings(
            &payload,
            "api",
            &state.tls_snapshot().profiles,
        )
        .is_err()
        {
            return error(
                StatusCode::BAD_REQUEST,
                "TLS004",
                "Invalid upstream TLS binding",
                request_id,
            );
        }
        let Some(updates) = payload.as_object() else {
            return unexpected(request_id);
        };
        for key in ["api_name", "api_version", "api_path"] {
            if payload.get(key).is_some() {
                let expected = if key == "api_name" {
                    parts[0].to_owned()
                } else if key == "api_version" {
                    parts[1].to_owned()
                } else {
                    format!("/{}/{}", parts[0], parts[1])
                };
                if payload.get(key).and_then(Value::as_str) != Some(expected.as_str()) {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "API005",
                        "API name and version cannot be updated",
                        request_id,
                    );
                }
            }
        }
        let existing = match storage.find_one("apis", &filter).await {
            Ok(Some(existing)) => existing,
            Ok(None) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "API003",
                    "API does not exist for the requested name and version",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        };
        // The pinned service checks the rename guard and existence first.
        if updates.is_empty() {
            return error(
                StatusCode::BAD_REQUEST,
                "API006",
                "No data to update",
                request_id,
            );
        }
        let desired_public = payload
            .get("api_public")
            .and_then(Value::as_bool)
            .or_else(|| existing.get("api_public").and_then(Value::as_bool))
            .unwrap_or(false);
        let desired_credits = payload
            .get("api_credits_enabled")
            .and_then(Value::as_bool)
            .or_else(|| existing.get("api_credits_enabled").and_then(Value::as_bool))
            .unwrap_or(false);
        if desired_public && desired_credits {
            return error(
                StatusCode::BAD_REQUEST,
                "API013",
                "Public API cannot have credits enabled",
                request_id,
            );
        }
        let changed = updates
            .iter()
            .any(|(key, value)| existing.get(key) != Some(value));
        if !changed {
            return error(
                StatusCode::BAD_REQUEST,
                "API002",
                "Unable to update api",
                request_id,
            );
        }
        return match storage.update_one("apis", &filter, &payload).await {
            Ok(Some(_)) => {
                audit::management_mutation(
                    username,
                    "api.update",
                    &format!("{}/{}", parts[0], parts[1]),
                    "success",
                );
                message(StatusCode::OK, "API updated successfully", request_id)
            }
            Ok(None) => error(
                StatusCode::BAD_REQUEST,
                "API003",
                "API does not exist for the requested name and version",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::DELETE {
        let existing = storage.find_one("apis", &filter).await.ok().flatten();
        return match storage.delete_one("apis", &filter).await {
            Ok(true) => {
                // The pinned proto file outlives its API; keep the upload so a
                // re-created API picks it up again.
                if let Some(existing) = existing
                    .filter(|api| api.get("api_grpc_proto_source").is_some_and(python_truthy))
                {
                    let mut pending = filter.clone();
                    merge_proto_metadata(&mut pending, &existing);
                    let _ = storage.insert_one("grpc_proto_uploads", pending).await;
                }
                audit::management_mutation(
                    username,
                    "api.delete",
                    &format!("{}/{}", parts[0], parts[1]),
                    "success",
                );
                message(StatusCode::OK, "API deleted successfully", request_id)
            }
            Ok(false) => error(
                StatusCode::BAD_REQUEST,
                "API003",
                "API does not exist for the requested name and version",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "GTW004",
        "Method not allowed",
        request_id,
    )
}

async fn user_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    mut payload: Value,
    query: &HashMap<String, String>,
    active_user: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path
        .strip_prefix("/users")
        .or_else(|| path.strip_prefix("/user"))
        .unwrap_or("")
        .trim_matches('/');
    if method == Method::GET && (suffix.is_empty() || suffix == "all") {
        // Python's `get_users(page: int = ..., page_size: int = ...)` typed
        // FastAPI query params: a non-numeric value produces a 422.
        if let Some(response) =
            int_query_validation_error(query, &["page", "page_size"], request_id)
        {
            return response;
        }
        if let Err(message_text) = validate_pagination(query) {
            return error(StatusCode::BAD_REQUEST, "PAG001", &message_text, request_id);
        }
        return match storage.find_many("users", &json!({})).await {
            Ok(items) => {
                let actor_is_admin = is_admin_user(state, active_user).await;
                let items = items
                    .into_iter()
                    .filter(|user| {
                        actor_is_admin || user.get("role").and_then(Value::as_str) != Some("admin")
                    })
                    .map(public_user)
                    .collect();
                success(
                    StatusCode::OK,
                    json!({"users": paginate_items(items, query)}),
                    request_id,
                )
            }
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::GET && suffix == "me" {
        return user_by(state, "username", active_user, active_user, request_id).await;
    }
    if method == Method::GET && suffix.starts_with("email/") {
        return user_by(
            state,
            "email",
            suffix.trim_start_matches("email/"),
            active_user,
            request_id,
        )
        .await;
    }
    if method == Method::POST && suffix.is_empty() {
        if !has_permission(state, active_user, "manage_users").await {
            return error(
                StatusCode::FORBIDDEN,
                "USR006",
                "Can only update your own information",
                request_id,
            );
        }
        return create_user(state, &mut payload, Some(active_user), request_id).await;
    }
    let target = suffix.split('/').next().unwrap_or("");
    if target.is_empty() {
        return error(
            StatusCode::NOT_FOUND,
            "USR002",
            "User not found",
            request_id,
        );
    }
    if method == Method::GET {
        return user_by(state, "username", target, active_user, request_id).await;
    }
    if method == Method::PUT {
        if active_user != target && !has_permission(state, active_user, "manage_users").await {
            return error(
                StatusCode::FORBIDDEN,
                "USR006",
                if suffix.ends_with("/update-password") {
                    "Can only update your own password"
                } else {
                    "Can only update your own information"
                },
                request_id,
            );
        }
        if !suffix.ends_with("/update-password")
            && normalize_update_user_model(&mut payload).is_err()
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
        if target == "admin" && suffix.ends_with("/update-password") {
            return error(
                StatusCode::FORBIDDEN,
                "USR022",
                "Super admin password cannot be changed via UI",
                request_id,
            );
        }
        if target == "admin" && !bootstrap_admin_update_fields_are_safe(&payload) {
            return error(
                StatusCode::FORBIDDEN,
                "USR020",
                "Super admin user cannot be modified",
                request_id,
            );
        }
        if active_user == target && !has_permission(state, active_user, "manage_users").await {
            let attempted = restricted_self_update_fields(&payload);
            if !attempted.is_empty() {
                return error(
                    StatusCode::FORBIDDEN,
                    "USR023",
                    &format!(
                        "Cannot modify restricted fields without manage_users permission: {}",
                        attempted.join(", ")
                    ),
                    request_id,
                );
            }
        }
        let existing = match storage
            .find_one("users", &json!({"username": target}))
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return error(
                    StatusCode::NOT_FOUND,
                    "USR002",
                    "User not found",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        };
        if existing.get("role").and_then(Value::as_str) == Some("admin")
            && !is_admin_user(state, active_user).await
        {
            return error(
                StatusCode::FORBIDDEN,
                "USR012",
                "Only admin may modify admin users",
                request_id,
            );
        }
        if let Some(email) = payload.get("email").and_then(Value::as_str)
            && existing.get("email").and_then(Value::as_str) != Some(email)
            && matches!(
                storage.find_one("users", &json!({"email": email})).await,
                Ok(Some(_))
            )
        {
            return error(
                StatusCode::BAD_REQUEST,
                "USR001",
                "Username or email already exists",
                request_id,
            );
        }
        if let Some(role_name) = payload.get("role").and_then(Value::as_str) {
            if role_name == "admin" && !is_admin_user(state, active_user).await {
                return error(
                    StatusCode::FORBIDDEN,
                    "USR013",
                    "Only admin may change admin role assignments",
                    request_id,
                );
            }
        }
        if suffix.ends_with("/update-password") {
            let Some(password) = payload.get("new_password").and_then(Value::as_str) else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "USR005",
                    "Password is required",
                    request_id,
                );
            };
            if !secure_password(password) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "USR005",
                    password_policy(),
                    request_id,
                );
            }
            let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
                Ok(password_hash) => password_hash,
                Err(_) => return unexpected(request_id),
            };
            payload = json!({"password": password_hash});
        } else if let Some(password) = payload.get("password").and_then(Value::as_str) {
            if !secure_password(password) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "USR005",
                    password_policy(),
                    request_id,
                );
            }
            let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
                Ok(password_hash) => password_hash,
                Err(_) => return unexpected(request_id),
            };
            payload["password"] = json!(password_hash);
        }
        let password_update = suffix.ends_with("/update-password");
        return match storage
            .update_one("users", &json!({"username": target}), &payload)
            .await
        {
            Ok(Some(_)) => {
                if !password_update
                    && payload.get("role").and_then(Value::as_str).is_some()
                    && purge_subscriptions_after_role_change(state, target)
                        .await
                        .is_err()
                {
                    return unexpected(request_id);
                }
                audit::management_mutation(
                    active_user,
                    if password_update {
                        "user.password_update"
                    } else {
                        "user.update"
                    },
                    target,
                    "success",
                );
                message(StatusCode::OK, "User updated successfully", request_id)
            }
            Ok(None) => error(
                StatusCode::NOT_FOUND,
                "USR002",
                "User not found",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::DELETE {
        if target == "admin" {
            return error(
                StatusCode::FORBIDDEN,
                "USR021",
                "Super admin user cannot be deleted",
                request_id,
            );
        }
        if active_user != target && !has_permission(state, active_user, "manage_users").await {
            return error(
                StatusCode::FORBIDDEN,
                "USR007",
                "Can only delete your own account",
                request_id,
            );
        }
        let existing = match storage
            .find_one("users", &json!({"username": target}))
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return error(
                    StatusCode::NOT_FOUND,
                    "USR002",
                    "User not found",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        };
        if existing.get("role").and_then(Value::as_str) == Some("admin")
            && !is_admin_user(state, active_user).await
        {
            return error(
                StatusCode::FORBIDDEN,
                "USR014",
                "Only admin may delete admin users",
                request_id,
            );
        }
        return match storage
            .delete_one("users", &json!({"username": target}))
            .await
        {
            Ok(true) => {
                audit::management_mutation(active_user, "user.delete", target, "success");
                message(StatusCode::OK, "User deleted successfully", request_id)
            }
            Ok(false) => error(
                StatusCode::NOT_FOUND,
                "USR002",
                "User not found",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "GTW004",
        "Method not allowed",
        request_id,
    )
}

/// UserService.purge_apis_after_role_change removes subscriptions whose API
/// role allowlist no longer admits the user's newly persisted role.
async fn purge_subscriptions_after_role_change(state: &AppState, username: &str) -> Result<(), ()> {
    let storage = state.storage.as_ref().ok_or(())?;
    let user = storage
        .find_one("users", &json!({"username": username}))
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    let role = user.get("role").and_then(Value::as_str).unwrap_or_default();
    let Some(subscription) = storage
        .find_one("subscriptions", &json!({"username": username}))
        .await
        .map_err(|_| ())?
    else {
        return Ok(());
    };
    let apis = subscription
        .get("apis")
        .and_then(Value::as_array)
        .ok_or(())?;
    let original_len = apis.len();
    let mut retained = apis.clone();
    let mut index = 0;
    // Python removes from `user_subscriptions['apis']` while iterating that
    // same list. Preserve its resulting index behavior for legacy `role`
    // records, including the skipped item after a removal.
    while index < retained.len() {
        let api_ref = retained[index].clone();
        let api_ref = api_ref.as_str().ok_or(())?;
        let mut segments = api_ref.split('/');
        let api_name = segments.next().ok_or(())?;
        let api_version = segments.next().ok_or(())?;
        if segments.next().is_some() {
            return Err(());
        }
        let api = storage
            .find_one(
                "apis",
                &json!({"api_name": api_name, "api_version": api_version}),
            )
            .await
            .map_err(|_| ())?;
        let permitted = api
            .as_ref()
            .and_then(|api| api.get("role"))
            .and_then(Value::as_array)
            .is_none_or(|roles| roles.iter().any(|entry| entry.as_str() == Some(role)));
        if !permitted {
            retained.remove(index);
        }
        index += 1;
    }
    if retained.len() != original_len {
        storage
            .update_one(
                "subscriptions",
                &json!({"username": username}),
                &json!({"apis": retained}),
            )
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

async fn endpoint_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    mut payload: Value,
    _query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path
        .strip_prefix("/endpoint")
        .unwrap_or("")
        .trim_matches('/');
    let validation_suffix = suffix
        .strip_prefix("endpoint/validation/")
        .or_else(|| suffix.strip_prefix("validation/"))
        // Deeper paths belong to the endpoint route registered before it.
        .filter(|endpoint_id| !endpoint_id.contains('/'))
        // GET /validation/{id} is shadowed by GET /{api_name}/{api_version}.
        .filter(|_| !(method == Method::GET && suffix.starts_with("validation/")));
    if let Some(endpoint_id) = validation_suffix {
        if method == Method::PUT
            && normalize_endpoint_validation_model(&mut payload, false).is_err()
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
        if method != Method::GET && !has_permission(state, username, "manage_endpoints").await {
            let (code, text) = if method == Method::PUT {
                (
                    "END014",
                    "You do not have permission to update endpoint validations",
                )
            } else {
                (
                    "END015",
                    "You do not have permission to delete endpoint validations",
                )
            };
            return error(StatusCode::FORBIDDEN, code, text, request_id);
        }
        let filter = json!({"endpoint_id": endpoint_id});
        if method == Method::GET {
            return match storage.find_one("endpoint_validations", &filter).await {
                Ok(Some(validation)) => {
                    success(StatusCode::OK, strip_internal(validation), request_id)
                }
                Ok(None) => error(
                    StatusCode::BAD_REQUEST,
                    "END018",
                    "Endpoint validation does not exist",
                    request_id,
                ),
                Err(_) => unexpected(request_id),
            };
        }
        if method == Method::PUT {
            if payload.get("validation_enabled") == Some(&Value::Bool(false)) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END020",
                    "Validation enabled is required",
                    request_id,
                );
            }
            match storage
                .find_one("endpoints", &json!({"endpoint_id": endpoint_id}))
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "END022",
                        "Endpoint does not exist",
                        request_id,
                    );
                }
                Err(_) => return unexpected(request_id),
            }
            return match storage
                .update_one("endpoint_validations", &filter, &payload)
                .await
            {
                Ok(_) => message(
                    StatusCode::OK,
                    "Endpoint validation updated successfully",
                    request_id,
                ),
                Err(_) => error(
                    StatusCode::BAD_REQUEST,
                    "END023",
                    "Unable to update endpoint validation",
                    request_id,
                ),
            };
        }
        if method == Method::DELETE {
            return match storage.delete_one("endpoint_validations", &filter).await {
                Ok(_) => message(
                    StatusCode::OK,
                    "Endpoint validation deleted successfully",
                    request_id,
                ),
                Err(_) => error(
                    StatusCode::BAD_REQUEST,
                    "END019",
                    "Unable to delete endpoint validation",
                    request_id,
                ),
            };
        }
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "GTW004",
            "Method not allowed",
            request_id,
        );
    }
    if (suffix == "endpoint/validation" || suffix == "validation") && method == Method::POST {
        if normalize_endpoint_validation_model(&mut payload, true).is_err() {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
        if !has_permission(state, username, "manage_endpoints").await {
            return error(
                StatusCode::FORBIDDEN,
                "END013",
                "You do not have permission to create endpoint validations",
                request_id,
            );
        }
        let endpoint_id = payload
            .get("endpoint_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if endpoint_id.is_empty() {
            return error(
                StatusCode::BAD_REQUEST,
                "END013",
                "Endpoint ID is required",
                request_id,
            );
        }
        match storage
            .find_one("endpoint_validations", &json!({"endpoint_id": endpoint_id}))
            .await
        {
            Ok(Some(_)) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END017",
                    "Endpoint validation already exists",
                    request_id,
                );
            }
            Ok(None) => {}
            Err(_) => return unexpected(request_id),
        }
        match storage
            .find_one("endpoints", &json!({"endpoint_id": endpoint_id}))
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END015",
                    "Endpoint does not exist",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        }
        return match storage.insert_one("endpoint_validations", payload).await {
            Ok(_) => {
                audit::management_mutation(
                    username,
                    "endpoint_validation.create",
                    "endpoint_validation",
                    "success",
                );
                message(
                    StatusCode::CREATED,
                    "Endpoint validation created successfully",
                    request_id,
                )
            }
            Err(_) => error(
                StatusCode::BAD_REQUEST,
                "END016",
                "Unable to create endpoint validation",
                request_id,
            ),
        };
    }
    if method == Method::POST && suffix.is_empty() {
        if normalize_endpoint_model(&mut payload, true).is_err() {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
        let _tls_guard = match lock_tls_binding_mutation(state, &payload, "endpoint").await {
            Ok(guard) => guard,
            Err(()) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TLS004",
                    "TLS profiles are unavailable",
                    request_id,
                );
            }
        };
        if let Some(policy) = payload
            .get("endpoint_client_tls_policy")
            .filter(|value| !value.is_null())
        {
            if crate::tls::policy::ClientTlsPolicy::validate_value(
                policy,
                &state.tls_snapshot().profiles,
                state.config.downstream_tls_mode == crate::config::DownstreamTlsMode::Native,
            )
            .is_err()
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "TLS003",
                    "Invalid client TLS policy",
                    request_id,
                );
            }
        }
        if crate::tls::profiles::validate_upstream_bindings(
            &payload,
            "endpoint",
            &state.tls_snapshot().profiles,
        )
        .is_err()
        {
            return error(
                StatusCode::BAD_REQUEST,
                "TLS004",
                "Invalid upstream TLS binding",
                request_id,
            );
        }
        if !has_permission(state, username, "manage_endpoints").await {
            return error(
                StatusCode::FORBIDDEN,
                "END010",
                "You do not have permission to create endpoints",
                request_id,
            );
        }
        for field in [
            "api_name",
            "api_version",
            "endpoint_method",
            "endpoint_uri",
            "endpoint_description",
        ] {
            if payload.get(field).and_then(Value::as_str).is_none() {
                return error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "VAL001",
                    "Missing required field",
                    request_id,
                );
            }
        }
        let api = match storage
            .find_one(
                "apis",
                &json!({"api_name": payload["api_name"], "api_version": payload["api_version"]}),
            )
            .await
        {
            Ok(Some(api)) => api,
            Ok(None) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END002",
                    "API does not exist for the requested name and version",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        };
        let duplicate_filter = json!({
            "api_name": payload["api_name"],
            "api_version": payload["api_version"],
            "endpoint_method": payload["endpoint_method"],
            "endpoint_uri": payload["endpoint_uri"],
        });
        if matches!(
            storage.find_one("endpoints", &duplicate_filter).await,
            Ok(Some(_))
        ) {
            return error(
                StatusCode::BAD_REQUEST,
                "END001",
                "Endpoint already exists for the requested API name, version and URI",
                request_id,
            );
        }
        if let Some(client_uri) = payload.get("client_uri").and_then(Value::as_str) {
            let conflicts = match storage
                .find_many(
                    "endpoints",
                    &json!({
                        "api_name": payload["api_name"],
                        "api_version": payload["api_version"],
                        "endpoint_method": payload["endpoint_method"],
                    }),
                )
                .await
            {
                Ok(endpoints) => endpoints,
                Err(_) => return unexpected(request_id),
            };
            if conflicts.iter().any(|endpoint| {
                endpoint.get("client_uri").and_then(Value::as_str) == Some(client_uri)
                    || (endpoint.get("client_uri").is_none_or(Value::is_null)
                        && endpoint.get("endpoint_uri").and_then(Value::as_str) == Some(client_uri))
            }) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END001",
                    "Client URI conflicts with an existing endpoint",
                    request_id,
                );
            }
        }
        payload["api_id"] = api.get("api_id").cloned().unwrap_or(Value::Null);
        payload["endpoint_id"] = json!(Uuid::new_v4().to_string());
        let target = format!(
            "{}/{}/{}{}",
            payload["api_name"].as_str().unwrap_or_default(),
            payload["api_version"].as_str().unwrap_or_default(),
            payload["endpoint_method"].as_str().unwrap_or_default(),
            payload["endpoint_uri"].as_str().unwrap_or_default(),
        );
        return match storage.insert_one("endpoints", payload).await {
            Ok(_) => {
                audit::management_mutation(username, "endpoint.create", &target, "success");
                message(
                    StatusCode::CREATED,
                    "Endpoint created successfully",
                    request_id,
                )
            }
            Err(_) => error(
                StatusCode::BAD_REQUEST,
                "END003",
                "Unable to insert endpoint",
                request_id,
            ),
        };
    }
    let parts = suffix.split('/').collect::<Vec<_>>();
    // The pinned listing takes no pagination parameters.
    if method == Method::GET && parts.len() == 2 {
        return match storage
            .find_many(
                "endpoints",
                &json!({"api_name": parts[0], "api_version": parts[1]}),
            )
            .await
        {
            Ok(items) if items.is_empty() => error(
                StatusCode::BAD_REQUEST,
                "END005",
                "No endpoints found for the requested API name and version",
                request_id,
            ),
            Ok(items) => success(
                StatusCode::OK,
                json!({"endpoints": items.into_iter().map(strip_internal).collect::<Vec<_>>()}),
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if parts.len() >= 4 {
        if method == Method::PUT && normalize_endpoint_model(&mut payload, false).is_err() {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
        let _tls_guard = if method == Method::PUT {
            match lock_tls_binding_mutation(state, &payload, "endpoint").await {
                Ok(guard) => guard,
                Err(()) => {
                    return error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "TLS004",
                        "TLS profiles are unavailable",
                        request_id,
                    );
                }
            }
        } else {
            None
        };
        if method == Method::PUT {
            if let Some(policy) = payload
                .get("endpoint_client_tls_policy")
                .filter(|value| !value.is_null())
            {
                if crate::tls::policy::ClientTlsPolicy::validate_value(
                    policy,
                    &state.tls_snapshot().profiles,
                    state.config.downstream_tls_mode == crate::config::DownstreamTlsMode::Native,
                )
                .is_err()
                {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "TLS003",
                        "Invalid client TLS policy",
                        request_id,
                    );
                }
            }
            if crate::tls::profiles::validate_upstream_bindings(
                &payload,
                "endpoint",
                &state.tls_snapshot().profiles,
            )
            .is_err()
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "TLS004",
                    "Invalid upstream TLS binding",
                    request_id,
                );
            }
        }
        let uri = format!("/{}", parts[3..].join("/"));
        let filter = json!({"endpoint_method": parts[0], "api_name": parts[1], "api_version": parts[2], "endpoint_uri": uri});
        if method == Method::PUT {
            if !has_permission(state, username, "manage_endpoints").await {
                return error(
                    StatusCode::FORBIDDEN,
                    "END011",
                    "You do not have permission to update endpoints",
                    request_id,
                );
            }
            let existing = match storage.find_one("endpoints", &filter).await {
                Ok(Some(endpoint)) => endpoint,
                Ok(None) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "END008",
                        "Endpoint does not exist for the requested API name, version and URI",
                        request_id,
                    );
                }
                Err(_) => return unexpected(request_id),
            };
            if ["endpoint_method", "api_name", "api_version", "endpoint_uri"]
                .iter()
                .any(|field| {
                    payload
                        .get(*field)
                        .is_some_and(|value| existing.get(*field) != Some(value))
                })
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END006",
                    "API method, name, version and URI cannot be updated",
                    request_id,
                );
            }
            if payload.as_object().is_some_and(|object| object.is_empty()) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END007",
                    "No data to update",
                    request_id,
                );
            }
            if payload.as_object().is_some_and(|updates| {
                updates
                    .iter()
                    .all(|(field, value)| existing.get(field) == Some(value))
            }) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "END003",
                    "Unable to update endpoint",
                    request_id,
                );
            }
            if let Some(client_uri) = payload.get("client_uri").and_then(Value::as_str) {
                if existing.get("client_uri").and_then(Value::as_str) != Some(client_uri) {
                    let conflicts = match storage
                        .find_many(
                            "endpoints",
                            &json!({"endpoint_method": parts[0], "api_name": parts[1], "api_version": parts[2]}),
                        )
                        .await
                    {
                        Ok(endpoints) => endpoints,
                        Err(_) => return unexpected(request_id),
                    };
                    if conflicts.iter().any(|endpoint| {
                        endpoint.get("endpoint_uri") != Some(&filter["endpoint_uri"])
                            && (endpoint.get("client_uri").and_then(Value::as_str)
                                == Some(client_uri)
                                || (endpoint.get("client_uri").is_none_or(Value::is_null)
                                    && endpoint.get("endpoint_uri").and_then(Value::as_str)
                                        == Some(client_uri)))
                    }) {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "END006",
                            "Client URI conflicts with an existing endpoint",
                            request_id,
                        );
                    }
                }
            }
        }
        if method == Method::DELETE {
            if !has_permission(state, username, "manage_endpoints").await {
                return error(
                    StatusCode::FORBIDDEN,
                    "END012",
                    "You do not have permission to delete endpoints",
                    request_id,
                );
            }
            return match storage.delete_one("endpoints", &filter).await {
                Ok(true) => {
                    audit::management_mutation(
                        username,
                        "endpoint.delete",
                        &filter.to_string(),
                        "success",
                    );
                    message(StatusCode::OK, "Endpoint deleted successfully", request_id)
                }
                Ok(false) => error(
                    StatusCode::BAD_REQUEST,
                    "END004",
                    "Endpoint does not exist for the requested API name, version and URI",
                    request_id,
                ),
                Err(_) => error(
                    StatusCode::BAD_REQUEST,
                    "END009",
                    "Unable to delete endpoint",
                    request_id,
                ),
            };
        }
        if method == Method::GET {
            return match storage.find_one("endpoints", &filter).await {
                Ok(Some(endpoint)) => success(StatusCode::OK, strip_internal(endpoint), request_id),
                Ok(None) => error(
                    StatusCode::BAD_REQUEST,
                    "END004",
                    "Endpoint does not exist for the requested API name, version and URI",
                    request_id,
                ),
                Err(_) => unexpected(request_id),
            };
        }
        if method == Method::PUT {
            return match storage.update_one("endpoints", &filter, &payload).await {
                Ok(Some(_)) => message(StatusCode::OK, "Endpoint updated successfully", request_id),
                Ok(None) | Err(_) => error(
                    StatusCode::BAD_REQUEST,
                    "END003",
                    "Unable to update endpoint",
                    request_id,
                ),
            };
        }
    }
    error(
        StatusCode::NOT_FOUND,
        "EPT002",
        "Endpoint not found",
        request_id,
    )
}

async fn login(
    state: &AppState,
    headers: &HeaderMap,
    payload: Value,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let Some(email) = payload.get("email").and_then(Value::as_str) else {
        audit::management_mutation("anonymous", "user.login", "unknown", "failed");
        return error(
            StatusCode::BAD_REQUEST,
            "AUTH001",
            "Missing email or password",
            request_id,
        );
    };
    let Some(password) = payload.get("password").and_then(Value::as_str) else {
        audit::management_mutation("anonymous", "user.login", email, "failed");
        return error(
            StatusCode::BAD_REQUEST,
            "AUTH001",
            "Missing email or password",
            request_id,
        );
    };
    let user = match storage.find_one("users", &json!({"email": email})).await {
        Ok(Some(user)) => user,
        _ => match storage.find_one("users", &json!({"username": email})).await {
            Ok(Some(user)) => user,
            _ => {
                audit::management_mutation("anonymous", "user.login", email, "failed");
                return error(
                    StatusCode::BAD_REQUEST,
                    "AUTH002",
                    "Invalid email or password",
                    request_id,
                );
            }
        },
    };
    let hash = password_hash(&user);
    if hash
        .as_deref()
        .is_none_or(|hash| !bcrypt::verify(password, hash).unwrap_or(false))
    {
        audit::management_mutation("anonymous", "user.login", email, "failed");
        return error(
            StatusCode::BAD_REQUEST,
            "AUTH002",
            "Invalid email or password",
            request_id,
        );
    }
    if user.get("active").and_then(Value::as_bool) == Some(false) {
        audit::management_mutation("anonymous", "user.login", email, "failed");
        return error(
            StatusCode::BAD_REQUEST,
            "AUTH007",
            "User is not active",
            request_id,
        );
    }
    let username = user
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or(email)
        .to_owned();
    audit::management_mutation(&username, "user.login", &username, "success");
    let role = user
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user")
        .to_owned();
    let now = unix_seconds() as usize;
    let expiry_seconds = auth_expiry_seconds();
    let claims = AccessClaims {
        sub: username.clone(),
        role,
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: now + expiry_seconds,
        iss: state.config.shared_storage.jwt_issuer.clone(),
        aud: state.config.shared_storage.jwt_audience.clone(),
    };
    let token = match sign_token(state, &claims) {
        Ok(token) => token,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "GTW999",
                "An unexpected error occurred",
                request_id,
            );
        }
    };
    let csrf = Uuid::new_v4().to_string();
    let _ = storage
        .set_ephemeral(
            &format!("csrf_token_map:{username}"),
            Value::String(csrf.clone()),
            expiry_seconds as u64,
        )
        .await;
    let secure = cookie_secure(headers);
    let same_site = cookie_same_site(secure);
    let domain_attribute = cookie_domain(headers)
        .map(|domain| format!("; Domain={domain}"))
        .unwrap_or_default();
    let mut response = success(StatusCode::OK, json!({"access_token": token}), request_id);
    let cookie_headers = response.headers_mut();
    cookie_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "csrf_token={csrf}; Path=/; Max-Age={expiry_seconds}; SameSite={same_site}{}{}",
            if secure { "; Secure" } else { "" },
            domain_attribute
        ))
        .unwrap(),
    );
    cookie_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "access_token_cookie={token}; Path=/; Max-Age={expiry_seconds}; HttpOnly; SameSite={same_site}{}{}",
            if secure { "; Secure" } else { "" },
            domain_attribute
        ))
        .unwrap(),
    );
    response
}

async fn register(state: &AppState, mut payload: Value, request_id: &str) -> Response {
    let email = payload
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let password = payload
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if email.is_empty() || password.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "AUTH001",
            "Missing email or password",
            request_id,
        );
    }
    payload["username"] = json!(email.split('@').next().unwrap_or(""));
    payload["role"] = json!("user");
    payload["active"] = json!(true);
    create_user(state, &mut payload, None, request_id).await
}

async fn create_user(
    state: &AppState,
    payload: &mut Value,
    actor: Option<&str>,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if normalize_create_user_model(payload).is_err() {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            request_id,
        );
    }
    if let (Some(actor), Some(role_name)) = (actor, payload.get("role").and_then(Value::as_str)) {
        if role_name == "admin" && !is_admin_user(state, actor).await {
            return error(
                StatusCode::FORBIDDEN,
                "USR015",
                "Only an administrator can create users with the administrator role",
                request_id,
            );
        }
    }
    let username = payload
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let email = payload
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let Some(password) = payload
        .get("password")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "USR005",
            password_policy(),
            request_id,
        );
    };
    if username.len() < 3 || email.len() < 3 || !secure_password(&password) {
        return error(
            StatusCode::BAD_REQUEST,
            "USR005",
            password_policy(),
            request_id,
        );
    }
    if matches!(
        storage
            .find_one("users", &json!({"username": username}))
            .await,
        Ok(Some(_))
    ) || matches!(
        storage.find_one("users", &json!({"email": email})).await,
        Ok(Some(_))
    ) {
        return error(
            StatusCode::BAD_REQUEST,
            "USR001",
            "Username or email already exists",
            request_id,
        );
    }
    if payload
        .get("custom_attributes")
        .and_then(Value::as_object)
        .is_some_and(|attrs| attrs.len() > 10)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "USR016",
            "Maximum 10 custom attributes allowed. Please replace an existing one.",
            request_id,
        );
    }
    let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(password_hash) => password_hash,
        Err(_) => return unexpected(request_id),
    };
    payload["password"] = json!(password_hash);
    set_default(payload, "groups", json!([]));
    set_default(payload, "active", json!(true));
    set_default(payload, "ui_access", json!(false));
    match storage.insert_one("users", payload.clone()).await {
        Ok(_) => {
            if let Some(actor) = actor {
                audit::management_mutation(actor, "user.create", &username, "success");
            } else {
                audit::management_mutation("anonymous", "user.register", &username, "success");
            }
            message(StatusCode::CREATED, "User created successfully", request_id)
        }
        Err(_) => unexpected(request_id),
    }
}

const ROLE_BOOLEAN_FIELDS: [&str; 15] = [
    "manage_users",
    "manage_apis",
    "manage_endpoints",
    "manage_groups",
    "manage_roles",
    "manage_routings",
    "manage_gateway",
    "manage_subscriptions",
    "manage_security",
    "manage_tiers",
    "manage_rate_limits",
    "manage_credits",
    "manage_auth",
    "view_analytics",
    "view_logs",
];

fn normalize_role_model(payload: &mut Value, create: bool) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, value| {
        (matches!(
            field.as_str(),
            "role_name" | "role_description" | "export_logs"
        ) || ROLE_BOOLEAN_FIELDS.contains(&field.as_str()))
            && (create || !value.is_null())
    });
    // The create model materializes each permission field, including
    // `export_logs`, while the update model drops null values before `$set`.
    for field in ROLE_BOOLEAN_FIELDS.into_iter().chain(["export_logs"]) {
        match object.get(field) {
            Some(value) if !value.is_null() => {
                object.insert(
                    field.to_owned(),
                    json!(security_setting_bool(value).ok_or(())?),
                );
            }
            Some(_) if create => return Err(()),
            Some(_) => {}
            None if create => {
                object.insert(field.to_owned(), json!(false));
            }
            None => {}
        }
    }
    if create || object.contains_key("role_name") {
        let value = object
            .get("role_name")
            .and_then(security_setting_string)
            .ok_or(())?;
        if value.is_empty() || value.chars().count() > 50 {
            return Err(());
        }
        object.insert("role_name".to_owned(), json!(value));
    }
    match object.get("role_description") {
        Some(value) if !value.is_null() => {
            let value = security_setting_string(value).ok_or(())?;
            if value.chars().count() > 255 || (!create && value.is_empty()) {
                return Err(());
            }
            object.insert("role_description".to_owned(), json!(value));
        }
        Some(_) if create => {}
        Some(_) => {
            object.remove("role_description");
        }
        None if create => {
            object.insert("role_description".to_owned(), Value::Null);
        }
        None => {}
    }
    Ok(())
}

fn normalize_group_model(payload: &mut Value, create: bool) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, value| {
        matches!(
            field.as_str(),
            "group_name" | "group_description" | "api_access"
        ) && (create || !value.is_null())
    });
    if create || object.contains_key("group_name") {
        let value = object
            .get("group_name")
            .and_then(security_setting_string)
            .ok_or(())?;
        if value.is_empty() || value.chars().count() > 50 {
            return Err(());
        }
        object.insert("group_name".to_owned(), json!(value));
    }
    match object.get("group_description") {
        Some(value) if !value.is_null() => {
            let value = security_setting_string(value).ok_or(())?;
            if value.chars().count() > 255 || (!create && value.is_empty()) {
                return Err(());
            }
            object.insert("group_description".to_owned(), json!(value));
        }
        Some(_) if create => {}
        Some(_) => {
            object.remove("group_description");
        }
        None if create => {
            object.insert("group_description".to_owned(), Value::Null);
        }
        None => {}
    }
    match object.get("api_access") {
        Some(Value::Array(items)) => {
            let items = items
                .iter()
                .map(security_setting_string)
                .collect::<Option<Vec<_>>>()
                .ok_or(())?
                .into_iter()
                .map(Value::String)
                .collect();
            object.insert("api_access".to_owned(), Value::Array(items));
        }
        Some(Value::Null) if create => {}
        Some(_) => return Err(()),
        None if create => {
            object.insert("api_access".to_owned(), json!([]));
        }
        None => {}
    }
    Ok(())
}

fn normalize_routing_model(payload: &mut Value, create: bool) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, value| {
        matches!(
            field.as_str(),
            "routing_name"
                | "routing_servers"
                | "routing_description"
                | "client_key"
                | "server_index"
        ) && (create || (!value.is_null() && field != "server_index"))
    });
    for field in ["routing_name", "client_key"] {
        if create && field == "client_key" && !object.contains_key(field) {
            continue;
        }
        if let Some(value) = object.get(field) {
            if value.is_null() {
                if create && field == "client_key" {
                    continue;
                }
                return Err(());
            }
            let value = security_setting_string(value).ok_or(())?;
            if value.is_empty() || value.chars().count() > 50 {
                return Err(());
            }
            object.insert(field.to_owned(), json!(value));
        } else if create && field == "routing_name" {
            return Err(());
        }
    }
    match object.get("routing_servers") {
        Some(Value::Array(servers)) if !servers.is_empty() => {
            let servers = servers
                .iter()
                .map(security_setting_string)
                .collect::<Option<Vec<_>>>()
                .ok_or(())?
                .into_iter()
                .map(Value::String)
                .collect();
            object.insert("routing_servers".to_owned(), Value::Array(servers));
        }
        Some(_) => return Err(()),
        None if create => return Err(()),
        None => {}
    }
    match object.get("routing_description") {
        Some(value) if !value.is_null() => {
            let value = security_setting_string(value).ok_or(())?;
            if value.chars().count() > 255 {
                return Err(());
            }
            object.insert("routing_description".to_owned(), json!(value));
        }
        Some(_) if create => {}
        Some(_) => {
            object.remove("routing_description");
        }
        None if create => {
            object.insert("routing_description".to_owned(), Value::Null);
        }
        None => {}
    }
    if create {
        match object.get("server_index") {
            Some(Value::Null) => {}
            Some(value) => {
                let value = rate_rule_integer(value)
                    .filter(|value| *value >= 0)
                    .ok_or(())?;
                object.insert("server_index".to_owned(), json!(value));
            }
            None => {
                object.insert("server_index".to_owned(), json!(0));
            }
        }
    }
    Ok(())
}

fn normalize_endpoint_model(payload: &mut Value, create: bool) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, value| {
        matches!(
            field.as_str(),
            "api_name"
                | "api_version"
                | "endpoint_method"
                | "endpoint_uri"
                | "endpoint_description"
                | "endpoint_servers"
                | "client_uri"
                | "api_id"
                | "endpoint_id"
                | "endpoint_client_tls_policy"
                | "endpoint_upstream_tls_profile"
                | "endpoint_upstream_tls_profiles"
        ) && (create
            || !value.is_null()
            || matches!(
                field.as_str(),
                "endpoint_client_tls_policy"
                    | "endpoint_upstream_tls_profile"
                    | "endpoint_upstream_tls_profiles"
            ))
    });
    for (field, configured_minimum, configured_maximum) in [
        ("api_name", 1, 50),
        ("api_version", 1, 10),
        ("endpoint_method", 1, 10),
        ("endpoint_uri", 1, 255),
        ("endpoint_description", 1, 255),
        ("client_uri", 1, 255),
        ("api_id", 1, 255),
        ("endpoint_id", 1, 255),
    ] {
        let (minimum, maximum) = if create && matches!(field, "api_id" | "endpoint_id") {
            (0, usize::MAX)
        } else {
            (configured_minimum, configured_maximum)
        };
        if let Some(value) = object.get(field) {
            if value.is_null() {
                if create && matches!(field, "client_uri" | "api_id" | "endpoint_id") {
                    continue;
                }
                return Err(());
            }
            let value = security_setting_string(value).ok_or(())?;
            let length = value.chars().count();
            if length < minimum || length > maximum {
                return Err(());
            }
            object.insert(field.to_owned(), json!(value));
        } else if create && !matches!(field, "client_uri" | "api_id" | "endpoint_id") {
            return Err(());
        }
    }
    match object.get("endpoint_servers") {
        Some(Value::Array(servers)) => {
            let servers = servers
                .iter()
                .map(security_setting_string)
                .collect::<Option<Vec<_>>>()
                .ok_or(())?
                .into_iter()
                .map(Value::String)
                .collect();
            object.insert("endpoint_servers".to_owned(), Value::Array(servers));
        }
        Some(Value::Null) if create => {}
        Some(_) => return Err(()),
        None => {}
    }
    if create {
        // Pydantic's `.dict()` persists unset optional fields as null.
        for field in ["endpoint_servers", "client_uri"] {
            object.entry(field).or_insert(Value::Null);
        }
    }
    Ok(())
}

fn normalize_endpoint_validation_model(payload: &mut Value, create: bool) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, _| {
        matches!(
            field.as_str(),
            "endpoint_id" | "validation_enabled" | "validation_schema"
        ) && (create || field != "endpoint_id")
    });
    if create {
        let endpoint_id = object
            .get("endpoint_id")
            .and_then(security_setting_string)
            .ok_or(())?;
        object.insert("endpoint_id".to_owned(), json!(endpoint_id));
    }
    let enabled = object
        .get("validation_enabled")
        .and_then(security_setting_bool)
        .ok_or(())?;
    object.insert("validation_enabled".to_owned(), json!(enabled));
    let schema = object
        .get("validation_schema")
        .and_then(normalize_validation_schema_model)
        .ok_or(())?;
    object.insert("validation_schema".to_owned(), schema);
    Ok(())
}

fn normalize_validation_schema_model(value: &Value) -> Option<Value> {
    let rules = value.as_object()?.get("validation_schema")?.as_object()?;
    let mut normalized = Map::new();
    for (path, rule) in rules {
        normalized.insert(path.clone(), normalize_field_validation_model(rule)?);
    }
    Some(json!({"validation_schema": normalized}))
}

fn normalize_field_validation_model(value: &Value) -> Option<Value> {
    let input = value.as_object()?;
    let mut output = Map::new();
    output.insert(
        "required".to_owned(),
        json!(security_setting_bool(input.get("required")?)?),
    );
    output.insert(
        "type".to_owned(),
        json!(security_setting_string(input.get("type")?)?),
    );
    for field in ["min", "max"] {
        let value = match input.get(field) {
            Some(Value::Null) | None => Value::Null,
            Some(value) => validation_model_number(value)?,
        };
        output.insert(field.to_owned(), value);
    }
    for field in ["pattern", "format", "custom_validator"] {
        let value = match input.get(field) {
            Some(Value::Null) | None => Value::Null,
            Some(value) => Value::String(security_setting_string(value)?),
        };
        output.insert(field.to_owned(), value);
    }
    let enum_values = match input.get("enum") {
        Some(Value::Null) | None => Value::Null,
        Some(Value::Array(values)) => Value::Array(values.clone()),
        Some(_) => return None,
    };
    output.insert("enum".to_owned(), enum_values);
    let nested = match input.get("nested_schema") {
        Some(Value::Null) | None => Value::Null,
        Some(Value::Object(fields)) => {
            let mut normalized = Map::new();
            for (name, rules) in fields {
                normalized.insert(name.clone(), normalize_field_validation_model(rules)?);
            }
            Value::Object(normalized)
        }
        Some(_) => return None,
    };
    output.insert("nested_schema".to_owned(), nested);
    let array_items = match input.get("array_items") {
        Some(Value::Null) | None => Value::Null,
        Some(value) => normalize_field_validation_model(value)?,
    };
    output.insert("array_items".to_owned(), array_items);
    Some(Value::Object(output))
}

fn validation_model_number(value: &Value) -> Option<Value> {
    match value {
        Value::Bool(value) => Some(json!(i64::from(*value))),
        Value::Number(value) if value.is_i64() || value.is_u64() => {
            Some(Value::Number(value.clone()))
        }
        Value::Number(value) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(|value| json!(value as i64)),
        Value::String(value) => crate::python_scalar::parse_model_integer(value)
            .and_then(|value| i64::try_from(value).ok())
            .map(|value| json!(value))
            .or_else(|| {
                value
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite())
                    .map(|value| json!(value))
            }),
        _ => None,
    }
}

fn normalize_subscription_model(payload: &mut Value) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, _| matches!(field.as_str(), "username" | "api_name" | "api_version"));
    for (field, minimum, maximum) in [
        ("username", 3, 50),
        ("api_name", 3, 50),
        ("api_version", 1, 5),
    ] {
        let value = object
            .get(field)
            .and_then(security_setting_string)
            .ok_or(())?;
        let length = value.chars().count();
        if length < minimum || length > maximum {
            return Err(());
        }
        object.insert(field.to_owned(), json!(value));
    }
    Ok(())
}

fn normalize_credit_model(payload: &mut Value, create: bool) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, _| {
        matches!(
            field.as_str(),
            "api_credit_group"
                | "api_key"
                | "api_key_header"
                | "credit_tiers"
                | "api_key_new"
                | "api_key_rotation_expires"
        )
    });
    for field in ["api_credit_group", "api_key", "api_key_header"] {
        let value = object
            .get(field)
            .and_then(security_setting_string)
            .ok_or(())?;
        if field == "api_credit_group" && (value.is_empty() || value.chars().count() > 50) {
            return Err(());
        }
        object.insert(field.to_owned(), json!(value));
    }
    for field in ["api_key_new", "api_key_rotation_expires"] {
        if let Some(value) = object.get(field) {
            if value.is_null() {
                if !create {
                    object.remove(field);
                }
                continue;
            }
            let value = if field == "api_key_rotation_expires" {
                tier_model_datetime(value).ok_or(())?
            } else {
                json!(security_setting_string(value).ok_or(())?)
            };
            object.insert(field.to_owned(), value);
        } else if create {
            object.insert(field.to_owned(), Value::Null);
        }
    }
    let tiers = object
        .get_mut("credit_tiers")
        .and_then(Value::as_array_mut)
        .filter(|tiers| !tiers.is_empty())
        .ok_or(())?;
    for tier in tiers {
        let tier = tier.as_object_mut().ok_or(())?;
        tier.retain(|field, _| {
            matches!(
                field.as_str(),
                "tier_name" | "credits" | "input_limit" | "output_limit" | "reset_frequency"
            )
        });
        for field in ["tier_name", "reset_frequency"] {
            let value = tier
                .get(field)
                .and_then(security_setting_string)
                .ok_or(())?;
            if field == "tier_name" && (value.is_empty() || value.chars().count() > 50) {
                return Err(());
            }
            tier.insert(field.to_owned(), json!(value));
        }
        for field in ["credits", "input_limit", "output_limit"] {
            let value = tier.get(field).and_then(rate_rule_integer).ok_or(())?;
            tier.insert(field.to_owned(), json!(value));
        }
    }
    Ok(())
}

/// Preserve the service-level validation that runs after FastAPI has parsed a
/// valid `CreditModel` and authenticated the caller.  These fields have no
/// Pydantic length constraint, so an empty string is model-valid but rejected
/// by `CreditService` with its domain-specific error.
fn validate_credit_definition_fields(payload: &Value) -> Result<(), (&'static str, &'static str)> {
    if payload
        .get("api_credit_group")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(("CRD009", "Credit group name is required"));
    }
    if ["api_key", "api_key_header"].iter().any(|field| {
        payload
            .get(*field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    }) {
        return Err(("CRD010", "API key and header are required"));
    }
    Ok(())
}

fn normalize_user_credit_model(payload: &mut Value) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, _| matches!(field.as_str(), "username" | "users_credits"));
    let username = object
        .get("username")
        .and_then(security_setting_string)
        .ok_or(())?;
    let username_length = username.chars().count();
    if !(3..=50).contains(&username_length) {
        return Err(());
    }
    object.insert("username".to_owned(), json!(username));
    let credits = object
        .get_mut("users_credits")
        .and_then(Value::as_object_mut)
        .ok_or(())?;
    for credit in credits.values_mut() {
        let credit = credit.as_object_mut().ok_or(())?;
        credit.retain(|field, _| {
            matches!(
                field.as_str(),
                "tier_name" | "available_credits" | "reset_date" | "user_api_key"
            )
        });
        let tier_name = credit
            .get("tier_name")
            .and_then(security_setting_string)
            .ok_or(())?;
        if tier_name.is_empty() || tier_name.chars().count() > 50 {
            return Err(());
        }
        credit.insert("tier_name".to_owned(), json!(tier_name));
        let available = credit
            .get("available_credits")
            .and_then(rate_rule_integer)
            .ok_or(())?;
        credit.insert("available_credits".to_owned(), json!(available));
        for field in ["reset_date", "user_api_key"] {
            if let Some(value) = credit.get(field) {
                if value.is_null() {
                    continue;
                }
                let value = security_setting_string(value).ok_or(())?;
                credit.insert(field.to_owned(), json!(value));
            }
            if !credit.contains_key(field) {
                credit.insert(field.to_owned(), Value::Null);
            }
        }
    }
    Ok(())
}

/// Mirror the observable Pydantic v1 CreateUserModel boundary before the
/// service hashes a password or persists a document.  The application-wide
/// exception handler intentionally collapses field detail to VAL001.
fn normalize_create_user_model(payload: &mut Value) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    // BaseModel's default Config ignores unrecognized request fields.
    object.retain(|field, _| {
        matches!(
            field.as_str(),
            "username"
                | "email"
                | "password"
                | "role"
                | "groups"
                | "rate_limit_duration"
                | "rate_limit_duration_type"
                | "rate_limit_enabled"
                | "throttle_duration"
                | "throttle_duration_type"
                | "throttle_wait_duration"
                | "throttle_wait_duration_type"
                | "throttle_queue_limit"
                | "throttle_enabled"
                | "custom_attributes"
                | "bandwidth_limit_bytes"
                | "bandwidth_limit_window"
                | "bandwidth_limit_enabled"
                | "active"
                | "ui_access"
        )
    });
    for (field, minimum, maximum) in [
        ("username", 3, 50),
        ("email", 3, 127),
        ("password", 16, 50),
        ("role", 2, 50),
    ] {
        let value = object
            .get(field)
            .and_then(security_setting_string)
            .ok_or(())?;
        let length = value.chars().count();
        if length < minimum || length > maximum {
            return Err(());
        }
        object.insert(field.to_owned(), json!(value));
    }

    let groups = match object.get("groups") {
        None => json!([]),
        Some(Value::Array(groups)) => Value::Array(
            groups
                .iter()
                .map(security_setting_string)
                .collect::<Option<Vec<_>>>()
                .ok_or(())?
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
        _ => return Err(()),
    };
    object.insert("groups".to_owned(), groups);

    for field in [
        "rate_limit_duration",
        "throttle_duration",
        "throttle_wait_duration",
        "throttle_queue_limit",
        "bandwidth_limit_bytes",
    ] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            let value = rate_rule_integer(value)
                .filter(|value| *value >= 0)
                .ok_or(())?;
            object.insert(field.to_owned(), json!(value));
        }
    }
    for (field, maximum) in [
        ("rate_limit_duration_type", 7),
        ("throttle_duration_type", 7),
        ("throttle_wait_duration_type", 7),
        ("bandwidth_limit_window", 10),
    ] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            let value = security_setting_string(value).ok_or(())?;
            if value.is_empty() || value.chars().count() > maximum {
                return Err(());
            }
            object.insert(field.to_owned(), json!(value));
        }
    }
    if !object.contains_key("bandwidth_limit_window") {
        object.insert("bandwidth_limit_window".to_owned(), json!("day"));
    }
    for field in [
        "rate_limit_duration",
        "rate_limit_duration_type",
        "rate_limit_enabled",
        "throttle_duration",
        "throttle_duration_type",
        "throttle_wait_duration",
        "throttle_wait_duration_type",
        "throttle_queue_limit",
        "throttle_enabled",
        "custom_attributes",
        "bandwidth_limit_bytes",
        "bandwidth_limit_enabled",
    ] {
        if !object.contains_key(field) {
            object.insert(field.to_owned(), Value::Null);
        }
    }
    if !object.contains_key("active") {
        object.insert("active".to_owned(), json!(true));
    }
    if !object.contains_key("ui_access") {
        object.insert("ui_access".to_owned(), json!(false));
    }
    for field in [
        "rate_limit_enabled",
        "throttle_enabled",
        "bandwidth_limit_enabled",
        "active",
        "ui_access",
    ] {
        if let Some(value) = object.get(field).filter(|value| !value.is_null()) {
            object.insert(
                field.to_owned(),
                json!(security_setting_bool(value).ok_or(())?),
            );
        }
    }
    if let Some(value) = object
        .get("custom_attributes")
        .filter(|value| !value.is_null())
    {
        if value.as_object().is_none() {
            if value.as_array().is_some_and(Vec::is_empty) {
                object.insert("custom_attributes".to_owned(), json!({}));
            } else {
                return Err(());
            }
        }
    }
    Ok(())
}

/// UpdateUserModel has the same field types as CreateUserModel but every
/// field is optional; its service discards explicit nulls before `$set`.
fn normalize_update_user_model(payload: &mut Value) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    object.retain(|field, value| {
        !value.is_null()
            && matches!(
                field.as_str(),
                "username"
                    | "email"
                    | "password"
                    | "role"
                    | "groups"
                    | "rate_limit_duration"
                    | "rate_limit_duration_type"
                    | "rate_limit_enabled"
                    | "throttle_duration"
                    | "throttle_duration_type"
                    | "throttle_wait_duration"
                    | "throttle_wait_duration_type"
                    | "throttle_queue_limit"
                    | "throttle_enabled"
                    | "custom_attributes"
                    | "bandwidth_limit_bytes"
                    | "bandwidth_limit_window"
                    | "bandwidth_limit_enabled"
                    | "active"
                    | "ui_access"
            )
    });
    for (field, minimum, maximum) in [
        ("username", 3, 50),
        ("email", 3, 127),
        ("password", 6, 50),
        ("role", 2, 50),
    ] {
        if let Some(value) = object.get(field) {
            let value = security_setting_string(value).ok_or(())?;
            let length = value.chars().count();
            if length < minimum || length > maximum {
                return Err(());
            }
            object.insert(field.to_owned(), json!(value));
        }
    }
    if let Some(value) = object.get("groups") {
        let Value::Array(groups) = value else {
            return Err(());
        };
        object.insert(
            "groups".to_owned(),
            Value::Array(
                groups
                    .iter()
                    .map(security_setting_string)
                    .collect::<Option<Vec<_>>>()
                    .ok_or(())?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    for field in [
        "rate_limit_duration",
        "throttle_duration",
        "throttle_wait_duration",
        "throttle_queue_limit",
        "bandwidth_limit_bytes",
    ] {
        if let Some(value) = object.get(field) {
            object.insert(
                field.to_owned(),
                json!(
                    rate_rule_integer(value)
                        .filter(|value| *value >= 0)
                        .ok_or(())?
                ),
            );
        }
    }
    for (field, maximum) in [
        ("rate_limit_duration_type", 7),
        ("throttle_duration_type", 7),
        ("throttle_wait_duration_type", 7),
        ("bandwidth_limit_window", 10),
    ] {
        if let Some(value) = object.get(field) {
            let value = security_setting_string(value).ok_or(())?;
            if value.is_empty() || value.chars().count() > maximum {
                return Err(());
            }
            object.insert(field.to_owned(), json!(value));
        }
    }
    for field in [
        "rate_limit_enabled",
        "throttle_enabled",
        "bandwidth_limit_enabled",
        "active",
        "ui_access",
    ] {
        if let Some(value) = object.get(field) {
            object.insert(
                field.to_owned(),
                json!(security_setting_bool(value).ok_or(())?),
            );
        }
    }
    if let Some(value) = object.get("custom_attributes")
        && value.as_object().is_none()
    {
        if value.as_array().is_some_and(Vec::is_empty) {
            object.insert("custom_attributes".to_owned(), json!({}));
        } else {
            return Err(());
        }
    }
    Ok(())
}

/// FastAPI validates UpdatePasswordModel before authentication and route
/// permissions. Pydantic v1 coerces JSON scalars to strings, ignores unknown
/// fields, and measures string bounds in Unicode characters.
fn normalize_update_password_model(payload: &mut Value) -> Result<(), ()> {
    let object = payload.as_object_mut().ok_or(())?;
    let password = object
        .get("new_password")
        .and_then(security_setting_string)
        .ok_or(())?;
    if !(6..=36).contains(&password.chars().count()) {
        return Err(());
    }
    object.clear();
    object.insert("new_password".to_owned(), json!(password));
    Ok(())
}

async fn user_by(
    state: &AppState,
    field: &str,
    value: &str,
    active_user: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let user = match storage.find_one("users", &json!({field: value})).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "USR002",
                "User not found",
                request_id,
            );
        }
        Err(_) => return unexpected(request_id),
    };
    if user.get("role").and_then(Value::as_str) == Some("admin")
        && !is_admin_user(state, active_user).await
    {
        return error(
            StatusCode::NOT_FOUND,
            "USR002",
            "User not found",
            request_id,
        );
    }
    if user.get("username").and_then(Value::as_str) != Some(active_user)
        && !has_permission(state, active_user, "manage_users").await
    {
        return error(
            StatusCode::FORBIDDEN,
            "USR008",
            "Unable to retrieve information for user",
            request_id,
        );
    }
    let bandwidth_username = user
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or(value)
        .to_owned();
    let mut user = public_user(user);
    let bandwidth_enabled =
        user.get("bandwidth_limit_enabled").and_then(Value::as_bool) != Some(false);
    let bandwidth_limit = user
        .get("bandwidth_limit_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if bandwidth_enabled && bandwidth_limit > 0 {
        let window_name = user
            .get("bandwidth_limit_window")
            .and_then(Value::as_str)
            .unwrap_or("day");
        let window = duration_to_seconds(window_name).max(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bucket = (now / window) * window;
        let usage = storage
            .current_counter(&bandwidth_key(&bandwidth_username, window, bucket))
            .await
            .unwrap_or(0);
        if let Some(object) = user.as_object_mut() {
            object.insert("bandwidth_usage_bytes".to_owned(), json!(usage));
            object.insert("bandwidth_resets_at".to_owned(), json!(bucket + window));
        }
    }
    success(StatusCode::OK, user, request_id)
}

async fn authorization_routes(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    method: Method,
    _payload: Value,
    claims: &AuthClaims,
    request_id: &str,
) -> Response {
    let username = claims.sub.as_deref().unwrap_or("");
    if path == "/authorization/refresh" && method == Method::POST {
        let now = unix_seconds() as usize;
        let Some(storage) = &state.storage else {
            return unexpected(request_id);
        };
        let user = match storage
            .find_one("users", &json!({"username": username}))
            .await
        {
            Ok(Some(user)) => user,
            _ => return unexpected(request_id),
        };
        let current_role = user
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user")
            .to_owned();
        let expiry_seconds = refresh_expiry_seconds();
        let token_claims = AccessClaims {
            sub: username.to_owned(),
            role: current_role,
            jti: Uuid::new_v4().to_string(),
            iat: now,
            exp: now + expiry_seconds,
            iss: state.config.shared_storage.jwt_issuer.clone(),
            aud: state.config.shared_storage.jwt_audience.clone(),
        };
        let token = match sign_token(state, &token_claims) {
            Ok(token) => token,
            Err(_) => return unexpected(request_id),
        };
        let csrf = Uuid::new_v4().to_string();
        if let Some(storage) = &state.storage {
            let _ = storage
                .set_ephemeral(
                    &format!("csrf_token_map:{username}"),
                    Value::String(csrf.clone()),
                    expiry_seconds as u64,
                )
                .await;
        }
        let secure = cookie_secure(headers);
        let same_site = cookie_same_site(secure);
        let domain_attribute = cookie_domain(headers)
            .map(|domain| format!("; Domain={domain}"))
            .unwrap_or_default();
        let mut response = success(StatusCode::OK, json!({"refresh_token": token}), request_id);
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "csrf_token={csrf}; Path=/; Max-Age={expiry_seconds}; SameSite={same_site}{}{}",
                if secure { "; Secure" } else { "" },
                domain_attribute
            ))
            .unwrap(),
        );
        response.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&format!("access_token_cookie={token}; Path=/; Max-Age={expiry_seconds}; HttpOnly; SameSite={same_site}{}{}", if secure {"; Secure"} else {""}, domain_attribute)).unwrap());
        return response;
    }
    if path == "/authorization/status" && method == Method::GET {
        return success(
            StatusCode::OK,
            json!({"message": "Token is valid"}),
            request_id,
        );
    }
    if path == "/authorization/invalidate" && method == Method::POST {
        let Some(storage) = &state.storage else {
            return unexpected(request_id);
        };
        if let Err(error_value) = storage
            .insert_one(
                "revocations",
                json!({
                    "type": "jti", "username": username, "jti": claims.jti, "expires_at": claims.exp
                }),
            )
            .await
        {
            // Repeating an already-persisted invalidation is safe and
            // idempotent.  Every other storage failure must be visible to the
            // caller rather than falsely claiming the token was revoked.
            if !error_value.is_duplicate_key() {
                return unexpected(request_id);
            }
        }
        audit::management_mutation(username, "authorization.invalidate", username, "success");
        let mut response = message(
            StatusCode::OK,
            "Your token has been invalidated",
            request_id,
        );
        // Python scopes the deleted cookie to COOKIE_DOMAIN unless the host is a
        // local/dev host, and clears both the primary and dev cookie names.
        let domain_attribute = cookie_domain(headers)
            .map(|domain| format!("; Domain={domain}"))
            .unwrap_or_default();
        for cookie_name in ["access_token_cookie", "access_token_cookie_dev"] {
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "{cookie_name}=; Path=/; Max-Age=0; HttpOnly{domain_attribute}"
                ))
                .unwrap(),
            );
        }
        return response;
    }
    let parts = path
        .trim_start_matches("/authorization/admin/")
        .split('/')
        .collect::<Vec<_>>();
    let admin_action = parts.len() == 2
        && matches!(
            (parts[0], &method),
            ("status", &Method::GET)
                | ("disable", &Method::POST)
                | ("enable", &Method::POST)
                | ("revoke", &Method::POST)
                | ("unrevoke", &Method::POST)
        );
    if admin_action {
        if !has_permission(state, username, "manage_auth").await {
            return error(
                StatusCode::FORBIDDEN,
                "AUTH900",
                "You do not have permission to manage auth",
                request_id,
            );
        }
        let target = parts[1];
        if is_admin_user(state, target).await && !is_admin_user(state, username).await {
            return json_response(
                StatusCode::NOT_FOUND,
                json!({"error_message": "User not found"}),
                request_id,
            );
        }
        if parts[0] == "status" {
            let Some(storage) = &state.storage else {
                return unexpected(request_id);
            };
            let Some(user) = storage
                .find_one("users", &json!({"username": target}))
                .await
                .ok()
                .flatten()
            else {
                return unexpected(request_id);
            };
            let revoked = storage
                .find_one(
                    "revocations",
                    &json!({"type": "revoke_all", "username": target}),
                )
                .await
                .ok()
                .flatten()
                .is_some();
            return success(
                StatusCode::OK,
                json!({"active": user.get("active").and_then(Value::as_bool).unwrap_or(false), "revoked": revoked}),
                request_id,
            );
        }
        if parts[0] == "disable" || parts[0] == "enable" {
            let active = parts[0] == "enable";
            if let Some(storage) = &state.storage {
                let update = storage
                    .update_one(
                        "users",
                        &json!({"username": target}),
                        &json!({"active": active}),
                    )
                    .await;
                if update.is_err() {
                    return unexpected(request_id);
                }
                if !active {
                    let _ = storage
                        .delete_one(
                            "revocations",
                            &json!({"type": "revoke_all", "username": target}),
                        )
                        .await;
                    if let Err(error_value) = storage
                        .insert_one(
                            "revocations",
                            json!({"type": "revoke_all", "username": target, "revoke_all": true, "revoked_at": unix_seconds()}),
                        )
                        .await
                        && !error_value.is_duplicate_key()
                    {
                        return unexpected(request_id);
                    }
                }
                audit::management_mutation(
                    username,
                    if active {
                        "authorization.enable"
                    } else {
                        "authorization.disable"
                    },
                    target,
                    "success",
                );
                return message(
                    StatusCode::OK,
                    &if active {
                        format!("User {target} enabled")
                    } else {
                        format!("User {target} disabled and tokens revoked")
                    },
                    request_id,
                );
            }
        }
        if parts[0] == "revoke" || parts[0] == "unrevoke" {
            let Some(storage) = &state.storage else {
                return unexpected(request_id);
            };
            if parts[0] == "revoke" {
                let _ = storage
                    .delete_one(
                        "revocations",
                        &json!({"type": "revoke_all", "username": target}),
                    )
                    .await;
                if let Err(error_value) = storage
                    .insert_one(
                        "revocations",
                        json!({"type": "revoke_all", "username": target, "revoke_all": true, "revoked_at": unix_seconds()}),
                    )
                    .await
                {
                    if !error_value.is_duplicate_key() {
                        return unexpected(request_id);
                    }
                }
            } else if storage
                .delete_one(
                    "revocations",
                    &json!({"type": "revoke_all", "username": target}),
                )
                .await
                .is_err()
            {
                return unexpected(request_id);
            }
            audit::management_mutation(
                username,
                if parts[0] == "revoke" {
                    "authorization.revoke"
                } else {
                    "authorization.unrevoke"
                },
                target,
                "success",
            );
            return message(
                StatusCode::OK,
                &if parts[0] == "revoke" {
                    format!("All tokens revoked for {target}")
                } else {
                    format!("Token revocation cleared for {target}")
                },
                request_id,
            );
        }
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

async fn platform_ip_filter(
    state: &AppState,
    headers: &HeaderMap,
    direct_addr: Option<SocketAddr>,
    request_id: &str,
) -> Option<Response> {
    let storage = state.storage.as_ref()?;
    let settings = match storage
        .find_one("settings", &json!({"type": "security_settings"}))
        .await
    {
        Ok(settings) => settings,
        Err(error_value) => {
            tracing::error!(error = %error_value, "security settings lookup failed; denying request");
            return Some(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SEC012",
                "Security policy is temporarily unavailable",
                request_id,
            ));
        }
    };
    let whitelist = settings
        .as_ref()
        .and_then(|value| value.get("ip_whitelist"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let blacklist = settings
        .as_ref()
        .and_then(|value| value.get("ip_blacklist"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if whitelist.is_empty() && blacklist.is_empty() {
        return None;
    }
    let api = json!({
        "api_ip_mode": if whitelist.is_empty() {"allow_all"} else {"whitelist"},
        "api_ip_whitelist": whitelist,
        "api_ip_blacklist": blacklist,
        "api_trust_x_forwarded_for": settings
            .as_ref()
            .and_then(|value| value.get("trust_x_forwarded_for"))
            .and_then(Value::as_bool)
            .unwrap_or(state.config.shared_storage.trust_x_forwarded_for)
    });
    match enforce_configured_api_ip_policy(
        &api,
        settings.as_ref(),
        headers,
        direct_addr.map(|addr| addr.ip()),
        &state.config.shared_storage,
    ) {
        Ok(()) => None,
        Err(failure) => {
            let direct_ip = direct_addr.map(|addr| addr.ip());
            let effective_ip = effective_client_ip_for_settings(
                settings.as_ref(),
                headers,
                direct_ip,
                settings
                    .as_ref()
                    .and_then(|value| value.get("trust_x_forwarded_for"))
                    .and_then(Value::as_bool)
                    .unwrap_or(state.config.shared_storage.trust_x_forwarded_for),
            )
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
            let source_ip = direct_ip.map(|ip| ip.to_string());
            global_ip_deny(
                &effective_ip,
                if failure.error_code == "API011" {
                    "blacklisted"
                } else {
                    "not_in_whitelist"
                },
                source_ip.as_deref(),
            );
            Some(error(
                StatusCode::FORBIDDEN,
                if failure.error_code == "API011" {
                    "SEC011"
                } else {
                    "SEC010"
                },
                if failure.error_code == "API011" {
                    "IP blocked"
                } else {
                    "IP not allowed"
                },
                request_id,
            ))
        }
    }
}

fn platform_openapi(request_id: &str) -> Response {
    match python_openapi_contract() {
        Ok(contract) => success(StatusCode::OK, contract.clone(), request_id),
        Err(message) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GTW999",
            message,
            request_id,
        ),
    }
}

fn python_openapi_contract() -> Result<&'static Value, &'static str> {
    if let Some(contract) = PYTHON_OPENAPI.get() {
        return Ok(contract);
    }
    let compressed = BASE64_STANDARD
        .decode(PYTHON_OPENAPI_GZIP_BASE64.trim())
        .map_err(|_| "Failed to decode embedded OpenAPI contract")?;
    let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|_| "Failed to decompress embedded OpenAPI contract")?;
    let contract = serde_json::from_slice(&decoded)
        .map_err(|_| "Failed to parse embedded OpenAPI contract")?;
    let _ = PYTHON_OPENAPI.set(contract);
    PYTHON_OPENAPI
        .get()
        .ok_or("Failed to initialize embedded OpenAPI contract")
}

enum RouteMatch {
    Found,
    NotFound,
    MethodNotAllowed(String),
}

/// Platform routes FastAPI serves outside the frozen schema
/// (`include_in_schema=False` and framework docs) plus Rust-native additions.
const UNLISTED_PLATFORM_ROUTES: &[(&str, &str)] = &[
    ("GET", "/platform/docs"),
    ("GET", "/platform/redoc"),
    ("GET", "/platform/openapi.json"),
    ("GET", "/platform/monitor/report"),
    ("GET", "/platform/logging/logs/download"),
    ("POST", "/platform/tools/rate-limit-simulator"),
];

/// `Allow` answered by the pinned server for multi-route platform paths.
/// Starlette names only the first registered route that matched the path, and
/// the frozen OpenAPI does not preserve registration order, so these values
/// were read from the pinned server with TRACE requests.
const PYTHON_ALLOW: &[(&str, &str)] = &[
    ("/platform/user", "POST"),
    ("/platform/user/{username}", "PUT"),
    ("/platform/api", "POST"),
    ("/platform/api/{api_name}/{api_version}", "PUT"),
    (
        "/platform/endpoint/{endpoint_method}/{api_name}/{api_version}/{endpoint_uri}",
        "PUT",
    ),
    (
        "/platform/endpoint/endpoint/validation/{endpoint_id}",
        "PUT",
    ),
    ("/platform/endpoint/validation/{endpoint_id}", "GET"),
    ("/platform/group/{group_name}", "PUT"),
    ("/platform/role", "POST"),
    ("/platform/role/{role_name}", "PUT"),
    ("/platform/routing/{client_key}", "PUT"),
    ("/platform/proto/{api_name}/{api_version}", "POST"),
    ("/platform/security/settings", "GET"),
    ("/platform/credit/{api_credit_group}", "PUT"),
    ("/platform/credit/{username}", "PUT"),
    ("/platform/vault", "POST"),
    ("/platform/vault/{key_name}", "GET"),
    ("/platform/tiers/", "POST"),
    ("/platform/tiers/{tier_id}", "GET"),
    ("/platform/tiers/assignments/{user_id}", "GET"),
    ("/platform/rate-limits/", "POST"),
    ("/platform/rate-limits/{rule_id}", "GET"),
];

/// Route table in registration order: (matcher, methods).
fn platform_route_table() -> &'static [(Regex, Vec<String>)] {
    static TABLE: OnceLock<Vec<(Regex, Vec<String>)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: Vec<(String, Vec<String>)> = Vec::new();
        if let Ok(contract) = python_openapi_contract()
            && let Some(paths) = contract.get("paths").and_then(Value::as_object)
        {
            for (template, item) in paths {
                if !template.starts_with("/platform") {
                    continue;
                }
                let mut methods: Vec<String> = item
                    .as_object()
                    .map(|item| {
                        item.keys()
                            .map(|method| method.to_ascii_uppercase())
                            .collect()
                    })
                    .unwrap_or_default();
                // Keep the pinned `Allow` method first; partial matches report it.
                if let Some((_, allow)) = PYTHON_ALLOW.iter().find(|(path, _)| path == template) {
                    methods.retain(|method| method != allow);
                    methods.insert(0, (*allow).to_owned());
                }
                table.push((template.clone(), methods));
            }
        }
        for (method, template) in UNLISTED_PLATFORM_ROUTES {
            table.push(((*template).to_owned(), vec![(*method).to_owned()]));
        }
        table
            .into_iter()
            .filter_map(|(template, methods)| Some((template_regex(&template)?, methods)))
            .collect()
    })
}

/// Compile a Starlette path template: `{name}` is one segment, `{name:path}`
/// is the remainder of the path.
fn template_regex(template: &str) -> Option<Regex> {
    static PARAM: OnceLock<Regex> = OnceLock::new();
    // FastAPI omits `:path` converters from OpenAPI; the only platform route
    // using one is the endpoint URI, which may contain slashes.
    let param = PARAM.get_or_init(|| {
        Regex::new(r"\{(?:endpoint_uri|[^}:]+(:path))\}|\{[^}:]+\}").expect("route param regex")
    });
    let mut pattern = String::from("^");
    let mut last = 0;
    for capture in param.captures_iter(template) {
        let whole = capture.get(0)?;
        pattern.push_str(&regex::escape(&template[last..whole.start()]));
        let path_param = capture.get(1).is_some() || whole.as_str() == "{endpoint_uri}";
        pattern.push_str(if path_param { ".*" } else { "[^/]+" });
        last = whole.end();
    }
    pattern.push_str(&regex::escape(&template[last..]));
    pattern.push('$');
    Regex::new(&pattern).ok()
}

/// The pinned platform routes let FastAPI render an authentication failure as
/// `{"detail": "Unauthorized"}`, except these, which wrap it in a route error
/// code. Captured from the pinned server with anonymous requests to every
/// frozen operation (routes where the pinned server instead crashes with a 500
/// keep the 401 and are recorded as approved differences).
const UNAUTHENTICATED_CODES: &[(&str, &str, &str, &str)] = &[
    ("GET", "/platform/api", "API_AUTH", "Unauthorized"),
    ("GET", "/platform/api/all", "API_AUTH", "Unauthorized"),
    (
        "POST",
        "/platform/authorization/invalidate",
        "AUTH005",
        "Unauthorized",
    ),
    (
        "GET",
        "/platform/authorization/status",
        "AUTH005",
        "Unauthorized",
    ),
    (
        "POST",
        "/platform/authorization/refresh",
        "AUTH003",
        "Unable to validate credentials",
    ),
    ("GET", "/platform/user", "GTW998", "Unauthorized"),
    ("GET", "/platform/user/all", "GTW998", "Unauthorized"),
    ("GET", "/platform/user/me", "GTW998", "Unauthorized"),
    (
        "POST",
        "/platform/proto/{api_name}/{api_version}",
        "GTW013",
        "Unauthorized",
    ),
    (
        "POST",
        "/platform/subscription/subscribe",
        "GEN001",
        "Unauthorized",
    ),
    (
        "POST",
        "/platform/subscription/unsubscribe",
        "GEN002",
        "Unauthorized",
    ),
];

fn unauthenticated(method: &Method, path: &str, _message: &str, request_id: &str) -> Response {
    static CODES: OnceLock<Vec<(&'static str, Regex, &'static str, &'static str)>> =
        OnceLock::new();
    let codes = CODES.get_or_init(|| {
        UNAUTHENTICATED_CODES
            .iter()
            .filter_map(|(method, template, code, text)| {
                Some((*method, template_regex(template)?, *code, *text))
            })
            .collect()
    });
    let full = format!("/platform{path}");
    // The backfill route is registered ahead of the proto upload template.
    if let Some((_, _, code, text)) = codes
        .iter()
        .filter(|_| path != "/proto/descriptors/backfill")
        .find(|(allowed, matcher, _, _)| *allowed == method.as_str() && matcher.is_match(&full))
    {
        return error(StatusCode::UNAUTHORIZED, code, text, request_id);
    }
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({"detail": "Unauthorized"}),
        request_id,
    )
}

/// Frozen operations whose FastAPI signature declares a JSON request model.
fn json_body_operations() -> &'static [(Regex, String)] {
    static TABLE: OnceLock<Vec<(Regex, String)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let Ok(contract) = python_openapi_contract() else {
            return Vec::new();
        };
        let Some(paths) = contract.get("paths").and_then(Value::as_object) else {
            return Vec::new();
        };
        let mut table = Vec::new();
        for (template, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            for (method, operation) in item {
                let json = operation
                    .pointer("/requestBody/content")
                    .and_then(Value::as_object)
                    .is_some_and(|content| content.contains_key("application/json"));
                if json && let Some(matcher) = template_regex(template) {
                    table.push((matcher, method.to_ascii_uppercase()));
                }
            }
        }
        table
    })
}

/// Every frozen operation in registration order with its JSON body schema.
fn operation_body_schemas() -> &'static [(Regex, String, Option<Value>)] {
    static TABLE: OnceLock<Vec<(Regex, String, Option<Value>)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let Ok(contract) = python_openapi_contract() else {
            return Vec::new();
        };
        let Some(paths) = contract.get("paths").and_then(Value::as_object) else {
            return Vec::new();
        };
        let mut table = Vec::new();
        for (template, item) in paths {
            let (Some(item), Some(matcher)) = (item.as_object(), template_regex(template)) else {
                continue;
            };
            for (method, operation) in item {
                let schema = operation
                    .pointer("/requestBody/content/application~1json/schema")
                    .cloned();
                table.push((matcher.clone(), method.to_ascii_uppercase(), schema));
            }
        }
        table
    })
}

/// FastAPI (pydantic v1) validation of a decoded JSON body against the model
/// the resolved route declares; `true` when the request must fail with 422.
fn body_fails_declared_model(path: &str, method: &Method, payload: &Value) -> bool {
    let full = format!("/platform{path}");
    let Some((_, _, Some(schema))) = operation_body_schemas()
        .iter()
        .find(|(matcher, allowed, _)| allowed == method.as_str() && matcher.is_match(&full))
    else {
        return false;
    };
    let Ok(contract) = python_openapi_contract() else {
        return false;
    };
    !pydantic_accepts(contract, schema, payload, 0)
}

fn pydantic_accepts(contract: &Value, schema: &Value, value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return true;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let pointer = reference.trim_start_matches('#');
        return contract
            .pointer(pointer)
            .is_none_or(|resolved| pydantic_accepts(contract, resolved, value, depth + 1));
    }
    if let Some(options) = schema.get("anyOf").and_then(Value::as_array) {
        return value.is_null()
            || options
                .iter()
                .any(|option| pydantic_accepts(contract, option, value, depth + 1));
    }
    if let Some(options) = schema.get("allOf").and_then(Value::as_array) {
        return options
            .iter()
            .all(|option| pydantic_accepts(contract, option, value, depth + 1));
    }
    let kind = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if schema.get("properties").is_some() {
                "object"
            } else {
                ""
            }
        });
    let number = |value: &Value| -> Option<f64> {
        match value {
            Value::Number(number) => number.as_f64(),
            Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
            Value::String(text) => text.trim().parse::<f64>().ok(),
            _ => None,
        }
    };
    let within_bounds = |amount: f64| {
        let bound = |key: &str| schema.get(key).and_then(Value::as_f64);
        bound("minimum").is_none_or(|limit| amount >= limit)
            && bound("maximum").is_none_or(|limit| amount <= limit)
            && bound("exclusiveMinimum").is_none_or(|limit| amount > limit)
            && bound("exclusiveMaximum").is_none_or(|limit| amount < limit)
    };
    match kind {
        "object" => {
            // pydantic v1 builds a dict from a list of key/value pairs too.
            if let Some(pairs) = value.as_array() {
                return schema.get("properties").is_none()
                    && pairs
                        .iter()
                        .all(|pair| pair.as_array().is_some_and(|pair| pair.len() == 2));
            }
            let Some(object) = value.as_object() else {
                return false;
            };
            let properties = schema.get("properties").and_then(Value::as_object);
            let required = schema
                .get("required")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            for name in required.iter().filter_map(Value::as_str) {
                if object.get(name).is_none_or(Value::is_null) {
                    return false;
                }
            }
            if let Some(properties) = properties {
                for (name, property) in properties {
                    match object.get(name) {
                        None | Some(Value::Null) => {}
                        Some(item) => {
                            if !pydantic_accepts(contract, property, item, depth + 1) {
                                return false;
                            }
                        }
                    }
                }
            }
            if let Some(additional) = schema.get("additionalProperties").filter(|v| v.is_object()) {
                let known = properties.map(|map| map.keys().cloned().collect::<Vec<_>>());
                for (name, item) in object {
                    if known.as_ref().is_some_and(|known| known.contains(name)) || item.is_null() {
                        continue;
                    }
                    if !pydantic_accepts(contract, additional, item, depth + 1) {
                        return false;
                    }
                }
            }
            true
        }
        "array" => {
            let Some(items) = value.as_array() else {
                return false;
            };
            let count = items.len() as f64;
            if schema
                .get("minItems")
                .and_then(Value::as_f64)
                .is_some_and(|min| count < min)
                || schema
                    .get("maxItems")
                    .and_then(Value::as_f64)
                    .is_some_and(|max| count > max)
            {
                return false;
            }
            schema.get("items").is_none_or(|item_schema| {
                items.iter().all(|item| {
                    item.is_null() || pydantic_accepts(contract, item_schema, item, depth + 1)
                })
            })
        }
        "string" => {
            // pydantic v1 coerces numbers (and bools, an int subclass) to str.
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => if *flag { "True" } else { "False" }.to_owned(),
                _ => return false,
            };
            let length = text.chars().count() as f64;
            schema
                .get("minLength")
                .and_then(Value::as_f64)
                .is_none_or(|min| length >= min)
                && schema
                    .get("maxLength")
                    .and_then(Value::as_f64)
                    .is_none_or(|max| length <= max)
        }
        "integer" => match value {
            Value::String(text) => crate::python_scalar::parse_model_integer(text)
                .is_some_and(|n| within_bounds(n as f64)),
            other => number(other).is_some_and(|n| within_bounds(n.trunc())),
        },
        "number" => number(value).is_some_and(within_bounds),
        "boolean" => match value {
            Value::Bool(_) => true,
            Value::Number(number) => matches!(number.as_f64(), Some(n) if n == 0.0 || n == 1.0),
            Value::String(text) => matches!(
                text.to_ascii_lowercase().as_str(),
                "0" | "1" | "true" | "false" | "t" | "f" | "yes" | "no" | "y" | "n" | "on" | "off"
            ),
            _ => false,
        },
        _ => true,
    }
}

/// Whether the frozen operation declares a JSON request model (FastAPI then
/// rejects an undecodable JSON body with 422 before the handler runs).
fn declares_json_body(path: &str, method: &Method) -> bool {
    let full = format!("/platform{path}");
    json_body_operations()
        .iter()
        .any(|(matcher, allowed)| allowed == method.as_str() && matcher.is_match(&full))
}

/// FastAPI only decodes a declared JSON model from a JSON request; any other
/// (or absent) Content-Type on a non-empty body fails validation with 422.
fn rejects_non_json_body(path: &str, method: &Method, headers: &HeaderMap, body: &[u8]) -> bool {
    if body.is_empty() || content_type_is_json(headers) {
        return false;
    }
    let full = format!("/platform{path}");
    json_body_operations()
        .iter()
        .any(|(matcher, allowed)| allowed == method.as_str() && matcher.is_match(&full))
}

/// Gateway routes in the pinned registration order, plus the Rust-native
/// `/api/features` probe and gRPC-Web CORS preflight.
const GATEWAY_ROUTES: &[(&str, &[&str])] = &[
    ("/api/status", &["GET"]),
    ("/api/health", &["GET"]),
    ("/api/caches", &["DELETE"]),
    ("/api/caches", &["OPTIONS"]),
    (
        "/api/rest/{path:path}",
        &["PATCH", "DELETE", "GET", "POST", "PUT"],
    ),
    ("/api/rest/{path:path}", &["HEAD"]),
    ("/api/rest/{path:path}", &["OPTIONS"]),
    ("/api/soap/{path:path}", &["GET", "POST"]),
    ("/api/grpc/{path:path}", &["GET", "POST"]),
    ("/api/soap/{path:path}", &["OPTIONS"]),
    ("/api/graphql/{path:path}", &["POST"]),
    ("/api/graphql/{path:path}", &["OPTIONS"]),
    ("/api/grpc/{path:path}", &["OPTIONS"]),
    ("/api/features", &["GET"]),
    // CORS preflights bypass this table, so only POST is a registered route.
    ("/grpc-web/{api_name}/{service}/{method}", &["POST"]),
];

/// Starlette-style route resolution for the data plane: unknown paths are a
/// bare 404 and known paths with other methods a 405 naming the first route.
pub(crate) async fn gateway_route_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    static TABLE: OnceLock<Vec<(Regex, &'static [&'static str])>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        GATEWAY_ROUTES
            .iter()
            .filter_map(|(template, methods)| Some((template_regex(template)?, *methods)))
            .collect()
    });
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.0.path().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    // CORS preflights are answered by the CORS middleware ahead of routing.
    if request.method() == Method::OPTIONS
        && request.headers().contains_key(header::ORIGIN)
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        return next.run(request).await;
    }
    let request_id = request_id_from(request.headers());
    let mut partial = None;
    for (matcher, methods) in table {
        if !matcher.is_match(&path) {
            continue;
        }
        if methods.contains(&request.method().as_str()) {
            return next.run(request).await;
        }
        partial = partial.or(Some(*methods));
    }
    let Some(methods) = partial else {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"detail": "Not Found"}),
            &request_id,
        );
    };
    let mut response = json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"detail": "Method Not Allowed"}),
        &request_id,
    );
    if let Ok(value) = HeaderValue::from_str(&methods.join(", ")) {
        response.headers_mut().insert(header::ALLOW, value);
    }
    response
}

fn python_route_match(path: &str, method: &Method) -> RouteMatch {
    // The TLS administration surface is a Rust-native addition.
    if path == "/tls" || path.starts_with("/tls/") {
        return RouteMatch::Found;
    }
    let full = format!("/platform{path}");
    let mut partial: Option<&str> = None;
    for (matcher, methods) in platform_route_table() {
        if !matcher.is_match(&full) {
            continue;
        }
        if methods.iter().any(|allowed| allowed == method.as_str()) {
            return RouteMatch::Found;
        }
        partial = partial.or(methods.first().map(String::as_str));
    }
    match partial {
        Some(allow) => RouteMatch::MethodNotAllowed(allow.to_owned()),
        None => RouteMatch::NotFound,
    }
}

fn platform_docs(path: &str, request_id: &str) -> Response {
    let html = if path == "/redoc" {
        r#"<!doctype html><html><head><title>Doorman API</title><script src="https://cdn.jsdelivr.net/npm/redoc@2.5.2/bundles/redoc.standalone.js"></script></head><body><redoc spec-url="/platform/openapi.json"></redoc></body></html>"#
    } else {
        r#"<!doctype html><html><head><title>Doorman API</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/platform/openapi.json',dom_id:'#swagger-ui'});</script></body></html>"#
    };
    let mut response = axum::response::Html(html).into_response();
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value.clone());
        response.headers_mut().insert("request_id", value);
    }
    response
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    request_id: &str,
) -> Result<AuthClaims, Response> {
    let claims = verify_request_token(headers, &state.config.shared_storage)
        .map_err(|_| unauthenticated(method, path, "Unauthorized", request_id))?;
    let username = claims.sub.as_deref().unwrap_or("");
    let Some(storage) = &state.storage else {
        return Err(unexpected(request_id));
    };
    if state.config.https_only
        && path != "/user/admin"
        && path != "/authorization"
        && path != "/authorization/register"
        && !csrf_matches(headers, storage, username).await
    {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "AUTH003",
            "Invalid CSRF token",
            request_id,
        ));
    }
    if let Ok(Some(_revocation)) = storage
        .find_one(
            "revocations",
            &json!({"type": "revoke_all", "username": username}),
        )
        .await
    {
        return Err(unauthenticated(
            method,
            path,
            "Token has been revoked",
            request_id,
        ));
    }
    if let Some(jti) = claims.jti.as_deref() {
        let filter = json!({"type": "jti", "username": username, "jti": jti});
        if let Ok(Some(revocation)) = storage.find_one("revocations", &filter).await {
            let expired = revocation
                .get("expires_at")
                .and_then(Value::as_u64)
                .is_some_and(|expires_at| expires_at <= unix_seconds());
            if expired {
                let _ = storage.delete_one("revocations", &filter).await;
            } else {
                return Err(unauthenticated(
                    method,
                    path,
                    "Token has been revoked",
                    request_id,
                ));
            }
        }
    }
    match storage
        .find_one("users", &json!({"username": username}))
        .await
    {
        Ok(Some(user)) if user.get("active").and_then(Value::as_bool) != Some(false) => Ok(claims),
        Ok(Some(_)) => Err(unauthenticated(
            method,
            path,
            "User is inactive",
            request_id,
        )),
        _ => Err(error(
            StatusCode::NOT_FOUND,
            "USR002",
            "User not found",
            request_id,
        )),
    }
}

async fn has_permission(state: &AppState, username: &str, permission: &str) -> bool {
    let Some(storage) = &state.storage else {
        return false;
    };
    let Ok(Some(user)) = storage
        .find_one("users", &json!({"username": username}))
        .await
    else {
        return false;
    };
    let Some(role_name) = user.get("role").and_then(Value::as_str) else {
        return false;
    };
    matches!(storage.find_one("roles", &json!({"role_name": role_name})).await, Ok(Some(role)) if role.get(permission).and_then(Value::as_bool).unwrap_or(false))
}

async fn is_admin_user(state: &AppState, username: &str) -> bool {
    let Some(storage) = &state.storage else {
        return false;
    };
    let Ok(Some(user)) = storage
        .find_one("users", &json!({"username": username}))
        .await
    else {
        return false;
    };
    let Some(role_name) = user.get("role").and_then(Value::as_str) else {
        return false;
    };
    is_admin_role(state, role_name).await
}

async fn is_admin_role(state: &AppState, role_name: &str) -> bool {
    if matches!(
        role_name.trim().to_ascii_lowercase().as_str(),
        "admin" | "platform admin"
    ) {
        return true;
    }
    let Some(storage) = &state.storage else {
        return false;
    };
    matches!(
        storage.find_one("roles", &json!({"role_name": role_name})).await,
        Ok(Some(role)) if role.get("platform_admin").and_then(Value::as_bool) == Some(true)
            || role.get("role_name").and_then(Value::as_str).is_some_and(|name| matches!(name.trim().to_ascii_lowercase().as_str(), "admin" | "platform admin"))
    )
}

async fn memory_dump(
    state: &AppState,
    payload: Value,
    username: &str,
    request_id: &str,
) -> Response {
    let path = match memory_request_path(&payload) {
        Ok(path) => path,
        Err(errors) => return validation_errors(errors, request_id),
    };
    if !has_permission(state, username, "manage_security").await {
        return error(
            StatusCode::FORBIDDEN,
            "SEC003",
            "You do not have permission to perform memory dump",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if !storage.is_memory() {
        return error(
            StatusCode::BAD_REQUEST,
            "MEM001",
            "Memory dump available only in memory-only mode",
            request_id,
        );
    }
    match crate::storage::snapshot::dump(storage, path.as_deref()).await {
        Ok(path) => {
            audit::management_mutation(username, "memory.dump", "memory_snapshot", "success");
            success(
                StatusCode::OK,
                json!({"response": {"path": path}}),
                request_id,
            )
        }
        Err(crate::storage::snapshot::SnapshotError::MissingKey)
            if env::var("MEM_ENCRYPTION_KEY")
                .unwrap_or_default()
                .is_empty() =>
        {
            error(
                StatusCode::BAD_REQUEST,
                "MEM002",
                "MEM_ENCRYPTION_KEY is not configured",
                request_id,
            )
        }
        Err(crate::storage::snapshot::SnapshotError::InvalidPath) => error(
            StatusCode::BAD_REQUEST,
            "MEM004",
            "Snapshot path must be a filename in the configured dump directory",
            request_id,
        ),
        Err(_) => unexpected(request_id),
    }
}

async fn memory_restore(
    state: &AppState,
    payload: Value,
    username: &str,
    request_id: &str,
) -> Response {
    let path = match memory_request_path(&payload) {
        Ok(path) => path,
        Err(errors) => return validation_errors(errors, request_id),
    };
    if !has_permission(state, username, "manage_security").await {
        return error(
            StatusCode::FORBIDDEN,
            "SEC004",
            "You do not have permission to perform memory restore",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if !storage.is_memory() {
        return error(
            StatusCode::BAD_REQUEST,
            "MEM001",
            "Memory restore available only in memory-only mode",
            request_id,
        );
    }
    match crate::storage::snapshot::restore(storage, path.as_deref()).await {
        Ok((version, created_at)) => {
            audit::management_mutation(username, "memory.restore", "memory_snapshot", "success");
            success(
                StatusCode::OK,
                json!({"response": {"version": version, "created_at": created_at}}),
                request_id,
            )
        }
        Err(crate::storage::snapshot::SnapshotError::MissingKey)
            if env::var("MEM_ENCRYPTION_KEY")
                .unwrap_or_default()
                .is_empty() =>
        {
            error(
                StatusCode::BAD_REQUEST,
                "MEM002",
                "MEM_ENCRYPTION_KEY is not configured",
                request_id,
            )
        }
        Err(crate::storage::snapshot::SnapshotError::InvalidPath) => error(
            StatusCode::BAD_REQUEST,
            "MEM004",
            "Snapshot path must be a filename in the configured dump directory",
            request_id,
        ),
        Err(crate::storage::snapshot::SnapshotError::Io(error_value))
            if error_value.kind() == std::io::ErrorKind::NotFound =>
        {
            error(
                StatusCode::NOT_FOUND,
                "MEM003",
                "Dump file not found",
                request_id,
            )
        }
        Err(_) => unexpected(request_id),
    }
}

fn memory_request_path(payload: &Value) -> Result<Option<String>, Vec<Value>> {
    if payload.is_null() {
        return Ok(None);
    }
    let Some(values) = payload.as_object() else {
        return Err(vec![json!({
            "loc": ["body"],
            "msg": "value is not a valid dict",
            "type": "type_error.dict"
        })]);
    };
    match values.get("path") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => security_setting_string(value).map(Some).ok_or_else(|| {
            vec![json!({
                "loc": ["body", "path"],
                "msg": "str type expected",
                "type": "type_error.str"
            })]
        }),
    }
}

async fn readiness(state: &AppState, privileged: bool, request_id: &str) -> Response {
    let (mongo_ok, redis_ok, memory_only, missing_grpc_descriptors, grpc_descriptor_errors) =
        if let Some(storage) = &state.storage {
            let mongo_ok = storage.mongo_healthy().await;
            let redis_ok = storage.redis_healthy().await;
            let (missing, errors) = match storage.find_many("apis", &json!({})).await {
                Ok(apis) => {
                    let errors = apis
                        .iter()
                        .filter(|api| {
                            api.get("api_type")
                                .and_then(Value::as_str)
                                .is_some_and(|kind| kind.eq_ignore_ascii_case("grpc"))
                                && bool_field_default(api, "active", true)
                                && !bool_field_default(api, "api_is_crud", false)
                                && api
                                    .get("api_grpc_descriptor_set")
                                    .and_then(Value::as_str)
                                    .map(|descriptor| descriptor.trim().is_empty())
                                    .unwrap_or(true)
                        })
                        .map(|api| {
                            json!({
                                "api_name": api.get("api_name").cloned().unwrap_or(Value::Null),
                                "api_version": api.get("api_version").cloned().unwrap_or(Value::Null),
                                "error": "gRPC descriptor is missing"
                            })
                        })
                        .collect::<Vec<_>>();
                    (errors.len(), errors)
                }
                Err(_) => (
                    1,
                    vec![json!({"error": "unable to inspect gRPC descriptor state"})],
                ),
            };
            (mongo_ok, redis_ok, storage.is_memory(), missing, errors)
        } else {
            (
                false,
                false,
                false,
                1,
                vec![json!({"error": "storage is unavailable"})],
            )
        };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs() as i64)
        .unwrap_or(i64::MAX);
    let tls_certificates_valid = state
        .runtime
        .tls_certificate_expiries
        .lock()
        .map(|expiries| expiries.values().all(|expiry| *expiry > now))
        .unwrap_or(false);
    let ready = mongo_ok && redis_ok && missing_grpc_descriptors == 0 && tls_certificates_valid;
    let status = if ready { "ready" } else { "degraded" };
    if !privileged {
        return success(StatusCode::OK, json!({"status": status}), request_id);
    }
    success(
        StatusCode::OK,
        json!({
            "status": status,
            "mongodb": mongo_ok,
            "redis": redis_ok,
            "mode": if memory_only { "memory" } else { "mongodb" },
            "cache_backend": if memory_only { "memory" } else { "redis" },
            "missing_grpc_descriptors": missing_grpc_descriptors,
            "grpc_descriptor_errors": grpc_descriptor_errors,
            "tls_certificates_valid": tls_certificates_valid
        }),
        request_id,
    )
}

async fn dashboard(state: &AppState, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let new_apis = storage
        .find_many("apis", &json!({}))
        .await
        .unwrap_or_default()
        .len();
    let subscriptions = storage
        .find_many("subscriptions", &json!({}))
        .await
        .unwrap_or_default();

    let analytics = global_analytics();
    let mut monthly_usage = Map::new();
    for point in analytics.get_timeseries() {
        let Ok(timestamp) = time::OffsetDateTime::from_unix_timestamp(point.timestamp as i64)
        else {
            continue;
        };
        let month = match u8::from(timestamp.month()) {
            1 => "Jan",
            2 => "Feb",
            3 => "Mar",
            4 => "Apr",
            5 => "May",
            6 => "Jun",
            7 => "Jul",
            8 => "Aug",
            9 => "Sep",
            10 => "Oct",
            11 => "Nov",
            _ => "Dec",
        };
        let count = monthly_usage
            .get(month)
            .and_then(Value::as_u64)
            .unwrap_or_default()
            .saturating_add(point.requests);
        monthly_usage.insert(month.to_owned(), json!(count));
    }
    let total_requests = monthly_usage
        .values()
        .filter_map(Value::as_u64)
        .sum::<u64>();

    let active_users_list = analytics
        .get_top_users(5)
        .into_iter()
        .map(|user| {
            let subscriber_count = subscriptions
                .iter()
                .find(|subscription| subscription["username"].as_str() == Some(&user.name))
                .and_then(|subscription| subscription["apis"].as_array())
                .map(Vec::len)
                .unwrap_or_default();
            json!({
                "username": user.name,
                "requests": format_dashboard_count(user.count),
                "subscribers": subscriber_count
            })
        })
        .collect::<Vec<_>>();

    let popular_apis = analytics
        .get_top_apis(10)
        .into_iter()
        .map(|api| {
            let api_suffix = api.name.rsplit(':').next().unwrap_or(&api.name);
            let subscriber_count = subscriptions
                .iter()
                .filter(|subscription| {
                    subscription["apis"].as_array().is_some_and(|entries| {
                        entries
                            .iter()
                            .any(|entry| entry.to_string().contains(api_suffix))
                    })
                })
                .count();
            json!({
                "name": api.name,
                "requests": format_dashboard_count(api.count),
                "subscribers": subscriber_count
            })
        })
        .collect::<Vec<_>>();

    success(
        StatusCode::OK,
        json!({
            "totalRequests": total_requests,
            "activeUsers": analytics.user_count(),
            "newApis": new_apis,
            "monthlyUsage": monthly_usage,
            "activeUsersList": active_users_list,
            "popularApis": popular_apis
        }),
        request_id,
    )
}

fn format_dashboard_count(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(character);
    }
    formatted
}

async fn monitor_metrics(
    state: &AppState,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    let analytics = global_analytics();
    let minutes = match query.get("range").map(String::as_str).unwrap_or("24h") {
        "1h" => 60,
        "7d" => 60 * 24 * 7,
        "30d" => 60 * 24 * 30,
        _ => 60 * 24,
    };
    let points = analytics.get_timeseries();
    let selected = points
        .into_iter()
        .rev()
        .take(minutes)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let group_by_day = query
        .get("group")
        .is_some_and(|value| value.eq_ignore_ascii_case("day"));
    let mut series = if group_by_day {
        let mut days = std::collections::BTreeMap::<u64, AggregatedPoint>::new();
        for point in &selected {
            let day = (point.timestamp / 86_400) * 86_400;
            let bucket = days.entry(day).or_insert_with(|| AggregatedPoint {
                timestamp: day,
                ..AggregatedPoint::default()
            });
            let prior = bucket.requests;
            bucket.requests = bucket.requests.saturating_add(point.requests);
            bucket.errors = bucket.errors.saturating_add(point.errors);
            bucket.bytes_in = bucket.bytes_in.saturating_add(point.bytes_in);
            bucket.bytes_out = bucket.bytes_out.saturating_add(point.bytes_out);
            if bucket.requests > 0 {
                bucket.latency_ms = ((bucket.latency_ms * prior as f64)
                    + (point.latency_ms * point.requests as f64))
                    / bucket.requests as f64;
            }
        }
        days.into_values()
            .map(|point| {
                json!({
                    "timestamp": point.timestamp,
                    "count": point.requests,
                    "error_count": point.errors,
                    "avg_ms": point.latency_ms,
                    "bytes_in": point.bytes_in,
                    "bytes_out": point.bytes_out,
                    "error_rate": if point.requests == 0 { 0.0 } else { point.errors as f64 / point.requests as f64 },
                })
            })
            .collect::<Vec<_>>()
    } else {
        selected
            .iter()
            .map(|point| {
                json!({
                    "timestamp": point.timestamp,
                    "count": point.requests,
                    "test_count": 0,
                    "error_count": point.errors,
                    "avg_ms": point.latency_ms,
                    "p95_ms": point.p95_ms(),
                    "bytes_in": point.bytes_in,
                    "bytes_out": point.bytes_out,
                    "error_rate": if point.requests == 0 { 0.0 } else { point.errors as f64 / point.requests as f64 },
                    "upstream_timeouts": 0,
                    "retries": 0,
                })
            })
            .collect::<Vec<_>>()
    };
    if query
        .get("sort")
        .is_some_and(|value| value.eq_ignore_ascii_case("desc"))
    {
        series.reverse();
    }
    let total_requests = selected.iter().map(|point| point.requests).sum::<u64>();
    let total_errors = selected.iter().map(|point| point.errors).sum::<u64>();
    let average_response_ms = if total_requests == 0 {
        0.0
    } else {
        selected
            .iter()
            .map(|point| point.latency_ms * point.requests as f64)
            .sum::<f64>()
            / total_requests as f64
    };
    // Python's MetricsStore.snapshot: top_apis/top_users/unique_users are
    // aggregated only from the buckets in the selected range (with a
    // documented global fallback when the range attributed no traffic),
    // not from the process-global all-time counters.
    let (range_start, range_end) = (
        selected.first().map_or(0, |point| point.timestamp),
        selected.last().map_or(u64::MAX, |point| point.timestamp),
    );
    let range_top_apis = analytics.get_top_apis_in_range(range_start, range_end, 10);
    let top_apis: Vec<(String, u64)> = if range_top_apis.is_empty() {
        analytics
            .get_top_apis(10)
            .into_iter()
            .map(|entry| (entry.name, entry.count))
            .collect()
    } else {
        range_top_apis
            .into_iter()
            .map(|entry| (entry.name, entry.count))
            .collect()
    };
    let range_top_users = analytics.get_top_users_in_range(range_start, range_end, 10);
    let (top_users, unique_users): (Vec<(String, u64)>, usize) = if range_top_users.is_empty() {
        let global = analytics.get_top_users(10);
        let count = global.len();
        (
            global
                .into_iter()
                .map(|entry| (entry.name, entry.count))
                .collect(),
            count,
        )
    } else {
        let count = range_top_users.len();
        (
            range_top_users
                .into_iter()
                .map(|entry| (entry.name, entry.count))
                .collect(),
            count,
        )
    };
    success(
        StatusCode::OK,
        json!({
            "uptime_seconds": state.runtime.started_at.elapsed().as_secs(),
            "active_requests": state.runtime.active_requests.load(std::sync::atomic::Ordering::Relaxed),
            "total_requests": total_requests,
            "total_test_requests": 0,
            "total_errors": total_errors,
            "avg_response_ms": average_response_ms,
            "status_counts": analytics.get_status_distribution(),
            "series": series,
            "top_apis": top_apis,
            "top_users": top_users,
            "unique_users": unique_users,
            "total_upstream_timeouts": 0,
            "total_retries": 0,
            "total_bytes_in": state.runtime.total_bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            "total_bytes_out": state.runtime.total_bytes_out.load(std::sync::atomic::Ordering::Relaxed)
        }),
        request_id,
    )
}

async fn monitor_report(
    state: &AppState,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    let start = query.get("start").map(String::as_str).unwrap_or("");
    let end = query.get("end").map(String::as_str).unwrap_or("");
    let start_ts = match parse_report_timestamp(start) {
        Ok(ts) => ts,
        Err(message_text) => {
            return error(StatusCode::BAD_REQUEST, "MON003", &message_text, request_id);
        }
    };
    let end_ts = match parse_report_timestamp(end) {
        Ok(ts) => ts,
        Err(message_text) => {
            return error(StatusCode::BAD_REQUEST, "MON003", &message_text, request_id);
        }
    };
    if end_ts < start_ts {
        return error(
            StatusCode::BAD_REQUEST,
            "MON003",
            "End date must be after start date",
            request_id,
        );
    }

    let (start_date, start_time_str) = report_date_time_utc(start_ts);
    let (end_date, end_time_str) = report_date_time_utc(end_ts);
    let directory = state
        .config
        .logs_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("platform-logs"));
    let mut log_query = HashMap::new();
    log_query.insert("start_date".to_owned(), start_date);
    log_query.insert("end_date".to_owned(), end_date);
    log_query.insert("start_time".to_owned(), start_time_str);
    log_query.insert("end_time".to_owned(), end_time_str);
    // Python pages through up to 100 * 1000 = 100,000 log-service results;
    // read_log_records already bounds total bytes read via MAX_LOG_EXPORT_BYTES.
    let logs = read_log_records(&directory, &log_query, 100_000).unwrap_or_default();

    let mut total = 0u64;
    let mut errors = 0u64;
    let mut total_ms = 0.0f64;
    let mut status_counts: std::collections::BTreeMap<u16, u64> = std::collections::BTreeMap::new();
    let mut api_totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut api_errors: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut user_totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for record in &logs {
        let endpoint = record.get("endpoint").and_then(Value::as_str).unwrap_or("");
        if endpoint.is_empty() || endpoint == "/platform" || endpoint.starts_with("/platform/") {
            continue;
        }
        total += 1;
        let status_code = record
            .get("status_code")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u16>().ok())
            .or_else(|| {
                record
                    .get("status_code")
                    .and_then(Value::as_u64)
                    .map(|value| value as u16)
            });
        let level = record
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase();
        let is_error = status_code.is_some_and(|code| code >= 400)
            || !matches!(level.as_str(), "INFO" | "DEBUG");
        if is_error {
            errors += 1;
        }
        if let Some(code) = status_code {
            *status_counts.entry(code).or_default() += 1;
        }
        if let Some(response_time) = record.get("response_time").and_then(log_number) {
            total_ms += response_time;
        }
        let api_key = report_api_from_endpoint(endpoint);
        *api_totals.entry(api_key.clone()).or_default() += 1;
        if is_error {
            *api_errors.entry(api_key).or_default() += 1;
        }
        if let Some(username) = record
            .get("user")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            *user_totals.entry(username.to_owned()).or_default() += 1;
        }
    }

    let analytics = global_analytics();
    let points_in_range = analytics
        .get_timeseries()
        .into_iter()
        .filter(|point| {
            point.timestamp >= start_ts.max(0) as u64 && point.timestamp <= end_ts.max(0) as u64
        })
        .collect::<Vec<_>>();
    // Python's own defensive fallback: if no log lines matched (e.g. logs
    // rotated away), reconstruct totals from the retained metrics buckets
    // instead of reporting an empty period.
    if total == 0 {
        total = points_in_range.iter().map(|point| point.requests).sum();
        errors = points_in_range.iter().map(|point| point.errors).sum();
        total_ms = points_in_range
            .iter()
            .map(|point| point.latency_ms * point.requests as f64)
            .sum();
        for (status, count) in analytics.get_status_distribution() {
            if let Ok(code) = status.parse::<u16>() {
                *status_counts.entry(code).or_default() += count;
            }
        }
        for entry in analytics.get_top_apis_in_range(
            start_ts.max(0) as u64,
            end_ts.max(0) as u64,
            usize::MAX,
        ) {
            api_totals.insert(entry.name.clone(), entry.count);
            if entry.error_count > 0 {
                api_errors.insert(entry.name, entry.error_count);
            }
        }
        for entry in analytics.get_top_users_in_range(
            start_ts.max(0) as u64,
            end_ts.max(0) as u64,
            usize::MAX,
        ) {
            user_totals.insert(entry.name, entry.count);
        }
    }

    let total_bytes_in: u64 = points_in_range.iter().map(|point| point.bytes_in).sum();
    let total_bytes_out: u64 = points_in_range.iter().map(|point| point.bytes_out).sum();
    let mut daily_bandwidth: std::collections::BTreeMap<u64, (u64, u64)> =
        std::collections::BTreeMap::new();
    for point in &points_in_range {
        let day_ts = (point.timestamp / 86_400) * 86_400;
        let entry = daily_bandwidth.entry(day_ts).or_default();
        entry.0 += point.bytes_in;
        entry.1 += point.bytes_out;
    }

    let average_ms = if total == 0 {
        0.0
    } else {
        total_ms / total as f64
    };
    let successes = total.saturating_sub(errors);
    let success_rate = if total == 0 {
        0.0
    } else {
        successes as f64 * 100.0 / total as f64
    };

    let mut csv = String::new();
    let _ = writeln!(csv, "Report,From,{},To,{}", csv_cell(start), csv_cell(end));
    csv.push_str("Overview\n");
    let _ = writeln!(csv, "total_requests,{total}");
    let _ = writeln!(csv, "total_errors,{errors}");
    let _ = writeln!(csv, "successes,{successes}");
    let _ = writeln!(csv, "success_rate,{success_rate:.2}%");
    let _ = writeln!(csv, "avg_response_ms,{average_ms:.2}");
    csv.push_str("\nBandwidth Overview\n");
    let _ = writeln!(csv, "total_bytes_in,{total_bytes_in}");
    let _ = writeln!(csv, "total_bytes_out,{total_bytes_out}");
    let _ = writeln!(
        csv,
        "total_bytes,{}",
        total_bytes_in.saturating_add(total_bytes_out)
    );
    csv.push_str("\nStatus Codes\nstatus,count\n");
    for (status, count) in &status_counts {
        let _ = writeln!(csv, "{status},{count}");
    }
    csv.push_str("\nAPI Usage\napi,total,errors,successes,success_rate\n");
    let mut apis = api_totals.into_iter().collect::<Vec<_>>();
    apis.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (api, count) in apis {
        let err = api_errors.get(&api).copied().unwrap_or_default();
        let succ = count.saturating_sub(err);
        let rate = if count == 0 {
            0.0
        } else {
            succ as f64 * 100.0 / count as f64
        };
        let _ = writeln!(csv, "{},{count},{err},{succ},{rate:.2}%", csv_cell(&api));
    }
    csv.push_str("\nUser Usage\nusername,requests\n");
    let mut users = user_totals.into_iter().collect::<Vec<_>>();
    users.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (user, count) in users {
        let _ = writeln!(csv, "{},{count}", csv_cell(&user));
    }
    csv.push_str("\nBandwidth (per day, UTC)\ndate,bytes_in,bytes_out,total\n");
    for (day_ts, (bytes_in, bytes_out)) in daily_bandwidth {
        let (date_str, _) = report_date_time_utc(day_ts as i64);
        let _ = writeln!(
            csv,
            "{date_str},{bytes_in},{bytes_out},{}",
            bytes_in.saturating_add(bytes_out)
        );
    }

    let mut response = ([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], csv).into_response();
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename=doorman_report_{start}_to_{end}.csv"
    )) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

/// `api` key derivation matching Python's `_api_from_endpoint` in
/// `monitor_routes.py::generate_report`.
fn report_api_from_endpoint(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix("/api/rest/") {
        let parts = rest.split('/').collect::<Vec<_>>();
        return format!("rest:{}", parts.first().copied().unwrap_or("unknown"));
    }
    if let Some(rest) = endpoint.strip_prefix("/api/graphql/") {
        let name = rest
            .rsplit('/')
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        return format!("graphql:{name}");
    }
    if let Some(rest) = endpoint.strip_prefix("/api/soap/") {
        let name = rest
            .rsplit('/')
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        return format!("soap:{name}");
    }
    "platform".to_owned()
}

/// Python's `_parse_ts`: try `%Y-%m-%dT%H:%M`, then `%Y-%m-%d`, then a
/// best-effort ISO-8601 fallback via `datetime.fromisoformat`. A naive
/// `datetime.strptime(...).timestamp()` in Python interprets the value in the
/// process's local timezone; this deployment (like the pinned reference's
/// container images) runs in UTC, so the two are equivalent here.
fn parse_report_timestamp(value: &str) -> Result<i64, String> {
    let invalid = || "Invalid date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM".to_owned();
    let parse_date = |text: &str| -> Option<time::Date> {
        let mut parts = text.splitn(3, '-');
        let year = parts.next()?.parse::<i32>().ok()?;
        let month = parts.next()?.parse::<u8>().ok()?;
        let day = parts.next()?.parse::<u8>().ok()?;
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()
    };
    let parse_time = |text: &str| -> Option<time::Time> {
        // Strict "%H:%M" callers pass exactly two fields; the fromisoformat
        // fallback below may also hand this "%H:%M:%S[.ffffff]", in which
        // case the seconds (whole part only; unix timestamps here are
        // second-resolution) are preserved rather than silently dropped.
        let mut fields = text.splitn(3, ':');
        let hour = fields.next()?;
        let minute = fields.next()?;
        let second = fields
            .next()
            .and_then(|value| value.split(['.', ',']).next())
            .unwrap_or("0");
        time::Time::from_hms(
            hour.parse().ok()?,
            minute.parse().ok()?,
            second.parse().ok()?,
        )
        .ok()
    };
    let to_ts = |date: time::Date, time_value: time::Time| {
        time::PrimitiveDateTime::new(date, time_value)
            .assume_utc()
            .unix_timestamp()
    };

    if let Some((date_part, time_part)) = value.split_once('T')
        && let (Some(date), Some(time_value)) = (parse_date(date_part), parse_time(time_part))
    {
        return Ok(to_ts(date, time_value));
    }
    if let Some(date) = parse_date(value) {
        return Ok(to_ts(date, time::Time::MIDNIGHT));
    }
    // fromisoformat fallback: accept "date time" (space separator) and an
    // optional trailing "Z"/offset the two strict formats above reject.
    let normalized = value.trim().replace('Z', "+00:00");
    let date_part = normalized.split(['T', ' ']).next().unwrap_or_default();
    let Some(date) = parse_date(date_part) else {
        return Err(invalid());
    };
    let time_part = normalized
        .split_once(['T', ' '])
        .map(|(_, rest)| rest)
        .map(|rest| rest.split(['+', '-']).next().unwrap_or_default())
        .unwrap_or_default();
    let time_value = if time_part.is_empty() {
        time::Time::MIDNIGHT
    } else {
        parse_time(time_part).ok_or_else(invalid)?
    };
    Ok(to_ts(date, time_value))
}

/// Formats a unix timestamp as UTC `(YYYY-MM-DD, HH:MM)`, matching Python's
/// `datetime.fromtimestamp(ts, timezone.utc).strftime(...)`.
fn report_date_time_utc(timestamp: i64) -> (String, String) {
    let Ok(value) = time::OffsetDateTime::from_unix_timestamp(timestamp) else {
        return (String::new(), String::new());
    };
    (
        format!(
            "{:04}-{:02}-{:02}",
            value.year(),
            value.month() as u8,
            value.day()
        ),
        format!("{:02}:{:02}", value.hour(), value.minute()),
    )
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}
/// Matches FastAPI's automatic validation of a typed integer query parameter
/// (e.g. `page: int = 1`): a present-but-non-numeric value never reaches the
/// route handler and instead produces a 422 with this `detail` shape, rather
/// than being silently coerced to a default.
fn int_query_validation_error(
    query: &HashMap<String, String>,
    fields: &[&str],
    request_id: &str,
) -> Option<Response> {
    for field in fields {
        if query
            .get(*field)
            .is_some_and(|value| value.parse::<i64>().is_err())
        {
            return Some(validation_errors(
                vec![json!({
                    "loc": ["query", field],
                    "msg": "value is not a valid integer",
                    "type": "type_error.integer"
                })],
                request_id,
            ));
        }
    }
    None
}

fn analytics_query_error(
    query: &HashMap<String, String>,
    has_limit: bool,
    request_id: &str,
) -> Option<Response> {
    if let Some(response) = int_query_validation_error(query, &["start_ts", "end_ts"], request_id) {
        return Some(response);
    }
    if !has_limit {
        return None;
    }
    let raw = query.get("limit")?;
    let Ok(limit) = raw.parse::<i64>() else {
        return Some(validation_errors(
            vec![json!({
                "loc": ["query", "limit"],
                "msg": "value is not a valid integer",
                "type": "type_error.integer"
            })],
            request_id,
        ));
    };
    if limit < 1 {
        return Some(validation_errors(
            vec![json!({
                "loc": ["query", "limit"],
                "msg": "ensure this value is greater than or equal to 1",
                "type": "value_error.number.not_ge",
                "ctx": {"limit_value": 1}
            })],
            request_id,
        ));
    }
    if limit > 100 {
        return Some(validation_errors(
            vec![json!({
                "loc": ["query", "limit"],
                "msg": "ensure this value is less than or equal to 100",
                "type": "value_error.number.not_le",
                "ctx": {"limit_value": 100}
            })],
            request_id,
        ));
    }
    None
}

fn analytics_denied(request_id: &str) -> Response {
    error(
        StatusCode::FORBIDDEN,
        "ANALYTICS001",
        "You do not have permission to view analytics",
        request_id,
    )
}

fn analytics_time_range(query: &HashMap<String, String>) -> (i64, i64) {
    if let (Some(start), Some(end)) = (
        query
            .get("start_ts")
            .and_then(|value| value.parse().ok())
            .filter(|value| *value != 0),
        query
            .get("end_ts")
            .and_then(|value| value.parse().ok())
            .filter(|value| *value != 0),
    ) {
        return (start, end);
    }
    let end = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let duration = match query.get("range").map(String::as_str).unwrap_or("24h") {
        "1h" => 3_600,
        "7d" => 604_800,
        "30d" => 2_592_000,
        _ => 86_400,
    };
    (end.saturating_sub(duration), end)
}

fn analytics_limit(query: &HashMap<String, String>) -> usize {
    query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10)
        .clamp(1, 100)
}

/// Python's `PercentileMetrics.calculate`: pool every raw latency sample from
/// every bucket (not per-bucket averages), sort, and index each percentile at
/// `max(0, int(p * n) - 1)`.
fn analytics_percentiles(points: &[AggregatedPoint]) -> Value {
    let values: Vec<f64> = points
        .iter()
        .flat_map(|point| point.latencies_ms.iter().copied())
        .collect();
    let (min, max) = (
        values.iter().copied().fold(f64::INFINITY, f64::min),
        values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
    );
    let (p50, p75, p90, p95, p99) = pooled_percentiles(values.iter().copied());
    json!({
        "p50": p50, "p75": p75, "p90": p90, "p95": p95, "p99": p99,
        "min": if values.is_empty() { 0.0 } else { min },
        "max": if values.is_empty() { 0.0 } else { max }
    })
}

fn analytics_entity(entity: &EntityCounter, key: &str) -> Value {
    json!({key: entity.name, "count": entity.count})
}

fn analytics_endpoint(entity: &EndpointEntity) -> Value {
    let error_rate = if entity.count == 0 {
        0.0
    } else {
        entity.error_count as f64 / entity.count as f64
    };
    let (p50, p75, p90, p95, p99) = entity.percentiles;
    json!({
        "endpoint_uri": entity.name,
        "count": entity.count,
        "error_count": entity.error_count,
        "error_rate": error_rate,
        "avg_ms": entity.avg_ms,
        "percentiles": {"p50": p50, "p75": p75, "p90": p90, "p95": p95, "p99": p99}
    })
}

fn analytics_series_point(point: &AggregatedPoint, metric_type: Option<&str>) -> Value {
    let error_rate = if point.requests == 0 {
        0.0
    } else {
        point.errors as f64 / point.requests as f64
    };
    let mut value = Map::new();
    value.insert("timestamp".to_owned(), json!(point.timestamp));
    match metric_type {
        Some("request_count") => {
            value.insert("count".to_owned(), json!(point.requests));
        }
        Some("error_rate") => {
            value.insert("error_rate".to_owned(), json!(error_rate));
            value.insert("error_count".to_owned(), json!(point.errors));
        }
        Some("latency") => {
            value.insert("avg_ms".to_owned(), json!(point.latency_ms));
            value.insert(
                "percentiles".to_owned(),
                analytics_percentiles(std::slice::from_ref(point)),
            );
        }
        Some("bandwidth") => {
            value.insert("bytes_in".to_owned(), json!(point.bytes_in));
            value.insert("bytes_out".to_owned(), json!(point.bytes_out));
        }
        Some(_) => {}
        None => {
            value.insert("count".to_owned(), json!(point.requests));
            value.insert("error_count".to_owned(), json!(point.errors));
            value.insert("error_rate".to_owned(), json!(error_rate));
            value.insert("avg_ms".to_owned(), json!(point.latency_ms));
            value.insert(
                "percentiles".to_owned(),
                analytics_percentiles(std::slice::from_ref(point)),
            );
            value.insert("bytes_in".to_owned(), json!(point.bytes_in));
            value.insert("bytes_out".to_owned(), json!(point.bytes_out));
            value.insert("unique_users".to_owned(), json!(0));
        }
    }
    Value::Object(value)
}

fn analytics_timeseries(query: &HashMap<String, String>, request_id: &str) -> Response {
    let (start_ts, end_ts) = analytics_time_range(query);
    let points =
        global_analytics().get_timeseries_range(start_ts.max(0) as u64, end_ts.max(0) as u64);
    let metric_type = query.get("metric_type").map(String::as_str);
    let series = points
        .iter()
        .map(|point| analytics_series_point(point, metric_type))
        .collect::<Vec<_>>();
    success(
        StatusCode::OK,
        json!({
            "time_range": {"start_ts": start_ts, "end_ts": end_ts},
            "granularity": query.get("granularity").map(String::as_str).unwrap_or("auto"),
            "series": series,
            "data_points": series.len()
        }),
        request_id,
    )
}

fn analytics_top(kind: &str, query: &HashMap<String, String>, request_id: &str) -> Response {
    let (start_ts, end_ts) = analytics_time_range(query);
    let limit = analytics_limit(query);
    let analytics = global_analytics();
    let (start_bound, end_bound) = (start_ts.max(0) as u64, end_ts.max(0) as u64);
    let response = match kind {
        "api" => {
            // Reconstructed from only the minute buckets in [start_ts, end_ts],
            // matching Python's enhanced_metrics_store.get_snapshot-backed top_apis
            // rather than an all-time process-global total.
            let all = analytics.get_top_apis_in_range(start_bound, end_bound, usize::MAX);
            let entries = all
                .iter()
                .take(limit)
                .map(|entry| analytics_entity(entry, "api"))
                .collect::<Vec<_>>();
            json!({
                "time_range": {"start_ts": start_ts, "end_ts": end_ts},
                "top_apis": entries,
                "total_apis": all.len()
            })
        }
        "user" => {
            let all = analytics.get_top_users_in_range(start_bound, end_bound, usize::MAX);
            let entries = all
                .iter()
                .take(limit)
                .map(|entry| analytics_entity(entry, "user"))
                .collect::<Vec<_>>();
            json!({
                "time_range": {"start_ts": start_ts, "end_ts": end_ts},
                "top_users": entries,
                "total_users": all.len()
            })
        }
        _ => {
            let all = analytics.get_top_endpoints_in_range(start_bound, end_bound, usize::MAX);
            let mut entries = all.iter().map(analytics_endpoint).collect::<Vec<_>>();
            let total_endpoints = entries.len();
            let sort_by = query.get("sort_by").map(String::as_str).unwrap_or("count");
            let sort_key = match sort_by {
                "error_rate" => Some("error_rate"),
                "avg_ms" => Some("avg_ms"),
                _ => None,
            };
            if let Some(key) = sort_key {
                entries.sort_by(|left, right| {
                    right[key]
                        .as_f64()
                        .unwrap_or_default()
                        .total_cmp(&left[key].as_f64().unwrap_or_default())
                });
            }
            entries.truncate(limit);
            json!({
                "time_range": {"start_ts": start_ts, "end_ts": end_ts},
                "sort_by": sort_by,
                "top_endpoints": entries,
                "total_endpoints": total_endpoints
            })
        }
    };
    success(StatusCode::OK, response, request_id)
}

async fn analytics_overview(
    state: &AppState,
    username: &str,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    if !has_permission(state, username, "view_analytics").await {
        return analytics_denied(request_id);
    }
    let (start_ts, end_ts) = analytics_time_range(query);
    let analytics = global_analytics();
    let points = analytics.get_timeseries_range(start_ts.max(0) as u64, end_ts.max(0) as u64);
    let total_requests = points.iter().map(|point| point.requests).sum::<u64>();
    let total_errors = points.iter().map(|point| point.errors).sum::<u64>();
    let total_ms = points
        .iter()
        .map(|point| point.latency_ms * point.requests as f64)
        .sum::<f64>();
    let total_bytes_in = points.iter().map(|point| point.bytes_in).sum::<u64>();
    let total_bytes_out = points.iter().map(|point| point.bytes_out).sum::<u64>();
    let error_rate = if total_requests == 0 {
        0.0
    } else {
        total_errors as f64 / total_requests as f64
    };
    let avg_response_ms = if total_requests == 0 {
        0.0
    } else {
        total_ms / total_requests as f64
    };
    let top_apis = analytics
        .get_top_apis(10)
        .iter()
        .map(|entry| analytics_entity(entry, "api"))
        .collect::<Vec<_>>();
    let top_users = analytics
        .get_top_users(10)
        .iter()
        .map(|entry| analytics_entity(entry, "user"))
        .collect::<Vec<_>>();
    success(
        StatusCode::OK,
        json!({
            "time_range": {
                "start_ts": start_ts,
                "end_ts": end_ts,
                "duration_seconds": end_ts.saturating_sub(start_ts)
            },
            "summary": {
                "total_requests": total_requests,
                "total_errors": total_errors,
                "error_rate": error_rate,
                "avg_response_ms": avg_response_ms,
                "unique_users": analytics.user_count(),
                "total_bandwidth": total_bytes_in + total_bytes_out,
                "bandwidth_in": total_bytes_in,
                "bandwidth_out": total_bytes_out
            },
            "percentiles": analytics_percentiles(&points),
            "top_apis": top_apis,
            "top_users": top_users,
            "status_distribution": analytics.get_status_distribution()
        }),
        request_id,
    )
}

async fn get_security_settings(
    state: &AppState,
    headers: &HeaderMap,
    direct_addr: Option<std::net::SocketAddr>,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let is_memory = state.config.shared_storage.storage_mode.to_uppercase() == "MEM";
    match storage
        .find_one("settings", &json!({"type": "security_settings"}))
        .await
    {
        Ok(current) => {
            let mut settings = merge_security_settings(state, current);
            let client_ip = direct_addr.map(|addr| addr.ip().to_string());
            let client_ip_xff = headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(str::trim);
            let warnings = if settings
                .get("trust_x_forwarded_for")
                .and_then(Value::as_bool)
                == Some(true)
                && settings
                    .get("xff_trusted_proxies")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
            {
                vec![
                    "Trust X-Forwarded-For is enabled, but no trusted proxies are configured. Set xff_trusted_proxies to avoid header spoofing.",
                ]
            } else {
                Vec::new()
            };
            if let Value::Object(ref mut map) = settings {
                map.insert("memory_only".to_owned(), json!(is_memory));
                map.insert("security_warnings".to_owned(), json!(warnings));
                map.insert(
                    "allow_localhost_bypass_locked".to_owned(),
                    json!(state.config.shared_storage.local_host_ip_bypass_locked),
                );
                if state.config.shared_storage.local_host_ip_bypass_locked {
                    map.insert(
                        "allow_localhost_bypass".to_owned(),
                        json!(state.config.shared_storage.local_host_ip_bypass),
                    );
                }
                map.insert("client_ip".to_owned(), json!(client_ip));
                map.insert("client_ip_xff".to_owned(), json!(client_ip_xff));
            }
            success(StatusCode::OK, strip_internal(settings), request_id)
        }
        Err(_) => unexpected(request_id),
    }
}

fn merge_security_settings(state: &AppState, current: Option<Value>) -> Value {
    crate::storage::security_settings::merge(&state.config, current.as_ref())
}

async fn upsert_security_settings(
    state: &AppState,
    username: &str,
    payload: Value,
    request_id: &str,
) -> Response {
    let payload = match normalize_security_settings(payload) {
        Ok(payload) => payload,
        Err(errors) => return validation_errors(errors, request_id),
    };
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let filter = json!({"type": "security_settings"});
    let existing = match storage.find_one("settings", &filter).await {
        Ok(existing) => existing,
        Err(_) => return unexpected(request_id),
    };
    let is_memory = state.config.shared_storage.storage_mode.to_uppercase() == "MEM";
    let mut updated_doc = merge_security_settings(state, existing);
    if let Value::Object(base) = &mut updated_doc {
        base.extend(payload);
    }
    // Python updates by type, not by collection order or the presence of _id.
    // In particular, imported memory records without _id must not cause the
    // whole settings collection to be replaced.
    let result = match storage.update_one("settings", &filter, &updated_doc).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => storage
            .insert_one("settings", updated_doc.clone())
            .await
            .map(|_| ()),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => {
            crate::storage::security_settings::persist(&state.config, &updated_doc);
            state
                .runtime
                .update_memory_autosave_config(MemoryAutosaveConfig::from_settings(Some(
                    &updated_doc,
                )));
            audit::management_mutation(
                username,
                "security.update_settings",
                "security_settings",
                "success",
            );
            let mut settings = strip_internal(updated_doc);
            if let Value::Object(ref mut map) = settings {
                map.insert("memory_only".to_owned(), json!(is_memory));
            }
            success(StatusCode::OK, settings, request_id)
        }
        Err(_) => unexpected(request_id),
    }
}

// Pydantic v1 accepts these exact JSON boolean representations, without
// trimming strings. Keep coercion local to this model, not global policy input.
fn security_setting_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => match value.as_f64()? {
            0.0 => Some(false),
            1.0 => Some(true),
            _ => None,
        },
        Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
            "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// Pydantic v1's str validator uses Python spelling for JSON scalars.
fn security_setting_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(if *value { "True" } else { "False" }.to_owned()),
        Value::Number(value) if value.is_i64() || value.is_u64() => Some(value.to_string()),
        Value::Number(value) => {
            let value = value.as_f64()?;
            let mut buffer = ryu::Buffer::new();
            // Ryū preserves Python's round-to-even choice for shortest
            // representations; Rust's Debug formatter differs at some ties.
            let rendered = buffer.format_finite(value);
            if value.abs() > 0.0 && value.abs() < 0.0001 && !rendered.contains('e') {
                // Ryū writes 1e-5 in decimal; Python switches at 1e-4.
                let (sign, unsigned) = rendered
                    .strip_prefix('-')
                    .map_or(("", rendered), |unsigned| ("-", unsigned));
                let digits = unsigned.strip_prefix("0.")?;
                let leading = digits.chars().take_while(|digit| *digit == '0').count();
                let digits = &digits[leading..];
                let mantissa = if digits.len() == 1 {
                    digits.to_owned()
                } else {
                    format!("{}.{}", &digits[..1], &digits[1..])
                };
                return Some(format!("{sign}{mantissa}e-{:02}", leading + 1));
            }
            // Python uses an explicit exponent sign and at least two digits.
            if let Some((mantissa, exponent)) = rendered.split_once('e') {
                let exponent = exponent.parse::<i32>().ok()?;
                Some(format!("{mantissa}e{exponent:+03}"))
            } else {
                Some(rendered.to_owned())
            }
        }
        _ => None,
    }
}

fn security_setting_interval(value: &Value) -> Result<u64, Value> {
    let integer_error = || {
        json!({
            "loc": ["body", "auto_save_frequency_seconds"],
            "msg": "value is not a valid integer", "type": "type_error.integer"
        })
    };
    let minimum_error = || {
        json!({
            "loc": ["body", "auto_save_frequency_seconds"],
            "msg": "ensure this value is greater than or equal to 60",
            "type": "value_error.number.not_ge", "ctx": {"limit_value": 60}
        })
    };
    let integer = match value {
        Value::Bool(value) => i128::from(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                i128::from(value)
            } else if let Some(value) = value.as_i64() {
                i128::from(value)
            } else {
                let value = value.as_f64().ok_or_else(integer_error)?.trunc();
                if value < 60.0 {
                    return Err(minimum_error());
                }
                // Do not let float-to-int saturation turn an overflow into an
                // accepted but different interval. Python's unbounded integers
                // beyond the runtime's u64 range remain a separate parity gap.
                if !value.is_finite() || value >= 18_446_744_073_709_551_616.0 {
                    return Err(integer_error());
                }
                value as i128
            }
        }
        Value::String(value) => {
            crate::python_scalar::parse_model_integer(value).ok_or_else(integer_error)?
        }
        _ => return Err(integer_error()),
    };
    if integer < 60 {
        return Err(minimum_error());
    }
    u64::try_from(integer).map_err(|_| integer_error())
}

fn normalize_security_settings(payload: Value) -> Result<Map<String, Value>, Vec<Value>> {
    let mut values = match payload {
        Value::Null => return Ok(Map::new()),
        Value::Object(values) => values,
        _ => {
            return Err(vec![json!({
                "loc": ["body"],
                "msg": "value is not a valid object",
                "type": "type_error.dict"
            })]);
        }
    };
    let mut normalized = Map::new();
    let mut errors = Vec::new();
    // Validation errors follow the Python model's declaration order.
    for key in [
        "enable_auto_save",
        "auto_save_frequency_seconds",
        "dump_path",
        "ip_whitelist",
        "ip_blacklist",
        "trust_x_forwarded_for",
        "xff_trusted_proxies",
        "allow_localhost_bypass",
    ] {
        let Some(value) = values.remove(key) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        match key {
            "enable_auto_save" | "trust_x_forwarded_for" | "allow_localhost_bypass" => {
                if let Some(value) = security_setting_bool(&value) {
                    normalized.insert(key.to_owned(), json!(value));
                } else {
                    errors.push(json!({"loc": ["body", key],
                        "msg": "value could not be parsed to a boolean", "type": "type_error.bool"}));
                }
                continue;
            }
            "auto_save_frequency_seconds" => {
                match security_setting_interval(&value) {
                    Ok(value) => {
                        normalized.insert(key.to_owned(), json!(value));
                    }
                    Err(error) => errors.push(error),
                }
                continue;
            }
            "dump_path" => {
                if let Some(value) = security_setting_string(&value) {
                    normalized.insert(key.to_owned(), json!(value));
                } else {
                    errors.push(json!({"loc": ["body", key],
                        "msg": "str type expected", "type": "type_error.str"}));
                }
                continue;
            }
            "ip_whitelist" | "ip_blacklist" | "xff_trusted_proxies" => {
                let Value::Array(values) = value else {
                    errors.push(json!({"loc": ["body", key],
                        "msg": "value is not a valid list", "type": "type_error.list"}));
                    continue;
                };
                let mut strings = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    if let Some(value) = security_setting_string(value) {
                        strings.push(value);
                    } else if value.is_null() {
                        errors.push(json!({"loc": ["body", key, index],
                            "msg": "none is not an allowed value", "type": "type_error.none.not_allowed"}));
                    } else {
                        errors.push(json!({"loc": ["body", key, index],
                            "msg": "str type expected", "type": "type_error.str"}));
                    }
                }
                normalized.insert(key.to_owned(), json!(strings));
            }
            // Pydantic's default model configuration ignores unknown fields.
            _ => continue,
        }
    }
    if errors.is_empty() {
        Ok(normalized)
    } else {
        Err(errors)
    }
}

async fn config_export(
    state: &AppState,
    username: &str,
    only: Option<&str>,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    let (permission, permission_code) = match only {
        None => ("manage_gateway", "CFG001"),
        Some("apis") => ("manage_apis", "CFG002"),
        Some("endpoints") => ("manage_endpoints", "CFG007"),
        Some("roles") => ("manage_roles", "CFG003"),
        Some("groups") => ("manage_groups", "CFG004"),
        Some("routings") => ("manage_routings", "CFG005"),
        Some(_) => {
            return error(
                StatusCode::NOT_FOUND,
                "CFG404",
                "Configuration export not found",
                request_id,
            );
        }
    };
    if !has_permission(state, username, permission).await {
        return error(
            StatusCode::FORBIDDEN,
            permission_code,
            "Insufficient permissions",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if let Some("apis") = only {
        if let (Some(api_name), Some(api_version)) =
            (query.get("api_name"), query.get("api_version"))
        {
            let filter = json!({"api_name": api_name, "api_version": api_version});
            let api = match storage.find_one("apis", &filter).await {
                Ok(Some(api)) => api,
                Ok(None) => {
                    return error(StatusCode::NOT_FOUND, "CFG404", "API not found", request_id);
                }
                Err(_) => return unexpected(request_id),
            };
            let endpoints = match storage.find_many("endpoints", &filter).await {
                Ok(endpoints) => endpoints
                    .into_iter()
                    .map(strip_internal)
                    .collect::<Vec<_>>(),
                Err(_) => return unexpected(request_id),
            };
            audit::config_export(username, only);
            return success(
                StatusCode::OK,
                json!({
                    "api": strip_internal(api),
                    "endpoints": endpoints
                }),
                request_id,
            );
        }
    }
    if let Some(collection) = only {
        let named_export = match collection {
            "roles" => query.get("role_name").map(|value| {
                (
                    json!({"role_name": value}),
                    "role",
                    "CFG405",
                    "Role not found",
                )
            }),
            "groups" => query.get("group_name").map(|value| {
                (
                    json!({"group_name": value}),
                    "group",
                    "CFG406",
                    "Group not found",
                )
            }),
            "routings" => query.get("client_key").map(|value| {
                (
                    json!({"client_key": value}),
                    "routing",
                    "CFG407",
                    "Routing not found",
                )
            }),
            _ => None,
        };
        if let Some((filter, response_key, missing_code, missing_text)) = named_export {
            return match storage.find_one(collection, &filter).await {
                Ok(Some(value)) => {
                    audit::config_export(username, only);
                    success(
                        StatusCode::OK,
                        json!({response_key: strip_internal(value)}),
                        request_id,
                    )
                }
                Ok(None) => error(
                    StatusCode::NOT_FOUND,
                    missing_code,
                    missing_text,
                    request_id,
                ),
                Err(_) => unexpected(request_id),
            };
        }
        let filter = if collection == "endpoints" {
            let mut filter = Map::new();
            for key in ["api_name", "api_version"] {
                if let Some(value) = query.get(key) {
                    filter.insert(key.to_owned(), json!(value));
                }
            }
            Value::Object(filter)
        } else {
            json!({})
        };
        let values = match storage.find_many(collection, &filter).await {
            Ok(values) => values.into_iter().map(strip_internal).collect::<Vec<_>>(),
            Err(_) => return unexpected(request_id),
        };
        audit::config_export(username, only);
        return success(StatusCode::OK, json!({collection: values}), request_id);
    }
    let mut output = Map::new();
    for collection in ["apis", "endpoints", "roles", "groups", "routings"] {
        let values = match storage.find_many(collection, &json!({})).await {
            Ok(values) => values.into_iter().map(strip_internal).collect::<Vec<_>>(),
            Err(_) => return unexpected(request_id),
        };
        output.insert(collection.to_owned(), json!(values));
    }
    audit::config_export(username, only);
    success(StatusCode::OK, Value::Object(output), request_id)
}

async fn config_import(
    state: &AppState,
    username: &str,
    payload: Value,
    request_id: &str,
) -> Response {
    if !has_permission(state, username, "manage_gateway").await {
        return error(
            StatusCode::FORBIDDEN,
            "CFG006",
            "Insufficient permissions",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let mut snapshot_data = Map::new();
    for collection in ["apis", "endpoints", "roles", "groups", "routings"] {
        let values = match storage.find_many(collection, &json!({})).await {
            Ok(values) => values.into_iter().map(strip_internal).collect::<Vec<_>>(),
            Err(_) => return unexpected(request_id),
        };
        snapshot_data.insert(collection.to_owned(), json!(values));
    }
    let timestamp = timestamp_now_naive().replace('T', " ");
    if storage
        .insert_one(
            "config_snapshots",
            json!({
                "snapshot_id": Uuid::new_v4().to_string(),
                "timestamp": timestamp,
                "created_by": username,
                "data": snapshot_data,
            }),
        )
        .await
        .is_err()
    {
        return unexpected(request_id);
    }
    let mut imported = Map::new();
    for collection in ["apis", "endpoints", "roles", "groups", "routings"] {
        let values = match payload.get(collection) {
            None => Vec::new(),
            Some(value) if !python_truthy_json(value) => Vec::new(),
            Some(Value::Array(values)) => values.clone(),
            Some(_) => return unexpected(request_id),
        };
        let mut count = 0;
        for value in values {
            let Some(document) = value.as_object() else {
                return unexpected(request_id);
            };
            if config_upsert(storage, collection, document).await.is_err() {
                return unexpected(request_id);
            }
            count += 1;
        }
        imported.insert(collection.to_owned(), json!(count));
    }
    audit::management_mutation(username, "config.import", "configuration", "success");
    success(
        StatusCode::OK,
        json!({"imported": Value::Object(imported)}),
        request_id,
    )
}

async fn config_upsert(
    storage: &SharedStorage,
    collection: &str,
    document: &Map<String, Value>,
) -> Result<(), crate::storage::runtime::StorageError> {
    let required: &[&str] = match collection {
        "apis" => &["api_name", "api_version"],
        "endpoints" => &["api_name", "api_version", "endpoint_method", "endpoint_uri"],
        "roles" => &["role_name"],
        "groups" => &["group_name"],
        "routings" => &["client_key"],
        _ => return Ok(()),
    };
    if required.iter().any(|field| {
        document
            .get(*field)
            .is_none_or(|value| !python_truthy_json(value))
    }) {
        return Ok(());
    }
    let filter = Value::Object(
        required
            .iter()
            .map(|field| ((*field).to_owned(), document[*field].clone()))
            .collect(),
    );
    let mut value = Value::Object(document.clone());
    strip_mongo_id(&mut value);
    if collection == "endpoints" {
        if let Some(api) = storage
            .find_one(
                "apis",
                &json!({
                    "api_name": document["api_name"],
                    "api_version": document["api_version"],
                }),
            )
            .await?
            && let Some(api_id) = api.get("api_id")
        {
            value["api_id"] = api_id.clone();
        }
        if value.get("endpoint_id").is_none() {
            value["endpoint_id"] = json!(Uuid::new_v4().to_string());
        }
    }
    let existing = storage.find_one(collection, &filter).await?;
    if collection == "apis" {
        if existing.is_none() {
            if value.get("api_id").is_none() {
                value["api_id"] = json!(Uuid::new_v4().to_string());
            }
            if value.get("api_path").is_none() {
                value["api_path"] = json!(format!(
                    "/{}/{}",
                    python_string(&document["api_name"]),
                    python_string(&document["api_version"]),
                ));
            }
        } else if value.get("api_id").is_none()
            && let Some(api_id) = existing.as_ref().and_then(|api| api.get("api_id"))
        {
            value["api_id"] = api_id.clone();
        }
    }
    if existing.is_some() {
        storage.update_one(collection, &filter, &value).await?;
    } else {
        storage.insert_one(collection, value).await?;
    }
    Ok(())
}

fn python_string(value: &Value) -> String {
    security_setting_string(value).unwrap_or_else(|| value.to_string())
}

async fn config_rollback(
    state: &AppState,
    username: &str,
    _payload: Value,
    request_id: &str,
) -> Response {
    if !has_permission(state, username, "manage_gateway").await {
        return http_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rollback failed",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let snapshots = match storage.find_many("config_snapshots", &json!({})).await {
        Ok(snapshots) => snapshots,
        Err(_) => {
            return http_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Rollback failed",
                request_id,
            );
        }
    };
    let Some(snapshot) = snapshots.into_iter().max_by(|left, right| {
        left.get("timestamp")
            .and_then(Value::as_str)
            .cmp(&right.get("timestamp").and_then(Value::as_str))
    }) else {
        return error(
            StatusCode::NOT_FOUND,
            "CFG404",
            "No snapshot found",
            request_id,
        );
    };
    let Some(data) = snapshot.get("data").and_then(Value::as_object) else {
        return http_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rollback failed",
            request_id,
        );
    };
    for collection in ["apis", "endpoints", "roles", "groups", "routings"] {
        let Some(values) = data.get(collection).and_then(Value::as_array) else {
            return http_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Rollback failed",
                request_id,
            );
        };
        if storage
            .replace_collection(collection, values.clone())
            .await
            .is_err()
        {
            return http_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Rollback failed",
                request_id,
            );
        }
    }
    let restored_to = snapshot.get("timestamp").cloned().unwrap_or(Value::Null);
    let snapshot_id = snapshot.get("snapshot_id").cloned().unwrap_or(Value::Null);
    audit::management_mutation(
        username,
        "config.rollback",
        snapshot_id.as_str().unwrap_or("latest"),
        "success",
    );
    success(
        StatusCode::OK,
        json!({"message": format!("Configuration rolled back to {}", restored_to.as_str().unwrap_or("latest"))}),
        request_id,
    )
}

async fn analytics_detail(
    state: &AppState,
    username: &str,
    kind: &str,
    key: &str,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    if !has_permission(state, username, "view_analytics").await {
        return analytics_denied(request_id);
    }
    let (start_ts, end_ts) = analytics_time_range(query);
    let analytics = global_analytics();
    if kind == "api" {
        let (api_name, version) = key.split_once('/').unwrap_or((key, ""));
        let api_key = format!("rest:{api_name}");
        let entry = analytics
            .get_top_apis(analytics.api_count())
            .into_iter()
            .find(|entry| entry.name == api_key);
        let Some(entry) = entry else {
            return error(
                StatusCode::NOT_FOUND,
                "ANALYTICS404",
                &format!("No data found for API: {api_name}/{version}"),
                request_id,
            );
        };
        let endpoint_prefix = format!("/{api_name}/{version}");
        let gateway_prefix = format!("/api/rest/{api_name}/{version}");
        let endpoints = analytics
            .get_top_endpoints(analytics.endpoint_count())
            .iter()
            .filter(|endpoint| {
                endpoint.name.starts_with(&endpoint_prefix)
                    || endpoint.name.starts_with(&gateway_prefix)
            })
            .map(|endpoint| {
                analytics_endpoint(&EndpointEntity {
                    name: endpoint.name.clone(),
                    count: endpoint.count,
                    error_count: endpoint.error_count,
                    avg_ms: 0.0,
                    percentiles: (0.0, 0.0, 0.0, 0.0, 0.0),
                })
            })
            .collect::<Vec<_>>();
        return success(
            StatusCode::OK,
            json!({
                "api_name": api_name,
                "version": version,
                "time_range": {"start_ts": start_ts, "end_ts": end_ts},
                "summary": analytics_entity(&entry, "api"),
                "endpoints": endpoints
            }),
            request_id,
        );
    }

    let entry = analytics
        .get_top_users(analytics.user_count())
        .into_iter()
        .find(|entry| entry.name == key);
    let Some(entry) = entry else {
        return error(
            StatusCode::NOT_FOUND,
            "ANALYTICS404",
            &format!("No data found for user: {key}"),
            request_id,
        );
    };
    success(
        StatusCode::OK,
        json!({
            "username": key,
            "time_range": {"start_ts": start_ts, "end_ts": end_ts},
            "summary": analytics_entity(&entry, "user")
        }),
        request_id,
    )
}

fn config_current(state: &AppState, request_id: &str) -> Response {
    success(
        StatusCode::OK,
        json!({
            "config": state.hot_reload.dump(),
            "source": "Environment variables override config file values",
            "reloadable_keys": ["GATEWAY_TIMEOUT", "RETRY_ENABLED", "RETRY_MAX_ATTEMPTS"],
            "restart_required": true,
            "reload_behavior": "Supported HTTP gateway settings apply to subsequent REST, GraphQL, and SOAP requests; remaining settings require restart"
        }),
        request_id,
    )
}

fn reloadable_keys() -> Value {
    json!([
        {
            "key": "LOG_LEVEL",
            "description": "Log level (DEBUG, INFO, WARNING, ERROR)",
            "example": "INFO"
        },
        {"key": "LOG_FORMAT", "description": "Log format (json, text)", "example": "json"},
        {"key": "LOG_FILE", "description": "Log file path", "example": "logs/doorman.log"},
        {"key": "GATEWAY_TIMEOUT", "description": "Gateway timeout in seconds", "example": "30"},
        {"key": "UPSTREAM_TIMEOUT", "description": "Upstream timeout in seconds", "example": "30"},
        {"key": "CONNECTION_TIMEOUT", "description": "Connection timeout in seconds", "example": "10"},
        {"key": "RATE_LIMIT_ENABLED", "description": "Enable rate limiting", "example": "true"},
        {"key": "RATE_LIMIT_REQUESTS", "description": "Requests per window", "example": "100"},
        {"key": "RATE_LIMIT_WINDOW", "description": "Window size in seconds", "example": "60"},
        {"key": "CACHE_TTL", "description": "Cache TTL in seconds", "example": "300"},
        {"key": "CACHE_MAX_SIZE", "description": "Maximum cache entries", "example": "1000"},
        {"key": "CIRCUIT_BREAKER_ENABLED", "description": "Enable circuit breaker", "example": "true"},
        {"key": "CIRCUIT_BREAKER_THRESHOLD", "description": "Failures before opening", "example": "5"},
        {"key": "CIRCUIT_BREAKER_TIMEOUT", "description": "Timeout before retry (seconds)", "example": "60"},
        {"key": "RETRY_ENABLED", "description": "Enable retry logic", "example": "true"},
        {"key": "RETRY_MAX_ATTEMPTS", "description": "Maximum retry attempts", "example": "3"},
        {"key": "RETRY_BACKOFF", "description": "Backoff multiplier", "example": "1.0"},
        {"key": "METRICS_ENABLED", "description": "Enable metrics collection", "example": "true"},
        {"key": "METRICS_INTERVAL", "description": "Metrics interval (seconds)", "example": "60"},
        {"key": "FEATURE_REQUEST_REPLAY", "description": "Enable request replay", "example": "false"},
        {"key": "FEATURE_AB_TESTING", "description": "Enable A/B testing", "example": "false"},
        {"key": "FEATURE_COST_ANALYTICS", "description": "Enable cost analytics", "example": "false"}
    ])
}

fn active_reloadable_keys() -> Value {
    json!([
        {"key": "GATEWAY_TIMEOUT", "description": "HTTP gateway timeout in seconds", "example": "30"},
        {"key": "RETRY_ENABLED", "description": "Enable HTTP gateway retries", "example": "true"},
        {"key": "RETRY_MAX_ATTEMPTS", "description": "Maximum HTTP gateway attempts", "example": "3"}
    ])
}

fn restart_required_keys() -> Value {
    let active = ["GATEWAY_TIMEOUT", "RETRY_ENABLED", "RETRY_MAX_ATTEMPTS"];
    Value::Array(
        reloadable_keys()
            .as_array()
            .into_iter()
            .flatten()
            .filter(|value| {
                value
                    .get("key")
                    .and_then(Value::as_str)
                    .is_none_or(|key| !active.contains(&key))
            })
            .cloned()
            .collect(),
    )
}

async fn demo_seed(
    state: &AppState,
    username: &str,
    query: &HashMap<String, String>,
    request_id: &str,
) -> Response {
    // Python: `if not await is_admin_user(username)` -- a role-based admin
    // check, not a literal username comparison.
    if !is_admin_user(state, username).await {
        return error(
            StatusCode::FORBIDDEN,
            "DEMO001",
            "Permission denied to run seeder",
            request_id,
        );
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    // Python has no such gate and will happily seed a real MongoDB; Rust
    // deliberately refuses outside memory mode as an additional safety guard
    // against seeding synthetic data into a production database. This is a
    // documented approved addition, not a parity gap, so it uses its own
    // error code rather than colliding with DEMO001 above.
    if !storage.is_memory() {
        return error(
            StatusCode::BAD_REQUEST,
            "DEMO002",
            "Demo seed is available only in memory mode",
            request_id,
        );
    }
    let query_usize = |key: &str, default: usize| {
        query
            .get(key)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default)
    };
    let options = crate::demo_seed::SeedOptions {
        users: query_usize("users", 40),
        apis: query_usize("apis", 15),
        endpoints: query_usize("endpoints", 6),
        groups: query_usize("groups", 8),
        protos: query_usize("protos", 6),
        logs: query_usize("logs", 1500),
        seed: query
            .get("seed")
            .and_then(|value| value.parse::<u64>().ok()),
    };
    match crate::demo_seed::run_seed(storage, &options).await {
        Ok(mut result) => {
            if let Some(object) = result.as_object_mut() {
                object.insert("message".to_owned(), json!("Seed completed"));
            }
            success(StatusCode::OK, result, request_id)
        }
        Err(error_value) => {
            tracing::error!(error = %error_value, "demo seed error");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DEMO999",
                "Failed to seed demo data",
                request_id,
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CorsCheckConfig {
    origins: Vec<String>,
    safe_origins: Vec<String>,
    credentials: bool,
    methods: Vec<String>,
    headers: Vec<String>,
    strict: bool,
    used_wildcard_headers: bool,
}

fn cors_check_config_from(get: impl Fn(&str) -> Option<String>) -> CorsCheckConfig {
    let csv = |value: String| {
        value
            .split(',')
            .map(|item| item.trim().to_owned())
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>()
    };
    let origins = {
        let value = get("ALLOWED_ORIGINS").unwrap_or_else(|| "http://localhost:3000".to_owned());
        let parsed = csv(value);
        if parsed.is_empty() {
            vec!["http://localhost:3000".to_owned()]
        } else {
            parsed
        }
    };
    let credentials = get("ALLOW_CREDENTIALS")
        .unwrap_or_else(|| "true".to_owned())
        .to_lowercase()
        == "true";
    let mut methods = {
        let value = get("ALLOW_METHODS")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD".to_owned());
        csv(value)
            .into_iter()
            .map(|method| method.to_uppercase())
            .collect::<Vec<_>>()
    };
    if methods.iter().any(|method| method == "*") {
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            .into_iter()
            .map(str::to_owned)
            .collect();
    }
    if !methods.iter().any(|method| method == "OPTIONS") {
        methods.push("OPTIONS".to_owned());
    }
    let raw_headers_value = get("ALLOW_HEADERS")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "*".to_owned());
    let used_wildcard_headers = raw_headers_value.split(',').any(|header| header == "*");
    let raw_headers = csv(raw_headers_value);
    let headers = if raw_headers.iter().any(|header| header == "*") {
        ["Accept", "Content-Type", "X-CSRF-Token", "Authorization"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        raw_headers
    };
    let strict = get("CORS_STRICT")
        .unwrap_or_else(|| "false".to_owned())
        .to_lowercase()
        == "true";
    let safe_origins = if credentials && origins.iter().any(|origin| origin == "*") {
        vec![
            "http://localhost".to_owned(),
            "http://localhost:3000".to_owned(),
        ]
    } else if strict {
        let safe = origins
            .iter()
            .filter(|origin| origin.as_str() != "*")
            .cloned()
            .collect::<Vec<_>>();
        if safe.is_empty() {
            vec![
                "http://localhost".to_owned(),
                "http://localhost:3000".to_owned(),
            ]
        } else {
            safe
        }
    } else {
        origins.clone()
    };
    CorsCheckConfig {
        origins,
        safe_origins,
        credentials,
        methods,
        headers,
        strict,
        used_wildcard_headers,
    }
}

fn cors_check(payload: Value, request_id: &str) -> Response {
    let payload = match normalize_cors_check(payload) {
        Ok(payload) => payload,
        Err(errors) => return validation_errors(errors, request_id),
    };
    cors_check_with_config(
        payload,
        request_id,
        &cors_check_config_from(|key| env::var(key).ok()),
    )
}

fn normalize_cors_check(payload: Value) -> Result<Value, Vec<Value>> {
    let Value::Object(values) = payload else {
        return Err(vec![json!({
            "loc": ["body"],
            "msg": "value is not a valid dict",
            "type": "type_error.dict"
        })]);
    };
    let mut errors = Vec::new();
    let mut normalized = Map::new();
    for field in ["origin", "method"] {
        match values.get(field) {
            None => errors.push(json!({"loc": ["body", field], "msg": "field required", "type": "value_error.missing"})),
            Some(Value::Null) => errors.push(json!({"loc": ["body", field], "msg": "none is not an allowed value", "type": "type_error.none.not_allowed"})),
            Some(value) => match security_setting_string(value) {
                Some(value) => {
                    normalized.insert(field.to_owned(), json!(value));
                }
                None => errors.push(json!({"loc": ["body", field], "msg": "str type expected", "type": "type_error.str"})),
            },
        }
    }
    match values.get("request_headers") {
        None | Some(Value::Null) => {}
        Some(Value::Array(headers)) => {
            let mut parsed = Vec::with_capacity(headers.len());
            for (index, header) in headers.iter().enumerate() {
                if header.is_null() {
                    errors.push(json!({"loc": ["body", "request_headers", index], "msg": "none is not an allowed value", "type": "type_error.none.not_allowed"}));
                } else if let Some(header) = security_setting_string(header) {
                    parsed.push(header);
                } else {
                    errors.push(json!({"loc": ["body", "request_headers", index], "msg": "str type expected", "type": "type_error.str"}));
                }
            }
            normalized.insert("request_headers".to_owned(), json!(parsed));
        }
        Some(_) => errors.push(json!({"loc": ["body", "request_headers"], "msg": "value is not a valid list", "type": "type_error.list"})),
    }
    match values.get("with_credentials") {
        None | Some(Value::Null) => {}
        Some(value) => match security_setting_bool(value) {
            Some(value) => {
                normalized.insert("with_credentials".to_owned(), json!(value));
            }
            None => errors.push(json!({"loc": ["body", "with_credentials"], "msg": "value could not be parsed to a boolean", "type": "type_error.bool"})),
        },
    }
    if errors.is_empty() {
        Ok(Value::Object(normalized))
    } else {
        Err(errors)
    }
}

fn normalize_chaos_toggle(payload: &Value) -> Result<(String, bool, i64), Vec<Value>> {
    let Some(values) = payload.as_object() else {
        return Err(vec![json!({
            "loc": ["body"],
            "msg": "value is not a valid dict",
            "type": "type_error.dict"
        })]);
    };
    let mut errors = Vec::new();
    let backend = match values.get("backend") {
        None => {
            errors.push(json!({"loc": ["body", "backend"], "msg": "field required", "type": "value_error.missing"}));
            None
        }
        Some(Value::Null) => {
            errors.push(json!({"loc": ["body", "backend"], "msg": "none is not an allowed value", "type": "type_error.none.not_allowed"}));
            None
        }
        Some(value) => match security_setting_string(value) {
            Some(value) => Some(value),
            None => {
                errors.push(json!({"loc": ["body", "backend"], "msg": "str type expected", "type": "type_error.str"}));
                None
            }
        },
    };
    let enabled = match values.get("enabled") {
        None => {
            errors.push(json!({"loc": ["body", "enabled"], "msg": "field required", "type": "value_error.missing"}));
            None
        }
        Some(Value::Null) => {
            errors.push(json!({"loc": ["body", "enabled"], "msg": "none is not an allowed value", "type": "type_error.none.not_allowed"}));
            None
        }
        Some(value) => match security_setting_bool(value) {
            Some(value) => Some(value),
            None => {
                errors.push(json!({"loc": ["body", "enabled"], "msg": "value could not be parsed to a boolean", "type": "type_error.bool"}));
                None
            }
        },
    };
    let duration_ms = match values.get("duration_ms") {
        None | Some(Value::Null) => Some(0),
        Some(value) => match rate_rule_integer(value) {
            Some(value) => Some(value),
            None => {
                errors.push(json!({"loc": ["body", "duration_ms"], "msg": "value is not a valid integer", "type": "type_error.integer"}));
                None
            }
        },
    };
    if errors.is_empty() {
        Ok((backend.unwrap(), enabled.unwrap(), duration_ms.unwrap()))
    } else {
        Err(errors)
    }
}

fn cors_check_with_config(payload: Value, request_id: &str, config: &CorsCheckConfig) -> Response {
    let origin = payload
        .get("origin")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    let method = payload
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_uppercase();
    let request_headers: Vec<String> = payload
        .get("request_headers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let with_credentials = payload
        .get("with_credentials")
        .and_then(Value::as_bool)
        .unwrap_or(config.credentials);

    let origin_allowed = config.safe_origins.contains(&origin)
        || (!config.strict && config.origins.iter().any(|origin| origin == "*"));
    let method_allowed = config.methods.iter().any(|candidate| candidate == &method);
    let allowed_headers_lower: Vec<String> = config
        .headers
        .iter()
        .map(|header| header.to_lowercase())
        .collect();
    let not_allowed_headers: Vec<String> = request_headers
        .iter()
        .filter(|h| !allowed_headers_lower.contains(&h.to_lowercase()))
        .cloned()
        .collect();
    let headers_allowed = not_allowed_headers.is_empty();
    let preflight_allowed = origin_allowed && method_allowed && headers_allowed;

    let mut notes: Vec<String> = Vec::new();
    if config.credentials && config.origins.iter().any(|origin| origin == "*") && !config.strict {
        notes.push("Wildcard origins with credentials can be rejected by browsers; prefer explicit origins or set CORS_STRICT=true.".into());
    }
    if config.used_wildcard_headers {
        notes.push("ALLOW_HEADERS='*' replaced with a conservative default set to satisfy credentialed requests.".into());
    }
    if !origin_allowed {
        notes.push("Origin is not allowed based on current configuration.".into());
    }
    if !method_allowed {
        notes.push("Requested method is not in ALLOW_METHODS.".into());
    }
    if !headers_allowed {
        notes.push(format!(
            "Some requested headers are not allowed: {}",
            not_allowed_headers.join(", ")
        ));
    }

    let preflight_headers = json!({
        "Access-Control-Allow-Origin": if origin_allowed { json!(&origin) } else { Value::Null },
        "Access-Control-Allow-Methods": config.methods.join(", "),
        "Access-Control-Allow-Headers": config.headers.join(", "),
        "Access-Control-Allow-Credentials": if with_credentials && config.credentials { "true" } else { "false" },
        "Vary": "Origin",
    });
    let actual_headers = json!({
        "Access-Control-Allow-Origin": if origin_allowed { json!(&origin) } else { Value::Null },
        "Access-Control-Allow-Credentials": if with_credentials && config.credentials { "true" } else { "false" },
        "Vary": "Origin",
    });

    success(
        StatusCode::OK,
        json!({
            "config": {
                "allowed_origins": config.origins,
                "effective_allowed_origins": config.safe_origins,
                "allow_credentials": config.credentials,
                "allow_methods": config.methods,
                "allow_headers": config.headers,
                "cors_strict": config.strict,
            },
            "input": {
                "origin": origin,
                "method": method,
                "request_headers": request_headers,
                "request_headers_normalized": request_headers.iter().map(|h| h.to_lowercase()).collect::<Vec<_>>(),
                "with_credentials": with_credentials,
            },
            "preflight": {
                "allowed": preflight_allowed,
                "allow_origin": origin_allowed,
                "method_allowed": method_allowed,
                "headers_allowed": headers_allowed,
                "not_allowed_headers": not_allowed_headers,
                "response_headers": preflight_headers,
            },
            "actual": {
                "allowed": origin_allowed,
                "response_headers": actual_headers,
            },
            "notes": notes,
        }),
        request_id,
    )
}

async fn subscription_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    mut payload: Value,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if method == Method::GET && path.starts_with("/subscription/available-apis/") {
        let target = path.trim_start_matches("/subscription/available-apis/");
        if target != username && !has_permission(state, username, "manage_subscriptions").await {
            return error(
                StatusCode::FORBIDDEN,
                "SUB011",
                "You do not have permission to view another user's APIs",
                request_id,
            );
        }
        let apis = storage
            .find_many("apis", &json!({}))
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|api| {
                json!({
                    "api_name": api.get("api_name"),
                    "api_version": api.get("api_version"),
                    "api_description": api.get("api_description")
                })
            })
            .collect::<Vec<_>>();
        return success(StatusCode::OK, json!({"apis": apis}), request_id);
    }
    if method == Method::GET && path.starts_with("/subscription/subscriptions") {
        let target = path
            .strip_prefix("/subscription/subscriptions/")
            .filter(|value| !value.is_empty())
            .unwrap_or(username);
        if target != username && !has_permission(state, username, "manage_subscriptions").await {
            return error(
                StatusCode::FORBIDDEN,
                "SUB011",
                "You do not have permission to view another user's subscriptions",
                request_id,
            );
        }
        let document = storage
            .find_one("subscriptions", &json!({"username": target}))
            .await
            .ok()
            .flatten();
        // The pinned service echoes the list under `subscriptions` once a
        // subscription document exists.
        let body = match document {
            Some(doc) => {
                let apis = doc.get("apis").cloned().unwrap_or_else(|| json!([]));
                json!({"apis": apis.clone(), "subscriptions": {"apis": apis}})
            }
            None => json!({"apis": []}),
        };
        return success(StatusCode::OK, body, request_id);
    }
    let operation = if method == Method::POST && path.ends_with("/subscribe") {
        Some(true)
    } else if method == Method::POST && path.ends_with("/unsubscribe") {
        Some(false)
    } else {
        None
    };
    if let Some(subscribe) = operation {
        if normalize_subscription_model(&mut payload).is_err() {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VAL001",
                "Validation Error",
                request_id,
            );
        }
        let target = payload
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or(username);
        if target != username && !has_permission(state, username, "manage_subscriptions").await {
            return error(
                StatusCode::FORBIDDEN,
                if subscribe { "SUB009" } else { "SUB010" },
                "Insufficient permissions",
                request_id,
            );
        }
        let api_name = payload
            .get("api_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let api_version = payload
            .get("api_version")
            .and_then(Value::as_str)
            .unwrap_or("");
        let api_document = match storage
            .find_one(
                "apis",
                &json!({"api_name": api_name, "api_version": api_version}),
            )
            .await
        {
            Ok(Some(api)) => api,
            _ => {
                // group_required raises HTTPException(404, 'API not found'),
                // which the route re-renders under its generic error code.
                return error(
                    StatusCode::NOT_FOUND,
                    if subscribe { "GEN001" } else { "GEN002" },
                    "API not found",
                    request_id,
                );
            }
        };
        // Python's group_required runs before SubscriptionService and evaluates
        // the user named in the request (which can differ from the actor).
        // Preserve that policy gate for both subscribing and unsubscribing.
        let generic_code = if subscribe { "GEN001" } else { "GEN002" };
        let target_user = match storage
            .find_one("users", &json!({"username": target}))
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => {
                return error(
                    StatusCode::NOT_FOUND,
                    generic_code,
                    "User not found",
                    request_id,
                );
            }
            Err(_) => return unexpected(request_id),
        };
        // group_required raises HTTPException(401, ...) rather than returning
        // False, so the pinned route answers 401 with its generic error code.
        if enforce_group_access(&api_document, &target_user).is_err() {
            return error(
                StatusCode::UNAUTHORIZED,
                generic_code,
                "You do not have the correct group for this",
                request_id,
            );
        }
        let api = format!("{api_name}/{api_version}");
        let existing = storage
            .find_one("subscriptions", &json!({"username": target}))
            .await
            .ok()
            .flatten();
        let mut apis = existing
            .as_ref()
            .and_then(|doc| doc.get("apis"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let present = apis.iter().any(|value| value.as_str() == Some(&api));
        if subscribe && present {
            return error(
                StatusCode::BAD_REQUEST,
                "SUB004",
                "User is already subscribed to the API",
                request_id,
            );
        }
        if !subscribe && !present {
            return error(
                StatusCode::BAD_REQUEST,
                "SUB006",
                "User is not subscribed to the API",
                request_id,
            );
        }
        if subscribe {
            apis.push(json!(api));
        } else {
            apis.retain(|value| value.as_str() != Some(&api));
        }
        let result = if existing.is_some() {
            storage
                .update_one(
                    "subscriptions",
                    &json!({"username": target}),
                    &json!({"apis": apis}),
                )
                .await
                .map(|_| ())
        } else {
            storage
                .insert_one("subscriptions", json!({"username": target, "apis": apis}))
                .await
                .map(|_| ())
        };
        return match result {
            Ok(()) => message(
                StatusCode::OK,
                if subscribe {
                    "Successfully subscribed to the API"
                } else {
                    "Successfully unsubscribed from the API"
                },
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

/// The pinned service projects exactly these four fields, with
/// `api_key_present = bool(doc.get('api_key'))`.
fn public_credit_definition(value: Value) -> Value {
    json!({
        "api_credit_group": value.get("api_credit_group").cloned().unwrap_or(Value::Null),
        "api_key_header": value.get("api_key_header").cloned().unwrap_or(Value::Null),
        "api_key_present": value.get("api_key").is_some_and(python_truthy_json),
        "credit_tiers": value.get("credit_tiers").cloned().unwrap_or(Value::Null),
    })
}

fn encrypt_credit_definition(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for field in ["api_key", "api_key_new"] {
        let encrypted = object
            .get(field)
            .and_then(Value::as_str)
            .and_then(|value| crate::storage::field_encryption::encrypt_value(Some(value)));
        if let Some(encrypted) = encrypted {
            object.insert(field.to_owned(), json!(encrypted));
        }
    }
}

fn transform_user_credit_keys(value: &mut Value, encrypt: bool) {
    let Some(credits) = value
        .get_mut("users_credits")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for credit in credits.values_mut() {
        let Some(credit) = credit.as_object_mut() else {
            continue;
        };
        let transformed = credit
            .get("user_api_key")
            .and_then(Value::as_str)
            .and_then(|value| {
                if encrypt {
                    crate::storage::field_encryption::encrypt_value(Some(value))
                } else {
                    crate::storage::field_encryption::decrypt_value(Some(value))
                }
            });
        if let Some(transformed) = transformed {
            credit.insert("user_api_key".to_owned(), json!(transformed));
        }
    }
}

async fn credit_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    mut payload: Value,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let suffix = path.strip_prefix("/credit").unwrap_or("").trim_matches('/');
    let model_result = if (method == Method::POST && suffix.is_empty()) || method == Method::PUT {
        normalize_credit_model(&mut payload, method == Method::POST && suffix.is_empty())
    } else if method == Method::POST && !suffix.is_empty() && suffix != "rotate-key" {
        normalize_user_credit_model(&mut payload)
    } else {
        Ok(())
    };
    if model_result.is_err() {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VAL001",
            "Validation Error",
            request_id,
        );
    }
    if method == Method::POST && suffix == "rotate-key" {
        let Some(group) = payload.get("api_credit_group").and_then(Value::as_str) else {
            return error(
                StatusCode::BAD_REQUEST,
                "CRD020",
                "api_credit_group is required",
                request_id,
            );
        };
        let existing = storage
            .find_one("user_credits", &json!({"username": username}))
            .await
            .ok()
            .flatten();
        let mut credits = existing
            .clone()
            .unwrap_or_else(|| json!({"username": username, "users_credits": {}}));
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut random = [0_u8; 32];
        random[..16].copy_from_slice(first.as_bytes());
        random[16..].copy_from_slice(second.as_bytes());
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let encrypted = crate::storage::field_encryption::encrypt_value(Some(&key))
            .unwrap_or_else(|| key.clone());
        let users_credits = credits
            .as_object_mut()
            .and_then(|value| value.get_mut("users_credits"))
            .and_then(Value::as_object_mut);
        let Some(users_credits) = users_credits else {
            return unexpected(request_id);
        };
        let group_credit = users_credits
            .entry(group.to_owned())
            .or_insert_with(|| json!({}));
        if !group_credit.is_object() {
            *group_credit = json!({
                "available_credits": 0,
                "tier_name": "default"
            });
        }
        group_credit["user_api_key"] = json!(encrypted);
        let result = if existing.is_some() {
            storage
                .update_one("user_credits", &json!({"username": username}), &credits)
                .await
                .map(|_| ())
        } else {
            storage
                .insert_one("user_credits", credits)
                .await
                .map(|_| ())
        };
        return match result {
            Ok(()) => success(StatusCode::OK, json!({"api_key": key}), request_id),
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::GET && suffix == "defs" {
        if !has_permission(state, username, "manage_credits").await {
            return error(
                StatusCode::FORBIDDEN,
                "CRD002",
                "Unable to retrieve credits",
                request_id,
            );
        }
        let mut values = storage
            .find_many("credit_defs", &json!({}))
            .await
            .unwrap_or_default()
            .into_iter()
            .map(public_credit_definition)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.get("api_credit_group")
                .and_then(Value::as_str)
                .cmp(&right.get("api_credit_group").and_then(Value::as_str))
        });
        // Python's `list_credit_definitions(page: int = 1, page_size: int = 50)`
        // typed FastAPI query params: a non-numeric value produces a 422.
        if let Some(response) =
            int_query_validation_error(query, &["page", "page_size"], request_id)
        {
            return response;
        }
        if let Err(message_text) = validate_pagination(query) {
            return error(StatusCode::BAD_REQUEST, "PAG001", &message_text, request_id);
        }
        let page = query
            .get("page")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let page_size = query
            .get("page_size")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(50);
        let total = values.len();
        let start = (page - 1).saturating_mul(page_size);
        let has_next = start.saturating_add(page_size) < total;
        values = values.into_iter().skip(start).take(page_size).collect();
        return success(
            StatusCode::OK,
            json!({
                "items": values,
                "page": page,
                "page_size": page_size,
                "has_next": has_next,
                "total": total
            }),
            request_id,
        );
    }
    if method == Method::GET && suffix == "all" {
        if !has_permission(state, username, "manage_credits").await {
            return error(
                StatusCode::FORBIDDEN,
                "CRD002",
                "Unable to retrieve credits for all users",
                request_id,
            );
        }
        // Python's `get_all_users_credits(page: int = 1, page_size: int = 10, ...)`
        // typed FastAPI query params: a non-numeric value produces a 422.
        if let Some(response) =
            int_query_validation_error(query, &["page", "page_size"], request_id)
        {
            return response;
        }
        if let Err(message_text) = validate_pagination(query) {
            return error(StatusCode::BAD_REQUEST, "PAG001", &message_text, request_id);
        }
        let page = query
            .get("page")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let page_size = query
            .get("page_size")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10);
        let search = query
            .get("search")
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let mut values = storage
            .find_many("user_credits", &json!({}))
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|value| {
                search.is_empty()
                    || value
                        .get("username")
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.to_ascii_lowercase().contains(&search))
                    || value
                        .get("users_credits")
                        .and_then(Value::as_object)
                        .is_some_and(|credits| {
                            credits
                                .keys()
                                .any(|group| group.to_ascii_lowercase().contains(&search))
                        })
            })
            .map(|mut value| {
                transform_user_credit_keys(&mut value, false);
                strip_internal(value)
            })
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.get("username")
                .and_then(Value::as_str)
                .cmp(&right.get("username").and_then(Value::as_str))
        });
        let total = values.len();
        let start = (page - 1).saturating_mul(page_size);
        let has_next = start.saturating_add(page_size) < total;
        let values = values
            .into_iter()
            .skip(start)
            .take(page_size)
            .collect::<Vec<_>>();
        return success(
            StatusCode::OK,
            json!({
                "user_credits": values,
                "page": page,
                "page_size": page_size,
                "has_next": has_next,
                "total": total
            }),
            request_id,
        );
    }
    if method == Method::POST && suffix.is_empty() {
        if !has_permission(state, username, "manage_credits").await {
            return error(
                StatusCode::FORBIDDEN,
                "CRD001",
                "You do not have permission to manage credits",
                request_id,
            );
        }
        if let Err((code, message_text)) = validate_credit_definition_fields(&payload) {
            return error(StatusCode::BAD_REQUEST, code, message_text, request_id);
        }
        let group = payload
            .get("api_credit_group")
            .and_then(Value::as_str)
            .unwrap_or("");
        if storage
            .find_one("credit_defs", &json!({"api_credit_group": group}))
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return error(
                StatusCode::BAD_REQUEST,
                "CRD001",
                "Credit group already exists",
                request_id,
            );
        }
        encrypt_credit_definition(&mut payload);
        return match storage.insert_one("credit_defs", payload).await {
            Ok(_) => message(
                StatusCode::CREATED,
                "Credit definition created successfully",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if let Some(group) = suffix.strip_prefix("defs/") {
        let filter = json!({"api_credit_group": group});
        if method == Method::GET {
            if !has_permission(state, username, "manage_credits").await {
                return error(
                    StatusCode::FORBIDDEN,
                    "CRD002",
                    "Unable to retrieve credits",
                    request_id,
                );
            }
            return match storage.find_one("credit_defs", &filter).await {
                Ok(Some(value)) => {
                    success(StatusCode::OK, public_credit_definition(value), request_id)
                }
                _ => error(
                    StatusCode::NOT_FOUND,
                    "CRD021",
                    "Credit definition not found",
                    request_id,
                ),
            };
        }
    }
    if method == Method::PUT || method == Method::DELETE {
        if !has_permission(state, username, "manage_credits").await {
            return error(
                StatusCode::FORBIDDEN,
                "CRD001",
                "You do not have permission to manage credits",
                request_id,
            );
        }
        let filter = json!({"api_credit_group": suffix});
        if method == Method::PUT {
            if let Err((code, message_text)) = validate_credit_definition_fields(&payload) {
                return error(StatusCode::BAD_REQUEST, code, message_text, request_id);
            }
            if payload
                .get("api_credit_group")
                .and_then(Value::as_str)
                .is_some_and(|group| group != suffix)
            {
                return error(
                    StatusCode::BAD_REQUEST,
                    "CRD003",
                    "Credit group name cannot be updated",
                    request_id,
                );
            }
            match storage.find_one("credit_defs", &filter).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "CRD004",
                        "Credit definition does not exist for the requested group",
                        request_id,
                    );
                }
                Err(_) => return unexpected(request_id),
            }
            encrypt_credit_definition(&mut payload);
            return match storage.update_one("credit_defs", &filter, &payload).await {
                Ok(Some(_)) => message(
                    StatusCode::OK,
                    "Credit definition updated successfully",
                    request_id,
                ),
                _ => error(
                    StatusCode::BAD_REQUEST,
                    "CRD004",
                    "Credit definition does not exist for the requested group",
                    request_id,
                ),
            };
        }
        return match storage.delete_one("credit_defs", &filter).await {
            Ok(true) => message(
                StatusCode::OK,
                "Credit definition deleted successfully",
                request_id,
            ),
            _ => error(
                StatusCode::BAD_REQUEST,
                "CRD007",
                "Credit definition does not exist for the requested group",
                request_id,
            ),
        };
    }
    if method == Method::POST && !suffix.is_empty() {
        if !has_permission(state, username, "manage_credits").await {
            return error(
                StatusCode::FORBIDDEN,
                "CRD001",
                "You do not have permission to manage credits",
                request_id,
            );
        }
        if payload
            .get("username")
            .and_then(Value::as_str)
            .is_some_and(|body_username| body_username != suffix)
        {
            return error(
                StatusCode::BAD_REQUEST,
                "CRD014",
                "Username in body does not match path",
                request_id,
            );
        }
        let mut value = payload;
        value["username"] = json!(suffix);
        transform_user_credit_keys(&mut value, true);
        let existing = storage
            .find_one("user_credits", &json!({"username": suffix}))
            .await
            .ok()
            .flatten();
        let result = if existing.is_some() {
            storage
                .update_one("user_credits", &json!({"username": suffix}), &value)
                .await
                .map(|_| ())
        } else {
            storage.insert_one("user_credits", value).await.map(|_| ())
        };
        return match result {
            Ok(()) => message(StatusCode::OK, "Credits saved successfully", request_id),
            Err(_) => unexpected(request_id),
        };
    }
    if method == Method::GET && !suffix.is_empty() {
        if suffix != username && !has_permission(state, username, "manage_credits").await {
            return error(
                StatusCode::FORBIDDEN,
                "CRD003",
                "Unable to retrieve credits for user",
                request_id,
            );
        }
        return match storage
            .find_one("user_credits", &json!({"username": suffix}))
            .await
        {
            Ok(Some(mut value)) => {
                transform_user_credit_keys(&mut value, false);
                success(StatusCode::OK, strip_internal(value), request_id)
            }
            _ => error(
                StatusCode::NOT_FOUND,
                "CRD017",
                "User credits not found",
                request_id,
            ),
        };
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

async fn vault_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let key = path.strip_prefix("/vault").unwrap_or("").trim_matches('/');
    if method == Method::GET && key.is_empty() {
        if storage
            .find_many("vault_entries", &json!({"username": username}))
            .await
            .is_err()
        {
            return unexpected(request_id);
        }
        // VaultService supplies `data=...`, but ResponseModel does not have a
        // `data` field. FastAPI filters it away, making a successful list
        // response the empty object in the pinned Python process.
        return success(StatusCode::OK, json!({}), request_id);
    }
    if method == Method::POST && key.is_empty() {
        let Some(key_name) = payload.get("key_name").and_then(security_setting_string) else {
            return vault_validation_error(request_id);
        };
        let Some(value) = payload.get("value").and_then(security_setting_string) else {
            return vault_validation_error(request_id);
        };
        let description = match payload.get("description") {
            Some(Value::Null) | None => Value::Null,
            Some(value) => match security_setting_string(value) {
                Some(value) if value.chars().count() <= 500 => json!(value),
                _ => return vault_validation_error(request_id),
            },
        };
        if key_name.is_empty() || key_name.chars().count() > 255 || value.is_empty() {
            return vault_validation_error(request_id);
        }
        // The model is validated before service execution, after which the
        // Python service checks the configured key before user/duplicate
        // lookup. Keep this ordering for the observable failure code.
        if env::var("VAULT_KEY")
            .ok()
            .is_none_or(|configured_key| configured_key.is_empty())
        {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "VAULT001",
                "Vault encryption is not configured. Set VAULT_KEY in environment variables.",
                request_id,
            );
        }
        if storage
            .find_one(
                "vault_entries",
                &json!({"username": username, "key_name": &key_name}),
            )
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return error(
                StatusCode::CONFLICT,
                "VAULT004",
                &format!("Vault entry with key_name \"{key_name}\" already exists"),
                request_id,
            );
        }
        let Some(user) = storage
            .find_one("users", &json!({"username": username}))
            .await
            .ok()
            .flatten()
        else {
            return error(
                StatusCode::NOT_FOUND,
                "VAULT002",
                "User not found",
                request_id,
            );
        };
        let Some(email) = user.get("email").and_then(Value::as_str) else {
            return error(
                StatusCode::BAD_REQUEST,
                "VAULT003",
                "User email is required for vault encryption",
                request_id,
            );
        };
        let encrypted_value = match crate::storage::vault::encrypt(&value, email, username) {
            Ok(value) => value,
            Err(crate::storage::vault::VaultError::MissingKey) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "VAULT001",
                    "Vault encryption is not configured. Set VAULT_KEY in environment variables.",
                    request_id,
                );
            }
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "VAULT005",
                    "Failed to encrypt vault value",
                    request_id,
                );
            }
        };
        let now = timestamp_now_python_utc();
        let entry = json!({"username": username, "key_name": key_name, "encrypted_value": encrypted_value, "description": description, "created_at": now, "updated_at": timestamp_now_python_utc()});
        return match storage.insert_one("vault_entries", entry).await {
            Ok(_) => message(
                StatusCode::CREATED,
                "Vault entry created successfully",
                request_id,
            ),
            Err(_) => unexpected(request_id),
        };
    }
    if !key.is_empty() {
        let filter = json!({"username": username, "key_name": key});
        if method == Method::GET {
            return match storage.find_one("vault_entries", &filter).await {
                Ok(Some(_)) => success(StatusCode::OK, json!({}), request_id),
                Ok(None) => error(
                    StatusCode::NOT_FOUND,
                    "VAULT007",
                    "Vault entry not found",
                    request_id,
                ),
                Err(_) => unexpected(request_id),
            };
        }
        if method == Method::PUT {
            let mut update = json!({"updated_at": timestamp_now_python_utc()});
            if let Some(description) = payload.get("description").filter(|value| !value.is_null()) {
                let Some(description) = security_setting_string(description)
                    .filter(|description| description.chars().count() <= 500)
                else {
                    return vault_validation_error(request_id);
                };
                update["description"] = json!(description);
            }
            return match storage.update_one("vault_entries", &filter, &update).await {
                Ok(Some(_)) => message(
                    StatusCode::OK,
                    "Vault entry updated successfully",
                    request_id,
                ),
                _ => error(
                    StatusCode::NOT_FOUND,
                    "VAULT007",
                    "Vault entry not found",
                    request_id,
                ),
            };
        }
        if method == Method::DELETE {
            return match storage.delete_one("vault_entries", &filter).await {
                Ok(true) => message(
                    StatusCode::OK,
                    "Vault entry deleted successfully",
                    request_id,
                ),
                _ => error(
                    StatusCode::NOT_FOUND,
                    "VAULT007",
                    "Vault entry not found",
                    request_id,
                ),
            };
        }
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

fn vault_validation_error(request_id: &str) -> Response {
    // The application-level Pydantic exception handler uses the project
    // envelope, not FastAPI's normal `detail` list, for vault models.
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "VAL001",
        "Validation Error",
        request_id,
    )
}

async fn quota_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if path == "/quota/usage/history" && method == Method::GET {
        return success(
            StatusCode::OK,
            json!({"user_id": username, "history": [], "note": "Historical tracking not yet fully implemented"}),
            request_id,
        );
    }
    let (tier, limits) = match quota_tier_and_limits(storage, username).await {
        Ok(value) => value,
        Err(_) => return quota_route_failure(path, request_id),
    };
    if path == "/quota/usage/export" && method == Method::POST {
        let Some(limits) = limits.as_ref() else {
            return http_detail(
                StatusCode::NOT_FOUND,
                "No limits found for user",
                request_id,
            );
        };
        let quotas = match quota_values(storage, username, limits).await {
            Ok(quotas) => quotas,
            Err(_) => return quota_route_failure(path, request_id),
        };
        // The pinned Python export intentionally contains request quotas only;
        // monthly bandwidth is present in the dashboard but not this payload.
        let export_quotas = quotas
            .iter()
            .filter(|quota| quota["quota_type"] != "monthly_bandwidth")
            .collect::<Vec<_>>();
        let export_data = json!({
            "user_id": username,
            "export_date": timestamp_now_naive(),
            "quotas": export_quotas.iter().map(|quota| quota_export_value(quota)).collect::<Vec<_>>(),
        });
        if query.get("format").is_some_and(|format| format == "csv") {
            let mut lines =
                vec!["Type,Current Usage,Limit,Remaining,Percentage Used,Reset At".to_owned()];
            for quota in &export_quotas {
                lines.push(format!(
                    "{},{},{},{},{:.2},{}",
                    quota["quota_type"].as_str().unwrap_or_default(),
                    quota["current_usage"].as_u64().unwrap_or_default(),
                    quota["limit"].as_u64().unwrap_or_default(),
                    quota["remaining"].as_u64().unwrap_or_default(),
                    quota["percentage_used"].as_f64().unwrap_or_default(),
                    quota["reset_at"].as_str().unwrap_or_default(),
                ));
            }
            return success(
                StatusCode::OK,
                json!({"format": "csv", "data": lines.join("\n")}),
                request_id,
            );
        }
        return success(
            StatusCode::OK,
            json!({"format": "json", "data": export_data}),
            request_id,
        );
    }
    if path == "/quota/tier/info" && method == Method::GET {
        return match tier.as_ref() {
            Some(value) => {
                let current_tier = quota_tier_info(value, value.get("limits"));
                let upgrade_options = match storage.find_many("tiers", &json!({})).await {
                    Ok(tiers) => tiers
                        .into_iter()
                        .filter(|candidate| {
                            candidate.get("tier_id") != value.get("tier_id")
                                && candidate
                                    .get("enabled")
                                    .and_then(Value::as_bool)
                                    == Some(true)
                        })
                        .map(|candidate| {
                            json!({
                                "tier_id": candidate.get("tier_id").cloned().unwrap_or(Value::Null),
                                "display_name": candidate.get("display_name").cloned().unwrap_or(Value::Null),
                                "price_monthly": candidate.get("price_monthly").cloned().unwrap_or(Value::Null),
                                "features": candidate.get("features").cloned().unwrap_or_else(|| json!([])),
                            })
                        })
                        .collect::<Vec<_>>(),
                    Err(_) => return quota_route_failure(path, request_id),
                };
                success(
                    StatusCode::OK,
                    json!({"current_tier": current_tier, "upgrade_options": upgrade_options}),
                    request_id,
                )
            }
            None => http_detail(
                StatusCode::NOT_FOUND,
                "No tier assigned to user",
                request_id,
            ),
        };
    }
    if path == "/quota/burst/status" && method == Method::GET {
        let Some(tier) = tier.as_ref() else {
            return http_detail(
                StatusCode::NOT_FOUND,
                "No tier assigned to user",
                request_id,
            );
        };
        let limits = limits.as_ref().or_else(|| tier.get("limits"));
        let value = |name| {
            limits
                .and_then(|limits| limits.get(name))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        return success(
            StatusCode::OK,
            json!({
                "user_id": username,
                "burst_limits": {
                    "per_minute": value("burst_per_minute"),
                    "per_hour": value("burst_per_hour"),
                    "per_second": value("burst_per_second"),
                },
                "burst_usage": {"per_minute": 0, "per_hour": 0, "per_second": 0},
                "note": "Live data from rate limiter",
            }),
            request_id,
        );
    }
    if path == "/quota/status" && method == Method::GET {
        let Some(tier) = tier.as_ref() else {
            return http_detail(
                StatusCode::NOT_FOUND,
                "No tier assigned to user",
                request_id,
            );
        };
        let Some(limits) = limits.as_ref() else {
            return http_detail(
                StatusCode::NOT_FOUND,
                "No limits found for user",
                request_id,
            );
        };
        let quotas = match quota_values(storage, username, limits).await {
            Ok(quotas) => quotas,
            Err(_) => return quota_route_failure(path, request_id),
        };
        let request_quotas = quotas.iter().filter(|quota| {
            quota["quota_type"]
                .as_str()
                .is_some_and(|name| name.contains("requests"))
        });
        let total_requests_used = request_quotas
            .clone()
            .map(|quota| quota["current_usage"].as_u64().unwrap_or_default())
            .sum::<u64>();
        let total_requests_limit = request_quotas
            .map(|quota| quota["limit"].as_u64().unwrap_or_default())
            .sum::<u64>();
        return success(
            StatusCode::OK,
            json!({
                "user_id": username,
                "tier_info": quota_tier_info(tier, Some(limits)),
                "quotas": quotas,
                "usage_summary": {
                    "total_requests_used": total_requests_used,
                    "total_requests_limit": total_requests_limit,
                    "has_warnings": quotas.iter().any(|quota| quota["is_warning"] == true),
                    "has_critical": quotas.iter().any(|quota| quota["is_critical"] == true),
                    "has_exhausted": quotas.iter().any(|quota| quota["is_exhausted"] == true),
                },
            }),
            request_id,
        );
    }
    if let Some(quota_type) = path.strip_prefix("/quota/status/")
        && method == Method::GET
    {
        let Some(limits) = limits.as_ref() else {
            return http_detail(
                StatusCode::NOT_FOUND,
                "No limits found for user",
                request_id,
            );
        };
        let field = match quota_type {
            "monthly_requests" => "monthly_request_quota",
            "daily_requests" => "daily_request_quota",
            "monthly_bandwidth" => "monthly_bandwidth_quota",
            _ => {
                return http_detail(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid quota type: {quota_type}"),
                    request_id,
                );
            }
        };
        let Some(limit) = limits
            .get(field)
            .and_then(Value::as_u64)
            .filter(|limit| *limit > 0)
        else {
            return http_detail(
                StatusCode::NOT_FOUND,
                &format!("Quota {quota_type} not configured for user"),
                request_id,
            );
        };
        return match quota_status(storage, username, quota_type, limit).await {
            Ok(status) => success(StatusCode::OK, status, request_id),
            Err(_) => quota_route_failure(path, request_id),
        };
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

fn quota_route_failure(path: &str, request_id: &str) -> Response {
    let detail = match path {
        "/quota/usage/history" => "Failed to get usage history",
        "/quota/usage/export" => "Failed to export usage data",
        "/quota/tier/info" => "Failed to get tier info",
        "/quota/burst/status" => "Failed to get burst status",
        _ => "Failed to get quota status",
    };
    http_detail(StatusCode::INTERNAL_SERVER_ERROR, detail, request_id)
}

async fn quota_tier_and_limits(
    storage: &SharedStorage,
    username: &str,
) -> Result<(Option<Value>, Option<Value>), crate::storage::runtime::StorageError> {
    let assignment = storage
        .find_one("user_tier_assignments", &json!({"user_id": username}))
        .await?;
    let active_assignment = assignment.as_ref().filter(|assignment| {
        crate::policy::tier::assignment_is_effective(assignment, unix_seconds())
    });
    let tier = if let Some(tier_id) = active_assignment
        .and_then(|assignment| assignment.get("tier_id"))
        .and_then(Value::as_str)
    {
        storage
            .find_one("tiers", &json!({"tier_id": tier_id}))
            .await?
    } else {
        storage
            .find_many("tiers", &json!({}))
            .await?
            .into_iter()
            .find(|tier| {
                tier.get("is_default")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
    };
    // The pinned TierService applies assignment overrides before checking the
    // assignment's effective dates, even when get_user_tier falls back.
    let limits = assignment
        .as_ref()
        .and_then(|assignment| assignment.get("override_limits"))
        .filter(|limits| limits.is_object())
        .cloned()
        .or_else(|| {
            tier.as_ref()
                .and_then(|tier| tier.get("limits"))
                .filter(|limits| limits.is_object())
                .cloned()
        });
    Ok((tier, limits))
}

async fn quota_values(
    storage: &SharedStorage,
    username: &str,
    limits: &Value,
) -> Result<Vec<Value>, crate::storage::runtime::StorageError> {
    let definitions = [
        ("monthly_requests", "monthly_request_quota"),
        ("daily_requests", "daily_request_quota"),
        ("monthly_bandwidth", "monthly_bandwidth_quota"),
    ];
    let mut values = Vec::new();
    for (name, field) in definitions {
        let Some(limit) = limits
            .get(field)
            .and_then(Value::as_u64)
            .filter(|limit| *limit > 0)
        else {
            continue;
        };
        values.push(quota_status(storage, username, name, limit).await?);
    }
    Ok(values)
}

async fn quota_status(
    storage: &SharedStorage,
    username: &str,
    name: &str,
    limit: u64,
) -> Result<Value, crate::storage::runtime::StorageError> {
    let (counter_type, period_key, reset_at) = quota_period(name);
    // QuotaTracker.check_quota deliberately fails open when Redis is
    // unavailable, returning zero usage with the configured limit intact.
    let current_usage = storage
        .current_counter(&format!(
            "quota:user:{username}:{counter_type}:month:{period_key}:usage"
        ))
        .await
        .unwrap_or(0);
    let percentage_used = current_usage as f64 / limit as f64 * 100.0;
    Ok(json!({
        "quota_type": name,
        "current_usage": current_usage,
        "limit": limit,
        "remaining": limit.saturating_sub(current_usage),
        "percentage_used": percentage_used,
        "reset_at": reset_at,
        "is_warning": percentage_used >= 80.0,
        "is_critical": percentage_used >= 95.0,
        "is_exhausted": current_usage >= limit,
        "burst_used": 0,
        "burst_limit": 0,
        "burst_percentage": 0.0,
    }))
}

fn quota_period(name: &str) -> (&'static str, String, String) {
    let now = time::OffsetDateTime::now_utc();
    let date = now.date();
    let month = u8::from(date.month());
    if name == "daily_requests" {
        let reset = date.next_day().unwrap_or(date);
        return (
            "requests",
            format!("{:04}-{:02}-{:02}", date.year(), month, date.day()),
            format!(
                "{:04}-{:02}-{:02}T00:00:00",
                reset.year(),
                u8::from(reset.month()),
                reset.day()
            ),
        );
    }
    let next_year = if month == 12 {
        date.year() + 1
    } else {
        date.year()
    };
    let next_month = if month == 12 {
        time::Month::January
    } else {
        time::Month::try_from(month + 1).unwrap_or(time::Month::January)
    };
    let reset = time::Date::from_calendar_date(next_year, next_month, 1).unwrap_or(date);
    (
        if name == "monthly_bandwidth" {
            "bandwidth"
        } else {
            "requests"
        },
        format!("{:04}-{:02}", date.year(), month),
        format!(
            "{:04}-{:02}-{:02}T00:00:00",
            reset.year(),
            u8::from(reset.month()),
            reset.day()
        ),
    )
}

fn quota_tier_info(tier: &Value, limits: Option<&Value>) -> Value {
    json!({
        "tier_id": tier.get("tier_id").cloned().unwrap_or(Value::Null),
        "tier_name": tier.get("name").cloned().unwrap_or(Value::Null),
        "display_name": tier.get("display_name").cloned().unwrap_or(Value::Null),
        "limits": limits.cloned().unwrap_or_else(|| json!({})),
        "price_monthly": tier.get("price_monthly").cloned().unwrap_or(Value::Null),
        "features": tier.get("features").cloned().unwrap_or_else(|| json!([])),
    })
}

fn quota_export_value(quota: &Value) -> Value {
    json!({
        "type": quota.get("quota_type").cloned().unwrap_or(Value::Null),
        "current_usage": quota.get("current_usage").cloned().unwrap_or(Value::Null),
        "limit": quota.get("limit").cloned().unwrap_or(Value::Null),
        "remaining": quota.get("remaining").cloned().unwrap_or(Value::Null),
        "percentage_used": quota.get("percentage_used").cloned().unwrap_or(Value::Null),
        "reset_at": quota.get("reset_at").cloned().unwrap_or(Value::Null),
    })
}

fn discovery_target(server: &str, path: &str) -> Result<String, String> {
    let base =
        Url::parse(server).map_err(|_| "API server must be an absolute HTTP(S) URL".to_owned())?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err("API server must be an absolute HTTP(S) URL".to_owned());
    }
    if Url::parse(path).is_ok() || path.starts_with("//") || path.contains("://") {
        return Err("Discovery URL must be relative to the API server".to_owned());
    }
    if let Ok(allowlist) = env::var("DISCOVERY_ALLOWED_HOSTS") {
        let host = base.host_str().unwrap_or_default();
        let allowed = allowlist
            .split(",")
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .any(|entry| {
                entry == host
                    || entry
                        .strip_prefix("*.")
                        .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
            });
        if !allowed {
            return Err("API server host is not in DISCOVERY_ALLOWED_HOSTS".to_owned());
        }
    }
    base.join(path)
        .map(|url| url.to_string())
        .map_err(|_| "Discovery URL must be relative to the API server".to_owned())
}

async fn api_discovery_routes(
    state: &AppState,
    parts: &[&str],
    method: &Method,
    username: &str,
    request_id: &str,
) -> Response {
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    let kind = parts[2];
    let action = parts.get(3).copied().unwrap_or("");
    // Python treats document import as endpoint management, while viewing and
    // refreshing discovery data are API-management operations.  Check before
    // the lookup so an unprivileged caller cannot use a missing API as a
    // permission oracle.
    if !(method == Method::POST && action == "import"
        || has_permission(state, username, "manage_apis").await)
    {
        return error(
            StatusCode::FORBIDDEN,
            "AUTHZ001",
            "Not authorized",
            request_id,
        );
    }
    let filter = json!({"api_name": parts[0], "api_version": parts[1]});
    let Some(api) = storage.find_one("apis", &filter).await.ok().flatten() else {
        if kind == "graphql" && action == "types" && method == Method::GET {
            return error(
                StatusCode::NOT_FOUND,
                "GQL003",
                "GraphQL schema is not cached",
                request_id,
            );
        }
        return error(StatusCode::NOT_FOUND, "API001", "API not found", request_id);
    };
    if kind == "openapi" {
        return openapi_discovery_route(
            state, storage, &api, &filter, parts, action, method, username, request_id,
        )
        .await;
    }
    if kind == "grpc" && action == "services" && method == Method::GET {
        // The pinned route reports the configured allow-list rather than
        // querying reflection.
        if api
            .get("api_servers")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return error(
                StatusCode::NOT_FOUND,
                "GRPC001",
                "No upstream servers configured",
                request_id,
            );
        }
        return success(
            StatusCode::OK,
            json!({
                "services": api
                    .get("api_grpc_allowed_services")
                    .filter(|value| python_truthy_json(value))
                    .cloned()
                    .unwrap_or_else(|| json!([])),
                "reflection_enabled": api.get("api_grpc_reflection_url").is_some_and(python_truthy_json),
                "note": "Auto-discovery via reflection not fully implemented in this demo route",
            }),
            request_id,
        );
    }
    if kind == "graphql" {
        let field = "api_graphql_schema";
        if action == "types" && method == Method::GET {
            let Some(schema) = api.get(field).filter(|value| !value.is_null()).cloned() else {
                return error(
                    StatusCode::NOT_FOUND,
                    "GQL003",
                    "GraphQL schema is not cached",
                    request_id,
                );
            };
            let types = schema
                .get("types")
                .or_else(|| schema.pointer("/data/__schema/types"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            return success(
                StatusCode::OK,
                json!({"types": types, "types_count": types.len()}),
                request_id,
            );
        }
        if method == Method::GET && action == "schema" {
            if let Some(schema) = api.get(field).filter(|value| !value.is_null()) {
                return graphql_schema_response(schema.clone(), true, request_id);
            }
            let Some(server) = api
                .get("api_servers")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
            else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "API003",
                    "API server is not configured",
                    request_id,
                );
            };
            let path = api
                .get("api_graphql_schema_url")
                .and_then(Value::as_str)
                .unwrap_or("/graphql");
            let target = match discovery_target(server, path) {
                Ok(target) => target,
                Err(message_text) => {
                    return error(StatusCode::BAD_REQUEST, "API003", &message_text, request_id);
                }
            };
            let Some(schema) = fetch_introspection_schema(state, target).await else {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "GQL002",
                    "Failed to fetch schema from upstream",
                    request_id,
                );
            };
            let _ = storage
                .update_one("apis", &filter, &json!({field: schema.clone()}))
                .await;
            return graphql_schema_response(schema, false, request_id);
        }
        if (parts.get(4) == Some(&"refresh") || action == "refresh") && method == Method::POST {
            let Some(server) = api
                .get("api_servers")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
            else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "API003",
                    "API server is not configured",
                    request_id,
                );
            };
            let path = api
                .get("api_graphql_schema_url")
                .and_then(Value::as_str)
                .unwrap_or("/graphql");
            let target = match discovery_target(server, path) {
                Ok(target) => target,
                Err(message_text) => {
                    return error(StatusCode::BAD_REQUEST, "API003", &message_text, request_id);
                }
            };
            let Some(schema) = fetch_introspection_schema(state, target).await else {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "GQL002",
                    "Failed to fetch schema",
                    request_id,
                );
            };
            let _ = storage
                .update_one("apis", &filter, &json!({field: schema.clone()}))
                .await;
            let types_count = schema
                .get("types")
                .and_then(Value::as_array)
                .map(|types| {
                    types
                        .iter()
                        .filter(|item| {
                            !item
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .starts_with("__")
                        })
                        .count()
                })
                .unwrap_or(0);
            let has_subscriptions = schema
                .get("subscriptionType")
                .is_some_and(|item| item.get("name").is_some_and(|name| !name.is_null()));
            return success(
                StatusCode::OK,
                json!({
                    "message": "Schema refreshed successfully",
                    "types_count": types_count,
                    "has_subscriptions": has_subscriptions,
                }),
                request_id,
            );
        }
    }
    let (field, configured_url) = if kind == "openapi" {
        ("api_openapi_spec", "api_openapi_url")
    } else if kind == "wsdl" {
        ("api_wsdl_content", "api_wsdl_url")
    } else {
        return error(
            StatusCode::NOT_FOUND,
            "GTW003",
            "Platform route does not exist",
            request_id,
        );
    };
    if method == Method::GET && action.is_empty() {
        if let Some(value) = api.get(field).filter(|value| !value.is_null()) {
            return discovery_document_response(kind, value.clone(), true, request_id);
        }
        // The pinned route checks the configured URL before the servers.
        let Some(path) = api
            .get(configured_url)
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
        else {
            return error(
                StatusCode::NOT_FOUND,
                "WSDL001",
                "No WSDL URL configured for this API",
                request_id,
            );
        };
        let Some(server) = api
            .get("api_servers")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_str)
        else {
            return error(
                StatusCode::NOT_FOUND,
                "WSDL002",
                "No upstream servers configured",
                request_id,
            );
        };
        let target = match discovery_target(server, path) {
            Ok(target) => target,
            Err(message_text) => {
                return error(StatusCode::BAD_REQUEST, "API003", &message_text, request_id);
            }
        };
        let document = match state.proxy_client.get(target).send().await {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(text) if kind == "openapi" => match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(_) => {
                        return error(
                            StatusCode::BAD_GATEWAY,
                            "API003",
                            "Invalid discovery response",
                            request_id,
                        );
                    }
                },
                Ok(text) => Value::String(text),
                Err(_) => {
                    return error(
                        StatusCode::BAD_GATEWAY,
                        "API003",
                        "Invalid discovery response",
                        request_id,
                    );
                }
            },
            _ => {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "API003",
                    "Unable to fetch discovery document",
                    request_id,
                );
            }
        };
        let _ = storage
            .update_one("apis", &filter, &json!({field: document.clone()}))
            .await;
        return discovery_document_response(kind, document, false, request_id);
    }
    if method == Method::POST && action == "refresh" {
        let Some(path) = api
            .get(configured_url)
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
        else {
            return error(
                StatusCode::NOT_FOUND,
                "WSDL001",
                "No WSDL URL configured",
                request_id,
            );
        };
        // Without a server the pinned route fetches the bare relative URL,
        // which fails as an upstream error.
        let Some(server) = api
            .get("api_servers")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_str)
        else {
            return error(
                StatusCode::BAD_GATEWAY,
                "WSDL003",
                "Failed to fetch WSDL",
                request_id,
            );
        };
        let target = match discovery_target(server, path) {
            Ok(target) => target,
            Err(message_text) => {
                return error(StatusCode::BAD_REQUEST, "API003", &message_text, request_id);
            }
        };
        return match state.proxy_client.get(target).send().await {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(text) => {
                    let value = if kind == "openapi" {
                        serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}))
                    } else {
                        Value::String(text)
                    };
                    let _ = storage
                        .update_one("apis", &filter, &json!({field: value.clone()}))
                        .await;
                    success(StatusCode::OK, value, request_id)
                }
                Err(_) => error(
                    StatusCode::BAD_GATEWAY,
                    "API003",
                    "Invalid discovery response",
                    request_id,
                ),
            },
            _ => error(
                StatusCode::BAD_GATEWAY,
                "API003",
                "Unable to fetch discovery document",
                request_id,
            ),
        };
    }
    if method == Method::POST && action == "import" {
        if !has_permission(state, username, "manage_endpoints").await {
            return error(
                StatusCode::FORBIDDEN,
                "AUTHZ001",
                "Insufficient permissions",
                request_id,
            );
        }
        if kind == "openapi" && api.get(field).is_none_or(Value::is_null) {
            return error(
                StatusCode::NOT_FOUND,
                "OPENAPI003",
                "No OpenAPI available",
                request_id,
            );
        }
        let (candidates, service_name, operations_found) = if kind == "openapi" {
            (
                crate::routes::discovery::openapi_endpoints(api.get(field).unwrap_or(&Value::Null)),
                String::new(),
                0,
            )
        } else {
            let Some(content) = api.get(field).and_then(Value::as_str) else {
                return error(
                    StatusCode::NOT_FOUND,
                    "WSDL003",
                    "No WSDL available",
                    request_id,
                );
            };
            let parsed = match crate::routes::discovery::parse_wsdl(content) {
                Ok(parsed) => parsed,
                Err(message) => {
                    return error(StatusCode::BAD_REQUEST, "WSDL004", &message, request_id);
                }
            };
            let service_name = parsed
                .get("service_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let operations_found = parsed
                .get("operations")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            (
                parsed
                    .get("endpoints")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
                service_name,
                operations_found,
            )
        };
        let endpoints_found = candidates.len();
        let mut imported = 0_u64;
        let mut skipped = 0_u64;
        for candidate in candidates {
            let uri = candidate
                .get("endpoint_uri")
                .or_else(|| candidate.get("uri"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let verb = candidate
                .get("endpoint_method")
                .or_else(|| candidate.get("method"))
                .and_then(Value::as_str)
                .unwrap_or("POST")
                .to_ascii_uppercase();
            if uri.is_empty() {
                skipped += 1;
                continue;
            }
            let duplicate = storage
                .find_one(
                    "endpoints",
                    &json!({
                        "api_name": parts[0],
                        "api_version": parts[1],
                        "endpoint_method": &verb,
                        "endpoint_uri": uri,
                    }),
                )
                .await
                .ok()
                .flatten()
                .is_some();
            if duplicate {
                skipped += 1;
                continue;
            }
            let endpoint = json!({
                "api_name": parts[0],
                "api_version": parts[1],
                "api_id": api.get("api_id").cloned().unwrap_or(Value::Null),
                "endpoint_id": Uuid::new_v4().to_string(),
                "endpoint_method": verb,
                "endpoint_uri": uri,
                "client_uri": uri,
                "endpoint_description": candidate.get("endpoint_description").or_else(|| candidate.get("description")).and_then(Value::as_str).unwrap_or(""),
                "endpoint_soap_action": candidate.get("soap_action").cloned().unwrap_or(Value::String(String::new())),
            });
            if storage.insert_one("endpoints", endpoint).await.is_ok() {
                imported += 1;
            } else {
                skipped += 1;
            }
        }
        return if kind == "openapi" {
            success(
                StatusCode::OK,
                json!({
                    "message": "OpenAPI import completed",
                    "endpoints_found": endpoints_found,
                    "endpoints_imported": imported,
                    "endpoints_skipped": skipped,
                }),
                request_id,
            )
        } else {
            success(
                StatusCode::OK,
                json!({
                    "message": "WSDL import completed",
                    "service_name": service_name,
                    "operations_found": operations_found,
                    "endpoints_imported": imported,
                    "endpoints_skipped": skipped,
                }),
                request_id,
            )
        };
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

async fn fetch_openapi_spec(state: &AppState, api: &Value, path: &str) -> Option<Value> {
    let servers = api.get("api_servers").and_then(Value::as_array)?;
    for server in servers.iter().filter_map(Value::as_str) {
        let Ok(target) = discovery_target(server, path) else {
            continue;
        };
        let Ok(response) = state.proxy_client.get(target).send().await else {
            continue;
        };
        if response.status() != StatusCode::OK {
            continue;
        }
        if let Ok(spec) = response.json::<Value>().await {
            return Some(spec);
        }
    }
    None
}

fn python_truthy_json(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn openapi_discovery_route(
    state: &AppState,
    storage: &SharedStorage,
    api: &Value,
    filter: &Value,
    parts: &[&str],
    action: &str,
    method: &Method,
    username: &str,
    request_id: &str,
) -> Response {
    let cached = api
        .get("api_openapi_spec")
        .filter(|value| python_truthy_json(value));
    if method == Method::GET && action.is_empty() {
        if let Some(spec) = cached {
            return success(StatusCode::OK, spec.clone(), request_id);
        }
        let Some(path) = api.get("api_openapi_url").and_then(Value::as_str) else {
            return error(
                StatusCode::NOT_FOUND,
                "OPENAPI001",
                "No OpenAPI URL configured for this API",
                request_id,
            );
        };
        if api
            .get("api_servers")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return error(
                StatusCode::NOT_FOUND,
                "OPENAPI002",
                "No upstream servers configured",
                request_id,
            );
        }
        let Some(spec) = fetch_openapi_spec(state, api, path).await else {
            return error(
                StatusCode::BAD_GATEWAY,
                "OPENAPI003",
                "Failed to fetch OpenAPI spec from upstream",
                request_id,
            );
        };
        let _ = storage
            .update_one("apis", filter, &json!({"api_openapi_spec": spec.clone()}))
            .await;
        return success(StatusCode::OK, spec, request_id);
    }
    if method == Method::POST && action == "refresh" {
        let Some(path) = api.get("api_openapi_url").and_then(Value::as_str) else {
            return error(
                StatusCode::NOT_FOUND,
                "OPENAPI001",
                "No OpenAPI URL configured",
                request_id,
            );
        };
        if api
            .get("api_servers")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return error(
                StatusCode::NOT_FOUND,
                "OPENAPI002",
                "No upstream servers configured",
                request_id,
            );
        }
        let Some(spec) = fetch_openapi_spec(state, api, path).await else {
            return error(
                StatusCode::BAD_GATEWAY,
                "OPENAPI003",
                "Failed to fetch OpenAPI spec",
                request_id,
            );
        };
        let _ = storage
            .update_one("apis", filter, &json!({"api_openapi_spec": spec.clone()}))
            .await;
        return success(
            StatusCode::OK,
            json!({
                "message": "OpenAPI spec refreshed successfully",
                "endpoints_found": spec.get("paths").and_then(Value::as_object).map_or(0, Map::len),
            }),
            request_id,
        );
    }
    if method == Method::POST && action == "import" {
        if !has_permission(state, username, "manage_endpoints").await {
            return error(
                StatusCode::FORBIDDEN,
                "AUTHZ001",
                "Not authorized",
                request_id,
            );
        }
        let spec = if let Some(spec) = cached.cloned() {
            Some(spec)
        } else if let Some(path) = api.get("api_openapi_url").and_then(Value::as_str) {
            let fetched = fetch_openapi_spec(state, api, path).await;
            if let Some(spec) = &fetched {
                let _ = storage
                    .update_one("apis", filter, &json!({"api_openapi_spec": spec.clone()}))
                    .await;
            }
            fetched
        } else {
            None
        };
        let Some(spec) = spec else {
            return error(
                StatusCode::NOT_FOUND,
                "OPENAPI003",
                "No OpenAPI spec available",
                request_id,
            );
        };
        let candidates = crate::routes::discovery::openapi_endpoints(&spec);
        let endpoints_found = candidates.len();
        let api_id = api.get("api_id").cloned().unwrap_or(Value::Null);
        let existing = storage
            .find_many("endpoints", &json!({"api_id": api_id.clone()}))
            .await
            .unwrap_or_default();
        let mut imported = 0_u64;
        let mut skipped = 0_u64;
        for candidate in candidates {
            let uri = candidate
                .get("endpoint_uri")
                .and_then(Value::as_str)
                .unwrap_or("");
            let method = candidate
                .get("endpoint_method")
                .and_then(Value::as_str)
                .unwrap_or("");
            let composite = format!("{method}/{}", uri.trim_start_matches('/'));
            let duplicate = existing.iter().any(|endpoint| {
                let existing_method = endpoint
                    .get("endpoint_method")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let existing_uri = endpoint
                    .get("endpoint_uri")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                format!("{existing_method}/{}", existing_uri.trim_start_matches('/')) == composite
            });
            if duplicate {
                skipped += 1;
                continue;
            }
            let description = candidate
                .get("endpoint_description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .take(127)
                .collect::<String>();
            let endpoint = json!({
                "api_id": api_id,
                "api_name": parts[0],
                "api_version": parts[1],
                "endpoint_id": Uuid::new_v4().to_string(),
                "endpoint_uri": uri,
                "endpoint_method": method,
                "endpoint_description": description,
            });
            if storage.insert_one("endpoints", endpoint).await.is_ok() {
                imported += 1;
            }
        }
        return success(
            StatusCode::OK,
            json!({
                "message": "OpenAPI import completed",
                "endpoints_found": endpoints_found,
                "endpoints_imported": imported,
                "endpoints_skipped": skipped,
            }),
            request_id,
        );
    }
    error(
        StatusCode::NOT_FOUND,
        "GTW003",
        "Platform route does not exist",
        request_id,
    )
}

/// Mirror of the pinned `fetch_introspection_schema`: only a 200 response with
/// no GraphQL errors and a `data.__schema` object yields a schema.
async fn fetch_introspection_schema(state: &AppState, target: String) -> Option<Value> {
    const INTROSPECTION_QUERY: &str = include_str!("graphql_introspection.graphql");
    let response = state
        .proxy_client
        .post(target)
        .header(header::ACCEPT, "application/json")
        .json(&json!({"query": INTROSPECTION_QUERY}))
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    let value = response.json::<Value>().await.ok()?;
    if value.get("errors").is_some_and(python_truthy_json) {
        return None;
    }
    value
        .pointer("/data/__schema")
        .filter(|schema| schema.is_object() && !schema.as_object().is_some_and(Map::is_empty))
        .cloned()
}

fn graphql_schema_response(schema: Value, cached: bool, request_id: &str) -> Response {
    let query = schema
        .get("queryType")
        .or_else(|| schema.pointer("/data/__schema/queryType"))
        .and_then(|item| item.get("name"))
        .cloned()
        .unwrap_or(Value::Null);
    let mutation = schema
        .get("mutationType")
        .or_else(|| schema.pointer("/data/__schema/mutationType"))
        .and_then(|item| item.get("name"))
        .cloned()
        .unwrap_or(Value::Null);
    let subscription = schema
        .get("subscriptionType")
        .or_else(|| schema.pointer("/data/__schema/subscriptionType"));
    let has_subscriptions = subscription.is_some_and(|item| !item.is_null());
    let subscription = subscription
        .and_then(|item| item.get("name"))
        .cloned()
        .unwrap_or(Value::Null);
    success(
        StatusCode::OK,
        json!({
            "cached": cached,
            "schema": schema,
            "operation_types": {
                "query": query,
                "mutation": mutation,
                "subscription": subscription,
            },
            "has_subscriptions": has_subscriptions,
        }),
        request_id,
    )
}

fn discovery_document_response(
    kind: &str,
    document: Value,
    cached: bool,
    request_id: &str,
) -> Response {
    if kind == "openapi" {
        return success(StatusCode::OK, document, request_id);
    }
    success(
        StatusCode::OK,
        json!({"wsdl": document, "cached": cached}),
        request_id,
    )
}

pub async fn backfill_grpc_descriptors(storage: &SharedStorage) -> DescriptorBackfill {
    let apis = match storage.find_many("apis", &json!({})).await {
        Ok(apis) => apis,
        Err(error_value) => {
            return DescriptorBackfill {
                errors: vec![json!({"api": null, "error": error_value.to_string()})],
                ..DescriptorBackfill::default()
            };
        }
    };
    let mut backfill = DescriptorBackfill::default();
    for api in apis {
        let grpc_configured = api
            .get("api_type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("GRPC"))
            || api.get("api_grpc_proto_source").is_some_and(python_truthy)
            || api.get("api_grpc_package").is_some_and(python_truthy);
        if !grpc_configured || api.get("active") == Some(&Value::Bool(false)) {
            continue;
        }
        backfill.scanned += 1;
        if api
            .get("api_grpc_descriptor_set")
            .is_some_and(python_truthy)
        {
            backfill.skipped += 1;
            continue;
        }
        let api_name = api
            .get("api_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let api_version = api
            .get("api_version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let api_label = format!("{api_name}/{api_version}");
        if api_name.is_empty() || api_version.is_empty() {
            backfill.errors.push(json!({
                "api": api_label,
                "error": "API name/version is missing",
            }));
            continue;
        }
        let Some(source) = api
            .get("api_grpc_proto_source")
            .and_then(Value::as_str)
            .filter(|source| !source.is_empty())
        else {
            backfill.errors.push(json!({
                "api": api_label,
                "error": "Proto source not found",
            }));
            continue;
        };
        let max_proto_size = env::var("MAX_PROTO_SIZE_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1024 * 1024);
        let source = match validate_proto_content(source.as_bytes(), max_proto_size) {
            Ok(source) => source,
            Err(error_value) => {
                backfill.errors.push(json!({
                    "api": api_label,
                    "error": error_value.chars().take(500).collect::<String>(),
                }));
                continue;
            }
        };
        match compile_proto(&source) {
            Ok((descriptor, digest)) => {
                let filter = json!({"api_name": api_name, "api_version": api_version});
                match storage
                    .update_one(
                        "apis",
                        &filter,
                        &json!({
                            "api_grpc_descriptor_set": descriptor,
                            "api_grpc_descriptor_sha256": digest,
                        }),
                    )
                    .await
                {
                    Ok(Some(_)) => backfill.updated += 1,
                    Ok(None) => backfill.errors.push(json!({
                        "api": api_label,
                        "error": "API disappeared while descriptor backfill was running",
                    })),
                    Err(error_value) => backfill.errors.push(json!({
                        "api": api_label,
                        "error": error_value.to_string(),
                    })),
                }
            }
            Err(error_value) => backfill.errors.push(json!({
                "api": api_label,
                "error": error_value.chars().take(500).collect::<String>(),
            })),
        }
    }
    backfill
}

async fn proto_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
    username: &str,
    request_id: &str,
) -> Response {
    if method == Method::POST {
        let max_size = env::var(crate::constants::Defaults::MAX_MULTIPART_SIZE_BYTES_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(crate::constants::Defaults::MAX_MULTIPART_SIZE_BYTES_DEFAULT);
        if headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > max_size)
        {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                crate::constants::ErrorCodes::REQUEST_TOO_LARGE,
                crate::constants::Messages::FILE_TOO_LARGE,
                request_id,
            );
        }
    }
    if !has_permission(state, username, "manage_apis").await {
        let (code, message_text) = if method == Method::PUT {
            ("API008", "You do not have permission to update proto files")
        } else if method == Method::DELETE {
            ("API008", "You do not have permission to delete proto files")
        } else {
            ("AUTH001", "User does not have permission to manage APIs")
        };
        return error(StatusCode::FORBIDDEN, code, message_text, request_id);
    }
    let Some(storage) = &state.storage else {
        return unexpected(request_id);
    };
    if path == "/proto/descriptors/backfill" && method == Method::POST {
        let backfill = backfill_grpc_descriptors(storage).await;
        return success(
            StatusCode::OK,
            json!({
                "scanned": backfill.scanned,
                "updated": backfill.updated,
                "skipped": backfill.skipped,
                "missing": backfill.missing(),
                "errors": backfill.errors,
            }),
            request_id,
        );
    }
    let parts = path
        .trim_start_matches("/proto/")
        .split('/')
        .collect::<Vec<_>>();
    if parts.len() != 2 {
        return error(StatusCode::NOT_FOUND, "API003", "API not found", request_id);
    }
    // The pinned handlers derive a proto file name from the path and reject
    // unusable names with 400 GTW013.
    if let Some(reason) = parts.iter().find_map(|part| proto_file_name_error(part)) {
        return error(
            StatusCode::BAD_REQUEST,
            "GTW013",
            &format!("Path validation error: {reason}"),
            request_id,
        );
    }
    let filter = json!({"api_name": parts[0], "api_version": parts[1]});
    if method == Method::GET {
        let proto_record = storage
            .find_one("apis", &filter)
            .await
            .ok()
            .flatten()
            .or(storage
                .find_one("grpc_proto_uploads", &filter)
                .await
                .ok()
                .flatten());
        let Some(proto_record) = proto_record else {
            return error(
                StatusCode::NOT_FOUND,
                "API002",
                &format!("Proto file not found for API {}/{}", parts[0], parts[1]),
                request_id,
            );
        };
        return match proto_record
            .get("api_grpc_proto_source")
            .and_then(Value::as_str)
        {
            Some(source) if !source.is_empty() => success(
                StatusCode::OK,
                // respond_rest drops `message` when a response body is present.
                json!({"content": source}),
                request_id,
            ),
            None => error(
                StatusCode::NOT_FOUND,
                "API002",
                &format!("Proto file not found for API {}/{}", parts[0], parts[1]),
                request_id,
            ),
            Some(_) => error(
                StatusCode::NOT_FOUND,
                "API002",
                &format!("Proto file not found for API {}/{}", parts[0], parts[1]),
                request_id,
            ),
        };
    }
    if method == Method::DELETE {
        let cleared_api = matches!(
            storage
                .update_one(
                    "apis",
                    &filter,
                    &json!({
                        "api_grpc_proto_source": null,
                        "api_grpc_descriptor_set": null,
                        "api_grpc_descriptor_sha256": null
                    }),
                )
                .await,
            Ok(Some(_))
        );
        let cleared_pending = storage
            .delete_one("grpc_proto_uploads", &filter)
            .await
            .unwrap_or(false);
        let _ = (cleared_api, cleared_pending);
        return message(
            StatusCode::OK,
            "Proto file and generated files deleted successfully",
            request_id,
        );
    }
    if method == Method::POST || method == Method::PUT {
        let max_proto_size = match env::var("MAX_PROTO_SIZE_BYTES") {
            Err(_) => 1024 * 1024,
            Ok(value) => match value.trim().parse::<i64>() {
                Ok(size) => usize::try_from(size).unwrap_or(0),
                // The pinned route rejects every upload when the limit is unusable.
                Err(_) => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        crate::constants::ErrorCodes::REQUEST_FILE_TYPE,
                        "Invalid proto file: MAX_PROTO_SIZE_BYTES is not an integer",
                        request_id,
                    );
                }
            },
        };
        let content = match extract_proto_source(headers, body) {
            Ok(content) => content,
            // The pinned route declares an UploadFile form field, so FastAPI
            // rejects any non-multipart request before the handler runs.
            Err(error_value) if error_value == NOT_MULTIPART => {
                return error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "VAL001",
                    "Validation Error",
                    request_id,
                );
            }
            Err(error_value) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    if error_value == "Only .proto files are allowed" {
                        "REQ003"
                    } else {
                        "REQ002"
                    },
                    &error_value,
                    request_id,
                );
            }
        };
        let source = match validate_proto_content(&content, max_proto_size) {
            Ok(source) => source,
            Err(error_value) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    crate::constants::ErrorCodes::REQUEST_FILE_TYPE,
                    &format!("Invalid proto file: {error_value}"),
                    request_id,
                );
            }
        };
        let (descriptor, digest) = match compile_proto(&source) {
            Ok(result) => result,
            Err(error_value) => {
                let message_text = if method == Method::PUT {
                    "Failed to generate gRPC code from proto file".to_owned()
                } else {
                    format!("Failed to generate gRPC code: {error_value}")
                };
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "API009",
                    &message_text,
                    request_id,
                );
            }
        };
        let mut proto_map = serde_json::Map::new();
        proto_map.insert("api_grpc_proto_source".to_string(), json!(source));
        proto_map.insert("api_grpc_descriptor_set".to_string(), json!(descriptor));
        proto_map.insert("api_grpc_descriptor_sha256".to_string(), json!(digest));
        if let Some(pkg) = extract_proto_package(&source) {
            proto_map.insert("api_grpc_package".to_string(), json!(pkg));
        }
        let proto_fields = Value::Object(proto_map);
        let result = storage.update_one("apis", &filter, &proto_fields).await;
        return match result {
            Ok(Some(_)) => message(
                StatusCode::OK,
                if method == Method::PUT {
                    "Proto file updated successfully"
                } else {
                    "Proto file uploaded and gRPC code generated successfully"
                },
                request_id,
            ),
            Ok(None) => {
                let pending_exists = storage
                    .find_one("grpc_proto_uploads", &filter)
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                let saved = if pending_exists {
                    matches!(
                        storage
                            .update_one("grpc_proto_uploads", &filter, &proto_fields)
                            .await,
                        Ok(Some(_))
                    )
                } else {
                    let mut pending = filter.clone();
                    if let (Value::Object(base), Value::Object(proto)) =
                        (&mut pending, &proto_fields)
                    {
                        for (key, value) in proto {
                            base.insert(key.clone(), value.clone());
                        }
                    }
                    storage
                        .insert_one("grpc_proto_uploads", pending)
                        .await
                        .is_ok()
                };
                if saved {
                    message(
                        StatusCode::OK,
                        if method == Method::PUT {
                            "Proto file updated successfully"
                        } else {
                            "Proto file uploaded and gRPC code generated successfully"
                        },
                        request_id,
                    )
                } else {
                    unexpected(request_id)
                }
            }
            Err(_) => unexpected(request_id),
        };
    }
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "GTW004",
        "Method not allowed",
        request_id,
    )
}

const NOT_MULTIPART: &str = "Request is not multipart/form-data";

fn extract_proto_source(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, String> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("multipart/form-data") {
        return Err(NOT_MULTIPART.to_owned());
    }
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(str::trim)
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| "Multipart boundary is missing".to_owned())?;
    let header_end = body
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| (index, 4))
        .or_else(|| {
            body.windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| (index, 2))
        })
        .ok_or_else(|| "Invalid multipart body".to_owned())?;
    let multipart_headers = std::str::from_utf8(&body[..header_end.0])
        .map_err(|_| "Invalid multipart body".to_owned())?;
    let disposition = multipart_headers
        .lines()
        .find(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-disposition:")
        })
        .ok_or_else(|| "Only .proto files are allowed".to_owned())?;
    let filename = disposition
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            part.strip_prefix("filename=")
                .or_else(|| part.strip_prefix("Filename="))
        })
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| "Only .proto files are allowed".to_owned())?;
    if !filename.to_ascii_lowercase().ends_with(".proto") {
        return Err("Only .proto files are allowed".to_owned());
    }
    let content = &body[header_end.0 + header_end.1..];
    let marker = format!("\r\n--{boundary}").into_bytes();
    let content_end = content
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap_or(content.len());
    let mut content = content[..content_end].to_vec();
    while content
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        content.pop();
    }
    Ok(content)
}

fn extract_proto_package(source: &str) -> Option<String> {
    static PACKAGE: OnceLock<Regex> = OnceLock::new();
    PACKAGE
        .get_or_init(|| Regex::new(r"\bpackage\s+([a-zA-Z0-9_.]+)\s*;").unwrap())
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|package| package.as_str().to_owned())
}

fn validate_proto_content(content: &[u8], max_size: usize) -> Result<String, String> {
    if content.len() > max_size {
        return Err(format!("File too large (max {max_size} bytes)"));
    }
    if content.contains(&0) {
        return Err("Invalid proto file: binary content detected".to_owned());
    }
    let source = std::str::from_utf8(content)
        .map_err(|_| "Invalid proto file: not valid UTF-8".to_owned())?;
    if !(source.contains("syntax") || source.contains("message") || source.contains("service")) {
        return Err("Invalid proto file: missing proto syntax (syntax/message/service)".to_owned());
    }
    static SUSPICIOUS: OnceLock<Regex> = OnceLock::new();
    if SUSPICIOUS
        .get_or_init(|| Regex::new(r"`|\$\(|;\s*(?:rm|mv|cp|chmod|cat|wget|curl)").unwrap())
        .is_match(source)
    {
        return Err("Invalid proto file: suspicious content detected".to_owned());
    }
    Ok(source.to_owned())
}

fn compile_proto(source: &str) -> Result<(String, String), String> {
    let directory = std::env::temp_dir().join(format!("doorman-proto-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).map_err(|error_value| error_value.to_string())?;
    let directory = ProtoCompileDirectory(directory);
    let source_path = directory.0.join("api.proto");
    let descriptor_path = directory.0.join("api.descriptor.pb");
    fs::write(&source_path, source).map_err(|error_value| error_value.to_string())?;
    let protoc_res = std::panic::catch_unwind(protoc_bin_vendored::protoc_bin_path);
    let protoc = match protoc_res {
        Ok(Ok(path)) => path,
        _ => std::path::PathBuf::from("protoc"),
    };
    let mut cmd = Command::new(&protoc);
    cmd.arg(format!("--proto_path={}", directory.0.display()));
    if let Ok(Ok(includes)) = std::panic::catch_unwind(protoc_bin_vendored::include_path) {
        if includes.exists() {
            cmd.arg(format!("--proto_path={}", includes.display()));
        }
    }
    if std::path::Path::new("/usr/include").exists() {
        cmd.arg("--proto_path=/usr/include");
    }
    if std::path::Path::new("/usr/local/include").exists() {
        cmd.arg("--proto_path=/usr/local/include");
    }
    cmd.arg(format!(
        "--descriptor_set_out={}",
        descriptor_path.display()
    ))
    .arg("--include_imports")
    .arg(&source_path);

    let output = cmd
        .output()
        .map_err(|error_value| error_value.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let bytes = fs::read(&descriptor_path).map_err(|error_value| error_value.to_string())?;
    use base64::Engine as _;
    use sha2::Digest as _;
    Ok((
        base64::engine::general_purpose::STANDARD.encode(&bytes),
        format!("{:x}", sha2::Sha256::digest(&bytes)),
    ))
}

async fn logging_routes(
    state: &AppState,
    path: &str,
    method: &Method,
    query: &HashMap<String, String>,
    username: &str,
    request_id: &str,
) -> Response {
    if !state.config.logs_enabled {
        return error(
            StatusCode::NOT_FOUND,
            "GTW003",
            "Platform route does not exist",
            request_id,
        );
    }
    if method != Method::GET {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "GTW004",
            "Method not allowed",
            request_id,
        );
    }
    let export = matches!(path, "/logging/logs/export" | "/logging/logs/download");
    let permission = if export { "export_logs" } else { "view_logs" };
    if !has_permission(state, username, permission).await {
        let (code, message_text) = match path {
            "/logging/logs/export" => ("LOG003", "You do not have permission to export logs"),
            "/logging/logs/download" => ("LOG004", "You do not have permission to download logs"),
            "/logging/logs/files" => ("LOG005", "You do not have permission to view log files"),
            "/logging/logs/statistics" => (
                "LOG002",
                "You do not have permission to view log statistics",
            ),
            _ => ("LOG001", "You do not have permission to view logs"),
        };
        return error(StatusCode::FORBIDDEN, code, message_text, request_id);
    }
    let directory = state
        .config
        .logs_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("platform-logs"));
    let mut files = Vec::new();
    match fs::read_dir(&directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => return unexpected(request_id),
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.path().is_file() && is_log_file_name(&name) {
                    files.push(name);
                }
            }
        }
        Err(error_value) if error_value.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return unexpected(request_id),
    }
    match path {
        "/logging/logs/files" => {
            let count = files.len();
            success(
                StatusCode::OK,
                json!({"log_files": files, "count": count}),
                request_id,
            )
        }
        "/logging/logs/statistics" => match log_statistics(&directory) {
            Ok(statistics) => success(StatusCode::OK, statistics, request_id),
            Err(LogExportError::Read) => unexpected(request_id),
            Err(_) => unexpected(request_id),
        },
        "/logging/logs" => {
            let limit = query
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 1_000);
            let offset = query
                .get("offset")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            match read_log_records(&directory, query, MAX_LOG_EXPORT_ENTRIES) {
                Ok(entries) => {
                    let total = entries.len();
                    let logs = entries
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    success(
                        StatusCode::OK,
                        json!({
                            "logs": logs,
                            "total": total,
                            "has_more": offset.saturating_add(limit) < total,
                        }),
                        request_id,
                    )
                }
                Err(_) => unexpected(request_id),
            }
        }
        "/logging/logs/export" | "/logging/logs/download" => match log_export(&directory, query) {
            Ok(export) if path == "/logging/logs/export" => success(
                StatusCode::OK,
                json!({
                    "format": export.format,
                    "data": export.data,
                    "filename": export.filename,
                }),
                request_id,
            ),
            Ok(export) => log_download_response(export, request_id),
            Err(LogExportError::InvalidFormat) => error(
                StatusCode::BAD_REQUEST,
                "LOG005",
                "Unsupported export format; use json or csv",
                request_id,
            ),
            Err(LogExportError::InvalidDate) => error(
                StatusCode::BAD_REQUEST,
                "LOG006",
                "Invalid export date; use YYYY-MM-DD",
                request_id,
            ),
            Err(LogExportError::Read) => unexpected(request_id),
        },
        _ => error(
            StatusCode::NOT_FOUND,
            "GTW003",
            "Platform route does not exist",
            request_id,
        ),
    }
}

const MAX_LOG_EXPORT_ENTRIES: usize = 10_000;
const MAX_LOG_EXPORT_BYTES: u64 = 50 * 1024 * 1024;

struct LogExport {
    format: String,
    data: String,
    filename: String,
}

enum LogExportError {
    InvalidFormat,
    InvalidDate,
    Read,
}

fn log_export(
    directory: &std::path::Path,
    query: &HashMap<String, String>,
) -> Result<LogExport, LogExportError> {
    let format = query
        .get("format")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "json".to_owned());
    if !matches!(format.as_str(), "json" | "csv") {
        return Err(LogExportError::InvalidFormat);
    }
    for key in ["start_date", "end_date"] {
        if let Some(value) = query.get(key)
            && !valid_log_date(value)
        {
            return Err(LogExportError::InvalidDate);
        }
    }

    Ok(render_log_export(
        &format,
        read_log_records(directory, query, MAX_LOG_EXPORT_ENTRIES)?,
    ))
}

/// The pinned LoggingService only reads `doorman.log*` and
/// `doorman-trail.log*`; other files in the directory (such as the persisted
/// metrics documents) are not logs.
fn is_log_file_name(name: &str) -> bool {
    name.starts_with("doorman.log") || name.starts_with("doorman-trail.log")
}

fn read_log_records(
    directory: &std::path::Path,
    query: &HashMap<String, String>,
    max_entries: usize,
) -> Result<Vec<Value>, LogExportError> {
    let mut paths = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => Some(entries),
        Err(error_value) if error_value.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(LogExportError::Read),
    };
    if let Some(entries) = entries {
        for entry in entries {
            let entry = entry.map_err(|_| LogExportError::Read)?;
            let file_type = entry.file_type().map_err(|_| LogExportError::Read)?;
            if !file_type.is_file() || !is_log_file_name(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let metadata = entry.metadata().map_err(|_| LogExportError::Read)?;
            paths.push((
                metadata.modified().unwrap_or(UNIX_EPOCH),
                metadata.len(),
                entry.path(),
            ));
        }
    };
    paths.sort_by(|left, right| right.0.cmp(&left.0));

    let mut read_bytes = 0_u64;
    let mut logs = Vec::new();
    for (_, size, path) in paths {
        read_bytes = read_bytes.saturating_add(size);
        if read_bytes > MAX_LOG_EXPORT_BYTES {
            return Err(LogExportError::Read);
        }
        let content = fs::read_to_string(path).map_err(|_| LogExportError::Read)?;
        for line in content.lines() {
            let Some(mut record) = parse_log_record(line) else {
                continue;
            };
            if log_record_matches(&record, query) {
                audit::redact_record(&mut record);
                logs.push(record);
                if logs.len() >= max_entries {
                    break;
                }
            }
        }
        if logs.len() >= max_entries {
            break;
        }
    }
    for line in crate::observability::logging::memory_log_snapshot()
        .into_iter()
        .rev()
        .take(max_entries)
    {
        let Some(mut record) = parse_log_record(&line) else {
            continue;
        };
        if log_record_matches(&record, query) {
            audit::redact_record(&mut record);
            logs.push(record);
        }
    }
    logs.sort_by(|left, right| {
        right
            .get("timestamp")
            .and_then(Value::as_str)
            .cmp(&left.get("timestamp").and_then(Value::as_str))
    });
    logs.truncate(max_entries);
    Ok(logs)
}

fn log_statistics(directory: &std::path::Path) -> Result<Value, LogExportError> {
    let logs = read_log_records(directory, &HashMap::new(), MAX_LOG_EXPORT_ENTRIES)?;
    let mut error_count = 0_u64;
    let mut warning_count = 0_u64;
    let mut info_count = 0_u64;
    let mut debug_count = 0_u64;
    let mut response_time_total = 0_f64;
    let mut response_time_count = 0_u64;
    let mut apis = HashMap::new();
    let mut users = HashMap::new();
    let mut endpoints = HashMap::new();
    for record in &logs {
        match record
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_uppercase()
            .as_str()
        {
            "ERROR" => error_count += 1,
            "WARNING" | "WARN" => warning_count += 1,
            "INFO" => info_count += 1,
            "DEBUG" => debug_count += 1,
            _ => {}
        }
        if let Some(response_time) = record.get("response_time").and_then(log_number) {
            response_time_total += response_time;
            response_time_count += 1;
        }
        increment_log_stat(&mut apis, record, "api");
        increment_log_stat(&mut users, record, "user");
        increment_log_stat(&mut endpoints, record, "endpoint");
    }
    let average = if response_time_count == 0 {
        0.0
    } else {
        (response_time_total / response_time_count as f64 * 100.0).round() / 100.0
    };
    Ok(json!({
        "total_logs": logs.len(),
        "error_count": error_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "debug_count": debug_count,
        "avg_response_time": average,
        "top_apis": top_log_statistics(apis),
        "top_users": top_log_statistics(users),
        "top_endpoints": top_log_statistics(endpoints),
    }))
}

fn log_number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|value| value.parse::<f64>().ok()))
        .filter(|value| value.is_finite())
}

fn increment_log_stat(counts: &mut HashMap<String, u64>, record: &Value, key: &str) {
    let Some(value) = record.get(key).and_then(Value::as_str) else {
        return;
    };
    if !value.is_empty() {
        *counts.entry(value.to_owned()).or_default() += 1;
    }
}

fn top_log_statistics(counts: HashMap<String, u64>) -> Vec<Value> {
    let mut entries = counts.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    entries
        .into_iter()
        .take(10)
        .map(|(name, count)| json!({"name": name, "count": count}))
        .collect()
}

fn valid_log_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}

fn parse_log_record(line: &str) -> Option<Value> {
    let line = line.trim();
    if let Ok(mut record) = serde_json::from_str::<Value>(line) {
        let values = record.as_object_mut()?;
        let timestamp = values
            .remove("time")
            .or_else(|| values.get("timestamp").cloned())
            .unwrap_or_else(|| Value::String(time::OffsetDateTime::now_utc().to_string()));
        let source = values
            .remove("name")
            .unwrap_or(Value::String(String::new()));
        let message = values
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let structured = extract_log_fields(message);
        for (key, value) in structured {
            values.entry(key).or_insert(value);
        }
        values.insert("timestamp".to_owned(), timestamp);
        values.insert("source".to_owned(), source);
        return Some(record);
    }

    let mut parts = line.splitn(4, " - ");
    let timestamp = parts.next()?;
    let source = parts.next()?;
    let level = parts.next()?;
    let full_message = parts.next()?;
    let (request_id, message) = full_message
        .split_once(" | ")
        .map_or((None, full_message), |(request_id, message)| {
            (Some(request_id), message)
        });
    let mut values = extract_log_fields(message);
    if let Some(request_id) = request_id {
        values.insert("request_id".to_owned(), json!(request_id));
    }
    values.insert(
        "timestamp".to_owned(),
        json!(timestamp.replace(' ', "T").replace(',', ".")),
    );
    values.insert(
        "level".to_owned(),
        json!(if request_id.is_some() { level } else { "DEBUG" }),
    );
    values.insert("message".to_owned(), json!(message));
    values.insert("source".to_owned(), json!(source));
    Some(Value::Object(values))
}

/// Compile each log-parsing pattern once; log queries parse up to thousands of
/// records, and compiling per record made them take tens of seconds.
fn cached_regex(pattern: &'static str) -> Option<Regex> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<&'static str, Regex>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().ok()?;
    if let Some(regex) = cache.get(pattern) {
        return Some(regex.clone());
    }
    let regex = Regex::new(pattern).ok()?;
    cache.insert(pattern, regex.clone());
    Some(regex)
}

fn extract_log_fields(message: &str) -> Map<String, Value> {
    let mut values = Map::new();
    let capture = |pattern: &'static str, group: usize| {
        cached_regex(pattern)?
            .captures(message)?
            .get(group)
            .map(|value| value.as_str().to_owned())
    };
    if let Some(value) = capture(r"(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})", 1) {
        values.insert("request_id".to_owned(), json!(value));
    }
    if let Some(value) = capture(r"Username: (\w+)", 1) {
        values.insert("user".to_owned(), json!(value));
    }
    if let Some(value) = capture(r"(?:effective_ip|client_ip)=([A-Fa-f0-9:.]+)", 1) {
        values.insert("ip_address".to_owned(), json!(value));
    } else if let Some(mut value) = capture(r"From:\s+(.+?)$", 1) {
        if value.matches(':').count() > 1 {
            if let Some((host, _)) = value.rsplit_once(':') {
                value = host.to_owned();
            }
        } else if let Some((host, _)) = value.split_once(':') {
            value = host.to_owned();
        }
        values.insert("ip_address".to_owned(), json!(value));
    }
    if let Some(pattern) = cached_regex(r"Endpoint: (\w+) (.+)")
        && let Some(captures) = pattern.captures(message)
    {
        values.insert("method".to_owned(), json!(&captures[1]));
        values.insert("endpoint".to_owned(), json!(&captures[2]));
    }
    if let Some(value) = capture(r"Total time: ([\d.]+)ms", 1) {
        values.insert("response_time".to_owned(), json!(value));
    }
    if (message.contains("Status check failed")
        || message.to_ascii_lowercase().contains("status_code"))
        && let Some(value) = capture(r"(?i)status_code[:\s]+(\d+)", 1)
    {
        values.insert("status_code".to_owned(), json!(value));
    }
    let endpoint = values
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lower = message.to_ascii_lowercase();
    let request_type = if ["/rest", "/soap", "/graphql"]
        .iter()
        .any(|part| endpoint.contains(part))
        || [
            "rest gateway",
            "soap gateway",
            "graphql gateway",
            "upstream",
        ]
        .iter()
        .any(|part| lower.contains(part))
    {
        "gateway"
    } else if endpoint.contains("/authorization")
        || ["login", "register", "token", "permission"]
            .iter()
            .any(|part| lower.contains(part))
    {
        "auth"
    } else {
        "platform"
    };
    values.insert("type".to_owned(), json!(request_type));
    values
}

fn log_record_matches(record: &Value, query: &HashMap<String, String>) -> bool {
    let value = |key: &str| record.get(key).and_then(Value::as_str).unwrap_or_default();
    if let Some(start_date) = query.get("start_date")
        && value("timestamp").get(..10).unwrap_or_default() < start_date.as_str()
    {
        return false;
    }
    if let Some(end_date) = query.get("end_date")
        && value("timestamp").get(..10).unwrap_or_default() > end_date.as_str()
    {
        return false;
    }
    let timestamp = value("timestamp");
    let timestamp_time = timestamp
        .get(11..16)
        .filter(|value| value.as_bytes().get(2) == Some(&b':'));
    if let Some(start_time) = query
        .get("start_time")
        .filter(|value| !value.trim().is_empty())
        && timestamp_time.is_none_or(|value| value < start_time.as_str())
    {
        return false;
    }
    if let Some(end_time) = query
        .get("end_time")
        .filter(|value| !value.trim().is_empty())
        && timestamp_time.is_none_or(|value| value > end_time.as_str())
    {
        return false;
    }
    for key in [
        "user",
        "api",
        "endpoint",
        "request_id",
        "method",
        "ip_address",
        "level",
        "type",
    ] {
        let Some(expected) = query.get(key).filter(|value| !value.trim().is_empty()) else {
            continue;
        };
        if !value(key)
            .to_ascii_lowercase()
            .contains(&expected.trim().to_ascii_lowercase())
        {
            return false;
        }
    }
    if let Some(expected) = query
        .get("status_code")
        .filter(|value| !value.trim().is_empty())
        && value("status_code") != expected.trim()
    {
        return false;
    }
    let response_time = record.get("response_time").and_then(log_number);
    if let Some(minimum) = query
        .get("min_response_time")
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        && response_time.is_none_or(|value| value < minimum)
    {
        return false;
    }
    if let Some(maximum) = query
        .get("max_response_time")
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        && response_time.is_none_or(|value| value > maximum)
    {
        return false;
    }
    if let Some(excluded) = query
        .get("exclude_type")
        .filter(|value| !value.trim().is_empty())
    {
        let excluded = excluded.trim().to_ascii_lowercase();
        if value("type").eq_ignore_ascii_case(&excluded)
            || (excluded == "platform"
                && value("endpoint")
                    .to_ascii_lowercase()
                    .contains("/platform/"))
        {
            return false;
        }
    }
    true
}

fn render_log_export(format: &str, logs: Vec<Value>) -> LogExport {
    let timestamp = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}{:02}{:02}_{:02}{:02}{:02}",
        timestamp.year(),
        u8::from(timestamp.month()),
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second(),
    );
    let (data, extension) = if format == "csv" {
        (render_log_csv(&logs), "csv")
    } else {
        (
            serde_json::to_string_pretty(&logs).unwrap_or_else(|_| "[]".to_owned()),
            "json",
        )
    };
    LogExport {
        format: format.to_owned(),
        data,
        filename: format!("logs_export_{stamp}.{extension}"),
    }
}

fn render_log_csv(logs: &[Value]) -> String {
    const COLUMNS: [&str; 15] = [
        "timestamp",
        "level",
        "message",
        "source",
        "user",
        "api",
        "endpoint",
        "method",
        "status_code",
        "response_time",
        "ip_address",
        "protocol",
        "request_id",
        "group",
        "role",
    ];
    let mut output = COLUMNS.join(",");
    output.push('\n');
    for record in logs {
        let values = COLUMNS.map(|column| {
            record
                .get(column)
                .map(|value| match value {
                    Value::String(value) => value.clone(),
                    value => value.to_string(),
                })
                .unwrap_or_default()
        });
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('"');
            output.push_str(&value.replace('"', "\"\""));
            output.push('"');
        }
        output.push('\n');
    }
    output
}

fn log_download_response(export: LogExport, request_id: &str) -> Response {
    let content_type = if export.format == "csv" {
        "text/csv; charset=utf-8"
    } else {
        "application/json"
    };
    let length = export.data.len().to_string();
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type)],
        Body::from(export.data),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename={}", export.filename)) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("request_id", value.clone());
        response.headers_mut().insert("x-request-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&length) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, value.clone());
        response.headers_mut().insert("x-body-length", value);
    }
    response
}

async fn discovery_parse(
    state: &AppState,
    path: &str,
    method: &Method,
    payload: Value,
    raw_body: &[u8],
    username: &str,
    request_id: &str,
) -> Response {
    if method != Method::POST {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "GTW004",
            "Method not allowed",
            request_id,
        );
    }
    if !has_permission(state, username, "manage_apis").await {
        return error(
            StatusCode::FORBIDDEN,
            "AUTHZ001",
            "Not authorized",
            request_id,
        );
    }
    if path == "/openapi/parse" {
        return match crate::routes::discovery::parse_openapi(&payload) {
            Ok(parsed) => success(StatusCode::OK, parsed, request_id),
            Err(message) => error(StatusCode::BAD_REQUEST, "OPENAPI004", &message, request_id),
        };
    }

    // The pinned route parses the raw request body as the WSDL document.
    let content = String::from_utf8_lossy(raw_body).into_owned();
    if let Err(message) = crate::routes::discovery::validate_wsdl(&content) {
        let message = if content.trim().is_empty() {
            message
        } else {
            format!("Invalid WSDL: {message}")
        };
        return error(StatusCode::BAD_REQUEST, "WSDL004", &message, request_id);
    }
    match crate::routes::discovery::parse_wsdl(&content) {
        Ok(parsed) => success(
            StatusCode::OK,
            json!({
                "service_name": parsed.get("service_name").cloned().unwrap_or(Value::String(String::new())),
                "target_namespace": parsed.get("target_namespace").cloned().unwrap_or(Value::String(String::new())),
                "operations": parsed.get("operations").cloned().unwrap_or_else(|| json!([])),
                "endpoints_count": parsed.get("endpoints").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            }),
            request_id,
        ),
        Err(message) => error(StatusCode::BAD_REQUEST, "WSDL004", &message, request_id),
    }
}

fn sign_token(
    state: &AppState,
    claims: &AccessClaims,
) -> Result<String, jsonwebtoken::errors::Error> {
    let config = &state.config.shared_storage;
    if let Some(raw) = &config.jwt_keys_json {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            let entries = value
                .get("keys")
                .and_then(Value::as_array)
                .cloned()
                .or_else(|| value.as_array().cloned())
                .unwrap_or_else(|| vec![value]);
            for entry in entries {
                if entry.get("active").and_then(Value::as_bool) == Some(false) {
                    continue;
                }
                let algorithm = entry
                    .get("algorithm")
                    .and_then(Value::as_str)
                    .unwrap_or("HS256");
                let kid = entry.get("kid").and_then(Value::as_str).map(str::to_owned);
                let mut header = Header::new(if algorithm.eq_ignore_ascii_case("RS256") {
                    Algorithm::RS256
                } else {
                    Algorithm::HS256
                });
                header.kid = kid;
                if algorithm.eq_ignore_ascii_case("RS256") {
                    let key = entry
                        .get("private_key_path")
                        .and_then(Value::as_str)
                        .and_then(|path| fs::read_to_string(path).ok())
                        .or_else(|| {
                            entry
                                .get("private_key")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        });
                    if let Some(key) = key {
                        return encode(
                            &header,
                            claims,
                            &EncodingKey::from_rsa_pem(key.as_bytes())?,
                        );
                    }
                } else if let Some(key) = entry
                    .get("secret")
                    .or_else(|| entry.get("key"))
                    .and_then(Value::as_str)
                {
                    return encode(&header, claims, &EncodingKey::from_secret(key.as_bytes()));
                }
            }
        }
    }
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(
            config
                .jwt_secret
                .as_deref()
                .unwrap_or("insecure-test-key")
                .as_bytes(),
        ),
    )
}

fn password_hash(user: &Value) -> Option<String> {
    match user.get("password")? {
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => String::from_utf8(
            values
                .iter()
                .map(|value| u8::try_from(value.as_u64()?).ok())
                .collect::<Option<Vec<_>>>()?,
        )
        .ok(),
        Value::Object(map) => {
            // Python DMP1 snapshots tag bytes separately from MongoDB's
            // Extended JSON binary representation. Preserve both formats so
            // existing users can log in without rewriting password hashes.
            let encoded = if map.get("__type__").and_then(Value::as_str) == Some("bytes") {
                map.get("data")
            } else {
                map.get("$binary").and_then(|binary| binary.get("base64"))
            };
            encoded
                .and_then(Value::as_str)
                .and_then(|raw| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw).ok()
                })
                .and_then(|bytes| String::from_utf8(bytes).ok())
        }
        _ => None,
    }
}

/// Restricted fields the caller attempted to set, sorted like Python's
/// `sorted(attempted_restricted)`. Python only counts a field as "attempted"
/// when its incoming value is not null, so a null-valued restricted field is
/// treated as safe here too.
fn restricted_self_update_fields(payload: &Value) -> Vec<String> {
    let Some(fields) = payload.as_object() else {
        return Vec::new();
    };
    let mut restricted: Vec<String> = fields
        .iter()
        .filter(|(field, value)| {
            matches!(field.as_str(), "role" | "groups" | "active" | "username") && !value.is_null()
        })
        .map(|(field, _)| field.clone())
        .collect();
    restricted.sort();
    restricted
}

fn bootstrap_admin_update_fields_are_safe(payload: &Value) -> bool {
    matches!(
        payload.as_object(),
        // Null values are not updates; bandwidth_limit_enabled is not operational.
        Some(fields) if fields.iter().filter(|(_, value)| !value.is_null()).all(|(field, _)| {
            matches!(
                field.as_str(),
                "bandwidth_limit_bytes"
                    | "bandwidth_limit_window"
                    | "rate_limit_duration"
                    | "rate_limit_duration_type"
                    | "rate_limit_enabled"
                    | "throttle_duration"
                    | "throttle_duration_type"
                    | "throttle_wait_duration"
                    | "throttle_wait_duration_type"
                    | "throttle_queue_limit"
                    | "throttle_enabled"
            )
        })
    )
}

fn secure_password(password: &str) -> bool {
    password.chars().count() >= 16
        && password.chars().any(char::is_uppercase)
        && password.chars().any(char::is_lowercase)
        && password.chars().any(char::is_numeric)
        && password
            .chars()
            .any(|c| "!@#$%^&*()-_=+[]{};:,.<>?/".contains(c))
}

fn password_policy() -> &'static str {
    "Password must include at least 16 characters, one uppercase letter, one lowercase letter, one digit, and one special character"
}

fn cookie_secure(headers: &HeaderMap) -> bool {
    let https_only = env_bool("HTTPS_ONLY", false);
    let inferred_secure = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"));
    let secure = env::var("COOKIE_SECURE")
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(https_only || inferred_secure);
    // Plain-HTTP local hosts never get Secure cookies unless HTTPS_ONLY is set,
    // so local runs stay usable (pinned behaviour).
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .rsplit_once(':')
                .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
                .map_or(value, |(name, _)| name)
                .to_ascii_lowercase()
        });
    if !inferred_secure
        && !https_only
        && host
            .is_some_and(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "testserver"))
    {
        return false;
    }
    secure
}

fn cookie_same_site(secure: bool) -> &'static str {
    let raw = env::var("COOKIE_SAMESITE").unwrap_or_default();
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "" | "strict" => "Strict",
        "none" if secure => "None",
        // Unknown values and None without Secure fall back to Lax.
        _ => "Lax",
    }
}

async fn csrf_matches(
    headers: &HeaderMap,
    storage: &crate::storage::runtime::SharedStorage,
    username: &str,
) -> bool {
    let Some(header_token) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    if cookie_value(headers, "csrf_token").as_deref() == Some(header_token) {
        return true;
    }
    matches!(
        storage.get_ephemeral(&format!("csrf_token_map:{username}")).await,
        Ok(Some(Value::String(value))) if value == header_token
    )
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(cookie_name, value)| (cookie_name == name).then(|| value.to_owned()))
}

fn cookie_domain(headers: &HeaderMap) -> Option<String> {
    let domain = env::var("COOKIE_DOMAIN").ok()?.trim().to_owned();
    if !domain.contains('.') {
        return None;
    }
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())?
        .split(':')
        .next()
        .unwrap_or_default();
    (host == domain || host.ends_with(&format!(".{domain}"))).then_some(domain)
}

fn auth_expiry_seconds() -> usize {
    let value = env::var("AUTH_EXPIRE_TIME")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30);
    let multiplier = match env::var("AUTH_EXPIRE_TIME_FREQ")
        .unwrap_or_else(|_| "minutes".to_owned())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "s" | "sec" | "second" | "seconds" => 1,
        "h" | "hr" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        "w" | "wk" | "week" | "weeks" => 7 * 24 * 60 * 60,
        _ => 60,
    };
    value.saturating_mul(multiplier)
}

fn refresh_expiry_seconds() -> usize {
    let value = env::var("AUTH_REFRESH_EXPIRE_TIME")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(7);
    let multiplier = match env::var("AUTH_REFRESH_EXPIRE_FREQ")
        .unwrap_or_else(|_| "days".to_owned())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "s" | "sec" | "second" | "seconds" => 1,
        "m" | "min" | "minute" | "minutes" => 60,
        "h" | "hr" | "hour" | "hours" => 60 * 60,
        "w" | "wk" | "week" | "weeks" => 7 * 24 * 60 * 60,
        _ => 24 * 60 * 60,
    };
    value.saturating_mul(multiplier)
}

fn request_id_from(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .or_else(|| headers.get("request_id"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

#[allow(clippy::too_many_arguments)]
async fn auth_ip_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    direct_addr: Option<SocketAddr>,
    limit_name: &str,
    default_limit: u64,
    window_name: &str,
    default_window: u64,
    request_id: &str,
) -> Option<Response> {
    if env_bool("LOGIN_IP_RATE_DISABLED", false) {
        return None;
    }
    let storage = state.storage.as_ref()?;
    let settings = match storage
        .find_one("settings", &json!({"type": "security_settings"}))
        .await
    {
        Ok(settings) => settings,
        Err(_) => {
            return Some(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SEC012",
                "Security policy is temporarily unavailable",
                request_id,
            ));
        }
    };
    let client_ip = effective_client_ip_for_settings(
        settings.as_ref(),
        headers,
        direct_addr.map(|addr| addr.ip()),
        settings
            .as_ref()
            .and_then(|settings| settings.get("trust_x_forwarded_for"))
            .and_then(Value::as_bool)
            .unwrap_or(state.config.shared_storage.trust_x_forwarded_for),
    )
    .map(|ip| ip.to_string())?;
    let limit = env::var(limit_name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_limit);
    let window = env::var(window_name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_window)
        .max(1);
    let now = unix_seconds();
    let bucket = now / window;
    let count = match storage
        .increment_window(&format!("ip_rate_limit:{client_ip}:{bucket}"), window)
        .await
    {
        Ok(count) => count,
        Err(_) => {
            return Some(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SEC012",
                "Security policy is temporarily unavailable",
                request_id,
            ));
        }
    };
    if count <= limit {
        return None;
    }
    let reset = (bucket + 1) * window;
    let retry_after = window - (now % window);
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "detail": {
                "error_code": "IP_RATE_LIMIT",
                "message": format!(
                    "Too many requests from your IP address. Please wait {retry_after} seconds before trying again. Limit: {limit} requests per {window} seconds."
                ),
                "retry_after": retry_after
            }
        }),
        request_id,
    );
    for (name, value) in [
        ("retry-after", retry_after),
        ("x-ratelimit-limit", limit),
        ("x-ratelimit-remaining", 0),
        ("x-ratelimit-reset", reset),
    ] {
        if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
            response.headers_mut().insert(name, value);
        }
    }
    Some(response)
}

async fn auth_account_rate_limit(
    state: &AppState,
    payload: &Value,
    limit_name: &str,
    default_limit: u64,
    window_name: &str,
    default_window: u64,
    request_id: &str,
) -> Option<Response> {
    let identifier = payload
        .get("email")
        .or_else(|| payload.get("username"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_ascii_lowercase();
    let storage = state.storage.as_ref()?;
    let limit = env::var(limit_name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_limit);
    let window = env::var(window_name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_window)
        .max(1);
    let now = unix_seconds();
    let bucket = now / window;
    let account_hash = format!("{:x}", Sha256::digest(identifier.as_bytes()));
    let key = format!("account_rate_limit:{limit_name}:{account_hash}:{bucket}");
    let count = storage.increment_window(&key, window).await.ok()?;
    if count <= limit {
        return None;
    }
    let retry_after = window - (now % window);
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "detail": {
                "error_code": "ACCOUNT_RATE_LIMIT",
                "message": "Too many attempts for this account. Please try again later.",
                "retry_after": retry_after
            }
        }),
        request_id,
    );
    let retry_after_value = retry_after.to_string();
    if let Ok(value) = HeaderValue::from_str(retry_after_value.as_str()) {
        response.headers_mut().insert("retry-after", value);
    }
    Some(response)
}

fn content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().ends_with("+json")
        })
}

/// Routes whose Python counterpart declares a required (non-Optional) typed
/// Pydantic body parameter, so FastAPI's global RequestValidationError
/// handler returns 422 VAL001 for a request with no body at all -- before
/// authentication, permission, or existence checks run -- regardless of
/// Content-Type. Confirmed against the pinned reference for every listed
/// route; routes with an `Optional`/defaulted body (memory dump/restore,
/// security settings) are deliberately excluded.
/// Python's service-layer message for a missing entity; collections without a
/// dedicated service message use the generic one.
fn not_found_message(collection: &str) -> &'static str {
    match collection {
        "roles" => "Role does not exist",
        "groups" => "Group does not exist",
        "routings" => "Routing does not exist",
        _ => "Resource not found",
    }
}

fn requires_nonempty_json_body(path: &str, method: &Method) -> bool {
    match *method {
        Method::POST => {
            path == "/credit/rotate-key"
                || (path.starts_with("/proto/") && path != "/proto/descriptors/backfill")
                || (path.starts_with("/rate-limits/") && path.ends_with("/duplicate"))
        }
        Method::PUT => {
            path.starts_with("/api/")
                || path.starts_with("/endpoint/")
                || path.starts_with("/group/")
                || path.starts_with("/proto/")
                || (path.starts_with("/rate-limits/") && !path.ends_with("/duplicate"))
                || path.starts_with("/role/")
                || path.starts_with("/routing/")
                || ((path.starts_with("/user/") || path.starts_with("/users/"))
                    && !path.ends_with("/update-password"))
                || path.starts_with("/vault/")
                || (path
                    .strip_prefix("/tiers/")
                    .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains('/')))
        }
        _ => false,
    }
}

fn is_subscription_mutation(path: &str, method: &Method) -> bool {
    matches!(method, &Method::POST)
        && matches!(
            path,
            "/subscription/subscribe" | "/subscription/unsubscribe"
        )
}

fn is_update_password_path(path: &str) -> bool {
    ["/user/", "/users/"].iter().any(|prefix| {
        path.strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty() && suffix.ends_with("/update-password"))
    })
}

fn subscription_payload_has_required_fields(payload: &Value) -> bool {
    ["username", "api_name", "api_version"]
        .iter()
        .all(|field| payload.get(*field).is_some_and(|value| !value.is_null()))
}

fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    url::form_urlencoded::parse(query.unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

fn paginate(items: Vec<Value>, query: &HashMap<String, String>) -> Value {
    let page = query
        .get("page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let page_size = query
        .get("page_size")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let start = (page - 1).saturating_mul(page_size);
    json!({
        "response": items
            .into_iter()
            .skip(start)
            .take(page_size)
            .collect::<Vec<_>>()
    })
}

/// Validate client pagination before applying the page window. This prevents
/// invalid values from being silently normalized and honors the configured
/// maximum on each request.
fn validate_pagination(query: &HashMap<String, String>) -> Result<(), String> {
    if query
        .get("page")
        .is_some_and(|value| value.parse::<usize>().ok().is_none_or(|number| number == 0))
    {
        return Err("page must be >= 1".to_owned());
    }
    let Some(page_size) = query.get("page_size") else {
        return Ok(());
    };
    let Some(page_size) = page_size.parse::<usize>().ok().filter(|number| *number > 0) else {
        return Err("page_size must be >= 1".to_owned());
    };
    if page_size > configured_max_page_size() {
        return Err(format!(
            "page_size must be <= {}",
            configured_max_page_size()
        ));
    }
    Ok(())
}

fn configured_max_page_size() -> usize {
    env::var("MAX_PAGE_SIZE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| value.parse::<i128>().ok())
        .map(|value| value.max(1) as usize)
        .unwrap_or(200)
}

/// The page window (default 100 per page) without any envelope.
fn paginate_items(items: Vec<Value>, query: &HashMap<String, String>) -> Vec<Value> {
    let page = query
        .get("page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let page_size = query
        .get("page_size")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    items
        .into_iter()
        .skip((page - 1).saturating_mul(page_size))
        .take(page_size)
        .collect()
}

fn paginate_named(items: Vec<Value>, query: &HashMap<String, String>, name: &str) -> Value {
    let page = query
        .get("page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let page_size = query
        .get("page_size")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let start = (page - 1).saturating_mul(page_size);
    let items = items
        .into_iter()
        .skip(start)
        .take(page_size)
        .collect::<Vec<_>>();
    json!({"response": {name: items}})
}
fn paginate_apis(mut items: Vec<Value>, query: &HashMap<String, String>) -> Value {
    items.sort_by_key(|value| value["api_name"].as_str().unwrap_or_default().to_owned());
    let page = query
        .get("page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let page_size = query
        .get("page_size")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10)
        .clamp(1, 200);
    let start = (page - 1).saturating_mul(page_size);
    let total = items.len();
    let apis = items
        .into_iter()
        .skip(start)
        .take(page_size)
        .collect::<Vec<_>>();
    json!({"apis": apis, "page": page, "page_size": page_size, "has_next": start.saturating_add(page_size) < total, "total": total})
}

fn strip_internal(mut value: Value) -> Value {
    strip_mongo_id(&mut value);
    value
}

fn public_user(mut value: Value) -> Value {
    if let Some(map) = value.as_object_mut() {
        map.remove("_id");
        map.remove("password");
    }
    value
}

fn schedule_restart() -> Result<(), (&'static str, &'static str)> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("PID_FILE") {
        candidates.push(std::path::PathBuf::from(path));
    }
    if let Some(path) = env::var_os("DOORMAN_PID_FILE") {
        candidates.push(std::path::PathBuf::from(path));
    }
    if let Ok(current_dir) = env::current_dir() {
        candidates.push(current_dir.join("doorman.pid"));
    }
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join("doorman.pid"));
    }
    let Some(pid_file) = candidates.into_iter().find(|path| path.exists()) else {
        return Err((
            "SEC004",
            "Restart not supported: no PID file found (run using 'doorman start' or contact your admin)",
        ));
    };
    let pid = fs::read_to_string(&pid_file)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or(("SEC005", "Failed to schedule restart"))?;
    let executable = env::current_exe().map_err(|_| ("SEC005", "Failed to schedule restart"))?;

    #[cfg(unix)]
    {
        Command::new("sh")
            .arg("-c")
            .arg(
                "sleep 1; kill -TERM \"$1\" || exit 1; while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; echo $$ > \"$3\"; exec \"$2\"",
            )
            .arg("doorman-restart")
            .arg(pid.to_string())
            .arg(executable)
            .arg(pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ("SEC005", "Failed to schedule restart"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, executable, pid_file);
        Err(("SEC005", "Failed to schedule restart"))
    }
}

fn set_default(target: &mut Value, key: &str, value: Value) {
    if target.get(key).is_none() {
        target[key] = value;
    }
}

fn success(status: StatusCode, payload: Value, request_id: &str) -> Response {
    json_response(status, payload, request_id)
}

fn message(status: StatusCode, text: &str, request_id: &str) -> Response {
    let mut response = json_response(status, json!({"message": text}), request_id);
    response.extensions_mut().insert(MessageEnvelope);
    response
}

fn error(status: StatusCode, code: &str, text: &str, request_id: &str) -> Response {
    json_response(
        status,
        json!({"error_code": code, "error_message": text}),
        request_id,
    )
}
fn http_detail(status: StatusCode, detail: &str, request_id: &str) -> Response {
    json_response(status, json!({"detail": detail}), request_id)
}

/// FastAPI's request validation failures all pass through the pinned global
/// RequestValidationError handler, which renders the VAL001 envelope; the
/// Pydantic error list is only logged, never returned.
fn validation_errors(errors: Vec<Value>, request_id: &str) -> Response {
    let errors = Value::Array(errors);
    tracing::debug!(%errors, "request validation failed");
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "VAL001",
        "Validation Error",
        request_id,
    )
}

/// The pinned tier routes return a bare `ResponseModel`, which FastAPI
/// serializes in full rather than through the respond_rest envelope.
fn response_model_envelope(message_text: &str, request_id: &str) -> Response {
    success(
        StatusCode::OK,
        json!({
            "status_code": 200,
            "response_headers": null,
            "response": null,
            "message": message_text,
            "error_code": null,
            "error_message": null,
        }),
        request_id,
    )
}

fn unexpected(request_id: &str) -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "GTW999",
        "An unexpected error occurred",
        request_id,
    )
}

pub(crate) fn json_response(status: StatusCode, payload: Value, request_id: &str) -> Response {
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let length = body.len().to_string();
    let mut response = (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("request_id", value.clone());
        response.headers_mut().insert("x-request-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&length) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, value.clone());
        response.headers_mut().insert("x-body-length", value);
    }
    response
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

// VaultService stores `datetime.now(UTC).isoformat()` directly. Unlike the
// RFC3339 formatter used elsewhere, that Python spelling ends in `+00:00`.
fn timestamp_now_python_utc() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.microsecond(),
    )
}

// Python's datetime.now().isoformat() produces a timezone-naive value for
// UserTierAssignment.assigned_at.  Keep this wire representation distinct
// from the RFC3339 timestamps used by newer platform endpoints.
fn timestamp_now_naive() -> String {
    timestamp_naive(time::OffsetDateTime::now_utc())
}

fn timestamp_after_days(days: i64) -> String {
    let now = time::OffsetDateTime::now_utc();
    timestamp_naive(now.checked_add(time::Duration::days(days)).unwrap_or(now))
}

fn timestamp_naive(now: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.microsecond(),
    )
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pinned_log_file_patterns_are_read_as_logs() {
        assert!(is_log_file_name("doorman.log"));
        assert!(is_log_file_name("doorman.log.3"));
        assert!(is_log_file_name("doorman-trail.log"));
        assert!(!is_log_file_name("metrics.json"));
        assert!(!is_log_file_name("enhanced_metrics.json"));
    }

    #[test]
    fn parse_report_timestamp_matches_pythons_strptime_cascade() {
        // "%Y-%m-%dT%H:%M"
        assert_eq!(
            parse_report_timestamp("2024-01-15T10:30").unwrap(),
            1_705_314_600
        );
        // "%Y-%m-%d" (midnight UTC)
        assert_eq!(parse_report_timestamp("2024-01-15").unwrap(), 1_705_276_800);
        // fromisoformat fallback: space separator and a trailing Z.
        assert_eq!(
            parse_report_timestamp("2024-01-15T10:30:00Z").unwrap(),
            1_705_314_600
        );
        // Seconds in the fromisoformat fallback are preserved, not truncated.
        assert_eq!(
            parse_report_timestamp("2024-01-15T10:30:45Z").unwrap(),
            1_705_314_645
        );
        assert!(parse_report_timestamp("not-a-date").is_err());
        assert_eq!(
            parse_report_timestamp("garbage").unwrap_err(),
            "Invalid date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM"
        );
    }

    #[test]
    fn report_date_time_utc_matches_python_strftime() {
        assert_eq!(
            report_date_time_utc(1_705_314_600),
            ("2024-01-15".to_owned(), "10:30".to_owned())
        );
    }

    #[test]
    fn report_api_from_endpoint_matches_python_classification() {
        assert_eq!(
            report_api_from_endpoint("/api/rest/orders/v1/list"),
            "rest:orders"
        );
        // Matches Python: `ep.split('/')` on "/api/rest/" yields a trailing
        // empty segment, so `parts[3]` is "" rather than ever reaching the
        // `len(parts) > 3` "unknown" fallback (unreachable via this prefix).
        assert_eq!(report_api_from_endpoint("/api/rest/"), "rest:");
        assert_eq!(
            report_api_from_endpoint("/api/graphql/catalog"),
            "graphql:catalog"
        );
        assert_eq!(
            report_api_from_endpoint("/api/soap/billing"),
            "soap:billing"
        );
        assert_eq!(report_api_from_endpoint("/platform/users"), "platform");
    }

    #[test]
    fn analytics_percentiles_pools_raw_samples_like_python_percentile_metrics() {
        let mut a = AggregatedPoint {
            timestamp: 0,
            requests: 2,
            ..Default::default()
        };
        a.latencies_ms.extend([10.0, 20.0]);
        let mut b = AggregatedPoint {
            timestamp: 60,
            requests: 1,
            ..Default::default()
        };
        b.latencies_ms.extend([100.0]);
        // Pooled sorted samples: [10, 20, 100], n = 3.
        // k = max(0, int(p*3) - 1): p50 -> int(1.5)-1=0 -> 10; p95 -> int(2.85)-1=1 -> 20.
        let result = analytics_percentiles(&[a, b]);
        assert_eq!(result["p50"], json!(10.0));
        assert_eq!(result["p95"], json!(20.0));
        assert_eq!(result["min"], json!(10.0));
        assert_eq!(result["max"], json!(100.0));

        let empty = analytics_percentiles(&[]);
        assert_eq!(empty["p50"], json!(0.0));
        assert_eq!(empty["min"], json!(0.0));
    }

    #[test]
    fn restricted_self_update_fields_matches_python_attempted_set() {
        // Null-valued restricted fields are not "attempted" in Python, since it
        // filters `v is not None` before intersecting with the restricted set.
        assert!(restricted_self_update_fields(&json!({"email": "a@b.com"})).is_empty());
        assert!(restricted_self_update_fields(&json!({"role": null})).is_empty());
        assert_eq!(
            restricted_self_update_fields(&json!({
                "username": "new", "active": true, "role": "admin", "email": "a@b.com"
            })),
            vec!["active", "role", "username"]
        );
    }

    #[test]
    fn tier_request_models_coerce_scalars_and_apply_defaults() {
        let mut create = json!({
            "tier_id": 7,
            "name": "not-an-enum",
            "display_name": true,
            "limits": {"requests_per_minute": "12", "enable_throttling": "yes"},
            "price_monthly": "19.5",
            "features": [1, false],
            "enabled": "off",
            "ignored": "field"
        });
        normalize_tier_request("/tiers", &Method::POST, &mut create).unwrap();
        assert_eq!(create["tier_id"], "7");
        assert_eq!(create["name"], "not-an-enum");
        assert_eq!(create["display_name"], "True");
        assert_eq!(create["limits"]["requests_per_minute"], 12);
        assert_eq!(create["limits"]["burst_per_second"], 0);
        assert_eq!(create["limits"]["max_queue_time_ms"], 5000);
        assert_eq!(create["limits"]["enable_throttling"], true);
        assert_eq!(create["price_monthly"], 19.5);
        assert_eq!(create["features"], json!(["1", "False"]));
        assert_eq!(create["is_default"], false);
        assert_eq!(create["enabled"], false);
        assert!(create.get("ignored").is_none());

        let mut action = json!({
            "user_id": 42,
            "new_tier_id": false,
            "grace_period_days": "3",
            "ignored": true
        });
        normalize_tier_request("/tiers/downgrade", &Method::POST, &mut action).unwrap();
        assert_eq!(
            action,
            json!({"user_id": "42", "new_tier_id": "False", "grace_period_days": 3})
        );

        let mut assignment = json!({
            "user_id": "dated",
            "tier_id": "pro",
            "effective_from": 0,
            "effective_until": "2020-1-2 3:04:05.12Z"
        });
        normalize_tier_request("/tiers/assignments", &Method::POST, &mut assignment).unwrap();
        assert_eq!(assignment["effective_from"], "1970-01-01T00:00:00+00:00");
        assert_eq!(
            assignment["effective_until"],
            "2020-01-02T03:04:05.120000+00:00"
        );
    }

    #[test]
    fn tier_request_models_reject_invalid_shapes_and_drop_update_nulls() {
        for mut invalid in [
            json!({"tier_id": "x", "name": "free", "display_name": "X", "limits": []}),
            json!({"user_id": "x", "temp_tier_id": "pro", "duration_days": null}),
            json!({"user_id": "x", "new_tier_id": "pro", "immediate": "sometimes"}),
            json!({"user_id": "x", "tier_id": "pro", "effective_from": "not-a-date"}),
            json!({"tier_ids": ["free"]}),
        ] {
            let (path, method) = if invalid.get("effective_from").is_some() {
                ("/tiers/assignments", Method::POST)
            } else if invalid.get("tier_id").is_some() {
                ("/tiers", Method::POST)
            } else if invalid.get("temp_tier_id").is_some() {
                ("/tiers/temporary-upgrade", Method::POST)
            } else if invalid.get("new_tier_id").is_some() {
                ("/tiers/upgrade", Method::POST)
            } else {
                ("/tiers/compare", Method::POST)
            };
            assert!(normalize_tier_request(path, &method, &mut invalid).is_err());
        }

        let mut update = json!({
            "display_name": null,
            "limits": null,
            "enabled": null,
            "features": null,
            "price_monthly": null,
            "description": null
        });
        normalize_tier_request("/tiers/pro", &Method::PUT, &mut update).unwrap();
        assert_eq!(update, json!({}));

        for (value, expected) in [
            ("true", Some(true)),
            ("YES", Some(true)),
            ("on", Some(true)),
            ("1", Some(true)),
            ("false", Some(false)),
            ("No", Some(false)),
            ("off", Some(false)),
            ("0", Some(false)),
            (" true ", None),
        ] {
            assert_eq!(pydantic_bool_string(value), expected);
        }
    }

    #[tokio::test]
    async fn tier_exception_envelopes_match_each_python_route() {
        for (operation, detail) in [
            ("get", "Failed to get tier"),
            ("update", "Failed to update tier"),
            ("delete", "Failed to delete tier"),
            ("assign", "Failed to assign user"),
            ("get_assignment", "Failed to get assignment"),
            ("get_user_tier", "Failed to get user tier"),
            ("remove_assignment", "Failed to remove assignment"),
            ("list_users", "Failed to list users"),
            ("upgrade", "Failed to upgrade tier"),
            ("downgrade", "Failed to downgrade tier"),
            ("temporary-upgrade", "Failed to create temporary upgrade"),
            ("trial/start", "Failed to start trial"),
            ("payment/failure", "Failed to handle payment failure"),
            ("compare", "Failed to compare tiers"),
        ] {
            let response = tier_detail_failure(operation, "tier-error");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["detail"],
                detail
            );
        }

        let response = tier_statistics_failure("tier-error");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "TIER999");
        assert_eq!(body["error_message"], "Failed to get statistics");
    }

    #[tokio::test]
    async fn rate_rule_exception_envelopes_match_each_python_route() {
        for (operation, detail) in [
            ("create", "Failed to create rule"),
            ("list", "Failed to list rules"),
            ("search", "Failed to search rules"),
            ("get", "Failed to get rule"),
            ("update", "Failed to update rule"),
            ("delete", "Failed to delete rule"),
            ("enable", "Failed to enable rule"),
            ("disable", "Failed to disable rule"),
            ("bulk/delete", "Failed to delete rules"),
            ("bulk/enable", "Failed to enable rules"),
            ("bulk/disable", "Failed to disable rules"),
            ("duplicate", "Failed to duplicate rule"),
            ("statistics", "Failed to get statistics"),
            ("status", "Failed to get rate limit status"),
        ] {
            let response = rate_rule_failure(operation, "rule-error");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["detail"],
                detail
            );
        }
    }

    #[tokio::test]
    async fn quota_exception_envelopes_match_each_python_route() {
        for (path, detail) in [
            ("/quota/status", "Failed to get quota status"),
            (
                "/quota/status/monthly_requests",
                "Failed to get quota status",
            ),
            ("/quota/usage/history", "Failed to get usage history"),
            ("/quota/usage/export", "Failed to export usage data"),
            ("/quota/tier/info", "Failed to get tier info"),
            ("/quota/burst/status", "Failed to get burst status"),
        ] {
            let response = quota_route_failure(path, "quota-error");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["detail"],
                detail
            );
        }
    }

    #[test]
    fn log_parsing_and_filters_match_python_service() {
        let record = parse_log_record(
            "2026-09-26 10:11:12,345 - doorman.gateway - INFO - 12345678-1234-1234-1234-123456789012 | Username: Alice Endpoint: GET /rest/pets Total time: 12.5ms status_code: 200 From: 127.0.0.1:1234",
        )
        .unwrap();
        assert_eq!(record["timestamp"], "2026-09-26T10:11:12.345");
        assert_eq!(record["user"], "Alice");
        assert_eq!(record["method"], "GET");
        assert_eq!(record["type"], "gateway");
        assert_eq!(record["ip_address"], "127.0.0.1");

        let filters = HashMap::from([
            ("user".to_owned(), "ali".to_owned()),
            ("endpoint".to_owned(), "/REST".to_owned()),
            ("start_time".to_owned(), "10:00".to_owned()),
            ("end_time".to_owned(), "11:00".to_owned()),
            ("status_code".to_owned(), "200".to_owned()),
        ]);
        assert!(log_record_matches(&record, &filters));
        assert!(!log_record_matches(
            &record,
            &HashMap::from([("exclude_type".to_owned(), "gateway".to_owned())])
        ));

        let debug =
            parse_log_record("2026-09-26 10:11:12 - doorman.gateway - ERROR - startup complete")
                .unwrap();
        assert_eq!(debug["level"], "DEBUG");
    }

    // Oracle: pinned models/security_settings_model.py, Pydantic 1.10.26.
    #[test]
    fn security_settings_scalar_coercion_matches_python_model() {
        for field in [
            "enable_auto_save",
            "trust_x_forwarded_for",
            "allow_localhost_bypass",
        ] {
            for (expected, values) in [
                (
                    true,
                    vec![
                        json!(true),
                        json!(1),
                        json!(1.0),
                        json!("TRUE"),
                        json!("yes"),
                        json!("on"),
                        json!("t"),
                        json!("Y"),
                        json!("1"),
                    ],
                ),
                (
                    false,
                    vec![
                        json!(false),
                        json!(0),
                        json!(0.0),
                        json!("FALSE"),
                        json!("no"),
                        json!("off"),
                        json!("f"),
                        json!("N"),
                        json!("0"),
                    ],
                ),
            ] {
                for value in values {
                    assert_eq!(
                        normalize_security_settings(json!({field: value})).unwrap()[field],
                        expected
                    );
                }
            }
            for value in [
                json!(2),
                json!(-1),
                json!(0.5),
                json!(" true "),
                json!(""),
                json!([]),
                json!({}),
            ] {
                assert_eq!(
                    normalize_security_settings(json!({field: value})).unwrap_err(),
                    vec![json!({
                        "loc": ["body", field], "msg": "value could not be parsed to a boolean", "type": "type_error.bool"
                    })]
                );
            }
        }
        for (value, expected) in [
            (json!(60.9), 60),
            (json!(120.0), 120),
            (json!("120"), 120),
            (json!(" 120 "), 120),
            (json!("+120"), 120),
            (json!("1_200"), 1200),
            (json!("١٢٠"), 120),
            (json!("１２０"), 120),
            (json!("𝟙𝟚𝟘"), 120),
            (json!("1_٢0"), 120),
            (json!("\u{a0}+١_٢٠\u{3000}"), 120),
        ] {
            assert_eq!(
                normalize_security_settings(json!({"auto_save_frequency_seconds": value})).unwrap()
                    ["auto_save_frequency_seconds"],
                expected
            );
        }
        for value in [
            json!(59),
            json!(59.9),
            json!(true),
            json!(false),
            json!(-1),
            json!("-120"),
            json!("-١٢٠"),
            json!("٥٩"),
        ] {
            assert_eq!(
                security_setting_interval(&value).unwrap_err(),
                json!({
                    "loc": ["body", "auto_save_frequency_seconds"], "msg": "ensure this value is greater than or equal to 60",
                    "type": "value_error.number.not_ge", "ctx": {"limit_value": 60}
                })
            );
        }
        for value in [
            json!("120.0"),
            json!("1e2"),
            json!("1__20"),
            json!("_120"),
            json!("120_"),
            json!("١__٢٠"),
            json!("²⁶⁰"),
            json!("\u{1c}120\u{1f}"),
            json!({}),
            json!([]),
        ] {
            assert_eq!(
                security_setting_interval(&value).unwrap_err()["type"],
                "type_error.integer"
            );
        }
        assert_eq!(
            security_setting_interval(&json!(u64::MAX)).unwrap(),
            u64::MAX
        );
        assert!(security_setting_interval(&json!(18_446_744_073_709_551_616.0)).is_err());
        assert!(
            normalize_security_settings(json!({"enable_auto_save": null, "unknown": true}))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn security_settings_list_coercion_and_indexed_errors_match_python() {
        for key in ["ip_whitelist", "ip_blacklist", "xff_trusted_proxies"] {
            assert_eq!(normalize_security_settings(json!({key: [
                "203.0.113.1", true, false, 120, 1.0, 1e-5, "invalid-ip", "203.0.113.0/33", "", " 203.0.113.1 "
            ]})).unwrap()[key], json!([
                "203.0.113.1", "True", "False", "120", "1.0", "1e-05", "invalid-ip", "203.0.113.0/33", "", " 203.0.113.1 "
            ]));
            assert_eq!(
                normalize_security_settings(json!({key: []})).unwrap()[key],
                json!([])
            );
            assert!(
                normalize_security_settings(json!({key: null}))
                    .unwrap()
                    .is_empty()
            );
            for value in [json!("203.0.113.1"), json!({}), json!(120), json!(true)] {
                assert_eq!(
                    normalize_security_settings(json!({key: value})).unwrap_err(),
                    vec![
                        json!({"loc": ["body", key], "msg": "value is not a valid list", "type": "type_error.list"})
                    ]
                );
            }
            assert_eq!(
                normalize_security_settings(json!({key: [null, [], {}, "valid", false]}))
                    .unwrap_err(),
                vec![
                    json!({"loc": ["body", key, 0], "msg": "none is not an allowed value", "type": "type_error.none.not_allowed"}),
                    json!({"loc": ["body", key, 1], "msg": "str type expected", "type": "type_error.str"}),
                    json!({"loc": ["body", key, 2], "msg": "str type expected", "type": "type_error.str"})
                ]
            );
        }
        let errors = normalize_security_settings(json!({
            "xff_trusted_proxies": [null], "ip_blacklist": [{}], "ip_whitelist": [[], null], "dump_path": {}, "trust_x_forwarded_for": "bad"
        })).unwrap_err();
        assert_eq!(
            errors
                .iter()
                .map(|error| error["loc"].clone())
                .collect::<Vec<_>>(),
            vec![
                json!(["body", "dump_path"]),
                json!(["body", "ip_whitelist", 0]),
                json!(["body", "ip_whitelist", 1]),
                json!(["body", "ip_blacklist", 0]),
                json!(["body", "trust_x_forwarded_for"]),
                json!(["body", "xff_trusted_proxies", 0])
            ]
        );
    }

    #[test]
    fn security_settings_dump_path_coercion_matches_python_model() {
        for (value, expected) in [
            (json!("nested/dump.bin"), "nested/dump.bin"),
            (json!(""), ""),
            (json!(true), "True"),
            (json!(false), "False"),
            (json!(0), "0"),
            (json!(-12), "-12"),
            (json!(u64::MAX), "18446744073709551615"),
            (json!(1.0), "1.0"),
            (json!(-0.0), "-0.0"),
            (json!(1.5), "1.5"),
            (json!(1e-4), "0.0001"),
            (json!(1e-5), "1e-05"),
            (json!(-1.25e-5), "-1.25e-05"),
            (json!(1e-6), "1e-06"),
            (json!(1e15), "1000000000000000.0"),
            (json!(1e16), "1e+16"),
            (json!(1e20), "1e+20"),
            (json!(1.2345678901234567), "1.2345678901234567"),
            (
                json!(f64::from_bits(4833791929896474481)),
                "1483282338825692.2",
            ),
            (
                json!(f64::from_bits(14056054566791133225)),
                "-1205932348796426.2",
            ),
        ] {
            assert_eq!(
                normalize_security_settings(json!({"dump_path": value})).unwrap()["dump_path"],
                expected
            );
        }
        assert!(
            normalize_security_settings(json!({"dump_path": null}))
                .unwrap()
                .is_empty()
        );
        for value in [json!([]), json!({})] {
            assert_eq!(
                normalize_security_settings(json!({"dump_path": value})).unwrap_err(),
                vec![json!({"loc": ["body", "dump_path"],
                    "msg": "str type expected", "type": "type_error.str"})]
            );
        }
        let errors = normalize_security_settings(json!({
            "enable_auto_save": "bad", "dump_path": {}, "trust_x_forwarded_for": "bad"
        }))
        .unwrap_err();
        assert_eq!(
            errors
                .iter()
                .map(|error| error["loc"][1].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["enable_auto_save", "dump_path", "trust_x_forwarded_for"]
        );
    }

    #[test]
    fn security_settings_scalar_errors_follow_python_declaration_order() {
        let errors = normalize_security_settings(json!({
            "trust_x_forwarded_for": "bad", "auto_save_frequency_seconds": "bad",
            "allow_localhost_bypass": "bad", "enable_auto_save": "bad"
        }))
        .unwrap_err();
        assert_eq!(
            errors
                .iter()
                .map(|error| error["loc"][1].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "enable_auto_save",
                "auto_save_frequency_seconds",
                "trust_x_forwarded_for",
                "allow_localhost_bypass"
            ]
        );
    }

    #[test]
    fn self_updates_without_user_management_cannot_change_authorization_fields() {
        assert!(restricted_self_update_fields(
            &json!({"email": "user@example.com", "custom_attributes": {}, "rate_limit_duration": 1})
        ).is_empty());
        assert!(!restricted_self_update_fields(&json!({"groups": ["admin"]})).is_empty());
        assert!(!restricted_self_update_fields(&json!({"role": "admin"})).is_empty());
        assert!(!restricted_self_update_fields(&json!({"active": true})).is_empty());
        assert!(!restricted_self_update_fields(&json!({"username": "other"})).is_empty());
    }

    #[test]
    fn bootstrap_admin_updates_are_limited_to_operational_fields() {
        assert!(bootstrap_admin_update_fields_are_safe(&json!({
            "rate_limit_duration": 1,
            "throttle_queue_limit": 1
        })));
        assert!(!bootstrap_admin_update_fields_are_safe(
            &json!({"email": "admin@example.com"})
        ));
    }

    #[test]
    fn enforces_the_python_password_policy() {
        let valid = test_password();
        assert!(secure_password(&valid));

        let short = Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(5)
            .collect::<String>();
        assert!(!secure_password(&short));

        let without_special = format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple().to_string().to_uppercase()
        );
        assert!(!secure_password(&without_special));

        // 16 characters but 18 bytes passes; 14 characters (16 bytes) must not.
        assert!(secure_password(&non_ascii_test_password(16)));
        assert!(!secure_password(&non_ascii_test_password(14)));
    }

    fn non_ascii_test_password(chars: usize) -> String {
        let bytes = Uuid::new_v4().into_bytes();
        let uppercase = char::from_u32(0xC0 + u32::from(bytes[0] % 0x17)).unwrap();
        let lowercase = char::from_u32(0xE0 + u32::from(bytes[1] % 0x17)).unwrap();
        let digit = char::from(bytes[2] % 10 + b'0');
        let special = char::from(bytes[3] % 15 + b'!');
        let padding = Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(chars - 4)
            .collect::<String>();
        format!("{uppercase}{lowercase}{digit}{special}{padding}")
    }

    fn test_password() -> String {
        let bytes = Uuid::new_v4().into_bytes();
        let uppercase = char::from(bytes[0] % 26 + b'A');
        let lowercase = char::from(bytes[1] % 26 + b'a');
        let digit = char::from(bytes[2] % 10 + b'0');
        let special = char::from(bytes[3] % 15 + b'!');
        format!("{uppercase}{lowercase}{digit}{special}{}", Uuid::new_v4())
    }

    #[test]
    fn pagination_is_one_based_and_capped() {
        let items = (0..5).map(|value| json!(value)).collect();
        let query = HashMap::from([
            ("page".to_owned(), "2".to_owned()),
            ("page_size".to_owned(), "2".to_owned()),
        ]);
        assert_eq!(paginate(items, &query), json!({"response": [2, 3]}));
    }

    // Oracle: pinned backend-services/routes/tools_routes.py and its CORS checker tests.
    #[tokio::test]
    async fn tools_cors_checker_matches_pinned_python_matrix() {
        let config = |vars: &[(&str, &str)]| {
            cors_check_config_from(|key| {
                vars.iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            })
        };
        let matching = config(&[
            ("ALLOWED_ORIGINS", "http://localhost:3000"),
            ("ALLOW_METHODS", "GET,POST"),
            ("ALLOW_HEADERS", "Content-Type,X-CSRF-Token"),
            ("ALLOW_CREDENTIALS", "true"),
            ("CORS_STRICT", "true"),
        ]);
        let allowed = cors_checker_payload(
            &matching,
            json!({
                "origin": "http://localhost:3000",
                "method": "GET",
                "request_headers": ["content-type", "X-CSRF-Token"],
                "with_credentials": true,
            }),
        )
        .await;
        assert_eq!(allowed["preflight"]["allowed"], true);
        assert_eq!(
            allowed["preflight"]["response_headers"]["Access-Control-Allow-Origin"],
            "http://localhost:3000"
        );
        assert_eq!(allowed["actual"]["response_headers"]["Vary"], "Origin");

        let denied_header = cors_checker_payload(
            &matching,
            json!({"origin": "http://localhost:3000", "method": "GET", "request_headers": ["X-Custom-Header"]}),
        )
        .await;
        assert_eq!(denied_header["preflight"]["allowed"], false);
        assert_eq!(
            denied_header["preflight"]["not_allowed_headers"],
            json!(["X-Custom-Header"])
        );
        let unknown_origin = cors_checker_payload(
            &matching,
            json!({"origin": "http://evil.example", "method": "GET"}),
        )
        .await;
        assert_eq!(unknown_origin["actual"]["allowed"], false);

        let denied_method = cors_checker_payload(
            &config(&[
                ("ALLOWED_ORIGINS", "http://ok.example"),
                ("ALLOW_METHODS", "GET"),
            ]),
            json!({"origin": "http://ok.example", "method": "DELETE"}),
        )
        .await;
        assert_eq!(denied_method["preflight"]["method_allowed"], false);

        let wildcard = config(&[
            ("ALLOWED_ORIGINS", "*"),
            ("ALLOW_CREDENTIALS", "true"),
            ("CORS_STRICT", "false"),
        ]);
        let wildcard_allowed = cors_checker_payload(
            &wildcard,
            json!({"origin": "http://arbitrary.example", "method": "GET", "request_headers": []}),
        )
        .await;
        assert_eq!(wildcard_allowed["preflight"]["allow_origin"], true);
        assert!(
            wildcard_allowed["notes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|note| note.as_str().unwrap().contains("Wildcard origins"))
        );
        let wildcard_without_credentials = cors_checker_payload(
            &config(&[
                ("ALLOWED_ORIGINS", "*"),
                ("ALLOW_CREDENTIALS", "false"),
                ("CORS_STRICT", "false"),
            ]),
            json!({"origin": "http://any-origin", "method": "GET"}),
        )
        .await;
        assert_eq!(wildcard_without_credentials["actual"]["allowed"], true);

        let strict_wildcard = config(&[
            ("ALLOWED_ORIGINS", "*"),
            ("ALLOW_CREDENTIALS", "true"),
            ("CORS_STRICT", "true"),
        ]);
        let wildcard_blocked = cors_checker_payload(
            &strict_wildcard,
            json!({"origin": "http://evil.example", "method": "GET", "with_credentials": true, "request_headers": ["Content-Type"]}),
        )
        .await;
        assert_eq!(wildcard_blocked["actual"]["allowed"], false);
        assert_eq!(
            wildcard_blocked["preflight"]["response_headers"]["Access-Control-Allow-Origin"],
            Value::Null
        );
        assert_eq!(
            wildcard_blocked["preflight"]["response_headers"]["Access-Control-Allow-Credentials"],
            "true"
        );

        let defaults = config(&[("ALLOW_METHODS", ""), ("ALLOW_HEADERS", "*")]);
        assert_eq!(
            defaults.methods,
            vec!["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"]
        );
        assert_eq!(
            defaults.headers,
            vec!["Accept", "Content-Type", "X-CSRF-Token", "Authorization"]
        );
        let options = cors_checker_payload(
            &config(&[("ALLOW_METHODS", "GET,POST")]),
            json!({"origin": "http://localhost:3000", "method": "OPTIONS"}),
        )
        .await;
        assert_eq!(options["preflight"]["method_allowed"], true);
    }

    async fn cors_checker_payload(config: &CorsCheckConfig, body: Value) -> Value {
        let response = cors_check_with_config(body, "cors-test", config);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
