use std::{env, fs, sync::atomic::Ordering, time::Duration};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    error::GatewayError,
    gateway::circuit_breaker::reset as reset_circuits,
    observability::audit,
    policy::{PolicyErrorBody, auth::verify_request_token, evaluator::is_revoked},
    state::AppState,
    storage::models::{PolicyDocuments, bool_field_default, string_field},
};

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    mongodb: bool,
    redis: bool,
    memory_usage: String,
    active_connections: u64,
    uptime: String,
}

#[derive(Serialize)]
pub struct FeaturesResponse {
    logs_enabled: bool,
}

#[derive(Clone, Copy)]
enum GatewayOperation {
    Status,
    ClearCaches,
}

pub async fn health(
    State(_state): State<AppState>,
    request: Request,
) -> Result<Response, GatewayError> {
    if request.method() != Method::GET {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    Ok(Json(HealthResponse { status: "online" }).into_response())
}

pub async fn features(State(state): State<AppState>) -> Json<FeaturesResponse> {
    Json(FeaturesResponse {
        logs_enabled: state.config.logs_enabled,
    })
}

pub async fn status(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, GatewayError> {
    if request.method() != Method::GET {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    if let Err(response) =
        require_manage_gateway(&state, request.headers(), GatewayOperation::Status).await
    {
        return Ok(response);
    }

    let (mongodb, redis) = match &state.storage {
        Some(storage) => tokio::join!(storage.mongo_healthy(), storage.redis_healthy()),
        None => (false, false),
    };
    Ok(Json(StatusResponse {
        status: "online",
        mongodb,
        redis,
        memory_usage: memory_usage(),
        active_connections: state.runtime.active_requests.load(Ordering::Relaxed),
        uptime: format_uptime(state.runtime.started_at.elapsed()),
    })
    .into_response())
}

pub async fn caches(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, GatewayError> {
    if request.method() == Method::OPTIONS {
        return Ok(cache_preflight(request.headers()));
    }
    if request.method() != Method::DELETE {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let origin = allowed_cache_origin(request.headers());
    if request.headers().contains_key(header::ORIGIN) && origin.is_none() {
        return Ok(policy_error(
            StatusCode::FORBIDDEN,
            "GTW008",
            "Origin is not allowed",
        ));
    }
    let username = match require_manage_gateway(
        &state,
        request.headers(),
        GatewayOperation::ClearCaches,
    )
    .await
    {
        Ok(username) => username,
        Err(response) => return Ok(with_cache_cors(response, origin.as_ref())),
    };

    if cookie_value(request.headers(), "access_token_cookie").is_some()
        && !csrf_matches(request.headers(), &state, &username).await
    {
        return Ok(with_cache_cors(
            policy_error(StatusCode::UNAUTHORIZED, "GTW401", "Invalid CSRF token"),
            origin.as_ref(),
        ));
    }

    let response = match &state.storage {
        Some(storage) => match storage.clear_gateway_state().await {
            Ok(()) => {
                reset_circuits(&state.runtime.circuits);
                audit::management_mutation(&username, "gateway.clear_caches", "all", "success");
                Json(json!({ "message": "All caches cleared" })).into_response()
            }
            Err(error) => {
                tracing::error!(error = %error, "failed to clear shared gateway state");
                policy_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "GTW999",
                    "An unexpected error occurred",
                )
            }
        },
        None => {
            tracing::error!("cannot clear gateway state without shared storage");
            policy_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "GTW999",
                "An unexpected error occurred",
            )
        }
    };
    Ok(with_cache_cors(response, origin.as_ref()))
}

async fn require_manage_gateway(
    state: &AppState,
    headers: &HeaderMap,
    operation: GatewayOperation,
) -> Result<String, Response> {
    let claims = verify_request_token(headers, &state.config.shared_storage)
        .map_err(|_| policy_error(StatusCode::UNAUTHORIZED, "GTW401", "Unauthorized"))?;
    let username = claims.sub.as_deref().unwrap_or_default();
    let documents = load_documents(state).await?;
    if is_revoked(&documents.revocations, username, claims.jti.as_deref()) {
        return Err(policy_error(
            StatusCode::UNAUTHORIZED,
            "GTW401",
            "Unauthorized",
        ));
    }
    let user = documents
        .users
        .iter()
        .find(|user| string_field(user, "username") == Some(username))
        .filter(|user| bool_field_default(user, "active", true))
        .ok_or_else(|| policy_error(StatusCode::UNAUTHORIZED, "GTW401", "Unauthorized"))?;
    let role_name = string_field(user, "role").unwrap_or_default();
    let allowed = documents.roles.iter().any(|role| {
        string_field(role, "role_name") == Some(role_name)
            && bool_field_default(role, "manage_gateway", false)
    });
    if !allowed {
        let (code, message) = match operation {
            GatewayOperation::Status => ("GTW013", "Forbidden"),
            GatewayOperation::ClearCaches => {
                ("GTW008", "You do not have permission to clear caches")
            }
        };
        return Err(policy_error(StatusCode::FORBIDDEN, code, message));
    }
    Ok(username.to_owned())
}

async fn load_documents(state: &AppState) -> Result<PolicyDocuments, Response> {
    if let Some(documents) = &state.policy_documents {
        return documents.lock().map(|guard| guard.clone()).map_err(|_| {
            policy_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "GTW006",
                "Internal server error",
            )
        });
    }
    let storage = state.storage.as_ref().ok_or_else(|| {
        policy_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GTW006",
            "Internal server error",
        )
    })?;
    storage.load_policy_documents().await.map_err(|error| {
        tracing::error!(error = %error, "failed to load policies for gateway operation");
        policy_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GTW006",
            "Internal server error",
        )
    })
}

fn policy_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(PolicyErrorBody {
            error_code: code.to_owned(),
            error_message: message.to_owned(),
        }),
    )
        .into_response()
}

fn with_cache_cors(mut response: Response, origin: Option<&HeaderValue>) -> Response {
    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    response
}

fn cache_preflight(headers: &HeaderMap) -> Response {
    let Some(origin) = allowed_cache_origin(headers) else {
        return policy_error(StatusCode::FORBIDDEN, "GTW008", "Origin is not allowed");
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    let response_headers = response.headers_mut();
    response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("DELETE"),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization, Content-Type, X-CSRF-Token"),
    );
    response_headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    response
}

fn allowed_cache_origin(headers: &HeaderMap) -> Option<HeaderValue> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
    let allowed = env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".to_owned())
        .split(',')
        .map(str::trim)
        .any(|value| value == origin);
    allowed
        .then(|| HeaderValue::from_str(origin).ok())
        .flatten()
}

async fn csrf_matches(headers: &HeaderMap, state: &AppState, username: &str) -> bool {
    let Some(token) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    if cookie_value(headers, "csrf_token").as_deref() == Some(token) {
        return true;
    }
    let Some(storage) = &state.storage else {
        return false;
    };
    matches!(
        storage.get_ephemeral(&format!("csrf_token_map:{username}")).await,
        Ok(Some(Value::String(value))) if value == token
    )
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

fn memory_usage() -> String {
    let rss_kib = proc_value_kib("/proc/self/status", "VmRSS:");
    let total_kib = proc_value_kib("/proc/meminfo", "MemTotal:");
    match (rss_kib, total_kib) {
        (Some(rss), Some(total)) if total > 0 => {
            format!("{:.1}%", (rss as f64 / total as f64) * 100.0)
        }
        _ => "unknown".to_owned(),
    }
}

fn proc_value_kib(path: &str, key: &str) -> Option<u64> {
    fs::read_to_string(path)
        .unwrap_or_else(|_| "http://localhost:3000".to_owned())
        .lines()
        .find(|line| line.starts_with(key))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn format_uptime(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m {seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_uptime_like_the_python_gateway() {
        assert_eq!(format_uptime(Duration::from_secs(59)), "0m 59s");
        assert_eq!(format_uptime(Duration::from_secs(3_661)), "1h 1m");
        assert_eq!(format_uptime(Duration::from_secs(90_061)), "1d 1h 1m");
    }
}
