use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::HttpBody,
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::AsyncWriteExt;

use crate::{
    middleware::request_id::RequestId,
    observability::{analytics_aggregator::global_analytics, metrics::observe_request},
    state::AppState,
    storage::runtime::GatewayMetric,
};

#[derive(Clone, Debug, Default)]
pub struct ActivityContext {
    pub username: Option<String>,
    pub api: Option<String>,
    pub endpoint: Option<String>,
    pub upstream: Option<String>,
}

#[derive(Serialize)]
struct ActivityRecord<'a> {
    time: String,
    name: &'static str,
    level: &'static str,
    message: &'static str,
    request_id: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    method: &'a str,
    endpoint: &'a str,
    status_code: u16,
    response_time: f64,
    bytes_in: u64,
    bytes_out: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
}

pub async fn track_active_requests(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let path = request.uri().path().to_owned();
    let method = request.method().to_string();
    let supplied_request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|value| value.0.clone())
        .or_else(|| {
            request
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let direct_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip().to_string());
    let user_agent = request
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // Python's SecurityAuditMiddleware._should_audit: every modification
    // method anywhere, plus every /platform/* request (its own comment notes
    // the narrower vault/auth/tiers checks are already subsumed by this
    // catch-all, since those paths all start with /platform/ too).
    let should_audit_platform_request =
        matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH")
            || path.starts_with("/platform/");
    let record_analytics = path.starts_with("/api/") || path.starts_with("/grpc-web/");
    let bytes_in = estimated_request_size(&request);
    let is_test = test_request(request.headers());
    state
        .runtime
        .active_requests
        .fetch_add(1, Ordering::Relaxed);
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or(supplied_request_id);
    let bytes_out = estimated_response_size(&response);
    let context = response
        .extensions()
        .get::<ActivityContext>()
        .cloned()
        .unwrap_or_default();
    let elapsed = started.elapsed();
    state
        .runtime
        .active_requests
        .fetch_sub(1, Ordering::Relaxed);
    observe_request(&state.runtime, elapsed, status);
    // Only fall back to a path-derived API key for a response the gateway
    // actually handled. A bare 404 means the route never resolved to a real
    // API (context.api was never set), so recording analytics for it would
    // fabricate a data point Python never produces -- its equivalent crashes
    // deep in the service before any metrics are recorded for an unknown API.
    let fallback_api = (status != 404).then(|| api_key(&path)).flatten();
    let effective_api = context.api.as_deref().or(fallback_api.as_deref());

    if should_audit_platform_request {
        crate::observability::audit::platform_request(
            context.username.as_deref().unwrap_or("anonymous"),
            &method,
            &path,
            status,
            elapsed.as_secs_f64() * 1000.0,
            user_agent.as_deref(),
        );
    }

    if record_analytics {
        state
            .runtime
            .total_bytes_in
            .fetch_add(bytes_in, Ordering::Relaxed);
        state
            .runtime
            .total_bytes_out
            .fetch_add(bytes_out, Ordering::Relaxed);
        if !is_test {
            global_analytics().record_request(
                effective_api,
                context.username.as_deref(),
                context.endpoint.as_deref().or(Some(path.as_str())),
                status,
                elapsed.as_secs_f64() * 1000.0,
                bytes_in,
                bytes_out,
            );
        }

        if let Some(storage) = &state.storage {
            let minute_start = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 60
                * 60;
            if let Err(error) = storage
                .record_gateway_metric(GatewayMetric {
                    minute_start,
                    status,
                    duration_micros: elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
                    bytes_in,
                    bytes_out,
                    api_key: effective_api,
                    username: context.username.as_deref(),
                    endpoint: context.endpoint.as_deref().or(Some(path.as_str())),
                    is_test,
                })
                .await
            {
                tracing::warn!(error = %error, "failed to persist gateway analytics bucket");
            }
        }
    }

    if state.config.logs_enabled
        && let Some(logs_dir) = state.config.logs_dir.as_deref()
    {
        let endpoint = context.endpoint.as_deref().unwrap_or(&path);
        let upstream = context
            .upstream
            .as_deref()
            .map(crate::observability::audit::redacted_upstream);
        let record = ActivityRecord {
            time: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            name: "doorman.gateway.rust",
            level: if status >= 500 {
                "ERROR"
            } else if status >= 400 {
                "WARNING"
            } else {
                "INFO"
            },
            message: "gateway request completed",
            request_id: &request_id,
            record_type: "gateway",
            method: &method,
            endpoint,
            status_code: status,
            response_time: elapsed.as_secs_f64() * 1_000.0,
            bytes_in,
            bytes_out,
            user: context.username.as_deref(),
            api: context.api.as_deref(),
            upstream: upstream.as_deref(),
            ip_address: direct_ip,
        };
        if let Err(error) = append_record(logs_dir, "doorman.log.rust", &record).await {
            let was_healthy = state
                .runtime
                .activity_log_healthy
                .swap(false, Ordering::Relaxed);
            if was_healthy {
                tracing::warn!(error = %error, "failed to append gateway activity log");
            }
        } else {
            let was_healthy = state
                .runtime
                .activity_log_healthy
                .swap(true, Ordering::Relaxed);
            if !was_healthy {
                tracing::info!("gateway activity log writing restored");
            }
        }
        if status == 401 || status == 403 || status == 429 || status >= 500 {
            if let Err(error) = append_record(logs_dir, "doorman-trail.log.rust", &record).await {
                let was_healthy = state
                    .runtime
                    .security_audit_log_healthy
                    .swap(false, Ordering::Relaxed);
                if was_healthy {
                    tracing::warn!(error = %error, "failed to append gateway audit log");
                }
            } else {
                let was_healthy = state
                    .runtime
                    .security_audit_log_healthy
                    .swap(true, Ordering::Relaxed);
                if !was_healthy {
                    tracing::info!("gateway audit log writing restored");
                }
            }
        }
    }
    response
}

async fn append_record(
    logs_dir: &Path,
    filename: &str,
    record: &ActivityRecord<'_>,
) -> std::io::Result<()> {
    tokio::fs::create_dir_all(logs_dir).await?;
    let path = logs_dir.join(filename);
    if tokio::fs::metadata(&path)
        .await
        .is_ok_and(|metadata| metadata.len() >= 10 * 1024 * 1024)
    {
        rotate(&path).await;
    }
    let mut line = serde_json::to_vec(record).unwrap_or_default();
    line.push(b'\n');
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(&line).await?;
    // The activity middleware only returns the client response after this
    // function completes. Explicitly flush Tokio's buffered file handle so a
    // caller can immediately inspect the completed-request record instead of
    // observing an occasionally empty, newly-created log file.
    file.flush().await
}

async fn rotate(path: &Path) {
    for index in (1..=5).rev() {
        let source = rotated_path(path, index - 1);
        let destination = rotated_path(path, index);
        if index == 5 {
            let _ = tokio::fs::remove_file(&destination).await;
        }
        let _ = tokio::fs::rename(source, destination).await;
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    if index == 0 {
        path.to_path_buf()
    } else {
        PathBuf::from(format!("{}.{}", path.display(), index))
    }
}

fn estimated_request_size(request: &Request) -> u64 {
    let body = request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let line = request.method().as_str().len() + request.uri().to_string().len() + 12;
    body.saturating_add(line as u64)
        .saturating_add(header_size(request.headers()))
}

fn estimated_response_size(response: &Response) -> u64 {
    let body = response
        .body()
        .size_hint()
        .exact()
        .or_else(|| {
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or(0);
    body.saturating_add(17)
        .saturating_add(header_size(response.headers()))
}

fn header_size(headers: &http::HeaderMap) -> u64 {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum::<usize>() as u64
        + 2
}

fn test_request(headers: &http::HeaderMap) -> bool {
    ["x-is-test", "x-doorman-test", "x-test-request"]
        .iter()
        .filter_map(|name| headers.get(*name))
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

fn api_key(path: &str) -> Option<String> {
    let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        [
            "api",
            protocol @ ("rest" | "graphql" | "soap" | "grpc"),
            name,
            ..,
        ] => Some(format!("{protocol}:{name}")),
        ["grpc-web", name, ..] => Some(format!("grpc:{name}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::api_key;

    #[test]
    fn identifies_api_across_public_protocol_paths() {
        assert_eq!(
            api_key("/api/rest/demo/v1/items").as_deref(),
            Some("rest:demo")
        );
        assert_eq!(
            api_key("/api/graphql/catalog").as_deref(),
            Some("graphql:catalog")
        );
        assert_eq!(
            api_key("/grpc-web/chat/Chat/Stream").as_deref(),
            Some("grpc:chat")
        );
        assert_eq!(api_key("/api/health"), None);
    }
}
