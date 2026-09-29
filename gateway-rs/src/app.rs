use axum::{
    Json, Router, middleware as axum_middleware,
    response::{IntoResponse, Response},
    routing::{any, get},
};
use http::StatusCode;
use std::any::Any;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{CompressionLayer, CompressionLevel, predicate::SizeAbove},
    trace::TraceLayer,
};

use crate::{
    middleware::{
        activity::track_active_requests,
        chaos::{chaos_middleware, latency_injection},
        platform_cors::{force_platform_vary, platform_cors},
        request_id::request_id,
        response_compat::response_compat,
        security_headers::security_headers,
        websocket_reject::reject_disabled_websockets,
    },
    policy::PolicyErrorBody,
    routes::{
        graphql::graphql_policy_then_execute,
        grpc::grpc_policy_then_execute,
        grpc_web::grpc_web_policy_then_execute,
        metrics::metrics,
        operations::{caches, features, health, status},
        platform::platform_dispatch,
        rest::rest_policy_then_proxy,
        soap::soap_policy_then_execute,
    },
    state::AppState,
};

pub fn build_router(state: AppState) -> Router {
    let compression = CompressionLayer::new()
        .gzip(state.config.compression_enabled)
        .no_br()
        .no_deflate()
        .no_zstd()
        .quality(CompressionLevel::Precise(state.config.compression_level))
        // Starlette treats the legacy gateway responses as streaming and emits
        // gzip whenever the client accepts it, even below its configured size.
        // Preserve that observed public wire contract during the Rust cutover.
        .compress_when(SizeAbove::new(1));
    let api = Router::new()
        .route("/rest/{*path}", any(rest_policy_then_proxy))
        .route("/graphql/{*path}", any(graphql_policy_then_execute))
        .route("/soap/{*path}", any(soap_policy_then_execute))
        .route("/grpc/{*path}", any(grpc_policy_then_execute))
        .route("/health", any(health))
        .route("/features", get(features))
        .route("/status", any(status))
        .route("/caches", any(caches))
        .fallback(gateway_route_not_found)
        .layer(axum_middleware::from_fn(chaos_middleware))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            response_compat,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(axum_middleware::from_fn(request_id))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &axum::extract::Request| {
            tracing::debug_span!("http_request", method = %request.method())
        }))
        .layer(
            tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer::from_shared(
                crate::gateway::headers::SENSITIVE_HEADERS
                    .iter()
                    .cloned()
                    .map(http::header::HeaderName::from_static)
                    .collect::<std::sync::Arc<[_]>>(),
            ),
        )
        .layer(
            tower_http::sensitive_headers::SetSensitiveResponseHeadersLayer::from_shared(
                crate::gateway::headers::SENSITIVE_HEADERS
                    .iter()
                    .cloned()
                    .map(http::header::HeaderName::from_static)
                    .collect::<std::sync::Arc<[_]>>(),
            ),
        )
        .layer(CatchPanicLayer::custom(handle_panic));
    let platform = Router::new()
        .route("/", any(platform_dispatch))
        .route("/{*path}", any(platform_dispatch))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            response_compat,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(axum_middleware::from_fn(platform_cors))
        .layer(axum_middleware::from_fn(request_id))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &axum::extract::Request| {
            tracing::debug_span!("http_request", method = %request.method())
        }))
        .layer(
            tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer::from_shared(
                crate::gateway::headers::SENSITIVE_HEADERS
                    .iter()
                    .cloned()
                    .map(http::header::HeaderName::from_static)
                    .collect::<std::sync::Arc<[_]>>(),
            ),
        )
        .layer(
            tower_http::sensitive_headers::SetSensitiveResponseHeadersLayer::from_shared(
                crate::gateway::headers::SENSITIVE_HEADERS
                    .iter()
                    .cloned()
                    .map(http::header::HeaderName::from_static)
                    .collect::<std::sync::Arc<[_]>>(),
            ),
        )
        .layer(CatchPanicLayer::custom(handle_panic));

    Router::new()
        .nest("/api", api)
        .nest("/platform", platform)
        .route(
            "/grpc-web/{api_name}/{service}/{method}",
            any(grpc_web_policy_then_execute),
        )
        .route("/metrics", get(metrics))
        .fallback(not_found)
        .layer(axum_middleware::from_fn(latency_injection))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            track_active_requests,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            reject_disabled_websockets,
        ))
        .layer(compression)
        .layer(axum_middleware::from_fn(force_platform_vary))
        .with_state(state)
}

async fn gateway_route_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(PolicyErrorBody {
            error_code: "GTW003".to_owned(),
            error_message: "Gateway route does not exist".to_owned(),
        }),
    )
        .into_response()
}

fn handle_panic(_panic: Box<dyn Any + Send + 'static>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(PolicyErrorBody {
            error_code: "ISE001".to_owned(),
            error_message: "Internal Server Error".to_owned(),
        }),
    )
        .into_response()
}

async fn not_found(request: axum::extract::Request) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut response = (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"detail": "Not Found"})),
    )
        .into_response();
    if let Ok(value) = http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("request_id", value.clone());
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    #[tokio::test]
    async fn panic_handler_matches_python_internal_error_envelope() {
        use http_body_util::BodyExt;

        let response = handle_panic(Box::new("boom"));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error_code": "ISE001",
                "error_message": "Internal Server Error"
            })
        );
    }

    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, header},
        routing::any,
    };
    use flate2::read::GzDecoder;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn gzip_wire_contract_covers_methods_content_types_and_errors() {
        let app = Router::new()
            .fallback(any(|request: axum::extract::Request| async move {
                let (status, content_type, body) = match request.uri().path() {
                    "/xml" => (
                        StatusCode::OK,
                        "application/xml",
                        "<item>xml</item>".repeat(80),
                    ),
                    "/error" => (
                        StatusCode::UNAUTHORIZED,
                        "application/json",
                        "{\"error\":\"denied\"}".repeat(80),
                    ),
                    _ => (
                        StatusCode::OK,
                        "application/json",
                        "{\"items\":[\"json\"]}".repeat(80),
                    ),
                };
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap()
            }))
            .layer(
                CompressionLayer::new()
                    .gzip(true)
                    .no_br()
                    .no_deflate()
                    .no_zstd()
                    .quality(CompressionLevel::Precise(6))
                    .compress_when(SizeAbove::new(1)),
            );

        for (method, path, expected_status, expected_type) in [
            (Method::GET, "/json", StatusCode::OK, "application/json"),
            (Method::POST, "/json", StatusCode::OK, "application/json"),
            (Method::PUT, "/xml", StatusCode::OK, "application/xml"),
            (Method::DELETE, "/json", StatusCode::OK, "application/json"),
            (
                Method::GET,
                "/error",
                StatusCode::UNAUTHORIZED,
                "application/json",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header(header::ACCEPT_ENCODING, "gzip")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status, "{path}");
            assert!(
                response.headers()[header::CONTENT_TYPE]
                    .to_str()
                    .unwrap()
                    .starts_with(expected_type)
            );
            assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
            let compressed = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
            let mut decoded = String::new();
            GzDecoder::new(compressed.as_ref())
                .read_to_string(&mut decoded)
                .unwrap();
            assert!(decoded.len() > 500, "{path}");
        }
    }
}
