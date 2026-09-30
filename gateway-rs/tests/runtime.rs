use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Method, Uri},
    routing::{any, get},
};
use doorman_gateway::storage::models::PolicyDocuments;
use doorman_gateway::{AppState, Config, build_router};
use http::{Request, StatusCode, header};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use tower::ServiceExt;

#[tokio::test]
async fn rust_health_matches_public_contract() {
    let config = Config::for_test("http://127.0.0.1:9".to_owned());
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-request-id"));
    assert!(response.headers().contains_key("request_id"));
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"status":"online"}"#
    );
}

#[tokio::test]
async fn disabled_logs_leave_request_metrics_running_without_creating_log_files() {
    let logs_dir =
        std::env::temp_dir().join(format!("doorman-disabled-logs-{}", uuid::Uuid::new_v4()));
    let mut config = Config::for_test("http://127.0.0.1:9".to_owned());
    config.logs_enabled = false;
    config.logs_dir = Some(logs_dir.clone());
    let state = AppState::new(config).unwrap();
    let runtime = state.runtime.clone();
    let app = build_router(state);

    let features = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/features")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(features.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(features.into_body(), 1024).await.unwrap(),
        r#"{"logs_enabled":false}"#
    );

    let health = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert!(runtime.request_total.load(Ordering::Relaxed) >= 2);
    assert!(!logs_dir.exists(), "disabled logging created {logs_dir:?}");
}

#[tokio::test]
async fn platform_routes_are_native_and_never_use_an_internal_backend() {
    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/platform/user/me", get(|| async { "upstream" })))
            .await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/platform/user/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    server.abort();
}

#[tokio::test]
async fn public_health_never_uses_an_internal_backend() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/api/health",
        get(|| async { Json(json!({ "status": "upstream" })) }),
    ))
    .await;
    let config = Config::for_test(upstream_url);
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"status":"online"}"#
    );
    server.abort();
}

#[tokio::test]
async fn public_health_never_uses_an_alternate_backend() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/api/health",
        get(|| async { Json(json!({ "status": "upstream" })) }),
    ))
    .await;
    let config = Config::for_test(upstream_url);
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"status":"online"}"#
    );
    server.abort();
}

#[tokio::test]
async fn rust_serves_health_independent_of_removed_rollout_flags() {
    let config = Config::for_test("http://127.0.0.1:9".to_owned());
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"status":"online"}"#
    );
}

#[tokio::test]
async fn platform_requests_are_not_forwarded_to_an_internal_backend() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/platform/api/all",
        any(|| async { StatusCode::IM_A_TEAPOT }),
    ))
    .await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/platform/api/all?value=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    server.abort();
}

#[tokio::test]
async fn spoofed_forwarding_headers_do_not_enable_platform_access() {
    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/platform/user/me", any(|| async { StatusCode::OK })))
            .await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/platform/user/me")
                .header("x-forwarded-for", "203.0.113.10")
                .header("x-real-ip", "203.0.113.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    server.abort();
}

#[tokio::test]
async fn rust_fails_closed_without_policy_storage() {
    async fn echo_uri(uri: Uri) -> String {
        uri.path_and_query().unwrap().as_str().to_owned()
    }

    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/api/rest/demo/v1/items", any(echo_uri))).await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rest/demo/v1/items?page=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW006","error_message":"Gateway state store unavailable"}"#
    );
    server.abort();
}

#[tokio::test]
async fn rust_serves_status_unauthorized_from_rust() {
    let config = Config::for_test("http://127.0.0.1:9".to_owned());
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("x-request-id"));
    assert!(response.headers().contains_key("request_id"));
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW401","error_message":"Unauthorized"}"#
    );
}

#[tokio::test]
async fn rust_handles_invalid_status_auth_locally() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/api/status",
        any(|| async { Json(json!({ "status": "upstream" })) }),
    ))
    .await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header("cookie", "theme=dark; access_token_cookie=token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW401","error_message":"Unauthorized"}"#
    );
    server.abort();
}

#[tokio::test]
async fn rust_serves_caches_preflight_from_rust() {
    let config = Config::for_test("http://127.0.0.1:9".to_owned());
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/caches")
                .header("origin", "http://localhost:3000")
                .header("access-control-request-method", "DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().contains_key("x-request-id"));
    assert!(response.headers().contains_key("request_id"));
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://localhost:3000"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "DELETE"
    );
    assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(), "");
}

#[tokio::test]
async fn rust_rejects_unallowlisted_cache_preflight() {
    let config = Config::for_test("http://127.0.0.1:9".to_owned());
    let app = build_router(AppState::new(config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/caches")
                .header("origin", "https://console.example")
                .header("access-control-request-method", "DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error_code"], "GTW008");
}

#[tokio::test]
async fn rust_handles_cache_delete_locally() {
    async fn echo_method(method: Method) -> Json<Value> {
        Json(json!({ "method": method.as_str() }))
    }

    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/api/caches", any(echo_method))).await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/caches")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"detail":"Unauthorized"}"#
    );
    server.abort();
}

#[tokio::test]
async fn rust_preflight_fails_closed_without_policy_storage() {
    async fn echo_uri(method: Method, uri: Uri) -> String {
        format!(
            "{} {}",
            method.as_str(),
            uri.path_and_query().unwrap().as_str()
        )
    }

    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/api/rest/demo/v1/items", any(echo_uri))).await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/rest/demo/v1/items?page=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW006","error_message":"Gateway state store unavailable"}"#
    );
    server.abort();
}

#[tokio::test]
async fn rust_rejects_unported_health_methods_in_rust() {
    let (upstream_url, server) = spawn_upstream(
        Router::new().route("/api/health", any(|| async { "upstream health method" })),
    )
    .await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    // Verified against the pinned server: Starlette renders the FastAPI detail body.
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        br#"{"detail":"Method Not Allowed"}"#.as_slice()
    );
    server.abort();
}

#[tokio::test]
async fn missing_endpoint_fails_closed_without_a_fallback() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/api/rest/demo/v1/missing",
        any(|| async { "upstream fallback" }),
    ))
    .await;
    let config = Config::for_test(upstream_url);
    let state = AppState::new(config)
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-1",
                "api_name": "demo",
                "api_version": "v1",
                "api_public": true,
            })],
            endpoints: vec![json!({
                "api_name": "demo",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/known",
            })],
            ..Default::default()
        });
    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rest/demo/v1/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW003","error_message":"Endpoint does not exist for the requested API"}"#
    );
    server.abort();
}

#[tokio::test]
async fn rest_head_uses_a_registered_get_endpoint_like_python() {
    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/p", any(|| async { StatusCode::OK }))).await;
    let state = AppState::new(Config::for_test("removed-internal-backend".to_owned()))
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-head",
                "api_name": "headok",
                "api_version": "v1",
                "api_public": true,
                "api_servers": [upstream_url],
            })],
            endpoints: vec![json!({
                "api_name": "headok",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/p",
                "endpoint_uri": "/p",
            })],
            ..Default::default()
        });
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/api/rest/headok/v1/p")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    server.abort();
}

#[tokio::test]
async fn strict_options_returns_405_for_an_unregistered_rest_endpoint() {
    if std::env::var_os("DOORMAN_STRICT_OPTIONS_CHILD").is_some() {
        let state = AppState::new(Config::for_test("http://127.0.0.1:9".to_owned()))
            .unwrap()
            .with_policy_documents(PolicyDocuments {
                apis: vec![json!({
                    "api_id": "api-options",
                    "api_name": "optunreg",
                    "api_version": "v1",
                    "api_public": true,
                })],
                ..Default::default()
            });
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/rest/optunreg/v1/not-made")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "strict_options_returns_405_for_an_unregistered_rest_endpoint",
            "--nocapture",
        ])
        .env("DOORMAN_STRICT_OPTIONS_CHILD", "1")
        .env("STRICT_OPTIONS_405", "true")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn unsupported_rest_method_returns_405_like_python() {
    let state = AppState::new(Config::for_test("http://127.0.0.1:9".to_owned()))
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-trace",
                "api_name": "unsup",
                "api_version": "v1",
                "api_public": true,
            })],
            endpoints: vec![json!({
                "api_name": "unsup",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/p",
            })],
            ..Default::default()
        });
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method("TRACE")
                .uri("/api/rest/unsup/v1/p")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn rust_policy_enforcement_rejects_rest_before_upstream() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/api/rest/demo/v1/missing",
        any(|| async { "upstream fallback" }),
    ))
    .await;
    let config = Config::for_test(upstream_url);
    let state = AppState::new(config)
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-1",
                "api_name": "demo",
                "api_version": "v1",
                "api_public": true,
            })],
            endpoints: vec![json!({
                "api_name": "demo",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/known",
            })],
            ..Default::default()
        });
    let app = build_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rest/demo/v1/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW003","error_message":"Endpoint does not exist for the requested API"}"#
    );
    server.abort();
}

#[tokio::test]
async fn graphql_nested_route_uses_the_original_public_uri() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/graphql",
        any(|| async { Json(json!({"data": {"ok": true}})) }),
    ))
    .await;
    let state = AppState::new(Config::for_test("http://127.0.0.1:9".to_owned()))
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-graphql",
                "api_name": "catalog",
                "api_version": "v1",
                "api_public": true,
                "api_servers": [upstream_url],
            })],
            endpoints: vec![json!({
                "api_name": "catalog",
                "api_version": "v1",
                "endpoint_method": "POST",
                "client_uri": "/graphql",
                "endpoint_uri": "/graphql",
            })],
            ..Default::default()
        });
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/graphql/catalog")
                .header("content-type", "application/json")
                .header("x-api-version", "v1")
                .body(Body::from(r#"{"query":"{ ok }"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body, json!({"data": {"ok": true}}));
    server.abort();
}

#[tokio::test]
async fn soap_nested_route_uses_the_original_public_uri() {
    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/soap",
        any(|| async {
            (
                [("content-type", "application/xml")],
                "<Envelope><Body><Pong/></Body></Envelope>",
            )
        }),
    ))
    .await;
    let state = AppState::new(Config::for_test("http://127.0.0.1:9".to_owned()))
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-soap",
                "api_name": "billing",
                "api_version": "v1",
                "api_public": true,
                "api_servers": [upstream_url],
            })],
            endpoints: vec![json!({
                "api_name": "billing",
                "api_version": "v1",
                "endpoint_method": "POST",
                "client_uri": "/soap",
                "endpoint_uri": "/soap",
            })],
            ..Default::default()
        });
    let envelope = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Ping/></soap:Body></soap:Envelope>"#;
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/soap/billing/v1/soap")
                .header("content-type", "text/xml")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(body, "<Envelope><Body><Pong/></Body></Envelope>");
    server.abort();
}

#[tokio::test]
async fn rust_compresses_large_gateway_responses_when_requested() {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let (upstream_url, server) = spawn_upstream(Router::new().route(
        "/large",
        get(|| async { Json(json!({"items": vec!["x"; 800]})) }),
    ))
    .await;
    let config = Config::for_test("http://127.0.0.1:9".to_owned());
    let state = AppState::new(config)
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-compression",
                "api_name": "compressed",
                "api_version": "v1",
                "api_public": true,
                "api_servers": [upstream_url],
            })],
            endpoints: vec![json!({
                "api_name": "compressed",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/large",
                "endpoint_uri": "/large",
            })],
            ..Default::default()
        });
    let app = build_router(state);
    let uncompressed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/rest/compressed/v1/large")
                .header("accept-encoding", "identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uncompressed.status(), StatusCode::OK);
    assert!(
        uncompressed.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert!(!uncompressed.headers().contains_key("content-encoding"));
    let uncompressed = to_bytes(uncompressed.into_body(), 4096).await.unwrap();
    let uncompressed_json: Value = serde_json::from_slice(&uncompressed).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rest/compressed/v1/large")
                .header("accept-encoding", "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-encoding"], "gzip");
    assert!(
        response.headers()["vary"]
            .to_str()
            .unwrap()
            .contains("accept-encoding")
    );
    let compressed = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
    assert!(compressed.len() < uncompressed.len());
    let mut decoded = Vec::new();
    GzDecoder::new(compressed.as_ref())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, uncompressed);
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded).unwrap(),
        uncompressed_json
    );
    server.abort();
}

async fn spawn_upstream(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), server)
}

#[tokio::test]
async fn preflight_fails_closed_without_storage() {
    async fn upstream_options(method: Method) -> String {
        format!("upstream {}", method.as_str())
    }

    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/api/rest/demo/v1/items", any(upstream_options))).await;
    let app = build_router(AppState::new(Config::for_test(upstream_url)).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/rest/demo/v1/items")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"error_code":"GTW006","error_message":"Gateway state store unavailable"}"#
    );
    server.abort();
}

#[tokio::test]
async fn oversized_rest_body_returns_legacy_413_without_reaching_upstream() {
    let (upstream_url, server) =
        spawn_upstream(Router::new().route("/items", any(|| async { StatusCode::IM_A_TEAPOT })))
            .await;
    let state = AppState::new(Config::for_test("removed-internal-backend".to_owned()))
        .unwrap()
        .with_policy_documents(PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-body-limit",
                "api_name": "limited",
                "api_version": "v1",
                "api_public": true,
                "api_servers": [upstream_url],
            })],
            endpoints: vec![json!({
                "api_name": "limited",
                "api_version": "v1",
                "endpoint_method": "POST",
                "client_uri": "/items",
                "endpoint_uri": "/items",
            })],
            ..Default::default()
        });
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/rest/limited/v1/items")
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 1024 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(body["error_code"], "REQ001");
    assert_eq!(
        body["error_message"],
        "Request entity too large (max: 1048576 bytes)"
    );
    server.abort();
}

#[tokio::test]
async fn rest_body_limit_matches_python_configured_boundary_contract() {
    if std::env::var_os("DOORMAN_REST_BODY_LIMIT_CHILD").is_some() {
        let (upstream_url, server) =
            spawn_upstream(Router::new().route("/items", any(|| async { StatusCode::OK }))).await;
        let state = AppState::new(Config::for_test("removed-internal-backend".to_owned()))
            .unwrap()
            .with_policy_documents(PolicyDocuments {
                apis: vec![json!({
                    "api_id": "api-body-limit-boundary",
                    "api_name": "limited-boundary",
                    "api_version": "v1",
                    "api_public": true,
                    "api_servers": [upstream_url],
                })],
                endpoints: vec![
                    json!({
                        "api_name": "limited-boundary",
                        "api_version": "v1",
                        "endpoint_method": "POST",
                        "client_uri": "/items",
                        "endpoint_uri": "/items",
                    }),
                    json!({
                        "api_name": "limited-boundary",
                        "api_version": "v1",
                        "endpoint_method": "GET",
                        "client_uri": "/items",
                        "endpoint_uri": "/items",
                    }),
                    json!({
                        "api_name": "limited-boundary",
                        "api_version": "v1",
                        "endpoint_method": "POST",
                        "client_uri": "/soap",
                        "endpoint_uri": "/items",
                    }),
                    json!({
                        "api_name": "limited-boundary",
                        "api_version": "v1",
                        "endpoint_method": "POST",
                        "client_uri": "/graphql",
                        "endpoint_uri": "/items",
                    }),
                ],
                ..Default::default()
            });

        let oversized = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/rest/limited-boundary/v1/items")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, "11")
                    .body(Body::from("12345678901"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let oversized_body: Value =
            serde_json::from_slice(&to_bytes(oversized.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(oversized_body["error_code"], "REQ001");
        assert_eq!(
            oversized_body["error_message"],
            "Request entity too large (max: 10 bytes)"
        );

        let spoofed_chunked = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/rest/limited-boundary/v1/items")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .header(header::CONTENT_LENGTH, "5")
                    .body(Body::from("12345678901"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(spoofed_chunked.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let spoofed_body: Value =
            serde_json::from_slice(&to_bytes(spoofed_chunked.into_body(), 1024).await.unwrap())
                .unwrap();
        assert_eq!(spoofed_body["error_code"], "REQ001");

        let at_limit = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/rest/limited-boundary/v1/items")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, "10")
                    .body(Body::from("1234567890"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(at_limit.status(), StatusCode::OK);

        let soap_within_protocol_limit = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/soap/limited-boundary/v1/soap")
                    .header(header::CONTENT_TYPE, "application/xml")
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .body(Body::from("<x>1234567890</x>"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            soap_within_protocol_limit.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let graphql_over_protocol_limit = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/graphql/limited-boundary")
                    .header("x-api-version", "v1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .body(Body::from("123456"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            graphql_over_protocol_limit.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            serde_json::from_slice::<Value>(
                &to_bytes(graphql_over_protocol_limit.into_body(), 1024)
                    .await
                    .unwrap()
            )
            .unwrap()["error_code"],
            "REQ001"
        );

        let no_content_length = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/rest/limited-boundary/v1/items")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_content_length.status(), StatusCode::OK);
        server.abort();
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "rest_body_limit_matches_python_configured_boundary_contract",
            "--nocapture",
        ])
        .env("DOORMAN_REST_BODY_LIMIT_CHILD", "1")
        .env("MAX_BODY_SIZE_BYTES", "10")
        .env_remove("MAX_BODY_SIZE_BYTES_REST")
        .env("MAX_BODY_SIZE_BYTES_SOAP", "20")
        .env("MAX_BODY_SIZE_BYTES_GRAPHQL", "5")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
