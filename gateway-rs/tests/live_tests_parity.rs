use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::body::{Body, to_bytes};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    response::Response,
    routing::{any, post},
};
use doorman_gateway::{
    AppState, Config, build_router,
    storage::{redis::bandwidth_key, runtime::SharedStorage},
};
use http::{HeaderMap, Method, Uri};
use http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tower::ServiceExt;

async fn test_app_state() -> AppState {
    test_app_state_with(|_| {}).await
}

#[tokio::test]
async fn hot_reload_changes_retry_and_timeout_on_real_http_requests() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let counter = attempts.clone();
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/retry",
                    any(move || {
                        let counter = counter.clone();
                        async move {
                            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                                StatusCode::SERVICE_UNAVAILABLE
                            } else {
                                StatusCode::OK
                            }
                        }
                    }),
                )
                .route(
                    "/slow",
                    any(|| async {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        StatusCode::OK
                    }),
                ),
        )
        .await
        .unwrap();
    });
    let directory =
        std::env::temp_dir().join(format!("doorman-http-reload-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut state = test_app_state().await;
    state.hot_reload = Arc::new(doorman_gateway::hot_reload::HotReloadConfig::new(Some(
        path.clone(),
    )));
    let storage = state.storage.as_ref().unwrap();
    storage.insert_one("apis", json!({"api_id":"reload-api","api_name":"reload","api_version":"v1","api_type":"REST","api_public":true,"api_servers":[upstream_url],"api_allowed_retry_count":0,"api_read_timeout":3})).await.unwrap();
    for endpoint in ["/retry", "/slow"] {
        storage.insert_one("endpoints", json!({"api_name":"reload","api_version":"v1","endpoint_method":"GET","endpoint_uri":endpoint})).await.unwrap();
    }
    let app = build_router(state);
    let token = login_admin(&app).await;
    assert_eq!(
        public_gateway_status(
            &app,
            Method::GET,
            "/api/rest/reload/v1/retry",
            None,
            Body::empty()
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    std::fs::write(&path, r#"{"retry":{"enabled":true,"max_attempts":2}}"#).unwrap();
    assert_eq!(
        authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/config/reload",
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    attempts.store(0, Ordering::SeqCst);
    assert_eq!(
        public_gateway_status(
            &app,
            Method::GET,
            "/api/rest/reload/v1/retry",
            None,
            Body::empty()
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        public_gateway_status(
            &app,
            Method::GET,
            "/api/rest/reload/v1/slow",
            None,
            Body::empty()
        )
        .await,
        StatusCode::OK
    );
    std::fs::write(
        &path,
        r#"{"gateway":{"timeout":1},"retry":{"enabled":false,"max_attempts":2}}"#,
    )
    .unwrap();
    assert_eq!(
        authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/config/reload",
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    attempts.store(0, Ordering::SeqCst);
    assert_eq!(
        public_gateway_status(
            &app,
            Method::GET,
            "/api/rest/reload/v1/retry",
            None,
            Body::empty()
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        public_gateway_status(
            &app,
            Method::GET,
            "/api/rest/reload/v1/slow",
            None,
            Body::empty()
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT
    );
    upstream.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

async fn test_app_state_with(configure: impl FnOnce(&mut Config)) -> AppState {
    let mut config = Config::for_test("removed-internal-backend".to_owned());
    config.https_only = false;
    configure(&mut config);
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();

    storage
        .insert_one(
            "roles",
            json!({
                "role_name": "admin",
                "manage_users": true,
                "manage_apis": true,
                "manage_endpoints": true,
                "manage_groups": true,
                "manage_roles": true,
                "manage_routings": true,
                "manage_gateway": true,
                "manage_subscriptions": true,
                "manage_credits": true,
                "manage_auth": true,
                "manage_security": true,
                "manage_tiers": true,
                "manage_rate_limits": true,
                "view_analytics": true,
                "view_logs": true,
                "export_logs": true
            }),
        )
        .await
        .unwrap();

    storage
        .insert_one(
            "users",
            json!({
                "username": "admin",
                "email": "admin@doorman.dev",
                "password": bcrypt::hash("AdminPassword123!", bcrypt::DEFAULT_COST).unwrap(),
                "role": "admin",
                "groups": ["ALL", "admin"],
                "active": true,
                "ui_access": true
            }),
        )
        .await
        .unwrap();

    let mut state = AppState::new(config).unwrap();
    state.storage = Some(Arc::new(storage));
    state
}

async fn login_admin(app: &axum::Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/authorization")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "admin@doorman.dev",
                        "password": "AdminPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    body["access_token"].as_str().unwrap().to_owned()
}
async fn response_json(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap();
    (status, body)
}

async fn authed_json_response(
    app: &axum::Router,
    token: &str,
    method: Method,
    uri: impl AsRef<str>,
    payload: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri.as_ref())
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-api-version", "v1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    response_json(response).await
}

async fn authed_empty_response(
    app: &axum::Router,
    token: &str,
    method: Method,
    uri: impl AsRef<str>,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri.as_ref())
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response_json(response).await
}

async fn echo_upstream(method: Method, uri: Uri, headers: HeaderMap) -> Json<Value> {
    Json(json!({
        "method": method.as_str(),
        "path": uri.path(),
        "x_api_key": headers.get("x-api-key").and_then(|value| value.to_str().ok()),
    }))
}

async fn start_echo_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/status", any(echo_upstream))
                .route("/ping", any(echo_upstream))
                .route("/echo", any(echo_upstream))
                .route("/whoami", any(echo_upstream))
                .route("/hit", any(echo_upstream))
                .route("/p", any(echo_upstream))
                .route("/items", any(echo_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

async fn request_id_upstream(headers: HeaderMap) -> Response {
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-upstream-request-id", request_id)
        .body(Body::from(json!({"request_id": request_id}).to_string()))
        .unwrap()
}

async fn start_request_id_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/echo", any(request_id_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

struct UpstreamStatusSequence {
    statuses: Vec<StatusCode>,
    attempts: AtomicUsize,
}

async fn rest_status_sequence_upstream(
    State(sequence): State<Arc<UpstreamStatusSequence>>,
) -> Response {
    let attempt = sequence.attempts.fetch_add(1, Ordering::SeqCst);
    let status = sequence
        .statuses
        .get(attempt)
        .copied()
        .unwrap_or_else(|| *sequence.statuses.last().expect("non-empty sequence"));
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"ok": status.is_success(), "attempt": attempt + 1}).to_string(),
        ))
        .unwrap()
}

async fn start_rest_status_sequence_upstream(
    statuses: Vec<StatusCode>,
) -> (String, Arc<UpstreamStatusSequence>, JoinHandle<()>) {
    assert!(!statuses.is_empty());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let sequence = Arc::new(UpstreamStatusSequence {
        statuses,
        attempts: AtomicUsize::new(0),
    });
    let server_sequence = sequence.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/r", any(rest_status_sequence_upstream))
                .with_state(server_sequence),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), sequence, server)
}

async fn rest_header_filter_upstream(headers: HeaderMap) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-upstream", "allowed")
        .header("x-secret", "blocked")
        .body(Body::from(
            json!({
                "x_allowed": headers.get("x-allowed").and_then(|value| value.to_str().ok()),
                "x_blocked": headers.get("x-blocked").and_then(|value| value.to_str().ok()),
            })
            .to_string(),
        ))
        .unwrap()
}

async fn start_rest_header_filter_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/headers", any(rest_header_filter_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

async fn marked_echo_upstream(State(marker): State<String>) -> Json<Value> {
    Json(json!({"upstream": marker}))
}

async fn start_marked_echo_upstream(marker: &str) -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let marker = marker.to_owned();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/echo", any(marked_echo_upstream))
                .route("/status", any(marked_echo_upstream))
                .with_state(marker),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

#[tokio::test]
async fn routing_precedence_and_round_robin_real_upstreams_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (api_a, api_a_server) = start_marked_echo_upstream("api-a").await;
    let (api_b, api_b_server) = start_marked_echo_upstream("api-b").await;
    let (endpoint_a, endpoint_a_server) = start_marked_echo_upstream("endpoint-a").await;
    let (endpoint_b, endpoint_b_server) = start_marked_echo_upstream("endpoint-b").await;
    let (client_a, client_a_server) = start_marked_echo_upstream("client-a").await;
    let (client_b, client_b_server) = start_marked_echo_upstream("client-b").await;
    let api_name = "routing-real";
    let api_version = "v1";

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "routing precedence and round robin",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [api_a, api_b],
            "api_type": "REST",
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "GET",
                "endpoint_uri": "/echo",
                "endpoint_description": "endpoint routing",
                "endpoint_servers": [endpoint_a, endpoint_b]
            }),
        ),
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "GET",
                "endpoint_uri": "/status",
                "endpoint_description": "API routing fallback"
            }),
        ),
        (
            "/platform/routing",
            json!({
                "client_key": "routing-client",
                "routing_name": "routing client override",
                "routing_servers": [client_a, client_b],
                "routing_description": "client route"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    for (path, client_key, expected) in [
        ("echo", Some("routing-client"), "client-a"),
        ("echo", Some("routing-client"), "client-b"),
        ("echo", None, "endpoint-a"),
        ("echo", None, "endpoint-b"),
        ("status", None, "api-a"),
        ("status", None, "api-b"),
        ("status", None, "api-a"),
    ] {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(format!("/api/rest/{api_name}/{api_version}/{path}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(client_key) = client_key {
            request = request.header("client-key", client_key);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, body) = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{path} via {expected}");
        assert_eq!(body["upstream"], expected, "{path} via {expected}");
    }

    for server in [
        api_a_server,
        api_b_server,
        endpoint_a_server,
        endpoint_b_server,
        client_a_server,
        client_b_server,
    ] {
        server.abort();
    }
}

#[tokio::test]
async fn gateway_no_upstream_servers_has_stable_error_contract() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "routing-no-upstream";
    let api_version = "v1";
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "no upstream response contract",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [],
            "api_type": "REST",
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "GET",
                "endpoint_uri": "/status",
                "endpoint_description": "no upstream endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/rest/{api_name}/{api_version}/status"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error_code"], "GTW001");
    assert_eq!(body["error_message"], "No upstream servers configured");
}

#[tokio::test]
async fn rest_retries_real_upstream_status_sequences_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (retry_500_url, retry_500, retry_500_server) = start_rest_status_sequence_upstream(vec![
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::OK,
    ])
    .await;
    let (retry_503_url, retry_503, retry_503_server) =
        start_rest_status_sequence_upstream(vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK])
            .await;
    let (retry_502_url, retry_502, retry_502_server) =
        start_rest_status_sequence_upstream(vec![StatusCode::BAD_GATEWAY, StatusCode::OK]).await;
    let (retry_504_url, retry_504, retry_504_server) =
        start_rest_status_sequence_upstream(vec![StatusCode::GATEWAY_TIMEOUT, StatusCode::OK])
            .await;
    let (no_retry_url, no_retry, no_retry_server) = start_rest_status_sequence_upstream(vec![
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::INTERNAL_SERVER_ERROR,
    ])
    .await;
    let (retry_limit_url, retry_limit, retry_limit_server) =
        start_rest_status_sequence_upstream(vec![
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::OK,
        ])
        .await;

    for (api_name, upstream_url, retry_count, expected_status, expected_attempts) in [
        ("rest-retry-500", retry_500_url, 1, StatusCode::OK, 2),
        ("rest-retry-502", retry_502_url, 1, StatusCode::OK, 2),
        ("rest-retry-503", retry_503_url, 1, StatusCode::OK, 2),
        ("rest-retry-504", retry_504_url, 1, StatusCode::OK, 2),
        (
            "rest-no-retry",
            no_retry_url,
            0,
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
        ),
        (
            "rest-retry-limit",
            retry_limit_url,
            1,
            StatusCode::INTERNAL_SERVER_ERROR,
            2,
        ),
    ] {
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/api",
            json!({
                "api_name": api_name,
                "api_version": "v1",
                "api_description": "REST retry status sequence",
                "api_allowed_roles": ["admin"],
                "api_allowed_groups": ["ALL"],
                "api_servers": [upstream_url],
                "api_type": "REST",
                "api_allowed_retry_count": retry_count,
                "active": true
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{api_name}");
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": "v1",
                "endpoint_method": "GET",
                "endpoint_uri": "/r",
                "endpoint_description": "retry endpoint"
            }),
        )
        .await;
        assert!(status.is_success(), "endpoint {api_name}: {status}");
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": "v1"}),
        )
        .await;
        assert!(status.is_success(), "subscription {api_name}: {status}");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/rest/{api_name}/v1/r"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status, "{api_name}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["ok"], expected_status.is_success(), "{api_name}");
        let attempts = match api_name {
            "rest-retry-500" => retry_500.attempts.load(Ordering::SeqCst),
            "rest-retry-502" => retry_502.attempts.load(Ordering::SeqCst),
            "rest-retry-503" => retry_503.attempts.load(Ordering::SeqCst),
            "rest-retry-504" => retry_504.attempts.load(Ordering::SeqCst),
            "rest-no-retry" => no_retry.attempts.load(Ordering::SeqCst),
            "rest-retry-limit" => retry_limit.attempts.load(Ordering::SeqCst),
            _ => unreachable!(),
        };
        assert_eq!(attempts, expected_attempts, "{api_name}");
    }
    retry_500_server.abort();
    retry_502_server.abort();
    retry_503_server.abort();
    retry_504_server.abort();
    no_retry_server.abort();
    retry_limit_server.abort();
}

#[tokio::test]
async fn rest_request_and_response_header_allowlists_real_upstream_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_rest_header_filter_upstream().await;
    let api_name = "rest-header-allowlist";
    let api_version = "v1";
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "REST header allowlists",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "REST",
            "api_allowed_headers": ["x-allowed", "x-upstream"],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "GET",
                "endpoint_uri": "/headers",
                "endpoint_description": "header allowlist endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/rest/{api_name}/{api_version}/headers"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-allowed", "yes")
                .header("x-blocked", "no")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-upstream"], "allowed");
    assert!(!response.headers().contains_key("x-secret"));
    let (_, body) = response_json(response).await;
    assert_eq!(body["x_allowed"], "yes");
    assert!(body["x_blocked"].is_null());
    upstream.abort();
}

async fn configure_ip_gateway(
    app: &axum::Router,
    token: &str,
    upstream_url: &str,
    api_name: &str,
    ip_mode: &str,
    whitelist: Value,
    blacklist: Value,
) {
    let api = json!({
        "api_name": api_name,
        "api_version": "v1",
        "api_description": format!("{api_name} v1"),
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": [upstream_url],
        "api_type": "REST",
        "api_allowed_retry_count": 0,
        "api_ip_mode": ip_mode,
        "api_ip_whitelist": whitelist,
        "api_ip_blacklist": blacklist,
        "api_trust_x_forwarded_for": true,
        "active": true,
    });
    let (status, _) = authed_json_response(app, token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": "v1",
        "endpoint_method": "GET",
        "endpoint_uri": "/p",
        "endpoint_description": "p",
    });
    let (status, _) =
        authed_json_response(app, token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription = json!({
        "api_name": api_name,
        "api_version": "v1",
        "username": "admin",
    });
    let (status, body) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success() || body["error_code"] == "SUB004");
}

async fn ip_gateway_response(
    app: &axum::Router,
    token: &str,
    api_name: &str,
    real_ip: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/rest/{api_name}/v1/p"))
        .extension(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            42000,
        )))
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(real_ip) = real_ip {
        builder = builder.header("x-real-ip", real_ip);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    response_json(response).await
}

#[tokio::test]
async fn live_test_61_api_ip_whitelist_and_blacklist_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "ip-policy-live-61";
    configure_ip_gateway(
        &app,
        &token,
        &upstream_url,
        api_name,
        "whitelist",
        json!(["1.2.3.4/32", "10.0.0.0/8"]),
        json!(["8.8.8.8/32"]),
    )
    .await;

    for allowed_ip in ["1.2.3.4", "10.23.45.6"] {
        let (status, body) = ip_gateway_response(&app, &token, api_name, Some(allowed_ip)).await;
        assert_eq!(status, StatusCode::OK, "allowed IP {allowed_ip}");
        assert_eq!(body["method"], "GET");
        assert_eq!(body["path"], "/p");
    }
    let (status, body) = ip_gateway_response(&app, &token, api_name, Some("8.8.8.8")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error_code"], "API011");
    upstream.abort();
}

#[tokio::test]
async fn live_test_61_localhost_bypass_when_no_forward_headers_parity() {
    let state = test_app_state_with(|config| {
        config.shared_storage.local_host_ip_bypass = true;
    })
    .await;
    let app = build_router(state);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "ip-bypass-live-61";
    configure_ip_gateway(
        &app,
        &token,
        &upstream_url,
        api_name,
        "whitelist",
        json!([]),
        json!([]),
    )
    .await;

    let (status, body) = ip_gateway_response(&app, &token, api_name, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["method"], "GET");
    assert_eq!(body["path"], "/p");
    upstream.abort();
}

async fn configure_bandwidth_gateway(
    app: &axum::Router,
    token: &str,
    upstream_url: &str,
    api_name: &str,
    method: Method,
    limit: u64,
    window: &str,
) {
    let (status, _) = authed_json_response(
        app,
        token,
        Method::PUT,
        "/platform/user/admin",
        json!({
            "bandwidth_limit_bytes": limit,
            "bandwidth_limit_window": window,
            "bandwidth_limit_enabled": true,
        }),
    )
    .await;
    assert!(status.is_success());

    let api = json!({
        "api_name": api_name,
        "api_version": "v1",
        "api_description": format!("{api_name} bandwidth"),
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": [upstream_url],
        "api_type": "REST",
        "api_allowed_retry_count": 0,
        "active": true,
    });
    let (status, _) = authed_json_response(app, token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": "v1",
        "endpoint_method": method.as_str(),
        "endpoint_uri": "/p",
        "endpoint_description": "bandwidth endpoint",
    });
    let (status, _) =
        authed_json_response(app, token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription = json!({"api_name": api_name, "api_version": "v1", "username": "admin"});
    let (status, body) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success() || body["error_code"] == "SUB004");
}

async fn configure_cors_gateway(
    app: &axum::Router,
    token: &str,
    api_name: &str,
    upstream_url: &str,
    origins: Value,
    credentials: bool,
) {
    let api = json!({
        "api_name": api_name,
        "api_version": "v1",
        "api_description": format!("{api_name} CORS parity"),
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": [upstream_url],
        "api_type": "REST",
        "api_allowed_retry_count": 0,
        "api_cors_allow_origins": origins,
        "api_cors_allow_methods": ["GET", "POST"],
        "api_cors_allow_headers": ["Content-Type", "X-CSRF-Token"],
        "api_cors_allow_credentials": credentials,
        "active": true,
    });
    let (status, _) = authed_json_response(app, token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": "v1",
        "endpoint_method": "GET",
        "endpoint_uri": "/echo",
        "endpoint_description": "CORS echo",
    });
    let (status, _) =
        authed_json_response(app, token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription = json!({
        "api_name": api_name,
        "api_version": "v1",
        "username": "admin",
    });
    let (status, _) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());
}

async fn cors_preflight(app: &axum::Router, token: &str, api_name: &str, origin: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(format!("/api/rest/{api_name}/v1/echo"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "X-CSRF-Token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn live_test_98_api_cors_preflight_and_actual_response_headers_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "cors-preflight-98";
    configure_cors_gateway(
        &app,
        &token,
        api_name,
        &upstream_url,
        json!(["http://example.com"]),
        true,
    )
    .await;

    let response = cors_preflight(&app, &token, api_name, "http://example.com").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://example.com"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    assert!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
            .to_str()
            .unwrap()
            .split(',')
            .any(|method| method.trim() == "OPTIONS")
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/rest/{api_name}/v1/echo"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ORIGIN, "http://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://example.com"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    upstream.abort();
}

#[tokio::test]
async fn live_test_99_cors_credentialed_wildcard_is_rejected_as_approved_security_divergence() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api = json!({
        "api_name": "cors-wildcard-99",
        "api_version": "v1",
        "api_description": "credentialed wildcard",
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": ["http://127.0.0.1:9"],
        "api_type": "REST",
        "api_cors_allow_origins": ["*"],
        "api_cors_allow_methods": ["GET", "OPTIONS"],
        "api_cors_allow_headers": ["Content-Type"],
        "api_cors_allow_credentials": true,
        "active": true,
    });

    let (status, body) =
        authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["detail"][0]["type"], "value_error.cors_origins");
}

#[tokio::test]
async fn live_test_99_cors_specific_origin_and_headers_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "cors-specific-99";
    configure_cors_gateway(
        &app,
        &token,
        api_name,
        &upstream_url,
        json!(["http://ok.example"]),
        false,
    )
    .await;

    let allowed = cors_preflight(&app, &token, api_name, "http://ok.example").await;
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://ok.example"
    );
    assert_eq!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "Content-Type, X-CSRF-Token"
    );

    let denied = cors_preflight(&app, &token, api_name, "http://bad.example").await;
    assert_eq!(denied.status(), StatusCode::NO_CONTENT);
    assert!(
        !denied
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    upstream.abort();
}

#[tokio::test]
async fn live_platform_cors_default_preflight_parity() {
    let app = build_router(test_app_state().await);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/platform/api")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://localhost:3000"
    );
}

#[tokio::test]
async fn live_platform_cors_tools_checker_default_methods_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (status, body) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/tools/cors/check",
        json!({
            "origin": "http://localhost:3000",
            "method": "GET",
            "request_headers": ["X-Rand"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let payload = body.get("response").unwrap_or(&body);
    let mut methods = payload["config"]["allow_methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|method| method.as_str().unwrap())
        .collect::<Vec<_>>();
    methods.sort_unstable();
    assert_eq!(
        methods,
        ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    );
}

async fn monitor_gateway_get(app: &axum::Router, token: &str, api_name: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/rest/{api_name}/v1/echo"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn monitor_metrics_accepts_python_range_parameters_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;

    for range in ["1h", "24h", "7d", "30d"] {
        let (status, metrics) = authed_empty_response(
            &app,
            &token,
            Method::GET,
            &format!("/platform/monitor/metrics?range={range}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "range={range}");
        assert!(metrics.is_object());
        assert!(metrics["series"].is_array());
        assert!(metrics["status_counts"].is_object());
    }
}

#[tokio::test]
async fn monitor_dashboard_liveness_readiness_and_metrics_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;

    let (status, dashboard) =
        authed_empty_response(&app, &token, Method::GET, "/platform/dashboard").await;
    assert_eq!(status, StatusCode::OK);
    assert!(dashboard.get("activeUsers").is_some());
    assert!(dashboard.get("newApis").is_some());

    let (status, metrics) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        "/platform/monitor/metrics?range=24h",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(metrics.is_object());

    let liveness = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/liveness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(liveness.status(), StatusCode::OK);
    let (_, liveness) = response_json(liveness).await;
    assert_eq!(liveness["status"], "alive");

    let readiness = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/readiness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(readiness.status(), StatusCode::OK);
    let (_, readiness) = response_json(readiness).await;
    assert!(matches!(
        readiness["status"].as_str(),
        Some("ready" | "degraded")
    ));
}

#[tokio::test]
async fn monitor_metrics_increment_status_series_and_top_apis_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    for api_name in ["monitor-mapi1", "monitor-mapi2"] {
        configure_cors_gateway(
            &app,
            &token,
            api_name,
            &upstream_url,
            json!(["http://localhost:3000"]),
            false,
        )
        .await;
    }
    assert_eq!(
        monitor_gateway_get(&app, &token, "monitor-mapi1").await,
        StatusCode::OK
    );
    for _ in 0..2 {
        assert_eq!(
            monitor_gateway_get(&app, &token, "monitor-mapi2").await,
            StatusCode::OK
        );
    }

    let (status, metrics) =
        authed_empty_response(&app, &token, Method::GET, "/platform/monitor/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(metrics["total_requests"].as_u64().unwrap_or(0) >= 3);
    assert!(metrics["status_counts"]["200"].as_u64().unwrap_or(0) >= 3);
    assert!(metrics["series"].is_array());
    assert!(metrics["top_apis"].as_array().unwrap().iter().any(|entry| {
        entry["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("rest:"))
    }));
    upstream.abort();
}

#[tokio::test]
async fn monitor_report_returns_python_compatible_csv_sections() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "monitor-report";
    configure_cors_gateway(
        &app,
        &token,
        api_name,
        &upstream_url,
        json!(["http://localhost:3000"]),
        false,
    )
    .await;
    assert_eq!(
        monitor_gateway_get(&app, &token, api_name).await,
        StatusCode::OK
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/platform/monitor/report?start=2026-08-26T12:00&end=2026-08-26T12:00")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    let text = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    for section in ["Report", "Overview", "Status Codes", "API Usage"] {
        assert!(text.contains(section), "missing CSV section {section}");
    }
    upstream.abort();
}

async fn bandwidth_gateway_response(
    app: &axum::Router,
    token: &str,
    api_name: &str,
    method: Method,
    payload: Option<Value>,
) -> (StatusCode, Value) {
    let body = payload.map(|value| value.to_string()).unwrap_or_default();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/api/rest/{api_name}/v1/p"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_LENGTH, body.len());
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    response_json(response).await
}

#[tokio::test]
async fn bandwidth_enforcement_and_usage_tracking_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "bandwidth-usage";
    configure_bandwidth_gateway(
        &app,
        &token,
        &upstream_url,
        api_name,
        Method::POST,
        80,
        "minute",
    )
    .await;

    let payload = json!({"data": "x".repeat(50)});
    let (first, _) =
        bandwidth_gateway_response(&app, &token, api_name, Method::POST, Some(payload.clone()))
            .await;
    let (second, _) =
        bandwidth_gateway_response(&app, &token, api_name, Method::POST, Some(payload)).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);

    let (status, user) =
        authed_empty_response(&app, &token, Method::GET, "/platform/user/me").await;
    assert_eq!(status, StatusCode::OK);
    assert!(user["bandwidth_usage_bytes"].as_u64().unwrap_or(0) > 0);
    assert!(user["bandwidth_resets_at"].as_u64().unwrap_or(0) > 0);
    upstream.abort();
}

#[tokio::test]
async fn monitor_tracks_gateway_bytes_in_and_out_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "bandwidth-monitor";
    configure_bandwidth_gateway(
        &app,
        &token,
        &upstream_url,
        api_name,
        Method::POST,
        1_000_000,
        "minute",
    )
    .await;
    let (_, before) =
        authed_empty_response(&app, &token, Method::GET, "/platform/monitor/metrics").await;
    let payload = json!({"pad": "z".repeat(30)});
    let payload_size = payload.to_string().len() as u64;

    for _ in 0..2 {
        let (status, _) =
            bandwidth_gateway_response(&app, &token, api_name, Method::POST, Some(payload.clone()))
                .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (_, after) =
        authed_empty_response(&app, &token, Method::GET, "/platform/monitor/metrics").await;
    assert!(
        after["total_bytes_in"].as_u64().unwrap_or(0)
            - before["total_bytes_in"].as_u64().unwrap_or(0)
            >= payload_size * 2
    );
    assert!(
        after["total_bytes_out"].as_u64().unwrap_or(0)
            > before["total_bytes_out"].as_u64().unwrap_or(0)
    );
    upstream.abort();
}

#[tokio::test]
async fn bandwidth_counts_request_and_response_bytes_parity() {
    let state = test_app_state().await;
    let storage = state.storage.clone().unwrap();
    let app = build_router(state);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "bandwidth-counting";
    configure_bandwidth_gateway(
        &app,
        &token,
        &upstream_url,
        api_name,
        Method::POST,
        1_000_000,
        "minute",
    )
    .await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let key = bandwidth_key("admin", 60, (now / 60) * 60);
    let before = storage.current_counter(&key).await.unwrap();
    let payload = "x".repeat(1234);
    let (status, _) = bandwidth_gateway_response(
        &app,
        &token,
        api_name,
        Method::POST,
        Some(json!({"data": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after = storage.current_counter(&key).await.unwrap();
    assert!(after - before >= 1234);
    assert!(after - before > 1234);
    upstream.abort();
}

#[tokio::test]
async fn live_bandwidth_limit_enforced_and_window_resets_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "bandwidth-window-live";
    configure_bandwidth_gateway(
        &app,
        &token,
        &upstream_url,
        api_name,
        Method::GET,
        1,
        "second",
    )
    .await;

    let (first, _) = bandwidth_gateway_response(&app, &token, api_name, Method::GET, None).await;
    let (second, _) = bandwidth_gateway_response(&app, &token, api_name, Method::GET, None).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (third, _) = bandwidth_gateway_response(&app, &token, api_name, Method::GET, None).await;
    assert_eq!(third, StatusCode::OK);
    upstream.abort();
}

struct CreditGatewaySetup<'a> {
    api_name: &'a str,
    credit_group: &'a str,
    group_key: &'a str,
    user_key: Option<&'a str>,
    upstream_url: &'a str,
    endpoint_method: Method,
    endpoint_uri: &'a str,
    available_credits: u64,
}

async fn configure_credit_gateway(app: &axum::Router, token: &str, setup: &CreditGatewaySetup<'_>) {
    let CreditGatewaySetup {
        api_name,
        credit_group,
        group_key,
        user_key,
        upstream_url,
        endpoint_method,
        endpoint_uri,
        available_credits,
    } = setup;

    let credit_definition = json!({"api_credit_group": credit_group, "api_key": group_key, "api_key_header": "x-api-key", "credit_tiers": [{"tier_name": "default", "credits": available_credits, "input_limit": 0, "output_limit": 0, "reset_frequency": "monthly"}]});
    let (status, _) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/credit",
        credit_definition,
    )
    .await;
    assert!(status.is_success());

    let mut user_credit = json!({"tier_name": "default", "available_credits": available_credits});
    if let Some(user_key) = user_key {
        user_credit["user_api_key"] = json!(user_key);
    }
    let credit_assignment =
        json!({"username": "admin", "users_credits": {(*credit_group): user_credit}});
    let (status, _) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/credit/admin",
        credit_assignment,
    )
    .await;
    assert!(status.is_success());

    let api = json!({"api_name": api_name, "api_version": "v1", "api_description": "credit gateway", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": [upstream_url], "api_type": "REST", "api_allowed_retry_count": 0, "active": true, "api_credits_enabled": true, "api_credit_group": credit_group});
    let (status, _) = authed_json_response(app, token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({"api_name": api_name, "api_version": "v1", "endpoint_method": endpoint_method.as_str(), "endpoint_uri": endpoint_uri, "endpoint_description": "credit gateway endpoint"});
    let (status, _) =
        authed_json_response(app, token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription = json!({"api_name": api_name, "api_version": "v1", "username": "admin"});
    let (status, _) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_00_health_and_auth_status_me_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;

    // test_status_ok: GET /api/health -> 200 OK
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "online");

    // test_auth_status_me: GET /platform/authorization/status -> 200 OK
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/authorization/status")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // GET /platform/user/me -> username == "admin", ui_access == true
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/user/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["username"], "admin");
    assert_eq!(body["ui_access"], true);
}

#[tokio::test]
async fn live_test_10_user_onboarding_lifecycle_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;

    let username = "user_onboarding_10";
    let email = "user10@example.com";
    let password = "StrongUserPassword123!";

    // Create user: POST /platform/user
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/user")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "username": username,
                        "email": email,
                        "password": password,
                        "role": "developer",
                        "groups": ["ALL"],
                        "ui_access": false
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // GET /platform/user/{username} -> verify email & ui_access: false
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/platform/user/{username}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["email"], email);
    assert_eq!(body["ui_access"], false);

    // PUT /platform/user/{username} -> update ui_access: true
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/platform/user/{username}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"ui_access": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    let new_password = "UpdatedUserPassword123!";
    let (password_status, _) = authed_json_response(
        &app,
        &token,
        Method::PUT,
        &format!("/platform/user/{username}/update-password"),
        json!({"old_password": password, "new_password": new_password}),
    )
    .await;
    assert!(password_status.is_success() || password_status == StatusCode::BAD_REQUEST);
    let login_password = if password_status.is_success() {
        new_password
    } else {
        password
    };

    // Login as user_onboarding_10
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/authorization")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": login_password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let user_token = body["access_token"].as_str().unwrap();
    let (status, me) =
        authed_empty_response(&app, user_token, Method::GET, "/platform/user/me").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["username"], username);
    assert_eq!(me["ui_access"], true);

    // DELETE /platform/user/{username}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/platform/user/{username}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn live_test_20_credit_defs_and_user_overrides_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;

    let credit_group = "cg-test-20";
    let api_key_val = "DUMMY_KEY_20";

    // POST /platform/credit
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/credit")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_credit_group": credit_group,
                        "api_key": api_key_val,
                        "api_key_header": "x-api-key",
                        "credit_tiers": [{
                            "tier_name": "default",
                            "credits": 10,
                            "input_limit": 0,
                            "output_limit": 0,
                            "reset_frequency": "monthly"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/platform/credit/defs/{credit_group}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // POST /platform/credit/admin
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/credit/admin")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "username": "admin",
                        "users_credits": {
                            credit_group: {
                                "tier_name": "default",
                                "available_credits": 10
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // GET /platform/credit/admin
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/credit/admin")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body["users_credits"].get(credit_group).is_some());
}

#[tokio::test]
async fn live_test_30_rest_gateway_basic_crud_and_subscription_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    let api_name = "rest-crud-api";
    let api_version = "v1";

    // Create API: POST /platform/api
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "api_description": "REST crud demo",
                        "api_allowed_roles": ["admin"],
                        "api_allowed_groups": ["ALL"],
                        "api_servers": [upstream_url],
                        "api_type": "REST",
                        "active": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Create Endpoint: POST /platform/endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/endpoint")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "endpoint_method": "POST",
                        "endpoint_uri": "/status",
                        "endpoint_description": "status"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // A valid nested payload must pass the configured validation schema and
    // continue to the real upstream, rather than only passing local parsing.
    let (status, endpoint) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/platform/endpoint/POST/{api_name}/{api_version}/status"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let endpoint_id = endpoint["endpoint_id"].as_str().unwrap();
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/endpoint/endpoint/validation",
        json!({
            "endpoint_id": endpoint_id,
            "validation_enabled": true,
            "validation_schema": {
                "validation_schema": {
                    "user.name": {"required": true, "type": "string", "min": 2}
                }
            }
        }),
    )
    .await;
    assert!(status.is_success());

    // Subscribe: POST /platform/subscription/subscribe
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/subscription/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "username": "admin"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Gateway request must reach the configured upstream with the registered path.
    let (status, body) = authed_json_response(
        &app,
        &token,
        Method::POST,
        &format!("/api/rest/{api_name}/{api_version}/status"),
        json!({"user": {"name": "Ada"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["method"], "POST");
    assert_eq!(body["path"], "/status");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/rest/{api_name}/{api_version}/status"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-request-id", "python-header-normalization")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"user": {"name": "Ada"}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-request-id"));
    assert!(response.headers().contains_key("request_id"));
    assert_eq!(
        response.headers()["x-request-id"],
        "python-header-normalization"
    );
    assert_eq!(
        response.headers()["request_id"],
        "python-header-normalization"
    );
    upstream.abort();
    // DELETE Endpoint & API
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/platform/endpoint/POST/{api_name}/{api_version}/status"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/platform/api/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn request_id_is_forwarded_to_authenticated_rest_upstream_and_response() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_request_id_upstream().await;
    let api_name = "request-id-propagation";
    let api_version = "v1";
    for (path, payload) in [
        (
            "/platform/api",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "api_description": "request-id propagation",
                "api_allowed_roles": ["admin"],
                "api_allowed_groups": ["ALL"],
                "api_servers": [upstream_url],
                "api_type": "REST",
                "api_allowed_retry_count": 0,
                "api_allowed_headers": ["X-Upstream-Request-ID"],
                "active": true
            }),
        ),
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "GET",
                "endpoint_uri": "/echo",
                "endpoint_description": "request-id echo"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/rest/{api_name}/{api_version}/echo"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!request_id.is_empty());
    assert_eq!(response.headers()["x-upstream-request-id"], request_id);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["request_id"],
        request_id
    );
    upstream.abort();
}

#[tokio::test]
async fn live_test_21_subscription_list_unsubscribe_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "subs-test-21";
    let api_version = "v1";

    let api = json!({
        "api_name": api_name,
        "api_version": api_version,
        "api_description": "subscription flow",
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": ["http://127.0.0.1:9"],
        "api_type": "REST",
        "active": true,
    });
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": api_version,
        "endpoint_method": "GET",
        "endpoint_uri": "/restricted",
        "endpoint_description": "restricted subscription route"
    });
    let (status, _) =
        authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let restricted_request = || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/rest/{api_name}/{api_version}/restricted"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let response = app.clone().oneshot(restricted_request()).await.unwrap();
    assert!(matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));

    let subscription =
        json!({"api_name": api_name, "api_version": api_version, "username": "admin"});
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription.clone(),
    )
    .await;
    assert!(status.is_success());

    let response = app.clone().oneshot(restricted_request()).await.unwrap();
    assert!(!matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));

    let (status, body) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        "/platform/subscription/subscriptions",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let apis = body["apis"].as_array().unwrap();
    let expected = Value::String(format!("{api_name}/{api_version}"));
    assert!(apis.iter().any(|api| api == &expected));

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/unsubscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let response = app.clone().oneshot(restricted_request()).await.unwrap();
    assert!(matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/{api_version}"),
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_31_endpoint_update_list_delete_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "endpoint-crud-31";
    let api_version = "v1";

    let api = json!({"api_name": api_name, "api_version": api_version, "api_description": "endpoint CRUD", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "active": true});
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({"api_name": api_name, "api_version": api_version, "endpoint_method": "GET", "endpoint_uri": "/z", "endpoint_description": "z"});
    let (status, _) =
        authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    // Keep multiple protocol methods on the same API discoverable through the
    // endpoint collection, as required by the Python onboarding contract.
    for (method, uri) in [("POST", "/b"), ("PUT", "/c")] {
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": method,
                "endpoint_uri": uri,
                "endpoint_description": format!("{method} {uri}"),
            }),
        )
        .await;
        assert!(status.is_success());
    }

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::PUT,
        &format!("/platform/endpoint/GET/{api_name}/{api_version}/z"),
        json!({"endpoint_description": "zzz"}),
    )
    .await;
    assert!(status.is_success());

    let (status, body) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/platform/endpoint/{api_name}/{api_version}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let endpoints = body
        .as_array()
        .or_else(|| body.get("endpoints").and_then(Value::as_array))
        .or_else(|| {
            body.pointer("/response/endpoints")
                .and_then(Value::as_array)
        })
        .or_else(|| body.get("response").and_then(Value::as_array))
        .expect("endpoint list response must be an array");
    assert!(
        endpoints
            .iter()
            .any(|endpoint| endpoint["endpoint_description"] == "zzz")
    );
    assert!(
        endpoints.len() >= 3
            && endpoints.iter().any(|endpoint| {
                endpoint["endpoint_method"] == "POST" && endpoint["endpoint_uri"] == "/b"
            })
            && endpoints.iter().any(|endpoint| {
                endpoint["endpoint_method"] == "PUT" && endpoint["endpoint_uri"] == "/c"
            }),
        "unexpected endpoint list response: {body}"
    );

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/endpoint/GET/{api_name}/{api_version}/z"),
    )
    .await;
    assert!(status.is_success());

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/api/rest/{api_name}/{api_version}/z"),
    )
    .await;
    assert!(status.is_client_error() || status.is_server_error());

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/{api_version}"),
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_30_credits_and_header_injection_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "credit-gateway-30";
    let credit_group = "credit-group-30";
    let group_key = "DUMMY_API_KEY_ABC";

    let setup = CreditGatewaySetup {
        api_name,
        credit_group,
        group_key,
        user_key: None,
        upstream_url: &upstream_url,
        endpoint_method: Method::POST,
        endpoint_uri: "/echo",
        available_credits: 2,
    };
    configure_credit_gateway(&app, &token, &setup).await;

    let (status, body) = authed_json_response(
        &app,
        &token,
        Method::POST,
        &format!("/api/rest/{api_name}/v1/echo"),
        json!({"ping": "pong"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["x_api_key"], group_key);

    let (status, credits) =
        authed_empty_response(&app, &token, Method::GET, "/platform/credit/admin").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        credits["users_credits"][credit_group]["available_credits"],
        1
    );

    upstream.abort();
    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/endpoint/POST/{api_name}/v1/echo"),
    )
    .await;
    assert!(status.is_success());
    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/v1"),
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_32_user_credit_key_override_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "credit-override-32";
    let credit_group = "credit-group-32";
    let group_key = "GROUP_KEY_ABC";
    let user_key = "USER_KEY_DEF";

    let setup = CreditGatewaySetup {
        api_name,
        credit_group,
        group_key,
        user_key: Some(user_key),
        upstream_url: &upstream_url,
        endpoint_method: Method::GET,
        endpoint_uri: "/whoami",
        available_credits: 3,
    };
    configure_credit_gateway(&app, &token, &setup).await;

    let (status, body) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/api/rest/{api_name}/v1/whoami"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["x_api_key"], user_key);
    upstream.abort();
    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/endpoint/GET/{api_name}/v1/whoami"),
    )
    .await;
    assert!(status.is_success());
    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/v1"),
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_33_rate_limiting_blocks_excess_requests_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;

    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "rl-test-api";
    let api_version = "v1";

    // Set user rate limit: 1 request / 60 seconds
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/platform/user/admin")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "rate_limit_duration": 1,
                        "rate_limit_duration_type": "second",
                        "throttle_duration": 999,
                        "throttle_duration_type": "second",
                        "throttle_queue_limit": 999,
                        "throttle_wait_duration": 0,
                        "throttle_wait_duration_type": "second"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Clear caches: DELETE /api/caches
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/caches")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Create API & endpoint
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "api_description": "rl test",
                        "api_allowed_roles": ["admin"],
                        "api_allowed_groups": ["ALL"],
                        "api_servers": [upstream_url],
                        "api_type": "REST",
                        "active": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/endpoint")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "endpoint_method": "GET",
                        "endpoint_uri": "/hit",
                        "endpoint_description": "hit"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/subscription/subscribe")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "username": "admin"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    wait_for_stable_rate_second().await;
    // First request -> processed by gateway evaluation
    let response1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/rest/{api_name}/{api_version}/hit"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Second immediate request -> rate limit exceeded (429 or 502 upstream unreachable)
    let response2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/rest/{api_name}/{api_version}/hit"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response1.status(), StatusCode::OK);
    assert_eq!(response2.status(), StatusCode::TOO_MANY_REQUESTS);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/api/rest/{api_name}/{api_version}/hit"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    upstream.abort();
}

async fn configure_tier_rate_gateway(
    app: &axum::Router,
    token: &str,
    api_name: &str,
    tier_id: &str,
    requests_per_minute: u64,
    upstream_url: &str,
) {
    // Match the Python fixture: the per-user limit must not mask the tier limit.
    let (status, _) = authed_json_response(
        app,
        token,
        Method::PUT,
        "/platform/user/admin",
        json!({
            "rate_limit_duration": 1_000_000,
            "rate_limit_duration_type": "second",
            "throttle_duration": 0,
            "throttle_duration_type": "second",
            "throttle_queue_limit": 0,
            "throttle_wait_duration": 0,
            "throttle_wait_duration_type": "second"
        }),
    )
    .await;
    assert!(status.is_success());

    let api = json!({
        "api_name": api_name,
        "api_version": "v1",
        "api_description": "tier rate-limit parity",
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": [upstream_url],
        "api_type": "REST",
        "active": true
    });
    let (status, _) = authed_json_response(app, token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": "v1",
        "endpoint_method": "GET",
        "endpoint_uri": "/hit",
        "endpoint_description": "tier rate-limit endpoint"
    });
    let (status, _) =
        authed_json_response(app, token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription = json!({"api_name": api_name, "api_version": "v1", "username": "admin"});
    let (status, _) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let tier = json!({
        "tier_id": tier_id,
        "name": "custom",
        "display_name": tier_id,
        "description": "tier rate-limit parity",
        "limits": {
            "requests_per_minute": requests_per_minute,
            "enable_throttling": false,
            "max_queue_time_ms": 0
        },
        "price_monthly": 0.0,
        "features": [],
        "is_default": false,
        "enabled": true
    });
    let (status, _) =
        authed_json_response(app, token, Method::POST, "/platform/tiers/", tier).await;
    assert!(status.is_success());

    let assignment = json!({"user_id": "admin", "tier_id": tier_id});
    let (status, _) = authed_json_response(
        app,
        token,
        Method::POST,
        "/platform/tiers/assignments",
        assignment,
    )
    .await;
    assert!(status.is_success());

    let (status, _) = authed_empty_response(app, token, Method::DELETE, "/api/caches").await;
    assert!(status.is_success());
}

async fn tier_gateway_request(app: &axum::Router, token: &str, api_name: &str) -> StatusCode {
    let (status, _) = authed_empty_response(
        app,
        token,
        Method::GET,
        &format!("/api/rest/{api_name}/v1/hit"),
    )
    .await;
    status
}

async fn wait_for_stable_tier_minute() {
    let second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 60;
    if second >= 55 {
        tokio::time::sleep(Duration::from_secs(61 - second)).await;
    }
}

async fn wait_for_stable_rate_second() {
    let remainder = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        % 1_000;
    // The two immediate requests below must use the same fixed one-second
    // window. Start early in a fresh window when the current one is nearly over.
    if remainder >= 400 {
        tokio::time::sleep(Duration::from_millis((1_000 - remainder + 25) as u64)).await;
    }
}

#[tokio::test]
async fn live_test_34_tier_rate_limiting_strict_local_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    configure_tier_rate_gateway(
        &app,
        &token,
        "tier-rate-strict-34",
        "tier-rate-strict-34",
        1,
        &upstream_url,
    )
    .await;

    wait_for_stable_tier_minute().await;
    assert_eq!(
        tier_gateway_request(&app, &token, "tier-rate-strict-34").await,
        StatusCode::OK
    );
    assert_eq!(
        tier_gateway_request(&app, &token, "tier-rate-strict-34").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    upstream.abort();
}

#[tokio::test]
async fn live_test_34_tier_vs_user_limits_priority_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    configure_tier_rate_gateway(
        &app,
        &token,
        "tier-rate-priority-34",
        "tier-rate-priority-34",
        1,
        &upstream_url,
    )
    .await;

    wait_for_stable_tier_minute().await;
    // The helper sets a 1,000,000-request user limit; the tier must win at one request.
    assert_eq!(
        tier_gateway_request(&app, &token, "tier-rate-priority-34").await,
        StatusCode::OK
    );
    assert_eq!(
        tier_gateway_request(&app, &token, "tier-rate-priority-34").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    upstream.abort();
}

#[tokio::test]
async fn live_test_34_tier_concurrent_requests_enforced_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    configure_tier_rate_gateway(
        &app,
        &token,
        "tier-rate-sequential-34",
        "tier-rate-sequential-34",
        2,
        &upstream_url,
    )
    .await;

    // Keep the pinned three-request/two-RPM batch inside one fixed minute. Without
    // this guard, a run beginning at :59 can split 2+1 across adjacent windows
    // and intermittently observe three successful requests.
    let second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 60;
    if second >= 55 {
        tokio::time::sleep(Duration::from_secs(61 - second)).await;
    }

    let results = [
        tier_gateway_request(&app, &token, "tier-rate-sequential-34").await,
        tier_gateway_request(&app, &token, "tier-rate-sequential-34").await,
        tier_gateway_request(&app, &token, "tier-rate-sequential-34").await,
    ];
    let successes = results
        .iter()
        .filter(|status| **status == StatusCode::OK)
        .count();
    let blocked = results
        .iter()
        .filter(|status| **status == StatusCode::TOO_MANY_REQUESTS)
        .count();
    // Preserve the Python assertion: at least one request makes it through and one is blocked.
    assert!(
        successes >= 1,
        "expected at least one success, got {successes}"
    );
    assert!(
        blocked >= 1,
        "expected at least one rate-limit response, got {blocked}"
    );
    upstream.abort();
}

#[tokio::test]
async fn live_test_45_soap_cors_preflight_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "soap-preflight-45";
    let api_version = "v1";

    let api = json!({"api_name": api_name, "api_version": api_version, "api_description": "SOAP preflight", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"], "api_type": "SOAP", "active": true, "api_cors_allow_origins": ["http://example.com"], "api_cors_allow_methods": ["POST"], "api_cors_allow_headers": ["Content-Type"]});
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());
    let endpoint = json!({"api_name": api_name, "api_version": api_version, "endpoint_method": "POST", "endpoint_uri": "/soap", "endpoint_description": "SOAP preflight endpoint"});
    let (status, _) =
        authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());
    let subscription =
        json!({"api_name": api_name, "api_version": api_version, "username": "admin"});
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(format!("/api/soap/{api_name}/{api_version}/soap"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("origin", "http://example.com")
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "Content-Type")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::NO_CONTENT
    ));

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/{api_version}"),
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_46_nonexistent_endpoint_gateway_error_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "gateway-error-46";
    let api_version = "v1";

    let api = json!({"api_name": api_name, "api_version": api_version, "api_description": "missing endpoint", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "active": true});
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());
    let subscription =
        json!({"api_name": api_name, "api_version": api_version, "username": "admin"});
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let (status, body) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/api/rest/{api_name}/{api_version}/nope"),
    )
    .await;
    assert!(matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST | StatusCode::INTERNAL_SERVER_ERROR
    ));
    let code = body
        .get("error_code")
        .or_else(|| body.pointer("/response/error_code"))
        .and_then(Value::as_str);
    assert!(matches!(
        code,
        Some("GTW003" | "GTW001" | "GTW002" | "GTW006")
    ));

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/{api_version}"),
    )
    .await;
    assert!(status.is_success());
}

#[tokio::test]
async fn live_test_41_soap_and_85_endpoint_validation_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;

    let api_name = "soapval-test";
    let api_version = "v1";

    // Create API
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "api_description": "soap val",
                        "api_allowed_roles": ["admin"],
                        "api_allowed_groups": ["ALL"],
                        "api_servers": ["http://127.0.0.1:9999"],
                        "api_type": "SOAP",
                        "active": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Create Endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/endpoint")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "api_name": api_name,
                        "api_version": api_version,
                        "endpoint_method": "POST",
                        "endpoint_uri": "/add",
                        "endpoint_description": "soap add"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
    )
    .await;
    assert!(status.is_success());

    // Enable validation on endpoint via /platform/endpoint/endpoint/validation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/platform/endpoint/POST/{api_name}/{api_version}/add"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let ep: Value = serde_json::from_slice(&bytes).unwrap();
    let endpoint_id = ep["endpoint_id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/endpoint/endpoint/validation")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "endpoint_id": endpoint_id,
                        "validation_enabled": true,
                        "validation_schema": {
                            "intA": {
                                "required": true,
                                "type": "string",
                                "min": 2
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

    // Send invalid XML (<intA>1</intA> length 1 < min 2) -> 400 Bad Request
    let xml_invalid = r#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Add><intA>1</intA></Add></soap:Body></soap:Envelope>"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/soap/{api_name}/{api_version}/add"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml_invalid))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn live_test_90_security_tools_and_config_export_import_parity() {
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login_admin(&app).await;

    // GET /platform/security/settings
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/security/settings")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // POST /platform/tools/cors/check
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/tools/cors/check")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"origin": "http://localhost:3000", "method": "GET"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // GET /platform/config/export/all
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/config/export/all")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let config_export: Value = serde_json::from_slice(&bytes).unwrap();

    // POST /platform/config/import
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/config/import")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(config_export.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let config_import: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert!(config_import["imported"].is_object());
}

async fn public_gateway_status(
    app: &axum::Router,
    method: Method,
    uri: impl AsRef<str>,
    content_type: Option<&str>,
    body: Body,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri.as_ref())
        .header("x-test", "1");
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn live_test_93_public_and_auth_optional_allow_unauthenticated() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    for (api_name, endpoint_uri, api_public, api_auth_required) in [
        ("public-auth-93", "/status", true, true),
        ("optional-auth-93", "/ping", false, false),
    ] {
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/api",
            json!({
                "api_name": api_name,
                "api_version": "v1",
                "api_description": "authentication mode parity",
                "api_allowed_roles": [],
                "api_allowed_groups": [],
                "api_servers": [&upstream_url],
                "api_type": "REST",
                "active": true,
                "api_public": api_public,
                "api_auth_required": api_auth_required
            }),
        )
        .await;
        assert!(status.is_success());

        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": "v1",
                "endpoint_method": "GET",
                "endpoint_uri": endpoint_uri,
                "endpoint_description": endpoint_uri
            }),
        )
        .await;
        assert!(status.is_success());

        for _ in 0..2 {
            let status = public_gateway_status(
                &app,
                Method::GET,
                format!("/api/rest/{api_name}/v1{endpoint_uri}?a=1&b=two"),
                None,
                Body::empty(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    upstream.abort();
}

#[tokio::test]
async fn live_test_35_bulk_public_rest_crud_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;

    for index in 0..3 {
        let api_name = format!("bulk-public-rest-35-{index}");
        let api = json!({"api_name": api_name, "api_version": "v1", "api_description": "public REST bulk parity", "api_allowed_roles": [], "api_allowed_groups": ["ALL"], "api_servers": [&upstream_url], "api_type": "SOAP", "active": true, "api_public": true});
        let (status, _) =
            authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
        assert!(status.is_success());

        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let endpoint = json!({"api_name": api_name, "api_version": "v1", "endpoint_method": method.as_str(), "endpoint_uri": "/items", "endpoint_description": format!("{method} /items")});
            let (status, _) =
                authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint)
                    .await;
            assert!(status.is_success());
        }

        // Public APIs remain callable without credentials even after the administrator
        // has been subscribed, matching the public-API subscription matrix contract.
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/subscription/subscribe",
            json!({"api_name": api_name, "api_version": "v1", "username": "admin"}),
        )
        .await;
        assert!(status.is_success());

        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let body = if matches!(method, Method::POST | Method::PUT) {
                Body::from(json!({"name": "x"}).to_string())
            } else {
                Body::empty()
            };
            let status = public_gateway_status(
                &app,
                method,
                format!("/api/rest/{api_name}/v1/items"),
                Some("application/json"),
                body,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
    }
    upstream.abort();
}

async fn bulk_soap_echo() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/xml; charset=utf-8")
        .body(Body::from(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Ok/></soap:Body></soap:Envelope>",
        ))
        .unwrap()
}

async fn start_bulk_soap_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/create", any(bulk_soap_echo))
                .route("/read", any(bulk_soap_echo))
                .route("/update", any(bulk_soap_echo))
                .route("/delete", any(bulk_soap_echo))
                .route("/soap", any(bulk_soap_echo)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

async fn soap_retry_upstream(State(attempts): State<Arc<AtomicUsize>>) -> Response {
    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "text/xml")
            .body(Body::from("<fault/>"))
            .unwrap();
    }
    bulk_soap_echo().await
}

async fn start_soap_retry_upstream() -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let server_attempts = attempts.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/soap", post(soap_retry_upstream))
                .with_state(server_attempts),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), attempts, server)
}

async fn graphql_hello(Json(payload): Json<Value>) -> Json<Value> {
    assert_eq!(payload["query"], "{ hello(name:\"Doorman\") }");
    Json(json!({"data": {"hello": "Hello, Doorman!"}}))
}

async fn start_graphql_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", axum::routing::post(graphql_hello)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

async fn graphql_public_crud_upstream(Json(_payload): Json<Value>) -> Json<Value> {
    Json(json!({"data": {"ok": true}}))
}

async fn start_graphql_public_crud_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/graphql",
                axum::routing::post(graphql_public_crud_upstream),
            ),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

// Python: backend-services/live-tests/test_35_public_bulk_onboarding.py::test_bulk_public_graphql_crud
#[tokio::test]
async fn live_test_35_bulk_public_graphql_crud_parity() {
    let (upstream_url, upstream) = start_graphql_public_crud_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;

    for index in 0..3 {
        let api_name = format!("bulk-public-graphql-35-{index}");
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/api",
            json!({
                "api_name": api_name,
                "api_version": "v1",
                "api_description": "public GraphQL bulk parity",
                "api_allowed_roles": [],
                "api_allowed_groups": [],
                "api_servers": [&upstream_url],
                "api_type": "GRAPHQL",
                "api_public": true,
                "active": true,
            }),
        )
        .await;
        assert!(status.is_success());
        let (status, _) = authed_json_response(
            &app,
            &token,
            Method::POST,
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": "v1",
                "endpoint_method": "POST",
                "endpoint_uri": "/graphql",
                "endpoint_description": "public GraphQL endpoint",
            }),
        )
        .await;
        assert!(status.is_success());

        for query in [
            "mutation { create(name: \"A\") }",
            "mutation { update(id: 1, name: \"B\") }",
            "{ read(id: 1) }",
            "mutation { delete(id: 1) }",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("/api/graphql/{api_name}"))
                        .header("x-api-version", "v1")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(json!({"query": query}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{query}");
        }
    }
    upstream.abort();
}

async fn graphql_variable_hello(Json(payload): Json<Value>) -> Json<Value> {
    assert_eq!(
        payload["query"],
        "query HelloOp($x: String!) { hello(name: $x) }"
    );
    let name = payload["variables"]["x"].as_str().unwrap();
    Json(json!({"data": {"hello": format!("Hello, {name}!")}}))
}

async fn start_graphql_validation_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", axum::routing::post(graphql_variable_hello)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

async fn graphql_error_upstream() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"errors": [{"message": "upstream boom", "status": 500}]}).to_string(),
        ))
        .unwrap()
}

async fn start_graphql_error_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", post(graphql_error_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}"), server)
}

async fn grpc_hello_upstream(request: axum::extract::Request) -> Response {
    assert_eq!(request.version(), http::Version::HTTP_2);
    let body = to_bytes(request.into_body(), 1024).await.unwrap();
    assert!(body.len() >= 5, "gRPC request must contain a data frame");
    assert_eq!(body[0], 0, "compressed gRPC requests are not expected");
    let length = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert_eq!(body.len(), length + 5);
    let message = &body[5..];
    assert_eq!(message[0], 0x0a, "HelloRequest.name field");
    assert_eq!(message[1] as usize, "Doorman".len());
    assert_eq!(&message[2..], b"Doorman");

    let reply = b"Hello, Doorman!";
    let mut framed = vec![0, 0, 0, 0, (reply.len() + 2) as u8, 0x0a, reply.len() as u8];
    framed.extend_from_slice(reply);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "0")
        .body(Body::from(framed))
        .unwrap()
}

async fn start_grpc_hello_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/grpcdemo_v1.Greeter/Hello", post(grpc_hello_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("grpc://{address}"), server)
}

async fn grpc_metadata_upstream(request: axum::extract::Request) -> Response {
    assert_eq!(
        request
            .headers()
            .get("x-meta-one")
            .and_then(|value| value.to_str().ok()),
        Some("alpha")
    );
    assert!(
        request.headers().contains_key("grpc-timeout"),
        "gRPC deadline must be forwarded as grpc-timeout"
    );
    grpc_hello_upstream(request).await
}

async fn start_grpc_metadata_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/grpcmeta_v1.Greeter/Hello", post(grpc_metadata_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("grpc://{address}"), server)
}

async fn grpc_status_upstream(request: axum::extract::Request) -> Response {
    assert_eq!(request.version(), http::Version::HTTP_2);
    let grpc_status = request
        .headers()
        .get("x-test-grpc-status")
        .and_then(|value| value.to_str().ok())
        .expect("allowlisted test status metadata")
        .parse::<u16>()
        .unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", grpc_status.to_string())
        .header("grpc-message", "pinned%20upstream%20status")
        .body(Body::empty())
        .unwrap()
}

async fn start_grpc_status_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/grpcstatus_v1.Greeter/Hello", post(grpc_status_upstream)),
        )
        .await
        .unwrap();
    });
    (format!("grpc://{address}"), server)
}

async fn grpc_server_stream_upstream(request: axum::extract::Request) -> Response {
    assert_eq!(request.version(), http::Version::HTTP_2);
    let body = to_bytes(request.into_body(), 1024).await.unwrap();
    assert_eq!(&body[5..], b"\x0a\x07Doorman");
    let mut framed = Vec::new();
    for reply in [b"\x0a\x03one".as_slice(), b"\x0a\x03two".as_slice()] {
        framed.extend_from_slice(&[0, 0, 0, 0, reply.len() as u8]);
        framed.extend_from_slice(reply);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "0")
        .body(Body::from(framed))
        .unwrap()
}

async fn start_grpc_server_stream_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/grpcstream_v1.Greeter/Watch",
                post(grpc_server_stream_upstream),
            ),
        )
        .await
        .unwrap();
    });
    (format!("grpc://{address}"), server)
}

async fn grpc_stream_modes_upstream(request: axum::extract::Request) -> Response {
    assert_eq!(request.version(), http::Version::HTTP_2);
    let path = request.uri().path().to_owned();
    let body = to_bytes(request.into_body(), 1024).await.unwrap();
    let mut values = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        assert_eq!(body[offset], 0, "compressed gRPC requests are not expected");
        let length = u32::from_be_bytes(body[offset + 1..offset + 5].try_into().unwrap()) as usize;
        let payload = &body[offset + 5..offset + 5 + length];
        assert_eq!(payload.len(), 2);
        assert_eq!(payload[0], 0x08, "Number.val field");
        values.push(payload[1]);
        offset += 5 + length;
    }

    let replies: Vec<Vec<u8>> = match path.as_str() {
        "/grpcmodes_v1.Streams/Sum" => {
            assert_eq!(values, vec![1, 2, 3]);
            vec![vec![
                0x08,
                values.iter().map(|value| *value as u16).sum::<u16>() as u8,
            ]]
        }
        "/grpcmodes_v1.Streams/Echo" => {
            assert_eq!(values, vec![7, 8]);
            values.into_iter().map(|value| vec![0x08, value]).collect()
        }
        unexpected => panic!("unexpected streaming gRPC path: {unexpected}"),
    };
    let mut framed = Vec::new();
    for reply in replies {
        framed.extend_from_slice(&[0, 0, 0, 0, reply.len() as u8]);
        framed.extend_from_slice(&reply);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "0")
        .body(Body::from(framed))
        .unwrap()
}

async fn start_grpc_stream_modes_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/grpcmodes_v1.Streams/Sum",
                    post(grpc_stream_modes_upstream),
                )
                .route(
                    "/grpcmodes_v1.Streams/Echo",
                    post(grpc_stream_modes_upstream),
                ),
        )
        .await
        .unwrap();
    });
    (format!("grpc://{address}"), server)
}

async fn grpc_resource_upstream(request: axum::extract::Request) -> Response {
    assert_eq!(request.version(), http::Version::HTTP_2);
    let path = request.uri().path().to_owned();
    let body = to_bytes(request.into_body(), 1024).await.unwrap();
    assert!(body.len() >= 5, "gRPC request must contain a data frame");
    assert_eq!(body[0], 0, "compressed gRPC requests are not expected");
    let length = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert_eq!(body.len(), length + 5);
    let message = &body[5..];

    let reply = match path.as_str() {
        "/grpcpublic_v1.Resource/Create" => {
            assert_eq!(message, b"\x0a\x01A");
            b"\x0a\x09created A".to_vec()
        }
        "/grpcpublic_v1.Resource/Read" => {
            assert_eq!(message, b"\x08\x01");
            b"\x0a\x06read 1".to_vec()
        }
        "/grpcpublic_v1.Resource/Update" => {
            assert_eq!(message, b"\x08\x01\x12\x01B");
            b"\x0a\x0bupdated 1:B".to_vec()
        }
        "/grpcpublic_v1.Resource/Delete" => {
            assert_eq!(message, b"\x08\x01");
            b"\x08\x01".to_vec()
        }
        unexpected => panic!("unexpected gRPC resource path: {unexpected}"),
    };
    let mut framed = vec![0, 0, 0, 0, reply.len() as u8];
    framed.extend_from_slice(&reply);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "0")
        .body(Body::from(framed))
        .unwrap()
}

async fn start_grpc_resource_upstream() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/grpcpublic_v1.Resource/Create",
                    post(grpc_resource_upstream),
                )
                .route("/grpcpublic_v1.Resource/Read", post(grpc_resource_upstream))
                .route(
                    "/grpcpublic_v1.Resource/Update",
                    post(grpc_resource_upstream),
                )
                .route(
                    "/grpcpublic_v1.Resource/Delete",
                    post(grpc_resource_upstream),
                ),
        )
        .await
        .unwrap();
    });
    (format!("grpc://{address}"), server)
}

#[tokio::test]
async fn live_test_36_public_grpc_with_proto_upload_parity() {
    let (upstream_url, upstream) = start_grpc_resource_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcpublic";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcpublic_v1;
service Resource {
  rpc Create (CreateRequest) returns (CreateReply) {}
  rpc Read (ReadRequest) returns (ReadReply) {}
  rpc Update (UpdateRequest) returns (UpdateReply) {}
  rpc Delete (DeleteRequest) returns (DeleteReply) {}
}
message CreateRequest { string name = 1; }
message CreateReply { string message = 1; }
message ReadRequest { int32 id = 1; }
message ReadReply { string message = 1; }
message UpdateRequest { int32 id = 1; string name = 2; }
message UpdateReply { string message = 1; }
message DeleteRequest { int32 id = 1; }
message DeleteReply { bool ok = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "public gRPC with uploaded proto",
            "api_allowed_roles": [],
            "api_allowed_groups": [],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_allowed_retry_count": 0,
            "api_public": true,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    let fetched = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched = to_bytes(fetched.into_body(), 64 * 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&fetched)
            .unwrap()
            .contains("package grpcpublic_v1")
    );

    let (status, api) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/platform/api/{api_name}/{api_version}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(api["api_grpc_package"], "grpcpublic_v1");

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/endpoint",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "endpoint_method": "POST",
            "endpoint_uri": "/grpc",
            "endpoint_description": "public gRPC endpoint"
        }),
    )
    .await;
    assert!(status.is_success());

    let public_preflight = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(format!("/api/grpc/{api_name}"))
                .header("x-api-version", api_version)
                .header(header::ORIGIN, "https://example.test")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public_preflight.status(), StatusCode::NO_CONTENT);

    for (request, expected) in [
        (
            json!({"method": "Resource.Create", "message": {"name": "A"}}),
            json!({"message": "created A"}),
        ),
        (
            json!({"method": "Resource.Read", "message": {"id": 1}}),
            json!({"message": "read 1"}),
        ),
        (
            json!({"method": "Resource.Update", "message": {"id": 1, "name": "B"}}),
            json!({"message": "updated 1:B"}),
        ),
        (
            json!({"method": "Resource.Delete", "message": {"id": 1}}),
            json!({"ok": true}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/grpc/{api_name}"))
                    .header("x-api-version", api_version)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected);
    }
    upstream.abort();
}

#[tokio::test]
async fn grpc_gateway_forwards_allowlisted_metadata_and_deadline() {
    let (upstream_url, upstream) = start_grpc_metadata_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcmeta";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcmeta_v1;
service Greeter { rpc Hello (HelloRequest) returns (HelloReply) {} }
message HelloRequest { string name = 1; }
message HelloReply { string message = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC metadata and deadline",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_allowed_headers": ["X-Meta-One"],
            "api_read_timeout": 2,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    // Match the Python good-payload contract: endpoint validation must allow a
    // valid gRPC message to reach and complete at the actual upstream.
    let (status, endpoint) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/platform/endpoint/POST/{api_name}/{api_version}/grpc"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let endpoint_id = endpoint["endpoint_id"].as_str().unwrap();
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/endpoint/endpoint/validation",
        json!({
            "endpoint_id": endpoint_id,
            "validation_enabled": true,
            "validation_schema": {
                "validation_schema": {
                    "name": {"required": true, "type": "string", "min": 2}
                }
            }
        }),
    )
    .await;
    assert!(status.is_success());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/grpc/{api_name}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-api-version", api_version)
                .header("x-meta-one", "alpha")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"method": "Greeter.Hello", "message": {"name": "Doorman"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"message": "Hello, Doorman!"}));
    upstream.abort();
}

#[tokio::test]
async fn grpc_gateway_maps_upstream_statuses_parity() {
    let (upstream_url, upstream) = start_grpc_status_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcstatus";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcstatus_v1;
service Greeter { rpc Hello (HelloRequest) returns (HelloReply) {} }
message HelloRequest { string name = 1; }
message HelloReply { string message = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC status mappings",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_allowed_headers": ["X-Test-Grpc-Status"],
            "api_allowed_retry_count": 0,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    // The policy gate must reject an authenticated caller before attempting the
    // JSON-to-gRPC invocation when that caller has not subscribed to this API.
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/user",
        json!({
            "username": "grpc-unsubscribed",
            "email": "grpc-unsubscribed@example.com",
            "password": "GrpcUnsubscribedPassword123!",
            "role": "admin",
            "groups": ["ALL"],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let unsubscribed_token = {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/platform/authorization")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "email": "grpc-unsubscribed@example.com",
                            "password": "GrpcUnsubscribedPassword123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response_json(response).await.1["access_token"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/grpc/{api_name}"))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {unsubscribed_token}"),
                )
                .header("x-api-version", api_version)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"method": "Greeter.Hello", "message": {}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["error_code"],
        "You are not subscribed to this resource"
    );

    let (_, metrics_before) =
        authed_empty_response(&app, &token, Method::GET, "/platform/monitor/metrics").await;
    let grpc_request_bytes = json!({"method": "Greeter.Hello", "message": {"name": "Doorman"}})
        .to_string()
        .len() as u64;

    for (grpc_status, expected_status) in [
        ("2", StatusCode::INTERNAL_SERVER_ERROR),
        ("3", StatusCode::BAD_REQUEST),
        ("4", StatusCode::GATEWAY_TIMEOUT),
        ("16", StatusCode::UNAUTHORIZED),
        ("7", StatusCode::FORBIDDEN),
        ("5", StatusCode::NOT_FOUND),
        ("8", StatusCode::TOO_MANY_REQUESTS),
        ("12", StatusCode::NOT_IMPLEMENTED),
        ("14", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/grpc/{api_name}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header("x-api-version", api_version)
                    .header("x-test-grpc-status", grpc_status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"method": "Greeter.Hello", "message": {"name": "Doorman"}})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = response_json(response).await;
        assert_eq!(status, expected_status, "gRPC status {grpc_status}");
        assert_eq!(body["error_code"], "GTW006");
    }
    let (_, metrics_after) =
        authed_empty_response(&app, &token, Method::GET, "/platform/monitor/metrics").await;
    assert!(
        metrics_after["total_bytes_in"].as_u64().unwrap_or(0)
            >= metrics_before["total_bytes_in"].as_u64().unwrap_or(0) + grpc_request_bytes * 9
    );
    assert!(
        metrics_after["total_bytes_out"].as_u64().unwrap_or(0)
            > metrics_before["total_bytes_out"].as_u64().unwrap_or(0)
    );
    upstream.abort();
}

#[tokio::test]
async fn grpc_gateway_server_streaming_parity() {
    let (upstream_url, upstream) = start_grpc_server_stream_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcstream";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcstream_v1;
service Greeter { rpc Watch (WatchRequest) returns (stream WatchReply) {} }
message WatchRequest { string name = 1; }
message WatchReply { string message = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC server streaming",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_allowed_retry_count": 0,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/grpc/{api_name}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-api-version", api_version)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "method": "Greeter.Watch",
                        "message": {"name": "Doorman"},
                        "stream": "server",
                        "max_items": 2
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"items": [{"message": "one"}, {"message": "two"}]})
    );
    upstream.abort();
}

#[tokio::test]
async fn grpc_gateway_client_and_bidi_streaming_parity() {
    let (upstream_url, upstream) = start_grpc_stream_modes_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcmodes";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcmodes_v1;
service Streams {
  rpc Sum (stream Number) returns (SumReply) {}
  rpc Echo (stream Number) returns (stream Number) {}
}
message Number { int32 val = 1; }
message SumReply { int32 sum = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC client and bidi streaming",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_allowed_retry_count": 0,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    for (request, expected) in [
        (
            json!({
                "method": "Streams.Sum",
                "message": {},
                "stream": "client",
                "messages": [{"val": 1}, {"val": 2}, {"val": 3}]
            }),
            json!({"sum": 6}),
        ),
        (
            json!({
                "method": "Streams.Echo",
                "message": {},
                "stream": "bidi",
                "messages": [{"val": 7}, {"val": 8}],
                "max_items": 10
            }),
            json!({"items": [{"val": 7}, {"val": 8}]}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/grpc/{api_name}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header("x-api-version", api_version)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, body) = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected);
    }
    upstream.abort();
}

#[tokio::test]
async fn live_test_grpc_reflection_no_proto_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpc-reflection";
    let api_version = "v1";

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC reflection fallback",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": ["grpc://127.0.0.1:9"],
            "api_type": "GRPC",
            "api_allowed_retry_count": 0,
            "api_grpc_package": "grpcbin",
            "api_public": true,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/endpoint",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "endpoint_method": "POST",
            "endpoint_uri": "/grpc",
            "endpoint_description": "gRPC reflection endpoint"
        }),
    )
    .await;
    assert!(status.is_success());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/grpc/{api_name}"))
                .header("x-api-version", api_version)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"method": "GRPCBin.Empty", "message": {}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error_code"], "GTW012");
}

#[tokio::test]
async fn live_test_59_grpc_invalid_method_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcbad";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcbad_v1;
service Greeter {}
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC invalid method",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": ["grpc://127.0.0.1:9"],
            "api_type": "GRPC",
            "api_allowed_retry_count": 0,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    let (status, body) = authed_json_response(
        &app,
        &token,
        Method::POST,
        format!("/api/grpc/{api_name}"),
        json!({"method": "Nope.Do", "message": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error_code"], "GTW006");
}

#[tokio::test]
async fn live_test_60_grpc_gateway_basic_flow_parity() {
    let (upstream_url, upstream) = start_grpc_hello_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcdemo";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcdemo_v1;
service Greeter { rpc Hello (HelloRequest) returns (HelloReply) {} }
message HelloRequest { string name = 1; }
message HelloReply { string message = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC demo",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_allowed_retry_count": 0,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/grpc/{api_name}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-api-version", api_version)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"method": "Greeter.Hello", "message": {"name": "Doorman"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"message": "Hello, Doorman!"}));
    upstream.abort();
}

#[tokio::test]
async fn grpc_web_unary_cors_and_streaming_policy_parity() {
    let (upstream_url, upstream) = start_grpc_hello_upstream().await;
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let api_name = "grpcweb";
    let api_version = "v1";
    let proto = r#"
syntax = "proto3";
package grpcdemo_v1;
service Greeter { rpc Hello (HelloRequest) returns (HelloReply) {} }
service Streams { rpc Sum (stream Number) returns (SumReply) {} }
message HelloRequest { string name = 1; }
message HelloReply { string message = 1; }
message Number { int32 val = 1; }
message SumReply { int32 sum = 1; }
"#;

    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "gRPC-Web browser gateway",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRPC",
            "api_grpc_web_enabled": true,
            "api_cors_allow_origins": ["https://console.doorman.dev"],
            "api_cors_allow_methods": ["POST"],
            "api_cors_allow_headers": ["Authorization", "Content-Type", "X-Api-Version", "X-Grpc-Web"],
            "api_cors_expose_headers": ["grpc-status", "grpc-message"],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/platform/proto/{api_name}/{api_version}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(proto))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);

    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/grpc",
                "endpoint_description": "gRPC-Web endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }

    let preflight = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(format!("/grpc-web/{api_name}/Greeter/Hello"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ORIGIN, "https://console.doorman.dev")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "Authorization, Content-Type, X-Api-Version, X-Grpc-Web",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://console.doorman.dev"
    );
    assert!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
            .to_str()
            .unwrap()
            .contains("POST")
    );
    assert!(
        preflight.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap()
            .contains("X-Grpc-Web")
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/grpc-web/{api_name}/Greeter/Hello"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-api-version", api_version)
                .header(header::ORIGIN, "https://console.doorman.dev")
                .header(header::CONTENT_TYPE, "application/grpc-web+proto")
                .header("x-grpc-web", "1")
                .body(Body::from(b"\x00\x00\x00\x00\x09\x0a\x07Doorman".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/grpc-web+proto"
    );
    assert_eq!(response.headers()["x-grpc-web"], "1");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://console.doorman.dev"
    );
    assert!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS]
            .to_str()
            .unwrap()
            .contains("grpc-status")
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(body.starts_with(b"\x00\x00\x00\x00\x11\x0a\x0fHello, Doorman!"));
    assert!(body.ends_with(b"grpc-status: 0\r\ngrpc-message: \r\n"));

    let rejected_stream = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/grpc-web/{api_name}/Streams/Sum"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-api-version", api_version)
                .header(header::CONTENT_TYPE, "application/grpc-web+proto")
                .body(Body::from(b"\x00\x00\x00\x00\x00".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected_stream.status(), StatusCode::OK);
    let body = to_bytes(rejected_stream.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body[0], 0x80, "gRPC-Web errors are trailer frames");
    let trailer_length = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert_eq!(body.len(), trailer_length + 5);
    let trailer = std::str::from_utf8(&body[5..]).unwrap();
    assert!(trailer.contains("grpc-status: 12\r\n"));
    assert!(trailer.contains("does not support client or bidirectional streaming"));
    upstream.abort();
}

#[tokio::test]
async fn live_test_35_bulk_public_soap_crud_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_bulk_soap_upstream().await;

    let envelope = "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Op/></soap:Body></soap:Envelope>";

    for index in 0..3 {
        let api_name = format!("bulk-public-soap-35-{index}");
        let api = json!({"api_name": api_name, "api_version": "v1", "api_description": "public SOAP bulk parity", "api_allowed_roles": [], "api_allowed_groups": [], "api_servers": [&upstream_url], "api_type": "REST", "active": true, "api_public": true});
        let (status, _) =
            authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
        assert!(status.is_success());

        for endpoint_uri in ["/create", "/read", "/update", "/delete"] {
            let endpoint = json!({"api_name": api_name, "api_version": "v1", "endpoint_method": "POST", "endpoint_uri": endpoint_uri, "endpoint_description": format!("SOAP {endpoint_uri}")});
            let (status, _) =
                authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint)
                    .await;
            assert!(status.is_success());
        }

        for endpoint_uri in ["create", "read", "update", "delete"] {
            let status = public_gateway_status(
                &app,
                Method::POST,
                format!("/api/soap/{api_name}/v1/{endpoint_uri}"),
                Some("text/xml"),
                Body::from(envelope),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
    }
    upstream.abort();
}

#[tokio::test]
async fn live_test_40_soap_gateway_basic_flow_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_bulk_soap_upstream().await;
    let api_name = "soap-gateway-40";

    let api = json!({"api_name": api_name, "api_version": "v1", "api_description": "SOAP gateway parity", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": [upstream_url], "api_type": "SOAP", "api_allowed_retry_count": 0, "active": true});
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());
    let endpoint = json!({"api_name": api_name, "api_version": "v1", "endpoint_method": "POST", "endpoint_uri": "/soap", "endpoint_description": "SOAP gateway endpoint"});
    let (status, _) =
        authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());
    let subscription = json!({"api_name": api_name, "api_version": "v1", "username": "admin"});
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let envelope = "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Op/></soap:Body></soap:Envelope>";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/soap/{api_name}/v1/soap"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "text/xml")
                .header("soapaction", "urn:local-op")
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/xml")
    );
    let body = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("<Ok/>"));
    upstream.abort();
}

#[tokio::test]
async fn soap_content_types_and_retry_real_upstream_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, attempts, upstream) = start_soap_retry_upstream().await;
    let api_name = "soap-retry-content";
    let api_version = "v1";
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "SOAP content types and retry",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "SOAP",
            "api_allowed_retry_count": 1,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for (path, payload) in [
        (
            "/platform/endpoint",
            json!({
                "api_name": api_name,
                "api_version": api_version,
                "endpoint_method": "POST",
                "endpoint_uri": "/soap",
                "endpoint_description": "SOAP retry endpoint"
            }),
        ),
        (
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": api_name, "api_version": api_version}),
        ),
    ] {
        let (status, _) = authed_json_response(&app, &token, Method::POST, path, payload).await;
        assert!(status.is_success(), "{path}: {status}");
    }
    let envelope = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Ping/></soap:Body></soap:Envelope>";
    for content_type in ["application/xml", "text/xml"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/soap/{api_name}/{api_version}/soap"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(envelope))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{content_type}");
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "503 was retried once");
    upstream.abort();
}

#[tokio::test]
async fn live_test_50_graphql_gateway_basic_flow_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_graphql_upstream().await;
    let api_name = "graphql-gateway-50";
    let api_version = "v1";

    let api = json!({
        "api_name": api_name,
        "api_version": api_version,
        "api_description": "GraphQL demo",
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": [upstream_url],
        "api_type": "GRAPHQL",
        "api_allowed_retry_count": 0,
        "active": true,
    });
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": api_version,
        "endpoint_method": "POST",
        "endpoint_uri": "/graphql",
        "endpoint_description": "graphql",
    });
    let (status, _) =
        authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription =
        json!({"api_name": api_name, "api_version": api_version, "username": "admin"});
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/graphql/{api_name}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-api-version", api_version)
                .body(Body::from(
                    json!({"query": "{ hello(name:\"Doorman\") }"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["hello"], "Hello, Doorman!");

    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/endpoint/POST/{api_name}/{api_version}/graphql"),
    )
    .await;
    assert!(status.is_success());
    let (status, _) = authed_empty_response(
        &app,
        &token,
        Method::DELETE,
        &format!("/platform/api/{api_name}/{api_version}"),
    )
    .await;
    assert!(status.is_success());
    upstream.abort();
}

#[tokio::test]
async fn graphql_public_error_envelope_normalizes_upstream_status_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_graphql_error_upstream().await;
    let api_name = "graphql-error-envelope";
    let api_version = "v1";
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/api",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "api_description": "public GraphQL error envelope",
            "api_allowed_roles": [],
            "api_allowed_groups": ["ALL"],
            "api_servers": [upstream_url],
            "api_type": "GRAPHQL",
            "api_public": true,
            "api_auth_required": false,
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/endpoint",
        json!({
            "api_name": api_name,
            "api_version": api_version,
            "endpoint_method": "POST",
            "endpoint_uri": "/graphql",
            "endpoint_description": "public GraphQL endpoint"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/graphql/{api_name}"))
                .header("x-api-version", api_version)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"query": "{ broken }", "variables": {}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["errors"][0]["message"], "upstream boom");
    assert_eq!(body["errors"][0]["status"], 500);
    upstream.abort();
}

#[tokio::test]
async fn live_test_66_graphql_missing_version_header_parity() {
    let app = build_router(test_app_state().await);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/graphql/version-required")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"query": "{ ok }"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "X-API-Version header is required");
}

#[tokio::test]
async fn live_test_52_graphql_validation_blocks_invalid_variables_parity() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_graphql_validation_upstream().await;
    let api_name = "graphql-validation-52";
    let api_version = "v1";

    let api = json!({
        "api_name": api_name,
        "api_version": api_version,
        "api_description": "gql val",
        "api_allowed_roles": ["admin"],
        "api_allowed_groups": ["ALL"],
        "api_servers": [upstream_url],
        "api_type": "GRAPHQL",
        "active": true,
    });
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", api).await;
    assert!(status.is_success());

    let endpoint = json!({
        "api_name": api_name,
        "api_version": api_version,
        "endpoint_method": "POST",
        "endpoint_uri": "/graphql",
        "endpoint_description": "gql",
    });
    let (status, _) =
        authed_json_response(&app, &token, Method::POST, "/platform/endpoint", endpoint).await;
    assert!(status.is_success());

    let subscription =
        json!({"api_name": api_name, "api_version": api_version, "username": "admin"});
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        subscription,
    )
    .await;
    assert!(status.is_success());

    let (status, endpoint) = authed_empty_response(
        &app,
        &token,
        Method::GET,
        &format!("/platform/endpoint/POST/{api_name}/{api_version}/graphql"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let endpoint_id = endpoint["endpoint_id"].as_str().unwrap();

    let validation = json!({
        "endpoint_id": endpoint_id,
        "validation_enabled": true,
        "validation_schema": {
            "validation_schema": {
                "HelloOp.x": {"required": true, "type": "string", "min": 2}
            }
        }
    });
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/endpoint/endpoint/validation",
        validation,
    )
    .await;
    assert!(status.is_success());

    let graphql_request = |value: &str| {
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/graphql/{api_name}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-api-version", api_version)
            .body(Body::from(
                json!({
                    "query": "query HelloOp($x: String!) { hello(name: $x) }",
                    "variables": {"x": value}
                })
                .to_string(),
            ))
            .unwrap()
    };

    let response = app.clone().oneshot(graphql_request("A")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app.clone().oneshot(graphql_request("Alan")).await.unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["hello"], "Hello, Alan!");
    upstream.abort();
}
#[tokio::test]
async fn python_gateway_patch_support_forwards_to_upstream() {
    let app = build_router(test_app_state().await);
    let token = login_admin(&app).await;
    let (upstream_url, upstream) = start_echo_upstream().await;
    let api_name = "patch-api";
    let api_version = "v1";
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/api", json!({"api_name": api_name, "api_version": api_version, "api_description": "PATCH gateway parity", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": [upstream_url], "api_type": "REST", "active": true})).await;
    assert!(status.is_success());
    let (status, _) = authed_json_response(&app, &token, Method::POST, "/platform/endpoint", json!({"api_name": api_name, "api_version": api_version, "endpoint_method": "PATCH", "endpoint_uri": "/items", "endpoint_description": "PATCH item"})).await;
    assert!(status.is_success());
    let (status, _) = authed_json_response(
        &app,
        &token,
        Method::POST,
        "/platform/subscription/subscribe",
        json!({"api_name": api_name, "api_version": api_version, "username": "admin"}),
    )
    .await;
    assert!(status.is_success());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/rest/{api_name}/{api_version}/items"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "patched"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["method"], "PATCH");
    assert_eq!(body["path"], "/items");
    upstream.abort();
}
