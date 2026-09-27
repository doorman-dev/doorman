use std::{
    ffi::OsString,
    io::{self, Write},
    net::SocketAddr,
    process::Command,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    routing::{any, get, post},
};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;
mod common;

static VAULT_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static METRICS_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static PAGINATION_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static TRACE_CAPTURE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn trace_capture_guard() -> tokio::sync::MutexGuard<'static, ()> {
    TRACE_CAPTURE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

struct EnvVarRestore(Vec<(&'static str, Option<OsString>)>);

impl EnvVarRestore {
    fn apply(values: &[(&'static str, Option<&str>)]) -> Self {
        let previous = values
            .iter()
            .map(|(name, _)| (*name, std::env::var_os(name)))
            .collect();
        // Tests that mutate process-wide environment state serialize on their
        // dedicated lock and restore the original values in Drop.
        unsafe {
            for (name, value) in values {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        Self(previous)
    }
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        unsafe {
            for (name, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

#[tokio::test]
async fn restored_python_and_mongo_password_bytes_support_login() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap();
    let original = storage.dump_memory_data().await.unwrap();
    let hash = bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap();
    let encoded = STANDARD.encode(hash.as_bytes());
    for password in [
        json!({"__type__": "bytes", "data": encoded}),
        json!({"$binary": {"base64": encoded, "subType": "00"}}),
        json!(hash.as_bytes()),
    ] {
        let mut restored = original.clone();
        restored.get_mut("users").unwrap()[0]["password"] = password;
        storage.restore_memory_data(restored).await.unwrap();
        let app = build_router(state.clone());
        let (cookie, _) = login(&app).await;
        let response = platform_request(
            &app,
            Method::GET,
            "/platform/authorization/status",
            Some(&cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    for password in [
        json!({"__type__": "bytes", "data": "not-base64"}),
        json!({"__type__": "unknown", "data": encoded}),
        json!([256, "invalid"]),
    ] {
        let mut restored = original.clone();
        restored.get_mut("users").unwrap()[0]["password"] = password;
        storage.restore_memory_data(restored).await.unwrap();
        let response = platform_request(
            &build_router(state.clone()),
            Method::POST,
            "/platform/authorization",
            None,
            None,
            Some(json!({"email": "admin@doorman.dev", "password": fixture_password()})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await["error_code"], "AUTH002");
    }
}

#[tokio::test]
async fn authenticated_mfa_route_remains_absent_like_python() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let response = platform_request(
        &app,
        Method::POST,
        "/platform/auth/mfa/verify",
        Some(&cookie),
        None,
        Some(json!({"totp": "123456"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn graphql_websocket_upgrade_has_no_route_like_python() {
    let app = build_router(memory_state(false).await);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/graphql")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
}

#[tokio::test]
async fn discovery_permissions_and_missing_document_contracts_match_python() {
    let (denied_app, denied_cookie) =
        discovery_permission_app("discovery-denied", false, false).await;
    for (method, path) in [
        (Method::GET, "/platform/api/discover/v1/openapi"),
        (Method::GET, "/platform/api/discover/v1/wsdl"),
        (Method::GET, "/platform/api/discover/v1/grpc/services"),
        (Method::GET, "/platform/api/discover/v1/graphql/schema"),
        (Method::GET, "/platform/api/discover/v1/graphql/types"),
        (Method::POST, "/platform/api/discover/v1/openapi/refresh"),
        (Method::POST, "/platform/api/discover/v1/wsdl/refresh"),
        (
            Method::POST,
            "/platform/api/discover/v1/graphql/schema/refresh",
        ),
    ] {
        let response =
            platform_request(&denied_app, method, path, Some(&denied_cookie), None, None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            response_json(response).await["error_code"],
            "AUTHZ001",
            "{path}"
        );
    }

    let (allowed_app, allowed_cookie) =
        discovery_permission_app("discovery-allowed", true, false).await;
    for path in [
        "/platform/api/missing/v1/openapi",
        "/platform/api/missing/v1/wsdl",
        "/platform/api/missing/v1/grpc/services",
        "/platform/api/missing/v1/graphql/schema",
    ] {
        let response = platform_request(
            &allowed_app,
            Method::GET,
            path,
            Some(&allowed_cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response_json(response).await["error_code"],
            "API001",
            "{path}"
        );
    }
    let response = platform_request(
        &allowed_app,
        Method::GET,
        "/platform/api/missing/v1/graphql/types",
        Some(&allowed_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(response).await["error_code"], "GQL003");

    for (path, code) in [
        ("/platform/api/discover/v1/openapi/refresh", "OPENAPI001"),
        ("/platform/api/discover/v1/wsdl/refresh", "WSDL001"),
    ] {
        let response = platform_request(
            &allowed_app,
            Method::POST,
            path,
            Some(&allowed_cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response_json(response).await["error_code"], code, "{path}");
    }
}

#[tokio::test]
async fn discovery_imports_require_endpoint_permission_like_python() {
    let (denied_app, denied_cookie) =
        discovery_permission_app("discovery-import-denied", true, false).await;
    for path in [
        "/platform/api/discover/v1/openapi/import",
        "/platform/api/discover/v1/wsdl/import",
    ] {
        let response = platform_request(
            &denied_app,
            Method::POST,
            path,
            Some(&denied_cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(
            response_json(response).await["error_code"],
            "AUTHZ001",
            "{path}"
        );
    }

    let (allowed_app, allowed_cookie) =
        discovery_permission_app("discovery-import-allowed", false, true).await;
    for (path, code) in [
        ("/platform/api/discover/v1/openapi/import", "OPENAPI003"),
        ("/platform/api/discover/v1/wsdl/import", "WSDL003"),
    ] {
        let response = platform_request(
            &allowed_app,
            Method::POST,
            path,
            Some(&allowed_cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(response_json(response).await["error_code"], code, "{path}");
    }
}

#[tokio::test]
async fn discovery_document_reads_fetch_once_and_reuse_the_python_cache_contract() {
    let openapi_calls = Arc::new(AtomicUsize::new(0));
    let wsdl_calls = Arc::new(AtomicUsize::new(0));
    let graphql_calls = Arc::new(AtomicUsize::new(0));
    let openapi_counter = openapi_calls.clone();
    let wsdl_counter = wsdl_calls.clone();
    let graphql_counter = graphql_calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/openapi.json",
                    get(move || {
                        let calls = openapi_counter.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Json(json!({
                                "openapi": "3.0.0",
                                "info": {"title": "Test API", "version": "1.0.0"},
                                "paths": {"/widgets": {"get": {"summary": "List widgets"}}}
                            }))
                        }
                    }),
                )
                .route(
                    "/service.wsdl",
                    get(move || {
                        let calls = wsdl_counter.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            "<definitions name=\"TestService\"><service name=\"TestService\"/></definitions>"
                        }
                    }),
                )
                .route(
                    "/graphql",
                    post(move || {
                        let calls = graphql_counter.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Json(json!({"data": {"__schema": {
                                "queryType": {"name": "Query"}, "mutationType": null,
                                "subscriptionType": null,
                                "types": [{"name": "Query", "kind": "OBJECT"}]
                            }}}))
                        }
                    }),
                ),
        )
        .await
        .unwrap();
    });
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap();
    for (name, api_type, extra) in [
        (
            "cached-openapi",
            "REST",
            json!({"api_openapi_url": "/openapi.json"}),
        ),
        (
            "cached-wsdl",
            "SOAP",
            json!({"api_wsdl_url": "/service.wsdl"}),
        ),
        ("cached-graphql", "GRAPHQL", json!({})),
    ] {
        let mut api = json!({
            "api_name": name, "api_version": "v1", "api_type": api_type,
            "api_servers": [format!("http://{address}")],
        });
        api.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        storage.insert_one("apis", api).await.unwrap();
    }
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    for _ in 0..2 {
        let response = platform_request(
            &app,
            Method::GET,
            "/platform/api/cached-openapi/v1/openapi",
            Some(&cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["info"]["title"], "Test API");
    }
    assert_eq!(openapi_calls.load(Ordering::SeqCst), 1);

    let refreshed = platform_request(
        &app,
        Method::POST,
        "/platform/api/cached-openapi/v1/openapi/refresh",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    assert_eq!(
        response_json(refreshed).await,
        json!({
            "message": "OpenAPI spec refreshed successfully",
            "endpoints_found": 1
        })
    );
    assert_eq!(openapi_calls.load(Ordering::SeqCst), 2);

    let imported = platform_request(
        &app,
        Method::POST,
        "/platform/api/cached-openapi/v1/openapi/import",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(imported.status(), StatusCode::OK);
    assert_eq!(
        response_json(imported).await,
        json!({
            "message": "OpenAPI import completed",
            "endpoints_found": 1,
            "endpoints_imported": 1,
            "endpoints_skipped": 0
        })
    );

    for (expected_cached, _) in [(false, 0), (true, 1)] {
        let response = platform_request(
            &app,
            Method::GET,
            "/platform/api/cached-wsdl/v1/wsdl",
            Some(&cookie),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["cached"], expected_cached);
        assert!(body["wsdl"].as_str().unwrap().contains("TestService"));
    }
    assert_eq!(wsdl_calls.load(Ordering::SeqCst), 1);

    let first = platform_request(
        &app,
        Method::GET,
        "/platform/api/cached-graphql/v1/graphql/schema",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first = response_json(first).await;
    assert_eq!(first["cached"], false);
    assert_eq!(first["schema"]["queryType"]["name"], "Query");
    assert_eq!(first["operation_types"]["query"], "Query");
    assert_eq!(first["has_subscriptions"], false);
    let second = platform_request(
        &app,
        Method::GET,
        "/platform/api/cached-graphql/v1/graphql/schema",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(response_json(second).await["cached"], true);
    assert_eq!(graphql_calls.load(Ordering::SeqCst), 1);
    let types = platform_request(
        &app,
        Method::GET,
        "/platform/api/cached-graphql/v1/graphql/types",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(types.status(), StatusCode::OK);
    let types = response_json(types).await;
    assert_eq!(types["types_count"], 1);
    assert_eq!(types["types"][0]["name"], "Query");
    upstream.abort();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes process-wide Prometheus settings for this test.
async fn prometheus_metrics_exposition_counters_allowlist_and_token_match_python() {
    let _lock = METRICS_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();
    let _environment = EnvVarRestore::apply(&[
        ("PROMETHEUS_ENABLED", Some("true")),
        ("PROMETHEUS_PUBLIC", Some("false")),
        ("PROMETHEUS_ALLOWLIST", None),
        ("PROMETHEUS_IP_ALLOWLIST", None),
        ("PROMETHEUS_TRUST_XFF", None),
        ("PROMETHEUS_BEARER_TOKEN", None),
        ("PROMETHEUS_TOKEN", None),
    ]);
    let state = memory_state(false).await;
    doorman_gateway::observability::metrics::observe_request(
        &state.runtime,
        std::time::Duration::from_millis(12),
        200,
    );
    state.runtime.retries_total.fetch_add(1, Ordering::Relaxed);
    state
        .runtime
        .upstream_timeouts_total
        .fetch_add(1, Ordering::Relaxed);
    let app = build_router(state);
    let loopback = SocketAddr::new("127.0.0.1".parse().unwrap(), 41000);
    let metrics_request = |forwarded: Option<&str>, token: Option<&str>| {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .extension(ConnectInfo(loopback));
        if let Some(forwarded) = forwarded {
            request = request.header("x-forwarded-for", forwarded);
        }
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request.body(Body::empty()).unwrap()
    };
    let exposed = app
        .clone()
        .oneshot(metrics_request(None, None))
        .await
        .unwrap();
    assert_eq!(exposed.status(), StatusCode::OK);
    assert!(
        exposed.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain; version=0.0.4")
    );
    let rendered = String::from_utf8(
        to_bytes(exposed.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(rendered.contains("doorman_http_request_duration_seconds_bucket"));
    assert!(rendered.contains("doorman_http_requests_total{code=\"200\"} 1"));
    assert!(rendered.contains("doorman_http_retries_total 1"));
    assert!(rendered.contains("doorman_upstream_timeouts_total 1"));

    let _restricted = EnvVarRestore::apply(&[
        ("PROMETHEUS_ALLOWLIST", Some("10.0.0.0/8")),
        ("PROMETHEUS_TRUST_XFF", Some("true")),
        ("PROMETHEUS_BEARER_TOKEN", Some("secret-token")),
    ]);
    let denied = app
        .clone()
        .oneshot(metrics_request(Some("203.0.113.10"), None))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let allowed = app
        .oneshot(metrics_request(Some("10.1.2.3"), Some("secret-token")))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn configuration_import_merges_without_data_loss_in_memory() {
    let state = memory_state(false).await;
    common::assert_configuration_import_merges_without_data_loss(state.storage.as_ref().unwrap())
        .await;
}

#[tokio::test]
async fn revocation_purge_preserves_active_and_revoke_all_in_memory() {
    let state = memory_state(false).await;
    common::assert_revocation_purge_preserves_active_and_revoke_all(
        state.storage.as_ref().unwrap(),
    )
    .await;
}

fn fixture_password() -> &'static str {
    static PASSWORD: OnceLock<String> = OnceLock::new();
    PASSWORD.get_or_init(random_password).as_str()
}

fn random_password() -> String {
    let bytes = Uuid::new_v4().into_bytes();
    let uppercase = char::from(bytes[0] % 26 + b'A');
    let lowercase = char::from(bytes[1] % 26 + b'a');
    let digit = char::from(bytes[2] % 10 + b'0');
    let special = char::from(bytes[3] % 15 + b'!');
    format!("{uppercase}{lowercase}{digit}{special}{}", Uuid::new_v4())
}

async fn memory_state(https_only: bool) -> AppState {
    let mut config = Config::for_test("removed-internal-backend".to_owned());
    config.https_only = https_only;
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
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
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

async fn response_envelope_rest_app(strict: bool, upstream_url: &str) -> axum::Router {
    let mut state = memory_state(false).await;
    state.config.strict_response_envelope = strict;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "envelope-rest", "api_version": "v1", "api_id": "envelope-rest",
                "api_type": "REST", "api_public": true, "api_allowed_groups": ["ALL"],
                "api_servers": [upstream_url], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoints",
            json!({
                "api_name": "envelope-rest", "api_version": "v1", "endpoint_method": "GET",
                "endpoint_uri": "/e", "client_uri": "/e"
            }),
        )
        .await
        .unwrap();
    build_router(state)
}

async fn response_envelope_graphql_app(strict: bool, upstream_url: &str) -> axum::Router {
    let mut state = memory_state(false).await;
    state.config.strict_response_envelope = strict;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "envelope-graphql", "api_version": "v1", "api_id": "envelope-graphql",
                "api_type": "GRAPHQL", "api_public": true, "api_allowed_groups": ["ALL"],
                "api_servers": [upstream_url], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoints",
            json!({
                "api_name": "envelope-graphql", "api_version": "v1", "endpoint_method": "POST",
                "endpoint_uri": "/graphql", "client_uri": "/graphql"
            }),
        )
        .await
        .unwrap();
    build_router(state)
}

async fn login(app: &axum::Router) -> (String, String) {
    login_as(app, "admin@doorman.dev", fixture_password()).await
}

async fn login_as(app: &axum::Router, email: &str, password: &str) -> (String, String) {
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
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    let csrf = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("csrf_token="))
        .unwrap()
        .to_owned();
    (cookies.join("; "), csrf)
}

async fn config_permission_app(permission: Option<&str>, username: &str) -> (axum::Router, String) {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap();
    let role_name = format!("{username}-role");
    let mut role = json!({"role_name": role_name});
    if let Some(permission) = permission {
        role[permission] = json!(true);
    }
    storage.insert_one("roles", role).await.unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": username,
                "email": format!("{username}@doorman.dev"),
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": format!("{username}-role"),
                "groups": ["ALL"],
                "active": true,
                "ui_access": true
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login_as(&app, &format!("{username}@doorman.dev"), fixture_password()).await;
    (app, cookie)
}

async fn discovery_permission_app(
    username: &str,
    manage_apis: bool,
    manage_endpoints: bool,
) -> (axum::Router, String) {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap();
    let role_name = format!("{username}-discovery-role");
    storage
        .insert_one(
            "roles",
            json!({
                "role_name": role_name,
                "manage_apis": manage_apis,
                "manage_endpoints": manage_endpoints,
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": username,
                "email": format!("{username}@doorman.dev"),
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": format!("{username}-discovery-role"),
                "groups": ["ALL"], "active": true, "ui_access": true,
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_id": "discovery-api", "api_name": "discover", "api_version": "v1",
                "api_servers": ["http://127.0.0.1:9"], "api_type": "REST",
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login_as(&app, &format!("{username}@doorman.dev"), fixture_password()).await;
    (app, cookie)
}

async fn state_with_security_settings(mut settings: Value) -> AppState {
    let state = memory_state(false).await;
    // Match the Python collection schema, with an unrelated record first to
    // ensure allow/deny behavior does not depend on collection ordering.
    settings["type"] = json!("security_settings");
    state
        .storage
        .as_ref()
        .unwrap()
        .insert_one(
            "settings",
            json!({
                "type":"other", "allow_localhost_bypass":true,
                "trust_x_forwarded_for":false, "ip_whitelist":[], "ip_blacklist":[]
            }),
        )
        .await
        .unwrap();
    state
        .storage
        .as_ref()
        .unwrap()
        .insert_one("settings", settings)
        .await
        .unwrap();
    state
}

fn platform_liveness_request(peer_ip: &str, forwarded_ip: Option<&str>) -> Request<Body> {
    let peer = SocketAddr::new(peer_ip.parse().unwrap(), 41000);
    let mut builder = Request::builder()
        .uri("/platform/monitor/liveness")
        .extension(ConnectInfo(peer));
    if let Some(forwarded_ip) = forwarded_ip {
        builder = builder.header("x-forwarded-for", forwarded_ip);
    }
    builder.body(Body::empty()).unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

async fn platform_request(
    app: &axum::Router,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    payload: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    let body = if let Some(payload) = payload {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(payload.to_string())
    } else {
        Body::empty()
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn authorization_login_status_invalid_and_guards_match_python() {
    let app = build_router(memory_state(false).await);

    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/authorization",
        None,
        None,
        Some(json!({"email": "unknown@example.com", "password": "bad"})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    for (method, path) in [
        (Method::GET, "/platform/user/me"),
        (Method::POST, "/platform/authorization/refresh"),
    ] {
        let response = platform_request(&app, method, path, None, None, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }

    let response = platform_request(
        &app,
        Method::POST,
        "/platform/authorization",
        None,
        None,
        Some(json!({
            "email": "admin@doorman.dev",
            "password": fixture_password()
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("access_token_cookie="))
    );
    let cookie = cookies.join("; ");

    let status = platform_request(
        &app,
        Method::GET,
        "/platform/authorization/status",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        response_json(status).await,
        json!({"message": "Token is valid"})
    );
}

#[tokio::test]
async fn malformed_core_entity_json_uses_python_validation_envelope_before_auth() {
    let app = build_router(memory_state(false).await);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/group")
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .body(Body::from(r#"{"group_name":"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["error_code"], "VAL001");
    assert_eq!(body["error_message"], "Validation Error");
}

#[tokio::test]
async fn malformed_subscription_json_uses_python_validation_envelope_before_auth() {
    let app = build_router(memory_state(false).await);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/subscription/subscribe")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["error_code"], "VAL001");
    assert_eq!(body["error_message"], "Validation Error");
}

#[tokio::test]
async fn malformed_typed_control_plane_json_validates_before_auth() {
    let app = build_router(memory_state(false).await);
    for (method, path) in [
        (Method::POST, "/platform/vault"),
        (Method::PUT, "/platform/vault/key-a"),
        (Method::POST, "/platform/credit"),
        (Method::POST, "/platform/tiers/"),
        (Method::POST, "/platform/tiers/upgrade"),
        (Method::PUT, "/platform/security/settings"),
        (Method::POST, "/platform/config/import"),
        (Method::POST, "/platform/memory/dump"),
        (Method::POST, "/platform/memory/restore"),
        (Method::POST, "/platform/tools/cors/check"),
        (Method::POST, "/platform/tools/chaos/toggle"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}"
        );
        let body = response_json(response).await;
        assert_eq!(body["error_code"], "VAL001", "{path}");
        assert_eq!(body["error_message"], "Validation Error", "{path}");
    }
}

#[tokio::test]
async fn user_create_requires_python_model_role_before_service_logic() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let response = platform_request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&cookie),
        None,
        Some(json!({
            "username": "missingrole",
            "email": "missingrole@example.com",
            "password": "A_secure_password_123!",
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(response).await,
        json!({"error_code": "VAL001", "error_message": "Validation Error"})
    );
}

#[tokio::test]
async fn update_password_model_validates_before_auth_and_matches_pydantic_bounds() {
    let app = build_router(memory_state(false).await);
    for body in [
        json!({}),
        json!({"new_password": []}),
        json!({"new_password": "short"}),
        json!({"new_password": "x".repeat(37)}),
    ] {
        let response = platform_request(
            &app,
            Method::PUT,
            "/platform/user/someone/update-password",
            None,
            None,
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response_json(response).await["error_code"], "VAL001");
    }

    for body in [
        json!({"new_password": "é".repeat(36)}),
        json!({"new_password": 123456, "unknown": "ignored"}),
    ] {
        let response = platform_request(
            &app,
            Method::PUT,
            "/platform/user/someone/update-password",
            None,
            None,
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn user_create_matches_pydantic_bounds_and_scalar_coercion() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    for body in [
        json!({"username": "ab", "email": "short@example.com", "password": "A_secure_password_123!", "role": "user"}),
        json!({"username": "longrole", "email": "longrole@example.com", "password": "A_secure_password_123!", "role": "x".repeat(51)}),
        json!({"username": "shortpassword", "email": "shortpassword@example.com", "password": "TooShort1!", "role": "user"}),
        json!({"username": "negative-rate", "email": "negative-rate@example.com", "password": "A_secure_password_123!", "role": "user", "rate_limit_duration": -1}),
        json!({"username": "scalar-groups", "email": "scalar-groups@example.com", "password": "A_secure_password_123!", "role": "user", "groups": "team"}),
        json!({"username": "null-groups", "email": "null-groups@example.com", "password": "A_secure_password_123!", "role": "user", "groups": null}),
        json!({"username": "unicode-too-long", "email": "unicode-too-long@example.com", "password": "A_secure_password_123!", "role": "é".repeat(51)}),
    ] {
        let response = platform_request(
            &app,
            Method::POST,
            "/platform/user",
            Some(&cookie),
            None,
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response_json(response).await["error_code"], "VAL001");
    }

    let scalar = platform_request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&cookie),
        None,
        Some(json!({
            "username": 123, "email": 456, "password": "A_secure_password_123!", "role": true,
            "groups": [1], "rate_limit_duration": "7", "active": "false", "unexpected": "ignored",
        })),
    )
    .await;
    assert_eq!(scalar.status(), StatusCode::CREATED);
    let created = platform_request(
        &app,
        Method::GET,
        "/platform/user/123",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    assert_eq!(created["username"], "123");
    assert_eq!(created["email"], "456");
    assert_eq!(created["role"], "True");
    assert_eq!(created["groups"], json!(["1"]));
    assert_eq!(created["rate_limit_duration"], 7);
    assert_eq!(created["active"], false);
    assert_eq!(created["bandwidth_limit_window"], "day");
    assert_eq!(created["ui_access"], false);
    assert!(created["throttle_duration"].is_null());
    assert!(created["custom_attributes"].is_null());
    assert!(created.get("unexpected").is_none());

    let unicode = platform_request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&cookie),
        None,
        Some(json!({
            "username": "é".repeat(50),
            "email": "unicode@example.com",
            "password": "A_secure_password_123!",
            "role": "é".repeat(50),
        })),
    )
    .await;
    assert_eq!(unicode.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn user_update_matches_pydantic_null_coercion_and_unknown_field_rules() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let created = platform_request(&app, Method::POST, "/platform/user", Some(&cookie), None, Some(json!({
        "username": "updateuser", "email": "updateuser@example.com", "password": "A_secure_password_123!", "role": "user",
    }))).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    for body in [
        json!({"email": "x"}),
        json!({"rate_limit_duration": -1}),
        json!({"groups": "team"}),
    ] {
        let response = platform_request(
            &app,
            Method::PUT,
            "/platform/user/updateuser",
            Some(&cookie),
            None,
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response_json(response).await["error_code"], "VAL001");
    }
    let updated = platform_request(&app, Method::PUT, "/platform/user/updateuser", Some(&cookie), None, Some(json!({
        "email": 123, "role": true, "groups": [1], "rate_limit_duration": "7", "active": "false",
        "custom_attributes": [], "unexpected": "ignored",
    }))).await;
    assert_eq!(updated.status(), StatusCode::OK);
    let nulls = platform_request(
        &app,
        Method::PUT,
        "/platform/user/updateuser",
        Some(&cookie),
        None,
        Some(json!({"email": null, "role": null, "active": null})),
    )
    .await;
    assert_eq!(nulls.status(), StatusCode::OK);
    let user = platform_request(
        &app,
        Method::GET,
        "/platform/user/updateuser",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(user.status(), StatusCode::OK);
    let user = response_json(user).await;
    assert_eq!(user["email"], "123");
    assert_eq!(user["role"], "True");
    assert_eq!(user["groups"], json!(["1"]));
    assert_eq!(user["rate_limit_duration"], 7);
    assert_eq!(user["active"], false);
    assert_eq!(user["custom_attributes"], json!({}));
    assert!(user.get("unexpected").is_none());
}

#[tokio::test]
async fn user_role_change_prunes_subscriptions_with_python_iteration_behavior() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    storage.insert_one("users", json!({"username": "rolechange", "email": "rolechange@example.com", "role": "former", "groups": [], "active": true})).await.unwrap();
    storage
        .insert_one(
            "apis",
            json!({"api_name": "kept", "api_version": "v1", "role": ["new"]}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "apis",
            json!({"api_name": "removed", "api_version": "v1", "role": ["former"]}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "apis",
            json!({"api_name": "adjacent", "api_version": "v1", "role": ["former"]}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "rolechange", "apis": ["kept/v1", "removed/v1", "adjacent/v1"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/user/rolechange",
        Some(&cookie),
        None,
        Some(json!({"role": "new"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let subscription = storage
        .find_one("subscriptions", &json!({"username": "rolechange"}))
        .await
        .unwrap()
        .unwrap();
    // The Python reference mutates the list while iterating, so its first
    // removal skips the adjacent incompatible subscription.
    assert_eq!(subscription["apis"], json!(["kept/v1", "adjacent/v1"]));
}

#[tokio::test]
async fn user_role_change_with_malformed_legacy_subscription_matches_python_failure() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    storage
        .insert_one(
            "users",
            json!({
                "username": "rolechangeinvalid", "email": "rolechangeinvalid@example.com",
                "role": "former", "groups": [], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "rolechangeinvalid", "apis": ["not-a-reference"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/user/rolechangeinvalid",
        Some(&cookie),
        None,
        Some(json!({"role": "new"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_json(updated).await["error_code"], "GTW999");
    // Like Python, the user write occurs before the purge encounters the
    // malformed legacy value and returns the generic route failure.
    assert_eq!(
        storage
            .find_one("users", &json!({"username": "rolechangeinvalid"}))
            .await
            .unwrap()
            .unwrap()["role"],
        "new"
    );
}

#[tokio::test]
async fn role_and_group_models_match_pydantic_defaults_coercion_and_empty_updates() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;

    let role = platform_request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&cookie),
        None,
        Some(json!({"role_name": 123, "manage_users": "true", "ignored": "field"})),
    )
    .await;
    assert_eq!(role.status(), StatusCode::CREATED);
    let role = platform_request(
        &app,
        Method::GET,
        "/platform/role/123",
        Some(&cookie),
        None,
        None,
    )
    .await;
    let role = response_json(role).await;
    assert_eq!(role["role_name"], "123");
    assert_eq!(role["role_description"], Value::Null);
    assert_eq!(role["manage_users"], true);
    assert_eq!(role["manage_apis"], false);
    assert_eq!(role["export_logs"], false);
    assert!(role.get("ignored").is_none());
    let role_update = platform_request(
        &app,
        Method::PUT,
        "/platform/role/123",
        Some(&cookie),
        None,
        Some(json!({"role_description": 456, "manage_apis": "on", "ignored": "field"})),
    )
    .await;
    assert_eq!(role_update.status(), StatusCode::OK);
    let role_update = response_json(role_update).await;
    assert_eq!(role_update["role_name"], "123");
    assert_eq!(role_update["role_description"], "456");
    assert_eq!(role_update["manage_apis"], true);
    let role = platform_request(
        &app,
        Method::GET,
        "/platform/role/123",
        Some(&cookie),
        None,
        None,
    )
    .await;
    let role = response_json(role).await;
    assert_eq!(role["role_description"], "456");
    assert_eq!(role["manage_apis"], true);
    assert!(role.get("ignored").is_none());
    let invalid_role = platform_request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&cookie),
        None,
        Some(json!({"role_name": ""})),
    )
    .await;
    assert_eq!(invalid_role.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let empty_role_update = platform_request(
        &app,
        Method::PUT,
        "/platform/role/123",
        Some(&cookie),
        None,
        Some(json!({"role_description": null, "ignored": "field"})),
    )
    .await;
    assert_eq!(empty_role_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(empty_role_update).await["error_code"],
        "ROLE007"
    );

    let group = platform_request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&cookie),
        None,
        Some(json!({
            "group_name": 456, "group_description": true, "api_access": [1, false], "ignored": "field"
        })),
    )
    .await;
    assert_eq!(group.status(), StatusCode::CREATED);
    let group = platform_request(
        &app,
        Method::GET,
        "/platform/group/456",
        Some(&cookie),
        None,
        None,
    )
    .await;
    let group = response_json(group).await;
    assert_eq!(group["group_name"], "456");
    assert_eq!(group["group_description"], "True");
    assert_eq!(group["api_access"], json!(["1", "False"]));
    assert!(group.get("ignored").is_none());
    let group_update = platform_request(
        &app,
        Method::PUT,
        "/platform/group/456",
        Some(&cookie),
        None,
        Some(json!({"group_description": 123, "api_access": [2], "ignored": "field"})),
    )
    .await;
    assert_eq!(group_update.status(), StatusCode::OK);
    let group = platform_request(
        &app,
        Method::GET,
        "/platform/group/456",
        Some(&cookie),
        None,
        None,
    )
    .await;
    let group = response_json(group).await;
    assert_eq!(group["group_description"], "123");
    assert_eq!(group["api_access"], json!(["2"]));
    assert!(group.get("ignored").is_none());
    let invalid_group = platform_request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&cookie),
        None,
        Some(json!({"group_name": "bad-group", "api_access": "not-a-list"})),
    )
    .await;
    assert_eq!(invalid_group.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let empty_group_update = platform_request(
        &app,
        Method::PUT,
        "/platform/group/456",
        Some(&cookie),
        None,
        Some(json!({"group_description": null, "ignored": "field"})),
    )
    .await;
    assert_eq!(empty_group_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(empty_group_update).await["error_code"],
        "GRP006"
    );
    for (path, field) in [
        ("/platform/role", "role_name"),
        ("/platform/group", "group_name"),
    ] {
        let accepted = platform_request(
            &app,
            Method::POST,
            path,
            Some(&cookie),
            None,
            Some(json!({field: "é".repeat(50)})),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::CREATED, "{path}");
        let rejected = platform_request(
            &app,
            Method::POST,
            path,
            Some(&cookie),
            None,
            Some(json!({field: "é".repeat(51)})),
        )
        .await;
        assert_eq!(
            rejected.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}"
        );
    }
}

#[tokio::test]
async fn routing_models_match_pydantic_generation_coercion_and_update_exclusion() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/routing",
        Some(&cookie),
        None,
        Some(json!({
            "routing_name": 123, "routing_servers": [1, true], "server_index": "2", "ignored": "field"
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = response_json(created).await;
    let message = body["message"].as_str().unwrap();
    let client_key = message
        .strip_prefix("Routing created successfully with key: ")
        .unwrap();
    assert!(uuid::Uuid::parse_str(client_key).is_ok());
    let routing = storage
        .find_one("routings", &json!({"client_key": client_key}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(routing["routing_name"], "123");
    assert_eq!(routing["routing_servers"], json!(["1", "True"]));
    assert_eq!(routing["server_index"], 2);
    assert_eq!(routing["routing_description"], Value::Null);
    assert!(routing.get("ignored").is_none());
    let updated = platform_request(
        &app,
        Method::PUT,
        &format!("/platform/routing/{client_key}"),
        Some(&cookie),
        None,
        Some(json!({"routing_servers": [2], "server_index": 99, "ignored": "field"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let routing = storage
        .find_one("routings", &json!({"client_key": client_key}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(routing["routing_servers"], json!(["2"]));
    assert_eq!(routing["server_index"], 2);
    let changed_key = platform_request(
        &app,
        Method::PUT,
        &format!("/platform/routing/{client_key}"),
        Some(&cookie),
        None,
        Some(json!({"client_key": "different-key"})),
    )
    .await;
    assert_eq!(changed_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(changed_key).await["error_code"], "RTG005");
    let no_op_update = platform_request(
        &app,
        Method::PUT,
        &format!("/platform/routing/{client_key}"),
        Some(&cookie),
        None,
        Some(json!({"routing_servers": ["2"]})),
    )
    .await;
    assert_eq!(no_op_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(no_op_update).await["error_code"], "RTG006");
    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/routing",
        Some(&cookie),
        None,
        Some(json!({"routing_name": "invalid", "routing_servers": []})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let empty_update = platform_request(
        &app,
        Method::PUT,
        &format!("/platform/routing/{client_key}"),
        Some(&cookie),
        None,
        Some(json!({"server_index": 42, "ignored": "field"})),
    )
    .await;
    assert_eq!(empty_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(empty_update).await["error_code"], "RTG007");
    let missing_update = platform_request(
        &app,
        Method::PUT,
        "/platform/routing/missing-key",
        Some(&cookie),
        None,
        Some(json!({"routing_name": "missing"})),
    )
    .await;
    assert_eq!(missing_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(missing_update).await["error_code"], "RTG004");
    let unicode_boundary = platform_request(
        &app,
        Method::POST,
        "/platform/routing",
        Some(&cookie),
        None,
        Some(json!({"routing_name": "é".repeat(50), "routing_servers": ["http://upstream"]})),
    )
    .await;
    assert_eq!(unicode_boundary.status(), StatusCode::CREATED);
    let unicode_too_long = platform_request(
        &app,
        Method::POST,
        "/platform/routing",
        Some(&cookie),
        None,
        Some(json!({"routing_name": "é".repeat(51), "routing_servers": ["http://upstream"]})),
    )
    .await;
    assert_eq!(unicode_too_long.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn endpoint_models_match_pydantic_coercion_bounds_and_null_elision() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    storage
        .insert_one(
            "apis",
            json!({"api_name": "endpoint-model", "api_version": "v1", "api_id": "source-api-id"}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/items", "endpoint_description": 123, "endpoint_servers": [1, false],
            "api_id": "", "endpoint_id": "", "ignored": "field"
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let endpoint = storage
        .find_one("endpoints", &json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/items"
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(endpoint["endpoint_description"], "123");
    assert_eq!(endpoint["endpoint_servers"], json!(["1", "False"]));
    assert_eq!(endpoint["client_uri"], Value::Null);
    assert_eq!(endpoint["api_id"], "source-api-id");
    assert!(endpoint.get("ignored").is_none());
    let unicode_boundary = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/unicode", "endpoint_description": "é".repeat(255)
        })),
    )
    .await;
    assert_eq!(unicode_boundary.status(), StatusCode::CREATED);
    let unicode_too_long = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/unicode-too-long", "endpoint_description": "é".repeat(256)
        })),
    )
    .await;
    assert_eq!(unicode_too_long.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let duplicate = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/items", "endpoint_description": "duplicate"
        })),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(duplicate).await["error_code"], "END001");
    let client_uri_conflict = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/alternate", "client_uri": "/items", "endpoint_description": "conflict"
        })),
    )
    .await;
    assert_eq!(client_uri_conflict.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(client_uri_conflict).await["error_code"],
        "END001"
    );
    let second = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/second", "client_uri": "/second-client", "endpoint_description": "second"
        })),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CREATED);
    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/endpoint-model/v1/items",
        Some(&cookie),
        None,
        Some(json!({"endpoint_description": true, "endpoint_servers": null, "ignored": "field"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let endpoint = storage
        .find_one("endpoints", &json!({"api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/items"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(endpoint["endpoint_description"], "True");
    assert_eq!(endpoint["endpoint_servers"], json!(["1", "False"]));
    let no_op_update = platform_request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/endpoint-model/v1/items",
        Some(&cookie),
        None,
        Some(json!({"endpoint_description": "True"})),
    )
    .await;
    assert_eq!(no_op_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(no_op_update).await["error_code"], "END003");
    let immutable_update = platform_request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/endpoint-model/v1/items",
        Some(&cookie),
        None,
        Some(json!({"endpoint_uri": "/moved"})),
    )
    .await;
    assert_eq!(immutable_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(immutable_update).await["error_code"],
        "END006"
    );
    let client_uri_update_conflict = platform_request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/endpoint-model/v1/second",
        Some(&cookie),
        None,
        Some(json!({"client_uri": "/items"})),
    )
    .await;
    assert_eq!(client_uri_update_conflict.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(client_uri_update_conflict).await["error_code"],
        "END006"
    );
    let empty_update = platform_request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/endpoint-model/v1/items",
        Some(&cookie),
        None,
        Some(json!({"endpoint_servers": null, "ignored": "field"})),
    )
    .await;
    assert_eq!(empty_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(empty_update).await["error_code"], "END007");
    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({"api_name": "endpoint-model", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/bad", "endpoint_description": ""})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let missing_api = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "missing-api", "api_version": "v1", "endpoint_method": "GET",
            "endpoint_uri": "/items", "endpoint_description": "missing parent"
        })),
    )
    .await;
    assert_eq!(missing_api.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(missing_api).await["error_code"], "END002");
    let missing_delete = platform_request(
        &app,
        Method::DELETE,
        "/platform/endpoint/GET/endpoint-model/v1/missing",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing_delete.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(missing_delete).await["error_code"], "END004");
}

#[tokio::test]
async fn incomplete_subscription_payload_uses_python_validation_envelope_before_auth() {
    let app = build_router(memory_state(false).await);
    let response = platform_request(
        &app,
        Method::POST,
        "/platform/subscription/subscribe",
        None,
        None,
        Some(json!({"username": "admin"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["error_code"], "VAL001");
    assert_eq!(body["error_message"], "Validation Error");
}

#[tokio::test]
async fn subscription_model_coerces_python_scalars_and_ignores_unknown_fields() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    storage
        .insert_one(
            "apis",
            json!({"api_name": "True", "api_version": "1", "api_allowed_groups": ["ALL"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let subscribed = platform_request(
        &app,
        Method::POST,
        "/platform/subscription/subscribe",
        Some(&cookie),
        None,
        Some(json!({"username": "admin", "api_name": true, "api_version": 1, "ignored": "field"})),
    )
    .await;
    assert_eq!(subscribed.status(), StatusCode::OK);
    let subscription = storage
        .find_one("subscriptions", &json!({"username": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(subscription["apis"], json!(["True/1"]));
    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/subscription/subscribe",
        Some(&cookie),
        None,
        Some(json!({"username": "ab", "api_name": "api", "api_version": "v1"})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let unicode_boundary = platform_request(
        &app,
        Method::POST,
        "/platform/subscription/subscribe",
        Some(&cookie),
        None,
        Some(json!({
            "username": "admin", "api_name": "é".repeat(50), "api_version": "v1"
        })),
    )
    .await;
    assert_eq!(unicode_boundary.status(), StatusCode::NOT_FOUND);
    let unicode_too_long = platform_request(
        &app,
        Method::POST,
        "/platform/subscription/subscribe",
        Some(&cookie),
        None,
        Some(json!({
            "username": "admin", "api_name": "é".repeat(51), "api_version": "v1"
        })),
    )
    .await;
    assert_eq!(unicode_too_long.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes reads of the process-global VAULT_KEY.
async fn vault_create_without_extra_permissions_matches_python_negative_contract() {
    let _guard = VAULT_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();
    let (app, cookie) = config_permission_app(None, "vault-limited").await;
    let response = platform_request(
        &app,
        Method::POST,
        "/platform/vault",
        Some(&cookie),
        None,
        Some(json!({"key_name": "k", "value": "v"})),
    )
    .await;
    assert!(
        !response.status().is_success(),
        "a user without vault permission created a secret: {}",
        response.status()
    );
}

#[tokio::test]
async fn authorization_malformed_json_returns_auth004() {
    let app = build_router(memory_state(false).await);
    for path in [
        "/platform/authorization",
        "/platform/authorization/register",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let payload = response_json(response).await;
        assert_eq!(payload["error_code"], "AUTH004", "{path}");
        assert_eq!(payload["error_message"], "Invalid JSON payload", "{path}");
    }
}

#[tokio::test]
async fn authorization_refresh_and_invalidate_match_python() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;

    let refresh = platform_request(
        &app,
        Method::POST,
        "/platform/authorization/refresh",
        Some(&cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);
    let refreshed_cookie = refresh
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        refreshed_cookie
            .split("; ")
            .any(|cookie| cookie.starts_with("access_token_cookie="))
    );
    let refresh_body = response_json(refresh).await;
    assert_eq!(
        refresh_body.as_object().map(|body| body.len()),
        Some(1),
        "the Python ResponseModel exposes only refresh_token"
    );
    assert!(
        refresh_body["refresh_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let status = platform_request(
        &app,
        Method::GET,
        "/platform/authorization/status",
        Some(&refreshed_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        response_json(status).await,
        json!({"message": "Token is valid"})
    );

    let invalidate = platform_request(
        &app,
        Method::POST,
        "/platform/authorization/invalidate",
        Some(&refreshed_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(invalidate.status(), StatusCode::OK);
    assert_eq!(
        response_json(invalidate).await,
        json!({"message": "Your token has been invalidated"})
    );

    let rejected = platform_request(
        &app,
        Method::GET,
        "/platform/user/me",
        Some(&refreshed_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_jti_revocation_allows_authorization_and_is_removed() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let invalidate = platform_request(
        &app,
        Method::POST,
        "/platform/authorization/invalidate",
        Some(&cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(invalidate.status(), StatusCode::OK);

    let revocation = storage
        .find_one("revocations", &json!({"type": "jti", "username": "admin"}))
        .await
        .unwrap()
        .unwrap();
    let filter = json!({
        "type": "jti",
        "username": "admin",
        "jti": revocation["jti"].clone()
    });

    storage
        .update_one("revocations", &filter, &json!({"expires_at": 0}))
        .await
        .unwrap();

    let status = platform_request(
        &app,
        Method::GET,
        "/platform/authorization/status",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);

    assert!(
        storage
            .find_one("revocations", &filter)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn authorization_refresh_reloads_current_user_role() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    storage
        .update_one(
            "users",
            &json!({"username": "admin"}),
            &json!({"role": "refreshed-role"}),
        )
        .await
        .unwrap();

    let refresh = platform_request(
        &app,
        Method::POST,
        "/platform/authorization/refresh",
        Some(&cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);
    let refreshed_cookie = refresh
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let token = refreshed_cookie
        .split("; ")
        .find_map(|cookie| cookie.strip_prefix("access_token_cookie="))
        .expect("refresh must issue an access cookie");
    let claims_segment = token
        .split('.')
        .nth(1)
        .expect("JWT must have a claims segment");
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_segment).unwrap()).unwrap();
    assert_eq!(claims["role"], "refreshed-role");

    let status = platform_request(
        &app,
        Method::GET,
        "/platform/authorization/status",
        Some(&refreshed_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        response_json(status).await,
        json!({"message": "Token is valid"})
    );
}

#[tokio::test]
async fn authorization_admin_lifecycle_and_revoke_match_python() {
    let app = build_router(memory_state(false).await);
    let (admin_cookie, _) = login(&app).await;
    let username = "qa-auth";
    let email = "qa-auth@example.com";
    let password = fixture_password();

    let create = platform_request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&admin_cookie),
        None,
        Some(json!({
            "username": username,
            "email": email,
            "password": password,
            "role": "admin",
            "groups": ["ALL"],
            "active": true
        })),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let (user_cookie, _) = login_as(&app, email, password).await;

    let status_path = format!("/platform/authorization/admin/status/{username}");
    let status = platform_request(
        &app,
        Method::GET,
        &status_path,
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    let status = response_json(status).await;
    assert_eq!(status, json!({"active": true, "revoked": false}));

    let revoke_path = format!("/platform/authorization/admin/revoke/{username}");
    let revoke = platform_request(
        &app,
        Method::POST,
        &revoke_path,
        Some(&admin_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(revoke.status(), StatusCode::OK);
    assert_eq!(
        response_json(revoke).await,
        json!({"message": format!("All tokens revoked for {username}")})
    );
    let rejected = platform_request(
        &app,
        Method::GET,
        "/platform/user/me",
        Some(&user_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

    let disable_path = format!("/platform/authorization/admin/disable/{username}");
    let disable = platform_request(
        &app,
        Method::POST,
        &disable_path,
        Some(&admin_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(disable.status(), StatusCode::OK);
    assert_eq!(
        response_json(disable).await,
        json!({"message": format!("User {username} disabled and tokens revoked")})
    );
    let status = platform_request(
        &app,
        Method::GET,
        &status_path,
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    let status = response_json(status).await;
    assert_eq!(status["active"], false);
    assert_eq!(status["revoked"], true);

    let enable_path = format!("/platform/authorization/admin/enable/{username}");
    let enable = platform_request(
        &app,
        Method::POST,
        &enable_path,
        Some(&admin_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(enable.status(), StatusCode::OK);
    assert_eq!(
        response_json(enable).await,
        json!({"message": format!("User {username} enabled")})
    );
    let unrevoke_path = format!("/platform/authorization/admin/unrevoke/{username}");
    let unrevoke = platform_request(
        &app,
        Method::POST,
        &unrevoke_path,
        Some(&admin_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(unrevoke.status(), StatusCode::OK);
    assert_eq!(
        response_json(unrevoke).await,
        json!({"message": format!("Token revocation cleared for {username}")})
    );
    let status = platform_request(
        &app,
        Method::GET,
        &status_path,
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    let status = response_json(status).await;
    assert_eq!(status["active"], true);
    assert_eq!(status["revoked"], false);

    for (method, action, expected) in [
        (
            Method::POST,
            "revoke",
            "All tokens revoked for missing-user",
        ),
        (
            Method::POST,
            "unrevoke",
            "Token revocation cleared for missing-user",
        ),
        (
            Method::POST,
            "disable",
            "User missing-user disabled and tokens revoked",
        ),
        (Method::POST, "enable", "User missing-user enabled"),
    ] {
        let response = platform_request(
            &app,
            method,
            &format!("/platform/authorization/admin/{action}/missing-user"),
            Some(&admin_cookie),
            None,
            Some(json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{action}");
        assert_eq!(response_json(response).await, json!({"message": expected}));
    }

    let missing_status = platform_request(
        &app,
        Method::GET,
        "/platform/authorization/admin/status/missing-user",
        Some(&admin_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing_status.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_json(missing_status).await["error_code"], "GTW999");
}

#[derive(Clone, Default)]
struct CapturedTrace(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedTrace {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedTrace {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedTrace {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[tokio::test]
async fn global_whitelist_blocks_non_whitelisted_with_trusted_proxy() {
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": true,
            "xff_trusted_proxies": ["127.0.0.1"],
            "ip_whitelist": ["198.51.100.10"],
            "ip_blacklist": [],
            "allow_localhost_bypass": false,
        }))
        .await,
    );
    let response = app
        .oneshot(platform_liveness_request("127.0.0.1", Some("203.0.113.10")))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["error_code"], "SEC010");
}

#[tokio::test]
async fn global_blacklist_blocks_with_trusted_proxy() {
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": true,
            "xff_trusted_proxies": ["127.0.0.1"],
            "ip_whitelist": [],
            "ip_blacklist": ["203.0.113.10"],
            "allow_localhost_bypass": false,
        }))
        .await,
    );
    let response = app
        .oneshot(platform_liveness_request("127.0.0.1", Some("203.0.113.10")))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["error_code"], "SEC011");
}

#[tokio::test]
async fn global_xff_is_ignored_when_the_direct_proxy_is_not_trusted() {
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": true,
            "xff_trusted_proxies": ["10.0.0.1"],
            "ip_whitelist": ["198.51.100.10"],
            "ip_blacklist": [],
            "allow_localhost_bypass": false,
        }))
        .await,
    );
    let response = app
        .oneshot(platform_liveness_request(
            "127.0.0.1",
            Some("198.51.100.10"),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["error_code"], "SEC010");
}

#[tokio::test]
async fn global_localhost_bypass_enabled_allows_without_forwarding_headers() {
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": false,
            "ip_whitelist": ["198.51.100.10"],
            "ip_blacklist": [],
            "allow_localhost_bypass": true,
        }))
        .await,
    );
    let response = app
        .oneshot(platform_liveness_request("127.0.0.1", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn global_localhost_bypass_disabled_blocks_without_forwarding_headers() {
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": false,
            "ip_whitelist": ["198.51.100.10"],
            "ip_blacklist": [],
            "allow_localhost_bypass": false,
        }))
        .await,
    );
    let response = app
        .clone()
        .oneshot(platform_liveness_request("127.0.0.1", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["error_code"], "SEC010");

    let settings_response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/platform/security/settings")
                .extension(ConnectInfo(SocketAddr::new(
                    "127.0.0.1".parse().unwrap(),
                    41000,
                )))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(settings_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn global_ip_denial_emits_the_python_audit_action() {
    let _trace_guard = trace_capture_guard().await;
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": true,
            "xff_trusted_proxies": ["127.0.0.1"],
            "ip_whitelist": ["198.51.100.10"],
            "ip_blacklist": [],
            "allow_localhost_bypass": false,
        }))
        .await,
    );
    let capture = CapturedTrace::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    let response = app
        .oneshot(platform_liveness_request("127.0.0.1", Some("203.0.113.10")))
        .with_subscriber(subscriber)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let events = capture.text();
    assert!(
        events.contains("ip.global_deny"),
        "captured events: {events}"
    );
    assert!(
        events.contains("not_in_whitelist"),
        "captured events: {events}"
    );
    assert!(events.contains("203.0.113.10"), "captured events: {events}");
}

#[tokio::test]
async fn global_ip_denial_audit_never_logs_raw_forwarded_header_values() {
    let _trace_guard = trace_capture_guard().await;
    let app = build_router(
        state_with_security_settings(json!({
            "trust_x_forwarded_for": true,
            "xff_trusted_proxies": ["127.0.0.1"],
            "ip_whitelist": ["198.51.100.10"],
            "ip_blacklist": [],
            "allow_localhost_bypass": false,
        }))
        .await,
    );
    let capture = CapturedTrace::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    let response = app
        .oneshot(platform_liveness_request(
            "127.0.0.1",
            Some("secret-forwarded-header-value"),
        ))
        .with_subscriber(subscriber)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !capture.text().contains("secret-forwarded-header-value"),
        "captured events: {}",
        capture.text()
    );
}

#[tokio::test]
async fn platform_documentation_is_private_and_registration_matches_python() {
    let app = build_router(memory_state(false).await);

    for path in [
        "/platform/openapi.json",
        "/platform/docs",
        "/platform/redoc",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }

    let missing_registration = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/authorization/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_registration.status(), StatusCode::BAD_REQUEST);
    let missing_registration: Value = serde_json::from_slice(
        &to_bytes(missing_registration.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(missing_registration["error_code"], "AUTH001");

    let registration = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/authorization/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "public@example.com",
                        "password": fixture_password()
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(registration.status(), StatusCode::CREATED);
    let registration: Value =
        serde_json::from_slice(&to_bytes(registration.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(registration["message"], "User created successfully");

    let (admin_cookie, _) = login(&app).await;
    for path in [
        "/platform/openapi.json",
        "/platform/docs",
        "/platform/redoc",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn user_managers_cannot_assign_or_escalate_to_admin() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "roles",
            json!({"role_name": "user-manager", "manage_users": true}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": "manager",
                "email": "manager@example.com",
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": "user-manager",
                "active": true
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login_as(&app, "manager@example.com", fixture_password()).await;

    for (method, path, payload) in [
        (
            "POST",
            "/platform/users",
            json!({
                "username": "new-admin",
                "email": "new-admin@example.com",
                "password": fixture_password(),
                "role": "admin"
            }),
        ),
        ("PUT", "/platform/users/manager", json!({"role": "admin"})),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn platform_preflight_is_public_with_python_credentials_default() {
    let app = build_router(memory_state(false).await);
    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
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
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    assert!(response.headers().contains_key("request_id"));
    assert!(response.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn memory_mode_login_crud_import_and_rollback_are_native() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    json!({
                        "api_name": "native",
                        "api_version": "v1",
                        "api_type": "REST",
                        "api_public": true,
                        "api_auth_required": false
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let imported = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/config/import")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    json!({
                        "apis": [{
                            "api_name": "replacement",
                            "api_version": "v1",
                            "api_id": "replacement-id",
                            "api_public": true
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(imported.status(), StatusCode::OK);

    let rollback = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/config/rollback")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rollback.status(), StatusCode::OK);

    let restored = app
        .oneshot(
            Request::builder()
                .uri("/platform/api/native/v1")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(restored.into_body(), 16 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["api_name"], "native");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes this test's process-global VAULT_KEY mutation.
async fn vault_lifecycle_encrypts_at_rest_and_never_returns_the_secret() {
    let _guard = VAULT_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();
    let previous = std::env::var_os("VAULT_KEY");
    // Environment mutation is serialized within this test target. No other
    // test consumes VAULT_KEY, and it is restored before the test returns.
    unsafe { std::env::set_var("VAULT_KEY", "vault-test-key-not-for-production") };

    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let secret = "vault-plaintext-must-not-leak";

    let created = platform_request(
        &app,
        Method::POST,
        "/platform/vault",
        Some(&cookie),
        None,
        Some(json!({
            "key_name": "payments",
            "value": secret,
            "description": "payment provider credential"
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        response_json(created).await,
        json!({"message": "Vault entry created successfully"})
    );

    let stored = storage
        .find_one(
            "vault_entries",
            &json!({"username": "admin", "key_name": "payments"}),
        )
        .await
        .unwrap()
        .unwrap();
    let ciphertext = stored["encrypted_value"].as_str().unwrap();
    assert!(ciphertext.starts_with("v1:"));
    assert_ne!(ciphertext, secret);
    assert!(!ciphertext.contains(secret));
    assert!(stored["created_at"].as_str().unwrap().ends_with("+00:00"));
    assert!(stored["updated_at"].as_str().unwrap().ends_with("+00:00"));

    for path in ["/platform/vault", "/platform/vault/payments"] {
        let response = platform_request(&app, Method::GET, path, Some(&cookie), None, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        // ResponseModel silently drops VaultService's `data` keyword, so the
        // pinned Python wire response is an empty object despite its OpenAPI
        // examples advertising entries and metadata.
        assert_eq!(response_json(response).await, json!({}), "{path}");
    }

    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/vault/payments",
        Some(&cookie),
        None,
        Some(json!({"description": "rotated externally"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(
        response_json(updated).await,
        json!({"message": "Vault entry updated successfully"})
    );
    let after_update = storage
        .find_one(
            "vault_entries",
            &json!({"username": "admin", "key_name": "payments"}),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_update["encrypted_value"], ciphertext);
    assert_eq!(after_update["description"], "rotated externally");

    let no_description_change = platform_request(
        &app,
        Method::PUT,
        "/platform/vault/payments",
        Some(&cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(no_description_change.status(), StatusCode::OK);
    let after_empty_update = storage
        .find_one(
            "vault_entries",
            &json!({"username": "admin", "key_name": "payments"}),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_empty_update["description"], "rotated externally");

    let coerced = platform_request(
        &app,
        Method::POST,
        "/platform/vault",
        Some(&cookie),
        None,
        Some(json!({"key_name": 12, "value": 34, "description": true})),
    )
    .await;
    assert_eq!(coerced.status(), StatusCode::CREATED);
    let coerced = storage
        .find_one(
            "vault_entries",
            &json!({"username": "admin", "key_name": "12"}),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(coerced["description"], "True");

    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/vault",
        Some(&cookie),
        None,
        Some(json!({"key_name": [], "value": {}})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response_json(invalid).await["error_code"], "VAL001");

    let deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/vault/payments",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(
        storage
            .find_one(
                "vault_entries",
                &json!({"username": "admin", "key_name": "payments"}),
            )
            .await
            .unwrap()
            .is_none()
    );

    unsafe {
        match previous {
            Some(value) => std::env::set_var("VAULT_KEY", value),
            None => std::env::remove_var("VAULT_KEY"),
        }
    };
}

#[tokio::test]
async fn https_mode_requires_matching_csrf_and_preserves_request_id() {
    let app = build_router(memory_state(true).await);
    let (cookie, csrf) = login(&app).await;

    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/user/me")
                .header(header::COOKIE, &cookie)
                .header("x-request-id", "csrf-rejected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(rejected.headers()["request_id"], "csrf-rejected");

    let mismatched = platform_request(
        &app,
        Method::GET,
        "/platform/user/me",
        Some(&cookie),
        Some("not-the-cookie"),
        None,
    )
    .await;
    assert_eq!(mismatched.status(), StatusCode::UNAUTHORIZED);

    let accepted = platform_request(
        &app,
        Method::GET,
        "/platform/user/me",
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);

    let http_app = build_router(memory_state(false).await);
    let (http_cookie, _) = login(&http_app).await;
    let accepted_without_csrf = platform_request(
        &http_app,
        Method::GET,
        "/platform/user/me",
        Some(&http_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(accepted_without_csrf.status(), StatusCode::OK);
}

// Cookie options are read per request from the environment in both the pinned
// Python routes and Rust compatibility handler. Run each variant in a child so
// Rust's parallel test workers never observe another case's cookie policy.
#[tokio::test]
async fn cookie_policy_and_host_only_domain_match_python() {
    if let Ok(case) = std::env::var("DOORMAN_COOKIE_POLICY_CHILD") {
        let app = build_router(memory_state(false).await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/platform/authorization")
                    .header(header::HOST, "testserver")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"email": "admin@doorman.dev", "password": fixture_password()})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        for cookie in &cookies {
            assert!(cookie.contains("Path=/"));
            assert!(cookie.contains("Max-Age=1800"));
            assert!(
                !cookie.contains("Domain="),
                "testserver must be host-only: {cookie}"
            );
            match case.as_str() {
                "default" => {
                    assert!(cookie.contains("SameSite=Strict"));
                    assert!(!cookie.contains("; Secure"));
                }
                "lax" => {
                    assert!(cookie.contains("SameSite=Lax"));
                    assert!(!cookie.contains("; Secure"));
                }
                "secure" => {
                    assert!(cookie.contains("SameSite=None"));
                    assert!(cookie.contains("; Secure"));
                }
                _ => unreachable!("unknown child case"),
            }
        }
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("csrf_token="))
        );
        assert!(cookies.iter().any(
            |cookie| cookie.starts_with("access_token_cookie=") && cookie.contains("HttpOnly")
        ));
        return;
    }

    for (case, same_site, https_only) in [
        ("default", None, "false"),
        ("lax", Some("Lax"), "false"),
        ("secure", Some("None"), "true"),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "cookie_policy_and_host_only_domain_match_python",
                "--nocapture",
            ])
            .env("DOORMAN_COOKIE_POLICY_CHILD", case)
            .env("HTTPS_ONLY", https_only)
            .env("COOKIE_DOMAIN", "testserver")
            .env_remove("COOKIE_SECURE")
            .env_remove("COOKIE_SAMESITE");
        if let Some(same_site) = same_site {
            command.env("COOKIE_SAMESITE", same_site);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "cookie case {case} failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn tampered_jwt_is_rejected_with_python_compatible_unauthorized_status() {
    use jsonwebtoken::{EncodingKey, Header, encode};

    let app = build_router(memory_state(false).await);
    let token = encode(
        &Header::default(),
        &json!({
            "sub": "admin", "jti": "forged", "exp": usize::MAX,
            "iss": "doorman-gateway", "aud": "doorman-gateway"
        }),
        &EncodingKey::from_secret(b"wrong-secret"),
    )
    .unwrap();
    let response = platform_request(
        &app,
        Method::GET,
        "/platform/user/me",
        Some(&format!("access_token_cookie={token}")),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["error_code"], "AUTH003");
    assert_eq!(body["error_message"], "Unauthorized");
}

#[tokio::test]
async fn strict_envelope_preserves_legacy_status_tokens_and_probe_shape() {
    let mut state = memory_state(false).await;
    state.config.strict_response_envelope = true;
    let app = build_router(state);

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
                        "password": fixture_password()
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-body-length"));
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["status_code"], 200);
    assert_eq!(body["access_token"], body["response"]["access_token"]);
    assert_eq!(body["refresh_token"], body["response"]["refresh_token"]);

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
                        "password": "wrong-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["status_code"], 400);
    assert!(body.get("error_code").is_some());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(body, json!({"status": "online"}));
}

#[tokio::test]
async fn rest_strict_response_envelope_wraps_proxy_message_like_python() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/e", get(|| async { Json(json!({"method": "GET"})) })),
        )
        .await
        .unwrap();
    });
    let loose = response_envelope_rest_app(false, &upstream_url).await;
    let strict = response_envelope_rest_app(true, &upstream_url).await;
    for (app, is_strict) in [(loose, false), (strict, true)] {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/rest/envelope-rest/v1/e")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4 * 1024).await.unwrap())
                .unwrap();
        if is_strict {
            assert_eq!(body["status_code"], 200);
            assert_eq!(body["response"]["method"], "GET");
        } else {
            assert!(body.get("status_code").is_none());
            assert_eq!(body["method"], "GET");
        }
    }
    upstream.abort();
}

#[tokio::test]
async fn graphql_strict_response_envelope_wraps_proxy_data_like_python() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/graphql",
                post(|| async { Json(json!({"data": {"pong": true}})) }),
            ),
        )
        .await
        .unwrap();
    });
    let loose = response_envelope_graphql_app(false, &upstream_url).await;
    let strict = response_envelope_graphql_app(true, &upstream_url).await;
    for (app, is_strict) in [(loose, false), (strict, true)] {
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/graphql/envelope-graphql")
                    .header("x-api-version", "v1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"query": "{ ping }", "variables": {}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4 * 1024).await.unwrap())
                .unwrap();
        if is_strict {
            assert_eq!(body["status_code"], 200);
            assert_eq!(body["response"]["data"]["pong"], true);
        } else {
            assert!(body.get("status_code").is_none());
            assert_eq!(body["data"]["pong"], true);
        }
    }
    upstream.abort();
}

#[tokio::test]
async fn graphql_group_restriction_blocks_subscribed_non_member_before_upstream() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "gql-group", "api_version": "v1", "api_id": "gql-group",
                "api_type": "GRAPHQL", "api_allowed_roles": ["admin"],
                "api_allowed_groups": ["vip-only"], "api_servers": ["http://127.0.0.1:9"], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoints",
            json!({
                "api_name": "gql-group", "api_version": "v1", "endpoint_method": "POST",
                "endpoint_uri": "/graphql", "client_uri": "/graphql"
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "admin", "apis": ["gql-group/v1"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/graphql/gql-group")
                .header(header::COOKIE, cookie)
                .header("x-api-version", "v1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"query": "{ ping }"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
}

#[tokio::test]
async fn soap_upstream_not_found_maps_to_python_404() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/call", post(|| async { StatusCode::NOT_FOUND })),
        )
        .await
        .unwrap();
    });
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "soap404", "api_version": "v1", "api_id": "soap404",
                "api_type": "SOAP", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"],
                "api_servers": [upstream_url], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoints",
            json!({
                "api_name": "soap404", "api_version": "v1", "endpoint_method": "POST",
                "endpoint_uri": "/call", "client_uri": "/call"
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "admin", "apis": ["soap404/v1"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/soap/soap404/v1/call")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from("<Request/>"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    upstream.abort();
}

#[tokio::test]
async fn soap_text_xml_valid_request_passes_endpoint_validation_and_proxies() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/call",
                post(|| async { ([(header::CONTENT_TYPE, "text/xml")], "<ok/>") }),
            ),
        )
        .await
        .unwrap();
    });
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "soaptext", "api_version": "v1", "api_id": "soaptext",
                "api_type": "SOAP", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"],
                "api_servers": [upstream_url], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoints",
            json!({
                "endpoint_id": "soaptext-call", "api_name": "soaptext", "api_version": "v1",
                "endpoint_method": "POST", "endpoint_uri": "/call", "client_uri": "/call"
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoint_validations",
            json!({
                "endpoint_id": "soaptext-call", "validation_enabled": true,
                "validation_schema": {"name": {"required": true, "type": "string", "min": 2}}
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "admin", "apis": ["soaptext/v1"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/soap/soaptext/v1/call")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "text/xml")
                .body(Body::from(
                    r#"<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><Request><name>Ab</name></Request></soapenv:Body></soapenv:Envelope>"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/xml");
    assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(), "<ok/>");
    upstream.abort();
}

#[tokio::test]
async fn platform_uses_the_configured_default_request_body_limit() {
    let app = build_router(memory_state(false).await);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/authorization")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'x'; 1024 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(body["error_code"], "REQ001");
}

#[tokio::test]
async fn configured_platform_body_limit_returns_python_413() {
    if std::env::var_os("DOORMAN_BODY_LIMIT_CHILD").is_some() {
        let app = build_router(memory_state(false).await);
        let within_limit = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/platform/authorization")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .body(Body::from("x".repeat(10)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(within_limit.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let get = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/platform/authorization/status")
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(get.status(), StatusCode::PAYLOAD_TOO_LARGE);

        for (method, path) in [
            (Method::POST, "/platform/authorization"),
            (Method::POST, "/platform/user"),
            (Method::POST, "/platform/api"),
            (Method::POST, "/platform/endpoint"),
            (Method::PUT, "/platform/user/testuser"),
            (Method::PATCH, "/platform/user/testuser"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .header(header::TRANSFER_ENCODING, "chunked")
                        .body(Body::from("x".repeat(100)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{path}");
            assert_eq!(
                response_json(response).await["error_code"],
                "REQ001",
                "{path}"
            );
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/platform/authorization")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .body(Body::from("x".repeat(100)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "configured_platform_body_limit_returns_python_413",
            "--nocapture",
        ])
        .env("DOORMAN_BODY_LIMIT_CHILD", "1")
        .env("MAX_BODY_SIZE_BYTES", "10")
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
async fn strict_wildcard_cors_allows_localhost_like_python() {
    if std::env::var_os("DOORMAN_CORS_CHILD").is_some() {
        let app = build_router(memory_state(false).await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/platform/monitor/liveness")
                    .header(header::ORIGIN, "http://localhost:3000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://localhost:3000"
        );
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
            "true"
        );
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "strict_wildcard_cors_allows_localhost_like_python",
            "--nocapture",
        ])
        .env("DOORMAN_CORS_CHILD", "1")
        .env("CORS_STRICT", "true")
        .env("ALLOWED_ORIGINS", "*")
        .env("ALLOW_CREDENTIALS", "true")
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
async fn proto_upload_ignores_the_client_filename_like_python() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let boundary = "doorman-proto-boundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../svc.proto\"\r\nContent-Type: application/octet-stream\r\n\r\nsyntax = \"proto3\"; package x;\r\n--{boundary}--\r\n"
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/proto/svc/v1")
                .header(header::COOKIE, cookie)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["message"],
        "Proto file uploaded and gRPC code generated successfully"
    );
}

#[tokio::test]
async fn proto_upload_extension_acceptance_matches_python_contract() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let boundary = "doorman-proto-extension-boundary";
    let multipart = |filename: &str, content_type: &str, content: &str| {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n{content}\r\n--{boundary}--\r\n"
        )
    };
    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/proto/sample/v1")
                .header(header::COOKIE, &cookie)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart(
                    "bad.txt",
                    "text/plain",
                    "syntax = \"proto3\";",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(rejected).await["error_code"], "REQ003");

    let accepted = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/proto/sample/v1")
                .header(header::COOKIE, &cookie)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart(
                    "ok.proto",
                    "application/octet-stream",
                    "syntax = \"proto3\";\npackage sample_v1;\nmessage Ping { string msg = 1; }",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert!(
        response_json(accepted).await["message"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .starts_with("proto file uploaded")
    );

    let updated = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/platform/proto/sample/v1")
                .header(header::COOKIE, &cookie)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart(
                    "sample.proto",
                    "text/plain",
                    "syntax = \"proto3\";\nmessage Pong { string y = 1; }",
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(
        response_json(updated).await,
        json!({"message": "Proto file updated successfully"})
    );
    let fetched = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/proto/sample/v1")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched = response_json(fetched).await;
    assert_eq!(fetched["message"], "Proto file retrieved successfully");
    assert!(fetched["content"].as_str().unwrap().contains("Pong"));
    let deleted = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/platform/proto/sample/v1")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(
        response_json(deleted).await,
        json!({"message": "Proto file and generated files deleted successfully"})
    );
    for path in [
        "/platform/proto/sample/v1",
        "/platform/proto/doesnotexist/v9",
    ] {
        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response_json(missing).await["error_code"],
            "API002",
            "{path}"
        );
    }
}

#[tokio::test]
async fn api_creation_attaches_proto_uploaded_before_the_api() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let source = "syntax = \"proto3\"; message Hello { string name = 1; }";
    let uploaded = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/proto/proto-before-api/v1")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(source))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uploaded.status(), StatusCode::OK);
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/api",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "proto-before-api", "api_version": "v1", "api_description": "preuploaded proto",
            "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"],
            "api_servers": ["grpc://127.0.0.1:50051"], "api_type": "GRPC", "active": true
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let stored = platform_request(
        &app,
        Method::GET,
        "/platform/api/proto-before-api/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(stored.status(), StatusCode::OK);
    let stored = response_json(stored).await;
    assert_eq!(stored["api_grpc_proto_source"], source);
    assert!(
        !stored["api_grpc_descriptor_set"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    assert!(
        !stored["api_grpc_descriptor_sha256"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
}

#[tokio::test]
async fn descriptor_backfill_compiles_active_grpc_apis_missing_descriptors() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "orders", "api_version": "v1", "api_type": "GRPC", "active": true,
                "api_grpc_proto_source": "syntax = \"proto3\"; message Order { string id = 1; }"
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "ready", "api_version": "v1", "api_type": "GRPC", "active": true,
                "api_grpc_proto_source": "syntax = \"proto3\"; message Ready {}",
                "api_grpc_descriptor_set": "already-present"
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let response = platform_request(
        &app,
        Method::POST,
        "/platform/proto/descriptors/backfill",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = response_json(response).await;
    assert_eq!(result["scanned"], 2);
    assert_eq!(result["updated"], 1);
    assert_eq!(result["skipped"], 1);
    assert_eq!(result["missing"], 0);
    let orders = storage
        .find_one("apis", &json!({"api_name": "orders", "api_version": "v1"}))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !orders["api_grpc_descriptor_set"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // Serializes this test's process-global MAX_PAGE_SIZE mutation.
async fn configured_pagination_caps_and_invalid_values_match_python() {
    let _lock = PAGINATION_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let request = |path| platform_request(&app, Method::GET, path, Some(&cookie), None, None);

    let api_cap = EnvVarRestore::apply(&[("MAX_PAGE_SIZE", Some("5"))]);
    assert_eq!(
        request("/platform/api/all?page=1&page_size=5")
            .await
            .status(),
        StatusCode::OK
    );
    let rejected = request("/platform/api/all?page=1&page_size=6").await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert!(response_json(rejected).await.get("error_message").is_some());
    drop(api_cap);

    let user_cap = EnvVarRestore::apply(&[("MAX_PAGE_SIZE", Some("3"))]);
    assert_eq!(
        request("/platform/user/all?page=1&page_size=3")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request("/platform/user/all?page=1&page_size=4")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    drop(user_cap);

    let invalid_values = EnvVarRestore::apply(&[("MAX_PAGE_SIZE", Some("10"))]);
    assert_eq!(
        request("/platform/role/all?page=0&page_size=5")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request("/platform/group/all?page=1&page_size=0")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    drop(invalid_values);
}

#[tokio::test]
async fn limited_role_cannot_manage_monitor_credits_caches_or_endpoint_validation() {
    let (app, cookie) = config_permission_app(None, "permission-limited").await;
    let monitor = platform_request(
        &app,
        Method::GET,
        "/platform/monitor/metrics",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(monitor.status(), StatusCode::FORBIDDEN);
    let credit = platform_request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&cookie),
        None,
        Some(json!({
            "api_credit_group": "limited",
            "api_key": "x",
            "api_key_header": "x-api-key",
            "credit_tiers": [{
                "tier_name": "default",
                "credits": 1,
                "input_limit": 0,
                "output_limit": 0,
                "reset_frequency": "monthly"
            }]
        })),
    )
    .await;
    assert_eq!(credit.status(), StatusCode::FORBIDDEN);
    let validation = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint/endpoint/validation",
        Some(&cookie),
        None,
        Some(json!({
            "endpoint_id": "missing",
            "validation_enabled": true,
            "validation_schema": {"validation_schema": {}}
        })),
    )
    .await;
    assert_eq!(validation.status(), StatusCode::FORBIDDEN);
    let caches = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/caches")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(caches.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rust_gateway_activity_json_has_queryable_python_log_fields() {
    let directory = std::env::temp_dir().join(format!("doorman-activity-log-{}", Uuid::new_v4()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/log", any(|| async { Json(json!({"ok": true})) })),
        )
        .await
        .unwrap();
    });
    let mut state = memory_state(false).await;
    state.config.logs_dir = Some(directory.clone());
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "log-api", "api_version": "v1", "api_id": "log-api",
                "api_type": "REST", "api_allowed_roles": ["admin"],
                "api_allowed_groups": ["ALL"], "api_servers": [upstream_url], "active": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "endpoints",
            json!({"api_name": "log-api", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/log"}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "admin", "apis": ["log-api/v1"]}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/rest/log-api/v1/log")
                .header(header::COOKIE, cookie)
                .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 10], 44000))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // The activity sink uses asynchronous filesystem I/O. Under the parallel
    // integration target, accept the same bounded eventual consistency that a
    // log reader has in production instead of racing a just-completed write.
    let record = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(records) = std::fs::read_to_string(directory.join("doorman.log.rust")) {
                if let Some(record) = records
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .find(|record| record["type"] == "gateway" && record["endpoint"] == "/log")
                {
                    return record;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gateway activity record");
    for field in [
        "request_id",
        "type",
        "user",
        "api",
        "endpoint",
        "method",
        "status_code",
        "response_time",
        "ip_address",
    ] {
        assert!(record.get(field).is_some(), "missing {field}: {record}");
    }
    assert_eq!(record["user"], "admin");
    assert_eq!(record["api"], "rest:log-api");
    assert_eq!(record["endpoint"], "/log");
    assert_eq!(record["method"], "GET");
    assert_eq!(record["status_code"], 200);
    assert_eq!(record["ip_address"], "192.0.2.10");
    upstream.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn proto_retrieval_requires_manage_apis_permission() {
    let (app, cookie) = config_permission_app(None, "proto-viewer").await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/platform/proto/private/v1")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_json(response).await;
    assert_eq!(body["error_code"], "AUTH001");
    assert_eq!(
        body["error_message"],
        "User does not have permission to manage APIs"
    );
}

#[tokio::test]
async fn platform_security_headers_csp_hsts_and_request_ids_match_python() {
    let app = build_router(memory_state(false).await);
    let plain = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/liveness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(plain.status(), StatusCode::OK);
    assert_eq!(plain.headers()["x-content-type-options"], "nosniff");
    assert_eq!(plain.headers()["x-frame-options"], "DENY");
    assert_eq!(plain.headers()["referrer-policy"], "no-referrer");
    assert!(
        plain.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    assert!(!plain.headers().contains_key("strict-transport-security"));
    assert!(!plain.headers()["x-request-id"].is_empty());
    assert_eq!(
        plain.headers()["x-request-id"],
        plain.headers()["request_id"]
    );

    let mut state = memory_state(true).await;
    state.config.content_security_policy = Some("default-src 'self'".to_owned());
    let secure_app = build_router(state);
    let secure = secure_app
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/liveness")
                .header("x-request-id", "python-request-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(secure.status(), StatusCode::OK);
    assert_eq!(
        secure.headers()["content-security-policy"],
        "default-src 'self'"
    );
    assert!(secure.headers().contains_key("strict-transport-security"));
    assert_eq!(secure.headers()["x-request-id"], "python-request-id");
    assert_eq!(secure.headers()["request_id"], "python-request-id");

    let docs_app = build_router(memory_state(false).await);
    let (cookie, _) = login(&docs_app).await;
    let docs = platform_request(
        &docs_app,
        Method::GET,
        "/platform/docs",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(docs.status(), StatusCode::OK);
    assert!(
        !docs.headers().contains_key("x-frame-options"),
        "{:?}",
        docs.headers()
    );
    assert!(
        docs.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors *")
    );
}

#[tokio::test]
async fn memory_mode_parses_and_imports_wsdl_without_an_external_service() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let wsdl = r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" targetNamespace="urn:billing"><service name="Billing"/><portType name="BillingPort"><operation name="Charge"><input message="tns:ChargeRequest"/><output message="tns:ChargeResponse"/></operation></portType><binding name="BillingBinding"><operation name="Charge"><soap:operation soapAction="urn:charge"/></operation></binding></definitions>"#;

    let preview = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/wsdl/parse")
                .header(header::CONTENT_TYPE, "application/xml")
                .header(header::COOKIE, &cookie)
                .body(Body::from(wsdl))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    let preview: Value =
        serde_json::from_slice(&to_bytes(preview.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(preview["service_name"], "Billing");
    assert_eq!(preview["operations"][0]["soap_action"], "urn:charge");

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    json!({
                        "api_name": "soap",
                        "api_version": "v1",
                        "api_type": "SOAP",
                        "api_public": true,
                        "api_auth_required": false,
                        "api_wsdl_content": wsdl
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let imported = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api/soap/v1/wsdl/import")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(imported.status(), StatusCode::OK);
    let imported: Value =
        serde_json::from_slice(&to_bytes(imported.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(imported["service_name"], "Billing");
    assert_eq!(imported["operations_found"], 1);
    assert_eq!(imported["endpoints_imported"], 1);
}

#[tokio::test]
async fn config_reload_routes_preserve_legacy_values_metadata_and_permissions() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "roles",
            json!({"role_name": "viewer", "manage_gateway": false}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": "viewer",
                "email": "viewer@doorman.dev",
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": "viewer",
                "groups": [],
                "active": true
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (admin_cookie, _) = login(&app).await;
    let (viewer_cookie, _) = login_as(&app, "viewer@doorman.dev", fixture_password()).await;

    let keys = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/config/reloadable-keys")
                .header(header::COOKIE, &viewer_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(keys.status(), StatusCode::FORBIDDEN);

    let keys = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/config/reloadable-keys")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(keys.status(), StatusCode::OK);
    let keys: Value =
        serde_json::from_slice(&to_bytes(keys.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(keys["total"], 3);
    assert_eq!(keys["reloadable_keys"][0]["key"], "GATEWAY_TIMEOUT");
    assert_eq!(keys["restart_required_keys"][0]["key"], "LOG_LEVEL");
    assert_eq!(keys["notes"].as_array().unwrap().len(), 3);

    for (method, path) in [
        ("GET", "/platform/config/current"),
        ("POST", "/platform/config/reload"),
        ("GET", "/platform/config/export/apis"),
        ("GET", "/platform/config/export/endpoints"),
        ("GET", "/platform/config/export/roles"),
        ("GET", "/platform/config/export/groups"),
        ("GET", "/platform/config/export/routings"),
    ] {
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, &viewer_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    let current = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/config/current")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(current.status(), StatusCode::OK);
    let current: Value =
        serde_json::from_slice(&to_bytes(current.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert!(current["config"].is_object());
    assert_eq!(
        current["source"],
        "Environment variables override config file values"
    );

    let reload = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/config/reload")
                .header(header::COOKIE, admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reload.status(), StatusCode::OK);
    let reload: Value =
        serde_json::from_slice(&to_bytes(reload.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        reload["message"],
        "Configuration reloaded; supported HTTP gateway settings apply to subsequent requests"
    );
    assert!(reload["config"].is_object());
    assert_eq!(
        reload["applied"],
        json!(["GATEWAY_TIMEOUT", "RETRY_ENABLED", "RETRY_MAX_ATTEMPTS"])
    );
    assert_eq!(reload["restart_required"], true);
}

#[tokio::test]
async fn api_create_and_update_preserve_python_pydantic_and_duplicate_contracts() {
    let state = memory_state(false).await;
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let create_payload = json!({
        "api_name": "contract",
        "api_version": "v1",
        "api_description": "original",
        "api_credits_enabled": true,
        "unknown_field": "ignored"
    });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(create_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value =
        serde_json::from_slice(&to_bytes(created.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(created["api"]["api_allowed_roles"], json!([]));
    assert_eq!(created["api"]["api_auth_required"], true);
    assert_eq!(created["api"]["api_ip_mode"], "allow_all");
    assert!(created["api"].get("unknown_field").is_none());

    let duplicate = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    json!({
                        "api_name": "contract",
                        "api_version": "v1",
                        "api_description": "must-not-overwrite",
                        "api_credits_enabled": false
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);

    let stored = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/api/contract/v1")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let stored: Value =
        serde_json::from_slice(&to_bytes(stored.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(stored["api_description"], "original");
    assert_eq!(stored["api_credits_enabled"], true);

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/api")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    json!({"api_name": "", "api_version": "version-too-long"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let invalid: Value =
        serde_json::from_slice(&to_bytes(invalid.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(invalid["detail"].as_array().unwrap().len(), 2);

    let empty_update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/platform/api/contract/v1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(json!({"api_description": null}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty_update.status(), StatusCode::BAD_REQUEST);
    let empty_update: Value =
        serde_json::from_slice(&to_bytes(empty_update.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(empty_update["error_code"], "API006");

    let conflict = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/platform/api/contract/v1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(json!({"api_public": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);
    let conflict: Value =
        serde_json::from_slice(&to_bytes(conflict.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(conflict["error_code"], "API013");
}

#[tokio::test]
async fn management_permissions_readiness_tools_and_restart_preserve_contract() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "roles",
            json!({
                "role_name": "limited",
                "manage_gateway": false,
                "manage_security": false,
                "view_analytics": false,
                "view_logs": false,
                "export_logs": false
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": "limited",
                "email": "limited@doorman.dev",
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": "limited",
                "groups": [],
                "active": true
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (admin_cookie, _) = login(&app).await;
    let (limited_cookie, _) = login_as(&app, "limited@doorman.dev", fixture_password()).await;

    for path in [
        "/platform/logging/logs",
        "/platform/config/export/all",
        "/platform/routing/all",
    ] {
        let denied =
            platform_request(&app, Method::GET, path, Some(&limited_cookie), None, None).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{path}");
    }

    let public_readiness = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/readiness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public_readiness.status(), StatusCode::OK);
    let public_readiness: Value =
        serde_json::from_slice(&to_bytes(public_readiness.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(public_readiness.as_object().unwrap().len(), 1);
    assert!(matches!(
        public_readiness["status"].as_str(),
        Some("ready" | "degraded")
    ));

    let admin_readiness = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/readiness")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let admin_readiness: Value =
        serde_json::from_slice(&to_bytes(admin_readiness.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(admin_readiness.as_object().unwrap().len(), 7);
    assert!(admin_readiness.get("mongodb").is_some());
    assert!(admin_readiness.get("cache_backend").is_some());

    for (method, path, code) in [
        ("GET", "/platform/security/settings", "SEC001"),
        ("GET", "/platform/monitor/metrics", "MON001"),
        ("GET", "/platform/monitor/report", "MON002"),
        ("GET", "/platform/analytics/timeseries", "ANALYTICS001"),
        ("GET", "/platform/analytics/top-apis", "ANALYTICS001"),
        ("GET", "/platform/dashboard", "ANALYTICS001"),
        ("POST", "/platform/tools/rate-limit-simulator", "RATE001"),
        ("GET", "/platform/openapi.json", "API008"),
        ("GET", "/platform/docs", "API008"),
        ("GET", "/platform/redoc", "API008"),
        ("POST", "/platform/tools/cors/check", "TLS001"),
        ("GET", "/platform/tools/grpc/check", "TLS001"),
        ("GET", "/platform/tools/chaos/stats", "TLS001"),
    ] {
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &limited_cookie)
                    .body(Body::from(
                        json!({"origin": "http://localhost:3000", "method": "GET"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "{path}");
        let denied: Value =
            serde_json::from_slice(&to_bytes(denied.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(denied["error_code"], code, "{path}");
    }

    let grpc_check = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/tools/grpc/check")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(grpc_check.status(), StatusCode::OK);
    let grpc_check: Value =
        serde_json::from_slice(&to_bytes(grpc_check.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(grpc_check["available"]["grpc"], true);
    assert_eq!(grpc_check["available"]["grpc_tools_protoc"], true);
    assert!(grpc_check["notes"].is_array());
    assert!(grpc_check["details"].is_object());

    let chaos = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/tools/chaos/toggle")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::from(
                    json!({"backend": "redis", "enabled": true, "duration_ms": 5}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(chaos.status(), StatusCode::OK);
    let chaos: Value =
        serde_json::from_slice(&to_bytes(chaos.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(chaos, json!({"backend": "redis", "enabled": true}));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let chaos_stats = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/tools/chaos/stats")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let chaos_stats: Value =
        serde_json::from_slice(&to_bytes(chaos_stats.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(chaos_stats["redis_outage"], false);
    assert!(chaos_stats["error_budget_burn"].is_number());

    let invalid_chaos_backend = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/tools/chaos/toggle")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::from(
                    json!({"backend": "notabackend", "enabled": true}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_chaos_backend.status(), StatusCode::BAD_REQUEST);

    let restart = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/security/restart")
                .header(header::COOKIE, admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restart.status(), StatusCode::CONFLICT);
    let restart: Value =
        serde_json::from_slice(&to_bytes(restart.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(restart["error_code"], "SEC004");
}

#[tokio::test]
async fn tools_permissions_and_required_models_match_python() {
    let (gateway_app, gateway_cookie) =
        config_permission_app(Some("manage_gateway"), "tools-gateway").await;
    let chaos = platform_request(
        &gateway_app,
        Method::POST,
        "/platform/tools/chaos/toggle",
        Some(&gateway_cookie),
        None,
        Some(json!({"backend": "mongo", "enabled": false})),
    )
    .await;
    assert_eq!(chaos.status(), StatusCode::OK);

    let cors_denied = platform_request(
        &gateway_app,
        Method::POST,
        "/platform/tools/cors/check",
        Some(&gateway_cookie),
        None,
        Some(json!({"origin": "http://localhost:3000", "method": "GET"})),
    )
    .await;
    assert_eq!(cors_denied.status(), StatusCode::FORBIDDEN);

    let missing = platform_request(
        &gateway_app,
        Method::POST,
        "/platform/tools/chaos/toggle",
        Some(&gateway_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let missing: Value =
        serde_json::from_slice(&to_bytes(missing.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(missing["detail"].as_array().unwrap().len(), 2);
    assert_eq!(missing["detail"][0]["loc"], json!(["body", "backend"]));
    assert_eq!(missing["detail"][1]["loc"], json!(["body", "enabled"]));

    let (security_app, security_cookie) =
        config_permission_app(Some("manage_security"), "tools-security").await;
    let cors = platform_request(
        &security_app,
        Method::POST,
        "/platform/tools/cors/check",
        Some(&security_cookie),
        None,
        Some(json!({"origin": "http://not-allowed.example", "method": "GET"})),
    )
    .await;
    assert_eq!(cors.status(), StatusCode::OK);
    let cors: Value =
        serde_json::from_slice(&to_bytes(cors.into_body(), 16 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        cors["preflight"]["response_headers"]["Access-Control-Allow-Origin"],
        Value::Null
    );

    let chaos_denied = platform_request(
        &security_app,
        Method::POST,
        "/platform/tools/chaos/toggle",
        Some(&security_cookie),
        None,
        Some(json!({"backend": "redis", "enabled": true})),
    )
    .await;
    assert_eq!(chaos_denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn readiness_degrades_when_an_active_grpc_api_lacks_a_descriptor() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_name": "missing-grpc-descriptor",
                "api_version": "v1",
                "api_type": "GRPC",
                "active": true,
                "api_is_crud": false
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let response = platform_request(
        &app,
        Method::GET,
        "/platform/monitor/readiness",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let readiness = response_json(response).await;
    assert_eq!(readiness["status"], "degraded");
    assert_eq!(readiness["missing_grpc_descriptors"], 1);
    assert_eq!(
        readiness["grpc_descriptor_errors"][0]["api_name"],
        "missing-grpc-descriptor"
    );
}

#[tokio::test]
async fn readiness_matches_python_and_ignores_v2_background_task_health() {
    let state = memory_state(false).await;
    state
        .runtime
        .metrics_persistence_healthy
        .store(false, Ordering::Relaxed);
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let response = platform_request(
        &app,
        Method::GET,
        "/platform/monitor/readiness",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let readiness = response_json(response).await;
    assert_eq!(readiness["status"], "ready");
    assert!(readiness.get("metrics_persistence_healthy").is_none());
}

#[tokio::test]
async fn dashboard_preserves_python_v2_response_contract() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/platform/dashboard")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();

    for key in [
        "totalRequests",
        "activeUsers",
        "newApis",
        "monthlyUsage",
        "activeUsersList",
        "popularApis",
    ] {
        assert!(body.get(key).is_some(), "missing dashboard field {key}");
    }
    assert!(body["totalRequests"].is_number());
    assert!(body["monthlyUsage"].is_object());
    assert!(body.get("users").is_none());
}

#[tokio::test]
async fn analytics_routes_preserve_python_v2_response_contracts() {
    use doorman_gateway::observability::analytics_aggregator::global_analytics;

    global_analytics().record_request(
        Some("rest:contract-analytics"),
        Some("analytics-user"),
        Some("/contract-analytics/v1/items"),
        503,
        25.0,
        11,
        29,
    );

    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;

    let overview = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/analytics/overview?range=1h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(overview.status(), StatusCode::OK);
    let overview: Value =
        serde_json::from_slice(&to_bytes(overview.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert!(overview["summary"]["total_requests"].as_u64().unwrap() >= 1);
    assert!(overview["time_range"]["duration_seconds"].is_number());
    assert!(overview["percentiles"]["p95"].is_number());
    assert!(overview["top_apis"].is_array());
    assert!(overview["status_distribution"].is_object());

    let timeseries = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/analytics/timeseries?range=1h&metric_type=error_rate")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let timeseries: Value =
        serde_json::from_slice(&to_bytes(timeseries.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(timeseries["granularity"], "auto");
    assert_eq!(
        timeseries["data_points"],
        timeseries["series"].as_array().unwrap().len()
    );
    assert!(timeseries["series"][0]["error_rate"].is_number());

    let top = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/analytics/top-apis?limit=1")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let top: Value =
        serde_json::from_slice(&to_bytes(top.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert!(top["top_apis"][0]["api"].is_string());
    assert!(top["total_apis"].is_number());

    for (path, field, kind) in [
        (
            "/platform/analytics/top-users?limit=0",
            "limit",
            "value_error.number.not_ge",
        ),
        (
            "/platform/analytics/overview?start_ts=not-an-int",
            "start_ts",
            "type_error.integer",
        ),
    ] {
        let invalid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let invalid: Value =
            serde_json::from_slice(&to_bytes(invalid.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(invalid["detail"][0]["loc"], json!(["query", field]));
        assert_eq!(invalid["detail"][0]["type"], kind);
    }

    let detail = app
        .oneshot(
            Request::builder()
                .uri("/platform/analytics/api/contract-analytics/v1?range=1h")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail: Value =
        serde_json::from_slice(&to_bytes(detail.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(detail["api_name"], "contract-analytics");
    assert_eq!(detail["version"], "v1");
    assert_eq!(detail["summary"]["api"], "rest:contract-analytics");
}
#[tokio::test]
async fn python_api_disabled_blocks_rest_graphql_grpc_and_soap() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let created = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": "disabled-api", "api_version": "v1", "api_description": "disabled API parity", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "active": true}))).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    for (method, path, payload, content_type) in [
        (
            Method::POST,
            "/platform/endpoint",
            json!({"api_name": "disabled-api", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/status", "endpoint_description": "status"}),
            "application/json",
        ),
        (
            Method::POST,
            "/platform/endpoint",
            json!({"api_name": "disabled-api", "api_version": "v1", "endpoint_method": "POST", "endpoint_uri": "/op", "endpoint_description": "op"}),
            "application/json",
        ),
        (
            Method::POST,
            "/platform/subscription/subscribe",
            json!({"username": "admin", "api_name": "disabled-api", "api_version": "v1"}),
            "application/json",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
    }
    let disabled = platform_request(
        &app,
        Method::PUT,
        "/platform/api/disabled-api/v1",
        Some(&cookie),
        None,
        Some(json!({"active": false})),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    for (method, path, content_type, body) in [
        (
            Method::GET,
            "/api/rest/disabled-api/v1/status",
            "application/json",
            "",
        ),
        (
            Method::POST,
            "/api/graphql/disabled-api",
            "application/json",
            "{\"query\":\"{__typename}\"}",
        ),
        (
            Method::POST,
            "/api/grpc/disabled-api",
            "application/json",
            "{\"method\":\"X\",\"message\":{}}",
        ),
        (
            Method::POST,
            "/api/soap/disabled-api/v1/op",
            "text/xml",
            "<Envelope/>",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, &cookie)
                    .header("x-api-version", "v1")
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        let body = response_json(response).await;
        assert_eq!(body["error_code"], "GTW012", "{path}");
    }
}
#[tokio::test]
async fn python_api_and_endpoint_crud_lookup_and_missing_contracts() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let api_name = "customer";
    let api_version = "v1";
    let created = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": api_name, "api_version": api_version, "api_description": "Customer API", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://upstream.local"], "api_type": "REST", "api_allowed_retry_count": 0}))).await;
    assert!(created.status().is_success());
    let api = platform_request(
        &app,
        Method::GET,
        "/platform/api/customer/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(api.status(), StatusCode::OK);
    let api = response_json(api).await;
    assert_eq!(api["api_name"], api_name);
    assert_eq!(api["api_version"], api_version);
    assert!(api.get("_id").is_none());
    let list = platform_request(
        &app,
        Method::GET,
        "/platform/api/all?page=1&page_size=10",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    assert!(
        list["apis"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value["api_name"] == api_name && value["api_version"] == api_version)
    );
    let group = platform_request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&cookie),
        None,
        Some(json!({"group_name": "customer-list", "group_description": "list", "api_access": []})),
    )
    .await;
    assert!(group.status().is_success());
    let role = platform_request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&cookie),
        None,
        Some(json!({"role_name": "customer-list", "role_description": "list"})),
    )
    .await;
    assert!(role.status().is_success());
    for path in [
        "/platform/api/all?page=1&page_size=5",
        "/platform/group/all?page=1&page_size=5",
        "/platform/role/all?page=1&page_size=5",
    ] {
        assert_eq!(
            platform_request(&app, Method::GET, path, Some(&cookie), None, None)
                .await
                .status(),
            StatusCode::OK,
            "{path}"
        );
    }
    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/api/customer/v1",
        Some(&cookie),
        None,
        Some(json!({"api_description": "Customer API Updated"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let endpoint = platform_request(&app, Method::POST, "/platform/endpoint", Some(&cookie), None, Some(json!({"api_name": api_name, "api_version": api_version, "endpoint_method": "GET", "endpoint_uri": "/profile", "endpoint_description": "Get profile"}))).await;
    assert!(endpoint.status().is_success());
    let endpoint = platform_request(
        &app,
        Method::GET,
        "/platform/endpoint/GET/customer/v1/profile",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::OK);
    assert_eq!(response_json(endpoint).await["endpoint_method"], "GET");
    let endpoints = platform_request(
        &app,
        Method::GET,
        "/platform/endpoint/customer/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoints.status(), StatusCode::OK);
    let endpoint_updated = platform_request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/customer/v1/profile",
        Some(&cookie),
        None,
        Some(json!({"endpoint_description": "Get customer profile"})),
    )
    .await;
    assert_eq!(endpoint_updated.status(), StatusCode::OK);
    let endpoint_deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/endpoint/GET/customer/v1/profile",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoint_deleted.status(), StatusCode::OK);
    let deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/api/customer/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    for method in [Method::PUT, Method::DELETE] {
        let missing = platform_request(
            &app,
            method,
            "/platform/api/doesnot/v9",
            Some(&cookie),
            None,
            Some(json!({"api_description": "x"})),
        )
        .await;
        assert!(matches!(
            missing.status(),
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
        ));
    }
}

#[tokio::test]
async fn native_rest_graphql_and_soap_crud_builders_match_python_flows() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;

    for (name, api_type, endpoint) in [
        ("builder-rest", "REST", "/items"),
        ("builder-graphql", "GRAPHQL", "/graphql"),
        ("builder-soap", "SOAP", "/soap"),
    ] {
        let created = platform_request(
            &app,
            Method::POST,
            "/platform/api",
            Some(&cookie),
            None,
            Some(json!({
                "api_name": name,
                "api_version": "v1",
                "api_type": api_type,
                "api_public": true,
                "api_auth_required": false,
                "api_is_crud": true,
                "api_crud_collection": format!("crud_data_{name}"),
                "api_crud_schema": {"name": {"type": "string"}, "age": {"type": "number"}},
                "active": true,
            })),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED, "{name}");
        let endpoint = platform_request(
            &app,
            Method::POST,
            "/platform/endpoint",
            Some(&cookie),
            None,
            Some(json!({
                "api_name": name,
                "api_version": "v1",
                "endpoint_method": "POST",
                "endpoint_uri": endpoint,
                "endpoint_description": "native CRUD endpoint",
            })),
        )
        .await;
        assert!(endpoint.status().is_success(), "{name}");
    }
    let rest_list_endpoint = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "builder-rest",
            "api_version": "v1",
            "endpoint_method": "GET",
            "endpoint_uri": "/items",
            "endpoint_description": "native CRUD list endpoint",
        })),
    )
    .await;
    assert!(rest_list_endpoint.status().is_success());
    let soap_wsdl_endpoint = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "builder-soap",
            "api_version": "v1",
            "endpoint_method": "GET",
            "endpoint_uri": "/soap",
            "endpoint_description": "native CRUD WSDL endpoint",
        })),
    )
    .await;
    assert!(soap_wsdl_endpoint.status().is_success());

    let rest_create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/rest/builder-rest/v1/items")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"name": "REST User", "age": 30}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest_create.status(), StatusCode::CREATED);
    let rest_item = response_json(rest_create).await;
    let rest_id = rest_item["_id"].as_str().unwrap().to_owned();
    let rest_list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/rest/builder-rest/v1/items")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest_list.status(), StatusCode::OK);
    assert!(
        response_json(rest_list).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["_id"] == rest_id)
    );

    let graphql_create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/graphql/builder-graphql")
                .header("x-api-version", "v1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"query": "mutation { createItem }", "variables": {"input": {"name": "GQL User", "age": 25}}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(graphql_create.status(), StatusCode::OK);
    let graphql_item = response_json(graphql_create).await["data"]["createItem"].clone();
    let graphql_list = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/graphql/builder-graphql")
                .header("x-api-version", "v1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"query": "query { listItems { _id name } }"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response_json(graphql_list).await["data"]["listItems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["_id"] == graphql_item["_id"])
    );

    let wsdl = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/soap/builder-soap/v1/soap?wsdl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wsdl.status(), StatusCode::OK);
    assert!(
        String::from_utf8(
            to_bytes(wsdl.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec()
        )
        .unwrap()
        .contains("createItem")
    );
    let soap = "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><tns:createItem xmlns:tns=\"http://doorman.dev/builder-soap\"><input>{&quot;name&quot;:&quot;SOAP User&quot;,&quot;age&quot;:40}</input></tns:createItem></soap:Body></soap:Envelope>";
    let soap_create = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/soap/builder-soap/v1/soap")
                .header(header::CONTENT_TYPE, "text/xml")
                .body(Body::from(soap))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(soap_create.status(), StatusCode::OK);
    assert!(
        String::from_utf8(
            to_bytes(soap_create.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec()
        )
        .unwrap()
        .contains("SOAP User")
    );
}

async fn api_cors_preflight(
    app: &axum::Router,
    cookie: &str,
    path: &str,
    origin: &str,
    method: &str,
    requested_headers: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(path)
                .header(header::COOKIE, cookie)
                .header("x-api-version", "v1")
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, requested_headers)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn public_api_cors_preflight(
    app: &axum::Router,
    path: &str,
    origin: &str,
    method: &str,
    requested_headers: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(path)
                .header("x-api-version", "v1")
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, requested_headers)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}
#[tokio::test]
async fn python_api_rest_cors_origin_and_header_matrix() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let api = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": "cors-exact", "api_version": "v1", "api_description": "CORS parity", "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "api_public": true, "api_cors_allow_origins": ["http://ok.example"], "api_cors_allow_methods": ["GET"], "api_cors_allow_headers": ["Content-Type", "Authorization"], "api_cors_allow_credentials": true, "api_cors_expose_headers": ["X-Resp-Id", "X-Trace-Id"]}))).await;
    assert!(api.status().is_success());
    let endpoint = platform_request(&app, Method::POST, "/platform/endpoint", Some(&cookie), None, Some(json!({"api_name": "cors-exact", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/status", "endpoint_description": "status"}))).await;
    assert!(endpoint.status().is_success());
    let public_preflight = public_api_cors_preflight(
        &app,
        "/api/rest/cors-exact/v1/status",
        "http://ok.example",
        "GET",
        "Content-Type",
    )
    .await;
    assert_eq!(public_preflight.status(), StatusCode::NO_CONTENT);
    let allowed = api_cors_preflight(
        &app,
        &cookie,
        "/api/rest/cors-exact/v1/status",
        "http://ok.example",
        "GET",
        "Content-Type, Authorization",
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://ok.example"
    );
    assert_eq!(allowed.headers()[header::VARY], "Origin");
    assert_eq!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    assert!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
            .to_str()
            .unwrap()
            .contains("OPTIONS")
    );
    assert!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap()
            .contains("Content-Type")
    );
    assert!(
        allowed.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS]
            .to_str()
            .unwrap()
            .contains("X-Resp-Id")
    );
    let blocked = api_cors_preflight(
        &app,
        &cookie,
        "/api/rest/cors-exact/v1/status",
        "http://bad.example",
        "GET",
        "Content-Type",
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::NO_CONTENT);
    assert!(
        !blocked
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    let disallowed = api_cors_preflight(
        &app,
        &cookie,
        "/api/rest/cors-exact/v1/status",
        "http://ok.example",
        "GET",
        "X-Other",
    )
    .await;
    assert_eq!(
        disallowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://ok.example"
    );
    assert!(
        !disallowed.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap()
            .contains("X-Other")
    );
    let wildcard = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": "cors-wildcard", "api_version": "v1", "api_description": "CORS wildcard", "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "api_cors_allow_origins": ["*"], "api_cors_allow_methods": ["GET"], "api_cors_allow_headers": ["*"]}))).await;
    assert!(wildcard.status().is_success());
    let endpoint = platform_request(&app, Method::POST, "/platform/endpoint", Some(&cookie), None, Some(json!({"api_name": "cors-wildcard", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/status", "endpoint_description": "status"}))).await;
    assert!(endpoint.status().is_success());
    let wildcard = api_cors_preflight(
        &app,
        &cookie,
        "/api/rest/cors-wildcard/v1/status",
        "http://any.example",
        "GET",
        "X-Random-Header",
    )
    .await;
    assert_eq!(wildcard.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        wildcard.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "http://any.example"
    );
    assert!(
        wildcard.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap()
            .contains('*')
    );
}
#[tokio::test]
async fn python_api_graphql_and_soap_cors_preflight() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    for (name, api_type, path, credentials) in [
        ("cors-gql", "GRAPHQL", "/api/graphql/cors-gql", true),
        ("cors-soap", "SOAP", "/api/soap/cors-soap/v1/op", false),
    ] {
        let api = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": name, "api_version": "v1", "api_description": "protocol CORS parity", "api_servers": ["http://127.0.0.1:9"], "api_type": api_type, "api_public": true, "api_cors_allow_origins": ["http://foo"], "api_cors_allow_methods": ["POST"], "api_cors_allow_headers": ["Content-Type"], "api_cors_allow_credentials": credentials}))).await;
        assert!(api.status().is_success(), "{api_type}");
        let public_preflight =
            public_api_cors_preflight(&app, path, "http://foo", "POST", "Content-Type").await;
        assert_eq!(
            public_preflight.status(),
            StatusCode::NO_CONTENT,
            "{api_type}"
        );
        let denied_header =
            public_api_cors_preflight(&app, path, "http://foo", "POST", "X-Not-Allowed").await;
        assert_eq!(denied_header.status(), StatusCode::NO_CONTENT, "{api_type}");
        assert!(
            !denied_header
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            "{api_type}"
        );
        let response =
            api_cors_preflight(&app, &cookie, path, "http://foo", "POST", "Content-Type").await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{api_type}");
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://foo"
        );
        assert!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
                .to_str()
                .unwrap()
                .contains("POST")
        );
        assert!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .unwrap()
                .contains("Content-Type")
        );
        if credentials {
            assert_eq!(
                response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
                "true"
            );
        } else {
            assert!(
                !response
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            );
        }
    }
}
#[tokio::test]
async fn python_single_api_export_import_roundtrip() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let api_name = "cfg-roundtrip";
    let created = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": api_name, "api_version": "v1", "api_description": "cfg demo", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "active": true}))).await;
    assert!(created.status().is_success());
    let endpoint = platform_request(&app, Method::POST, "/platform/endpoint", Some(&cookie), None, Some(json!({"api_name": api_name, "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/x", "endpoint_description": "x"}))).await;
    assert!(endpoint.status().is_success());
    let exported = platform_request(
        &app,
        Method::GET,
        "/platform/config/export/apis?api_name=cfg-roundtrip&api_version=v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(exported.status(), StatusCode::OK);
    let exported = response_json(exported).await;
    let exported = exported.get("response").unwrap_or(&exported);
    let api = exported["api"].clone();
    let endpoints = exported["endpoints"].clone();
    assert_eq!(api["api_name"], api_name);
    assert!(
        endpoints
            .as_array()
            .unwrap()
            .iter()
            .any(|endpoint| endpoint["endpoint_uri"] == "/x")
    );
    let endpoint_deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/endpoint/GET/cfg-roundtrip/v1/x",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoint_deleted.status(), StatusCode::OK);
    let api_deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/api/cfg-roundtrip/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(api_deleted.status(), StatusCode::OK);
    let imported = platform_request(
        &app,
        Method::POST,
        "/platform/config/import",
        Some(&cookie),
        None,
        Some(json!({"apis": [api], "endpoints": endpoints})),
    )
    .await;
    assert_eq!(imported.status(), StatusCode::OK);
    let api = platform_request(
        &app,
        Method::GET,
        "/platform/api/cfg-roundtrip/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(api.status(), StatusCode::OK);
    let endpoint = platform_request(
        &app,
        Method::GET,
        "/platform/endpoint/GET/cfg-roundtrip/v1/x",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::OK);
}
#[tokio::test]
async fn python_endpoint_failure_and_validation_crud_contracts() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&cookie),
        None,
        Some(json!({"api_name": "x"})),
    )
    .await;
    assert!(matches!(
        invalid.status(),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
    ));
    let missing = platform_request(
        &app,
        Method::GET,
        "/platform/endpoint/GET/na/v1/does/not/exist",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let missing = response_json(missing).await;
    assert_eq!(missing["error_code"], "END004");
    assert_eq!(
        missing["error_message"],
        "Endpoint does not exist for the requested API name, version and URI"
    );
    let empty = platform_request(
        &app,
        Method::GET,
        "/platform/endpoint/na/v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(empty).await["error_code"], "END005");
    let api = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": "valapi", "api_version": "v1", "api_description": "validation api", "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"], "api_type": "REST", "active": true}))).await;
    assert!(api.status().is_success());
    let endpoint = platform_request(&app, Method::POST, "/platform/endpoint", Some(&cookie), None, Some(json!({"api_name": "valapi", "api_version": "v1", "endpoint_method": "POST", "endpoint_uri": "/payload", "endpoint_description": "payload"}))).await;
    assert!(endpoint.status().is_success());
    let endpoint = platform_request(
        &app,
        Method::GET,
        "/platform/endpoint/POST/valapi/v1/payload",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::OK);
    let endpoint_id = response_json(endpoint).await["endpoint_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let schema = json!({"validation_schema": {"id": {
        "required": 1,
        "type": "string",
        "min": "2",
        "nested_schema": null,
        "ignored": "field"
    }}});
    let validation = json!({
        "endpoint_id": endpoint_id.clone(),
        "validation_enabled": "yes",
        "validation_schema": schema,
        "ignored": "field"
    });
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/endpoint/endpoint/validation",
        Some(&cookie),
        None,
        Some(validation.clone()),
    )
    .await;
    assert!(created.status().is_success());
    let fetched = platform_request(
        &app,
        Method::GET,
        &format!("/platform/endpoint/endpoint/validation/{endpoint_id}"),
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched = response_json(fetched).await;
    assert_eq!(fetched["validation_enabled"], true);
    let id_rules = &fetched["validation_schema"]["validation_schema"]["id"];
    assert_eq!(id_rules["required"], true);
    assert_eq!(id_rules["min"], 2);
    assert_eq!(id_rules["max"], Value::Null);
    assert_eq!(id_rules["pattern"], Value::Null);
    assert!(id_rules.get("ignored").is_none());
    assert!(fetched.get("ignored").is_none());
    let updated = platform_request(
        &app,
        Method::PUT,
        &format!("/platform/endpoint/endpoint/validation/{endpoint_id}"),
        Some(&cookie),
        None,
        Some(validation.clone()),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let invalid = platform_request(
        &app,
        Method::PUT,
        &format!("/platform/endpoint/endpoint/validation/{endpoint_id}"),
        Some(&cookie),
        None,
        Some(json!({"validation_enabled": true})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let deleted = platform_request(
        &app,
        Method::DELETE,
        &format!("/platform/endpoint/endpoint/validation/{endpoint_id}"),
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
}
#[tokio::test]
async fn python_config_export_sections_and_import_variants() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let all = platform_request(
        &app,
        Method::GET,
        "/platform/config/export/all",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(all.status(), StatusCode::OK);
    let all = response_json(all).await;
    let all = all.get("response").unwrap_or(&all);
    for section in ["apis", "roles", "groups", "routings", "endpoints"] {
        assert!(all[section].is_array(), "{section}");
    }
    for path in [
        "/platform/config/export/apis",
        "/platform/config/export/roles",
        "/platform/config/export/groups",
        "/platform/config/export/routings",
        "/platform/config/export/endpoints",
    ] {
        let response = platform_request(&app, Method::GET, path, Some(&cookie), None, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    let api = platform_request(&app, Method::POST, "/platform/api", Some(&cookie), None, Some(json!({"api_name": "filterapi", "api_version": "v1", "api_description": "filter api", "api_servers": ["http://127.0.0.1:9"], "api_type": "REST"}))).await;
    assert!(api.status().is_success());
    let endpoint = platform_request(&app, Method::POST, "/platform/endpoint", Some(&cookie), None, Some(json!({"api_name": "filterapi", "api_version": "v1", "endpoint_method": "GET", "endpoint_uri": "/x", "endpoint_description": "x"}))).await;
    assert!(endpoint.status().is_success());
    let endpoints = platform_request(
        &app,
        Method::GET,
        "/platform/config/export/endpoints?api_name=filterapi&api_version=v1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(endpoints.status(), StatusCode::OK);
    let endpoints = response_json(endpoints).await;
    let endpoints = endpoints.get("response").unwrap_or(&endpoints);
    assert!(
        endpoints["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|endpoint| endpoint["endpoint_uri"] == "/x")
    );
    assert!(
        endpoints["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .all(|endpoint| endpoint["api_name"] == "filterapi" && endpoint["api_version"] == "v1")
    );
    for section in [
        json!({"apis": []}),
        json!({"roles": []}),
        json!({"groups": []}),
        json!({"routings": []}),
        json!({"endpoints": []}),
        json!({"apis": [], "endpoints": []}),
        json!({"roles": [], "groups": []}),
    ] {
        let variant_app = build_router(memory_state(false).await);
        let (variant_cookie, _) = login(&variant_app).await;
        let imported = platform_request(
            &variant_app,
            Method::POST,
            "/platform/config/import",
            Some(&variant_cookie),
            None,
            Some(section),
        )
        .await;
        assert_eq!(imported.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn python_config_permissions_granular_export_and_gateway_import_contracts() {
    for (permission, username, allowed, denied) in [
        (
            "manage_apis",
            "config-apis",
            "/platform/config/export/apis",
            "/platform/config/export/roles",
        ),
        (
            "manage_roles",
            "config-roles",
            "/platform/config/export/roles",
            "/platform/config/export/apis",
        ),
        (
            "manage_groups",
            "config-groups",
            "/platform/config/export/groups",
            "/platform/config/export/roles",
        ),
        (
            "manage_routings",
            "config-routings",
            "/platform/config/export/routings",
            "/platform/config/export/endpoints",
        ),
    ] {
        let (app, cookie) = config_permission_app(Some(permission), username).await;
        let allowed_response =
            platform_request(&app, Method::GET, allowed, Some(&cookie), None, None).await;
        assert_eq!(
            allowed_response.status(),
            StatusCode::OK,
            "{permission}: {allowed}"
        );
        let denied_response =
            platform_request(&app, Method::GET, denied, Some(&cookie), None, None).await;
        assert_eq!(
            denied_response.status(),
            StatusCode::FORBIDDEN,
            "{permission}: {denied}"
        );
    }
    let (gateway_app, gateway_cookie) =
        config_permission_app(Some("manage_gateway"), "config-gateway").await;
    let export_all = platform_request(
        &gateway_app,
        Method::GET,
        "/platform/config/export/all",
        Some(&gateway_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(export_all.status(), StatusCode::OK);
    let import = platform_request(
        &gateway_app,
        Method::POST,
        "/platform/config/import",
        Some(&gateway_cookie),
        None,
        Some(json!({"apis": []})),
    )
    .await;
    assert_eq!(import.status(), StatusCode::OK);
    let (limited_app, limited_cookie) = config_permission_app(None, "config-limited").await;
    for (method, path, payload, code) in [
        (Method::GET, "/platform/config/export/apis", None, "CFG002"),
        (Method::GET, "/platform/config/export/all", None, "CFG001"),
        (
            Method::POST,
            "/platform/config/import",
            Some(json!({"apis": []})),
            "CFG006",
        ),
    ] {
        let response = platform_request(
            &limited_app,
            method,
            path,
            Some(&limited_cookie),
            None,
            payload,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(response_json(response).await["error_code"], code, "{path}");
    }
}

#[tokio::test]
async fn config_export_missing_named_resources_return_python_404() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let role = platform_request(
        &app,
        Method::GET,
        "/platform/config/export/roles?role_name=admin",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(role.status(), StatusCode::OK);
    let role = response_json(role).await;
    assert_eq!(role["role"]["role_name"], "admin");
    assert!(role.get("roles").is_none());
    for (path, code, message) in [
        (
            "/platform/config/export/apis?api_name=nope&api_version=v9",
            "CFG404",
            "API not found",
        ),
        (
            "/platform/config/export/roles?role_name=nope-role",
            "CFG405",
            "Role not found",
        ),
        (
            "/platform/config/export/groups?group_name=nope-group",
            "CFG406",
            "Group not found",
        ),
        (
            "/platform/config/export/routings?client_key=nope-key",
            "CFG407",
            "Routing not found",
        ),
    ] {
        let response = platform_request(&app, Method::GET, path, Some(&cookie), None, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let response = response_json(response).await;
        assert_eq!(response["error_code"], code, "{path}");
        assert_eq!(response["error_message"], message, "{path}");
    }
}

#[tokio::test]
async fn config_rollback_preserves_python_permission_and_missing_snapshot_quirks() {
    let (limited_app, limited_cookie) = config_permission_app(None, "rollback-limited").await;
    let denied = platform_request(
        &limited_app,
        Method::POST,
        "/platform/config/rollback",
        Some(&limited_cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_json(denied).await,
        json!({"detail": "Rollback failed"})
    );

    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let missing = platform_request(
        &app,
        Method::POST,
        "/platform/config/rollback",
        Some(&cookie),
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await,
        json!({"error_code": "CFG404", "error_message": "No snapshot found"})
    );
}

#[tokio::test]
async fn python_config_import_ignores_malformed_entries() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    let mut before = std::collections::HashMap::new();
    for collection in ["apis", "endpoints", "roles", "groups", "routings"] {
        before.insert(
            collection,
            storage.find_many(collection, &json!({})).await.unwrap(),
        );
    }
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let payload = json!({"apis": [{"api_name": "x-only"}, {"api_version": "v1"}], "endpoints": [{"api_name": "x", "endpoint_method": "GET"}], "roles": [{"bad": "doc"}], "groups": [{"bad": "doc"}], "routings": [{"bad": "doc"}]});
    let response = platform_request(
        &app,
        Method::POST,
        "/platform/config/import",
        Some(&cookie),
        None,
        Some(payload),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    for collection in ["apis", "endpoints", "roles", "groups", "routings"] {
        assert_eq!(
            storage.find_many(collection, &json!({})).await.unwrap(),
            before[collection],
            "{collection}"
        );
    }
}

#[tokio::test]
async fn api_create_update_delete_emit_named_audit_events() {
    let _trace_guard = trace_capture_guard().await;
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let capture = CapturedTrace::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let create = platform_request(
        &app,
        Method::POST,
        "/platform/api",
        Some(&cookie),
        None,
        Some(json!({
            "api_name": "audit-api", "api_version": "v1", "api_type": "REST",
            "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"],
            "api_servers": ["http://127.0.0.1:9"], "active": true
        })),
    )
    .with_subscriber(dispatch.clone())
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let update = platform_request(
        &app,
        Method::PUT,
        "/platform/api/audit-api/v1",
        Some(&cookie),
        None,
        Some(json!({"api_description": "updated"})),
    )
    .with_subscriber(dispatch.clone())
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    let delete = platform_request(
        &app,
        Method::DELETE,
        "/platform/api/audit-api/v1",
        Some(&cookie),
        None,
        None,
    )
    .with_subscriber(dispatch)
    .await;
    assert_eq!(delete.status(), StatusCode::OK);
    let events = capture.text();
    for action in ["api.create", "api.update", "api.delete"] {
        assert!(events.contains(action), "missing {action}: {events}");
    }
}

#[tokio::test]
async fn python_config_export_emits_audit_event() {
    let _trace_guard = trace_capture_guard().await;
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let capture = CapturedTrace::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/platform/config/export/apis")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = capture.text();
    assert!(
        events.contains("config.export"),
        "captured events: {events}"
    );
    assert!(events.contains("apis"), "captured events: {events}");
}

#[tokio::test]
async fn platform_mutations_emit_payload_free_audit_events() {
    let _trace_guard = trace_capture_guard().await;
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let capture = CapturedTrace::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/config/import")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "apis": [{
                            "api_name": "audit-safe",
                            "api_version": "v1",
                            "api_grpc_descriptor_set": "secret-descriptor-must-not-appear"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = capture.text();
    assert!(
        events.contains("platform.post"),
        "captured events: {events}"
    );
    assert!(events.contains("config"), "captured events: {events}");
    assert!(events.contains("success"), "captured events: {events}");
    assert!(
        !events.contains("secret-descriptor-must-not-appear"),
        "captured events: {events}"
    );
}

#[tokio::test]
async fn python_credit_definition_masks_secret_key_material() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let create = platform_request(&app, Method::POST, "/platform/credit", Some(&cookie), None, Some(json!({"api_credit_group": "maskgroup", "api_key": "VERY-SECRET-KEY", "api_key_header": "x-api-key", "credit_tiers": [{"tier_name": "default", "credits": 5, "input_limit": 0, "output_limit": 0, "reset_frequency": "monthly"}]}))).await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let response = platform_request(
        &app,
        Method::GET,
        "/platform/credit/defs/maskgroup",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let body = body.get("response").unwrap_or(&body);
    assert_eq!(body["api_credit_group"], "maskgroup");
    assert_eq!(body["api_key_header"], "x-api-key");
    assert_eq!(body["api_key_present"], true);
    assert!(body.get("api_key").is_none());
    let list = platform_request(
        &app,
        Method::GET,
        "/platform/credit/defs",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = response_json(list).await;
    assert_eq!(list["page"], 1);
    assert_eq!(list["page_size"], 50);
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["api_credit_group"], "maskgroup");
    let missing = platform_request(
        &app,
        Method::GET,
        "/platform/credit/defs/missing",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(missing).await["error_code"], "CRD021");
}

#[tokio::test]
async fn credit_models_match_pydantic_required_fields_coercion_and_unknown_elision() {
    let state = memory_state(false).await;
    let storage = state.storage.as_ref().unwrap().clone();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;
    let create = platform_request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&cookie),
        None,
        Some(json!({
            "api_credit_group": true, "api_key": false, "api_key_header": 7,
            "api_key_new": 9,
            "credit_tiers": [
                {
                    "tier_name": 1, "credits": "8", "input_limit": true, "output_limit": 3.9,
                    "reset_frequency": false, "ignored": "field"
                },
                {
                    "tier_name": "é".repeat(50), "credits": 1, "input_limit": 2,
                    "output_limit": 3, "reset_frequency": "monthly"
                }
            ], "ignored": "field"
        })),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let credit = storage
        .find_one("credit_defs", &json!({"api_credit_group": "True"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credit["api_key"], "False");
    assert_eq!(credit["api_key_header"], "7");
    assert_eq!(credit["api_key_new"], "9");
    assert!(credit["api_key_rotation_expires"].is_null());
    assert_eq!(
        credit["credit_tiers"][0],
        json!({
            "tier_name": "1", "credits": 8, "input_limit": 1, "output_limit": 3,
            "reset_frequency": "False"
        })
    );
    assert_eq!(
        credit["credit_tiers"][1],
        json!({
            "tier_name": "é".repeat(50), "credits": 1, "input_limit": 2, "output_limit": 3,
            "reset_frequency": "monthly"
        })
    );
    assert!(credit.get("ignored").is_none());
    let duplicate = platform_request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&cookie),
        None,
        Some(json!({
            "api_credit_group": "True", "api_key": "key", "api_key_header": "header",
            "credit_tiers": [{"tier_name": "default", "credits": 1, "input_limit": 0, "output_limit": 0, "reset_frequency": "monthly"}]
        })),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(duplicate).await["error_code"], "CRD001");
    let renamed = platform_request(
        &app,
        Method::PUT,
        "/platform/credit/True",
        Some(&cookie),
        None,
        Some(json!({
            "api_credit_group": "renamed", "api_key": "key", "api_key_header": "header",
            "credit_tiers": [{"tier_name": "default", "credits": 1, "input_limit": 0, "output_limit": 0, "reset_frequency": "monthly"}]
        })),
    )
    .await;
    assert_eq!(renamed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(renamed).await["error_code"], "CRD003");
    let empty_key = platform_request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&cookie),
        None,
        Some(json!({
            "api_credit_group": "empty-key", "api_key": "", "api_key_header": "header",
            "credit_tiers": [{"tier_name": "default", "credits": 1, "input_limit": 0, "output_limit": 0, "reset_frequency": "monthly"}]
        })),
    )
    .await;
    assert_eq!(empty_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(empty_key).await["error_code"], "CRD010");
    let invalid_definition = platform_request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&cookie),
        None,
        Some(json!({"api_credit_group": "invalid", "api_key": "key", "api_key_header": "header", "credit_tiers": []})),
    )
    .await;
    assert_eq!(
        invalid_definition.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let user_credits = platform_request(
        &app,
        Method::POST,
        "/platform/credit/admin",
        Some(&cookie),
        None,
        Some(json!({
            "username": "admin",
            "users_credits": {
                "True": {"tier_name": 2, "available_credits": "4", "user_api_key": false, "ignored": "field"},
                "unicode": {"tier_name": "é".repeat(50), "available_credits": 1}
            },
            "ignored": "field"
        })),
    )
    .await;
    assert_eq!(user_credits.status(), StatusCode::OK);
    let user_credits = storage
        .find_one("user_credits", &json!({"username": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user_credits["users_credits"]["True"],
        json!({"tier_name": "2", "available_credits": 4, "reset_date": null, "user_api_key": "False"})
    );
    assert_eq!(
        user_credits["users_credits"]["unicode"],
        json!({"tier_name": "é".repeat(50), "available_credits": 1, "reset_date": null, "user_api_key": null})
    );
    let mismatched_username = platform_request(
        &app,
        Method::POST,
        "/platform/credit/admin",
        Some(&cookie),
        None,
        Some(json!({
            "username": true,
            "users_credits": {"group": {"tier_name": "tier", "available_credits": 1}}
        })),
    )
    .await;
    assert_eq!(mismatched_username.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(mismatched_username).await["error_code"],
        "CRD014"
    );
    let invalid_user_credits = platform_request(
        &app,
        Method::POST,
        "/platform/credit/admin",
        Some(&cookie),
        None,
        Some(json!({"username": "admin", "users_credits": {"group": {"tier_name": "tier"}}})),
    )
    .await;
    assert_eq!(
        invalid_user_credits.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let missing_update = platform_request(
        &app,
        Method::PUT,
        "/platform/credit/missing",
        Some(&cookie),
        None,
        Some(json!({
            "api_credit_group": "missing", "api_key": "key", "api_key_header": "header",
            "credit_tiers": [{"tier_name": "default", "credits": 1, "input_limit": 0, "output_limit": 0, "reset_frequency": "monthly"}]
        })),
    )
    .await;
    assert_eq!(missing_update.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(missing_update).await["error_code"], "CRD004");
    let missing_delete = platform_request(
        &app,
        Method::DELETE,
        "/platform/credit/missing",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing_delete.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(missing_delete).await["error_code"], "CRD007");
}

#[tokio::test]
async fn quota_status_uses_nested_effective_limits_and_tracker_usage() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    let no_tier_app = build_router(state.clone());
    let (no_tier_cookie, _) = login(&no_tier_app).await;
    let no_tier_status = platform_request(
        &no_tier_app,
        Method::GET,
        "/platform/quota/status",
        Some(&no_tier_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(no_tier_status.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(no_tier_status).await["detail"],
        "No tier assigned to user"
    );
    let no_limits = platform_request(
        &no_tier_app,
        Method::GET,
        "/platform/quota/status/monthly_requests",
        Some(&no_tier_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(no_limits.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(no_limits).await["detail"],
        "No limits found for user"
    );
    storage
        .insert_one(
            "tiers",
            json!({
                "tier_id": "quota-pro", "name": "pro", "display_name": "Quota Pro",
                "price_monthly": 49.99, "features": ["priority"], "enabled": true,
                "limits": {
                    "monthly_request_quota": 10, "daily_request_quota": 4,
                    "monthly_bandwidth_quota": 1000, "burst_per_minute": 3,
                    "burst_per_hour": 7, "burst_per_second": 1
                }
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "tiers",
            json!({
                "tier_id": "quota-free", "name": "free", "display_name": "Quota Free",
                "enabled": true, "is_default": true, "limits": {"monthly_request_quota": 1}
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "user_tier_assignments",
            json!({"user_id": "admin", "tier_id": "quota-pro"}),
        )
        .await
        .unwrap();
    let date = time::OffsetDateTime::now_utc().date();
    let monthly_key = format!(
        "quota:user:admin:requests:month:{:04}-{:02}:usage",
        date.year(),
        u8::from(date.month())
    );
    for _ in 0..8 {
        storage.increment_window(&monthly_key, 3_600).await.unwrap();
    }
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let status = platform_request(
        &app,
        Method::GET,
        "/platform/quota/status",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    let status = response_json(status).await;
    assert_eq!(status["tier_info"]["tier_id"], "quota-pro");
    assert_eq!(status["tier_info"]["limits"]["monthly_request_quota"], 10);
    let monthly = status["quotas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|quota| quota["quota_type"] == "monthly_requests")
        .unwrap();
    assert_eq!(monthly["current_usage"], 8);
    assert_eq!(monthly["remaining"], 2);
    assert_eq!(monthly["percentage_used"], 80.0);
    assert_eq!(monthly["is_warning"], true);
    assert_eq!(monthly["is_critical"], false);
    assert_eq!(monthly["burst_used"], 0);
    assert_eq!(monthly["burst_limit"], 0);
    assert_eq!(monthly["burst_percentage"], 0.0);
    assert!(monthly["reset_at"].as_str().unwrap().ends_with("T00:00:00"));
    assert_eq!(status["usage_summary"]["total_requests_used"], 8);
    assert_eq!(status["usage_summary"]["total_requests_limit"], 14);
    assert_eq!(status["usage_summary"]["has_warnings"], true);

    let specific = platform_request(
        &app,
        Method::GET,
        "/platform/quota/status/monthly_requests",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(specific.status(), StatusCode::OK);
    assert_eq!(response_json(specific).await["current_usage"], 8);

    let invalid = platform_request(
        &app,
        Method::GET,
        "/platform/quota/status/not-a-quota",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid).await,
        json!({"detail": "Invalid quota type: not-a-quota"})
    );

    let export = platform_request(
        &app,
        Method::POST,
        "/platform/quota/usage/export?format=csv",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(export.status(), StatusCode::OK);
    let export = response_json(export).await;
    assert_eq!(export["format"], "csv");
    assert!(
        export["data"]
            .as_str()
            .unwrap()
            .starts_with("Type,Current Usage")
    );
    assert!(
        export["data"]
            .as_str()
            .unwrap()
            .contains("monthly_requests,8,10,2,80.00")
    );
    assert!(
        !export["data"]
            .as_str()
            .unwrap()
            .contains("monthly_bandwidth")
    );

    let tier_info = platform_request(
        &app,
        Method::GET,
        "/platform/quota/tier/info",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(tier_info.status(), StatusCode::OK);
    let tier_info = response_json(tier_info).await;
    assert_eq!(tier_info["current_tier"]["display_name"], "Quota Pro");
    assert_eq!(tier_info["upgrade_options"][0]["tier_id"], "quota-free");

    let burst = platform_request(
        &app,
        Method::GET,
        "/platform/quota/burst/status",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(burst.status(), StatusCode::OK);
    let burst = response_json(burst).await;
    assert_eq!(burst["burst_limits"]["per_minute"], 3);
    assert_eq!(burst["burst_usage"]["per_minute"], 0);
    assert_eq!(burst["note"], "Live data from rate limiter");

    storage
        .update_one(
            "user_tier_assignments",
            &json!({"user_id": "admin"}),
            &json!({
                "effective_until": 0,
                "override_limits": {"monthly_request_quota": 99}
            }),
        )
        .await
        .unwrap();
    let expired_assignment = platform_request(
        &app,
        Method::GET,
        "/platform/quota/tier/info",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(expired_assignment.status(), StatusCode::OK);
    assert_eq!(
        response_json(expired_assignment).await["current_tier"]["tier_id"],
        "quota-free"
    );
    let expired_status = platform_request(
        &app,
        Method::GET,
        "/platform/quota/status",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(expired_status.status(), StatusCode::OK);
    let expired_status = response_json(expired_status).await;
    assert_eq!(expired_status["tier_info"]["tier_id"], "quota-free");
    assert_eq!(
        expired_status["tier_info"]["limits"]["monthly_request_quota"],
        99
    );
}

#[tokio::test]
async fn tier_assignment_create_returns_python_assignment_contract() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "tiers",
            json!({
                "tier_id": "assignment-pro", "name": "pro", "display_name": "Assignment Pro",
                "limits": {"requests_per_minute": 100}, "enabled": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "tiers",
            json!({
                "tier_id": "assignment-default", "name": "free", "display_name": "Assignment Default",
                "limits": {"requests_per_minute": 10}, "is_default": true, "enabled": true
            }),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let default_tier = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/assignments/unassigned-user/tier",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(default_tier.status(), StatusCode::OK);
    assert_eq!(
        response_json(default_tier).await["tier_id"],
        "assignment-default"
    );

    let created = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/assignments",
        Some(&cookie),
        None,
        Some(json!({
            "user_id": "assignment-user", "tier_id": "assignment-pro",
            "notes": "manual upgrade", "effective_from": "2020-01-01T00:00:00",
            "override_limits": {"requests_per_minute": 125}
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    assert_eq!(created["user_id"], "assignment-user");
    assert_eq!(created["tier_id"], "assignment-pro");
    assert_eq!(created["notes"], "manual upgrade");
    assert_eq!(created["override_limits"]["requests_per_minute"], 125);
    assert_eq!(created["effective_from"], "2020-01-01T00:00:00");
    assert!(created["effective_until"].is_null());
    assert!(created["assigned_by"].is_null());
    let assigned_at = created["assigned_at"].as_str().unwrap();
    assert!(assigned_at.contains('T'));
    assert!(!assigned_at.ends_with('Z'));

    let assigned_tier = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/assignments/assignment-user/tier",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(assigned_tier.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_json(assigned_tier).await["detail"],
        "Failed to get user tier"
    );

    // Python replaces the assignment on a second request, so omitted optional
    // fields are explicit nulls rather than stale fields from the first one.
    let reassigned = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/assignments",
        Some(&cookie),
        None,
        Some(json!({"user_id": "assignment-user", "tier_id": "assignment-pro"})),
    )
    .await;
    assert_eq!(reassigned.status(), StatusCode::CREATED);
    let reassigned = response_json(reassigned).await;
    assert!(reassigned["notes"].is_null());
    assert!(reassigned["override_limits"].is_null());

    let stored = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/assignments/assignment-user",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(stored.status(), StatusCode::OK);
    let stored = response_json(stored).await;
    assert!(stored["notes"].is_null());
    assert!(stored["override_limits"].is_null());

    let missing_tier = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/assignments",
        Some(&cookie),
        None,
        Some(json!({"user_id": "assignment-user", "tier_id": "missing-tier"})),
    )
    .await;
    assert_eq!(missing_tier.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_tier).await["detail"],
        "Tier missing-tier not found"
    );

    let comparison = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/compare",
        Some(&cookie),
        None,
        Some(json!(["assignment-pro", "missing-tier"])),
    )
    .await;
    assert_eq!(comparison.status(), StatusCode::OK);
    let comparison = response_json(comparison).await;
    assert!(comparison.is_array());
    assert_eq!(comparison[0]["tier_id"], "assignment-pro");
    assert!(comparison[0].get("enabled").is_none());

    let removed = platform_request(
        &app,
        Method::DELETE,
        "/platform/tiers/assignments/assignment-user",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(removed.status(), StatusCode::OK);
    assert_eq!(
        response_json(removed).await["message"],
        "Assignment removed"
    );
    let absent = platform_request(
        &app,
        Method::DELETE,
        "/platform/tiers/assignments/assignment-user",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(absent).await["detail"],
        "No assignment found for user assignment-user"
    );
}

#[tokio::test]
async fn tier_actions_create_python_style_assignment_records() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    for (tier_id, name, is_default) in [("action-free", "free", true), ("action-pro", "pro", false)]
    {
        storage
            .insert_one(
                "tiers",
                json!({
                    "tier_id": tier_id, "name": name, "display_name": name,
                    "limits": {"requests_per_minute": 10}, "is_default": is_default,
                }),
            )
            .await
            .unwrap();
    }
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let upgrade = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/upgrade",
        Some(&cookie),
        None,
        Some(json!({"user_id": "action-user", "new_tier_id": "action-pro"})),
    )
    .await;
    assert_eq!(upgrade.status(), StatusCode::OK);
    let upgrade = response_json(upgrade).await;
    assert_eq!(upgrade["tier_id"], "action-pro");
    assert_eq!(upgrade["notes"], "Upgraded from action-free");
    assert!(upgrade["effective_from"].as_str().unwrap().contains('T'));
    assert!(upgrade["effective_until"].is_null());

    let downgrade = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/downgrade",
        Some(&cookie),
        None,
        Some(json!({
            "user_id": "action-user", "new_tier_id": "action-free", "grace_period_days": 2
        })),
    )
    .await;
    assert_eq!(downgrade.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_json(downgrade).await["detail"],
        "Failed to downgrade tier"
    );

    let temporary = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/temporary-upgrade",
        Some(&cookie),
        None,
        Some(json!({
            "user_id": "action-user", "temp_tier_id": "action-pro", "duration_days": 3
        })),
    )
    .await;
    assert_eq!(temporary.status(), StatusCode::OK);
    let temporary = response_json(temporary).await;
    assert_eq!(temporary["notes"], "Temporary upgrade for 3 days");
    assert!(temporary["effective_until"].as_str().unwrap().contains('T'));

    let trial_missing = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/trial/start",
        Some(&cookie),
        None,
        Some(json!({"user_id": "action-user", "tier_id": "missing-tier"})),
    )
    .await;
    assert_eq!(trial_missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(trial_missing).await["detail"],
        "Tier missing-tier not found"
    );

    let payment_failure = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/payment/failure",
        Some(&cookie),
        None,
        Some(json!({"user_id": "action-user", "reason": "declined"})),
    )
    .await;
    assert_eq!(payment_failure.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_json(payment_failure).await["detail"],
        "Failed to handle payment failure"
    );

    let payment_failure = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/payment/failure",
        Some(&cookie),
        None,
        Some(json!({"user_id": "fresh-payment-user", "reason": "declined"})),
    )
    .await;
    assert_eq!(payment_failure.status(), StatusCode::OK);
    let payment_failure = response_json(payment_failure).await;
    assert_eq!(payment_failure["tier_id"], "action-free");
    assert_eq!(payment_failure["assigned_by"], "system:payment_failure");
    assert_eq!(
        payment_failure["notes"],
        "Downgraded from action-free with 0 day grace period"
    );
}

#[tokio::test]
async fn tier_users_and_statistics_match_python_shapes() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    for (tier_id, display_name) in [("stats-free", "Stats Free"), ("stats-pro", "Stats Pro")] {
        storage
            .insert_one(
                "tiers",
                json!({
                    "tier_id": tier_id, "name": tier_id, "display_name": display_name,
                    "limits": {"requests_per_minute": 10},
                }),
            )
            .await
            .unwrap();
    }
    for assignment in [
        json!({"user_id": "stats-active", "tier_id": "stats-pro"}),
        json!({
            "user_id": "stats-future", "tier_id": "stats-pro",
            "effective_from": "2999-01-01T00:00:00"
        }),
    ] {
        storage
            .insert_one("user_tier_assignments", assignment)
            .await
            .unwrap();
    }
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let users = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/stats-pro/users?skip=1&limit=1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(users.status(), StatusCode::OK);
    let users = response_json(users).await;
    assert!(users.is_array());
    assert_eq!(users.as_array().unwrap().len(), 1);
    assert_eq!(users[0]["user_id"], "stats-future");

    let tier_stats = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/stats-pro/statistics",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(tier_stats.status(), StatusCode::OK);
    let tier_stats = response_json(tier_stats).await;
    assert_eq!(tier_stats["total_users"], 2);
    assert_eq!(tier_stats["active_users"], 1);
    assert_eq!(tier_stats["inactive_users"], 1);

    let all_stats = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/statistics/all",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(all_stats.status(), StatusCode::OK);
    let all_stats = response_json(all_stats).await;
    assert!(all_stats.is_array());
    let free = all_stats
        .as_array()
        .unwrap()
        .iter()
        .find(|stat| stat["tier_id"] == "stats-free")
        .unwrap();
    assert_eq!(free["total_users"], 0);
    let pro = all_stats
        .as_array()
        .unwrap()
        .iter()
        .find(|stat| stat["tier_id"] == "stats-pro")
        .unwrap();
    assert_eq!(pro["tier_name"], "Stats Pro");
    assert_eq!(pro["active_users"], 1);
}

#[tokio::test]
async fn tier_delete_protects_assigned_tiers_like_python() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    for tier_id in ["delete-assigned", "delete-empty"] {
        storage
            .insert_one(
                "tiers",
                json!({
                    "tier_id": tier_id, "name": tier_id, "display_name": tier_id,
                    "limits": {"requests_per_minute": 10},
                }),
            )
            .await
            .unwrap();
    }
    storage
        .insert_one(
            "user_tier_assignments",
            json!({"user_id": "delete-user", "tier_id": "delete-assigned"}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let blocked = platform_request(
        &app,
        Method::DELETE,
        "/platform/tiers/delete-assigned",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(blocked).await["detail"],
        "Cannot delete tier delete-assigned: 1 users are assigned to it"
    );

    let deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/tiers/delete-empty",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(response_json(deleted).await["message"], "Tier deleted");

    let missing = platform_request(
        &app,
        Method::DELETE,
        "/platform/tiers/delete-empty",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await["detail"],
        "Tier delete-empty not found"
    );
}

#[tokio::test]
async fn tier_crud_returns_normalized_python_tier_contracts() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/",
        Some(&cookie),
        None,
        Some(json!({
            "tier_id": "crud-pro", "name": "pro", "display_name": "CRUD Pro",
            "limits": {"requests_per_minute": 100}, "features": ["priority"]
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    assert_eq!(created["tier_id"], "crud-pro");
    assert_eq!(created["limits"]["requests_per_minute"], 100);
    assert!(created["limits"]["requests_per_hour"].is_null());
    assert_eq!(created["limits"]["burst_per_minute"], 0);
    assert_eq!(created["limits"]["max_queue_time_ms"], 5000);
    assert_eq!(created["is_default"], false);
    assert_eq!(created["enabled"], true);
    assert!(created["created_at"].as_str().unwrap().contains('T'));

    let duplicate = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/",
        Some(&cookie),
        None,
        Some(json!({
            "tier_id": "crud-pro", "name": "pro", "display_name": "Changed",
            "limits": {"requests_per_minute": 1}
        })),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::CREATED);
    assert_eq!(response_json(duplicate).await["display_name"], "CRUD Pro");

    let disabled = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/",
        Some(&cookie),
        None,
        Some(json!({
            "tier_id": "crud-free", "name": "free", "display_name": "CRUD Free",
            "limits": {}, "enabled": false
        })),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::CREATED);

    let listed = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/?enabled_only=true&skip=0&limit=1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["page"], 1);
    assert_eq!(listed["page_size"], 1);
    assert_eq!(listed["tiers"][0]["tier_id"], "crud-pro");

    let search = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/?search=crud",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(search.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let search = response_json(search).await;
    assert_eq!(search["error_code"], "TIER999");
    assert_eq!(search["error_message"], "Failed to list tiers");

    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/tiers/crud-pro",
        Some(&cookie),
        None,
        Some(json!({"display_name": "CRUD Pro Updated", "limits": {"requests_per_day": 10}})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await;
    assert_eq!(updated["display_name"], "CRUD Pro Updated");
    assert_eq!(updated["limits"]["requests_per_day"], 10);
    assert_eq!(updated["limits"]["burst_per_hour"], 0);

    let missing = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/missing-tier",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await["detail"],
        "Tier missing-tier not found"
    );
}

#[tokio::test]
async fn tier_public_and_protected_route_boundaries_match_python() {
    let app = build_router(memory_state(false).await);
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/",
        None,
        None,
        Some(json!({
            "tier_id": "public-tier", "name": "custom", "display_name": "Public Tier",
            "limits": {"requests_per_minute": 12}
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let fetched = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/public-tier",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);

    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/tiers/public-tier",
        None,
        None,
        Some(json!({"display_name": "Public Tier Updated"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);

    let assigned = platform_request(
        &app,
        Method::POST,
        "/platform/tiers/assignments",
        None,
        None,
        Some(json!({"user_id": "public-user", "tier_id": "public-tier"})),
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::CREATED);
    let assignment = platform_request(
        &app,
        Method::GET,
        "/platform/tiers/assignments/public-user",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(assignment.status(), StatusCode::OK);

    for path in ["/platform/tiers/", "/platform/tiers/statistics/all"] {
        let protected = platform_request(&app, Method::GET, path, None, None, None).await;
        assert_eq!(protected.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn rate_limit_statistics_and_shadowed_status_match_python_contracts() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one("roles", json!({"role_name": "rule-viewer"}))
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": "rule-viewer", "email": "rule-viewer@doorman.dev",
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": "rule-viewer", "groups": ["ALL"], "active": true, "ui_access": true,
            }),
        )
        .await
        .unwrap();
    for rule in [
        json!({
            "rule_id": "global-low", "rule_type": "global", "time_window": "minute", "limit": 50,
            "priority": 1, "enabled": true, "description": "global rule"
        }),
        json!({
            "rule_id": "viewer-high", "rule_type": "per_user", "target_identifier": "rule-viewer",
            "time_window": "second", "limit": 5, "burst_allowance": 2, "priority": 10, "enabled": true
        }),
        json!({
            "rule_id": "other-user", "rule_type": "per_user", "target_identifier": "other",
            "time_window": "hour", "limit": 10, "enabled": true
        }),
        json!({
            "rule_id": "disabled-ip", "rule_type": "per_ip", "time_window": "day", "limit": 1,
            "enabled": false
        }),
        json!({
            "rule_id": "legacy-no-enabled", "rule_type": "global", "time_window": "day", "limit": 1
        }),
    ] {
        storage.insert_one("rate_limit_rules", rule).await.unwrap();
    }
    let app = build_router(state);
    let (viewer_cookie, _) = login_as(&app, "rule-viewer@doorman.dev", fixture_password()).await;
    let (_admin_cookie, _) = login(&app).await;

    let status = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/status",
        Some(&viewer_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status.status(), StatusCode::NOT_FOUND);
    let status = response_json(status).await;
    assert_eq!(status["detail"], "Rule status not found");

    let statistics = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/statistics/summary",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(statistics.status(), StatusCode::OK);
    let statistics = response_json(statistics).await;
    assert_eq!(statistics["total_rules"], 5);
    assert_eq!(statistics["enabled_rules"], 3);
    assert_eq!(statistics["disabled_rules"], 2);
    assert_eq!(statistics["rules_by_type"]["global"], 2);
    assert_eq!(statistics["rules_by_type"]["per_user"], 2);
    assert_eq!(statistics["rules_by_type"]["per_ip"], 1);
    assert_eq!(statistics["rules_by_type"]["per_api"], 0);
}

#[tokio::test]
async fn rate_limit_bulk_routes_preserve_pinned_python_failures() {
    let state = memory_state(false).await;
    let storage = state.storage.clone().unwrap();
    storage
        .insert_one(
            "rate_limit_rules",
            json!({"rule_id": "bulk-rule", "rule_type": "global", "time_window": "minute", "limit": 10}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (cookie, _) = login(&app).await;

    let enabled = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/bulk/enable",
        Some(&cookie),
        None,
        Some(json!({"rule_ids": ["bulk-rule", "missing"]})),
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(enabled).await["detail"],
        "Rule bulk not found"
    );

    let disabled = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/bulk/disable",
        Some(&cookie),
        None,
        Some(json!({"rule_ids": ["bulk-rule", "missing"]})),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(disabled).await["detail"],
        "Rule bulk not found"
    );

    let deleted = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/bulk/delete",
        Some(&cookie),
        None,
        Some(json!({"rule_ids": ["bulk-rule", "missing"]})),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_json(deleted).await["detail"],
        "Failed to delete rules"
    );
}

#[tokio::test]
async fn rate_limit_crud_and_action_envelopes_match_python() {
    let app = build_router(memory_state(false).await);
    let (cookie, _) = login(&app).await;
    let created = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        Some(&cookie),
        None,
        Some(json!({
            "rule_id": "crud-rule", "rule_type": "global", "time_window": "minute", "limit": 15,
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    assert_eq!(created["rule_id"], "crud-rule");
    assert_eq!(created["target_identifier"], Value::Null);
    assert_eq!(created["burst_allowance"], 0);
    assert_eq!(created["priority"], 0);
    assert_eq!(created["enabled"], true);
    assert_eq!(created["description"], Value::Null);
    assert!(created["created_at"].as_str().unwrap().contains('T'));

    let duplicate_create = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        Some(&cookie),
        None,
        Some(json!({
            "rule_id": "crud-rule", "rule_type": "global", "time_window": "minute", "limit": 15,
        })),
    )
    .await;
    assert_eq!(duplicate_create.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(duplicate_create).await["detail"],
        "Rule with ID crud-rule already exists"
    );

    let listed = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/?rule_type=global&enabled_only=true&skip=0&limit=1",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert!(listed.is_array());
    assert_eq!(listed[0]["rule_id"], "crud-rule");

    let invalid_enabled = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/?enabled_only=not-a-bool",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(invalid_enabled.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response_json(invalid_enabled).await["error_code"], "VAL001");

    let updated = platform_request(
        &app,
        Method::PUT,
        "/platform/rate-limits/crud-rule",
        Some(&cookie),
        None,
        Some(json!({"limit": 20, "description": "updated rule"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await;
    assert_eq!(updated["limit"], 20);
    assert_eq!(updated["description"], "updated rule");
    assert_eq!(updated["rule_type"], "global");

    let null_update = platform_request(
        &app,
        Method::PUT,
        "/platform/rate-limits/crud-rule",
        Some(&cookie),
        None,
        Some(json!({"limit": null, "description": null, "enabled": null})),
    )
    .await;
    assert_eq!(null_update.status(), StatusCode::OK);
    let null_update = response_json(null_update).await;
    assert_eq!(null_update["limit"], 20);
    assert_eq!(null_update["description"], "updated rule");
    assert_eq!(null_update["enabled"], true);

    let coerced = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        None,
        None,
        Some(json!({
            "rule_id": 123, "rule_type": "global", "time_window": "minute", "limit": "5",
            "burst_allowance": "2", "priority": "7", "enabled": "false", "description": true,
        })),
    )
    .await;
    assert_eq!(coerced.status(), StatusCode::CREATED);
    let coerced = response_json(coerced).await;
    assert_eq!(coerced["rule_id"], "123");
    assert_eq!(coerced["limit"], 5);
    assert_eq!(coerced["burst_allowance"], 2);
    assert_eq!(coerced["priority"], 7);
    assert_eq!(coerced["enabled"], false);
    assert_eq!(coerced["description"], "True");

    // Pydantic v1's non-strict integer accepts a JSON float by truncation and
    // accepts booleans, while a decimal string is rejected. Extra fields use
    // the model's default ignore policy.
    let float_limit = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        None,
        None,
        Some(json!({
            "rule_id": "float-limit", "rule_type": "global", "time_window": "minute", "limit": 1.5,
        })),
    )
    .await;
    assert_eq!(float_limit.status(), StatusCode::CREATED);
    assert_eq!(response_json(float_limit).await["limit"], 1);

    let boolean_limit = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        None,
        None,
        Some(json!({
            "rule_id": "boolean-limit", "rule_type": "global", "time_window": "minute", "limit": true,
        })),
    )
    .await;
    assert_eq!(boolean_limit.status(), StatusCode::CREATED);
    assert_eq!(response_json(boolean_limit).await["limit"], 1);

    let decimal_string_limit = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        None,
        None,
        Some(json!({
            "rule_id": "decimal-string-limit", "rule_type": "global", "time_window": "minute", "limit": "1.5",
        })),
    )
    .await;
    assert_eq!(
        decimal_string_limit.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        response_json(decimal_string_limit).await["error_code"],
        "VAL001"
    );

    let unknown_field = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        None,
        None,
        Some(json!({
            "rule_id": "unknown-field", "rule_type": "global", "time_window": "minute", "limit": 1,
            "unrecognized": "silently ignored",
        })),
    )
    .await;
    assert_eq!(unknown_field.status(), StatusCode::CREATED);
    assert!(
        response_json(unknown_field)
            .await
            .get("unrecognized")
            .is_none()
    );

    let copied = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/crud-rule/duplicate",
        Some(&cookie),
        None,
        Some(json!({"new_rule_id": "crud-rule-copy"})),
    )
    .await;
    assert_eq!(copied.status(), StatusCode::CREATED);
    let copied = response_json(copied).await;
    assert_eq!(copied["rule_id"], "crud-rule-copy");
    assert_eq!(copied["description"], "Copy of crud-rule");
    assert_eq!(copied["limit"], 20);

    let numeric_copy = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/crud-rule/duplicate",
        None,
        None,
        Some(json!({"new_rule_id": 456})),
    )
    .await;
    assert_eq!(numeric_copy.status(), StatusCode::CREATED);
    assert_eq!(response_json(numeric_copy).await["rule_id"], "456");

    let missing_copy = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/missing-source/duplicate",
        None,
        None,
        Some(json!({"new_rule_id": "unused"})),
    )
    .await;
    assert_eq!(missing_copy.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_copy).await["detail"],
        "Source rule missing-source not found"
    );

    let disabled = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/crud-rule/disable",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_eq!(response_json(disabled).await["enabled"], false);

    let deleted = platform_request(
        &app,
        Method::DELETE,
        "/platform/rate-limits/crud-rule",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(
        response_json(deleted).await,
        json!({"deleted": true, "rule_id": "crud-rule"})
    );

    let missing = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/missing-rule",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await["detail"],
        "Rule missing-rule not found"
    );

    let invalid = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        Some(&cookie),
        None,
        Some(json!({
            "rule_id": "invalid-rule", "rule_type": "global", "time_window": "minute", "limit": 0,
        })),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response_json(invalid).await["error_code"], "VAL001");
}

#[tokio::test]
async fn rate_limit_management_is_public_and_uses_python_priority_search_contracts() {
    let app = build_router(memory_state(false).await);
    for rule in [
        json!({
            "rule_id": "search-low", "rule_type": "global", "time_window": "minute", "limit": 5,
            "priority": 1, "description": "needle description",
        }),
        json!({
            "rule_id": "search-high", "rule_type": "per_api", "time_window": "minute", "limit": 5,
            "priority": 10, "target_identifier": "needle target",
        }),
        json!({
            "rule_id": "unrelated", "rule_type": "per_user", "time_window": "minute", "limit": 5,
            "priority": 100, "target_identifier": "ordinary",
        }),
    ] {
        let created = platform_request(
            &app,
            Method::POST,
            "/platform/rate-limits/",
            None,
            None,
            Some(rule),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
    }

    let listed = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/?skip=0&limit=100",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert_eq!(listed[0]["rule_id"], "unrelated");
    assert_eq!(listed[1]["rule_id"], "search-high");
    assert_eq!(listed[2]["rule_id"], "search-low");

    let search = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/search?q=needle",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(search.status(), StatusCode::OK);
    let search = response_json(search).await;
    // The Python memory backend does not implement Mongo's `$regex` query.
    assert_eq!(search, json!([]));

    let search_does_not_match_type = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/search?q=per_user",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(search_does_not_match_type.status(), StatusCode::OK);
    assert_eq!(response_json(search_does_not_match_type).await, json!([]));

    let malformed_specific = platform_request(
        &app,
        Method::POST,
        "/platform/rate-limits/",
        None,
        None,
        Some(json!({
            "rule_id": "missing-target", "rule_type": "per_user", "time_window": "minute", "limit": 5,
        })),
    )
    .await;
    assert_eq!(
        malformed_specific.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        response_json(malformed_specific).await["detail"],
        "Failed to create rule"
    );

    let status_without_token = platform_request(
        &app,
        Method::GET,
        "/platform/rate-limits/status",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status_without_token.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(status_without_token).await["detail"],
        "Rule status not found"
    );
}
