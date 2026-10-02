use std::sync::{Arc, OnceLock, atomic::Ordering};

use axum::body::{Body, to_bytes};
use doorman_gateway::{
    AppState, Config, build_router,
    middleware::chaos::{
        CHAOS_ENABLED, CHAOS_ERROR_BUDGET_BURN, CHAOS_ERROR_STATUS, CHAOS_EVENTS_COUNT,
        CHAOS_LATENCY_MS, CHAOS_MONGO_OUTAGE, CHAOS_REDIS_OUTAGE,
    },
    storage::runtime::SharedStorage,
};
use http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt;

static PARITY_SUITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn reset_chaos_state() {
    CHAOS_ENABLED.store(false, Ordering::Relaxed);
    CHAOS_LATENCY_MS.store(0, Ordering::Relaxed);
    CHAOS_ERROR_STATUS.store(0, Ordering::Relaxed);
    CHAOS_EVENTS_COUNT.store(0, Ordering::Relaxed);
    CHAOS_ERROR_BUDGET_BURN.store(0, Ordering::Relaxed);
    CHAOS_REDIS_OUTAGE.store(false, Ordering::Relaxed);
    CHAOS_MONGO_OUTAGE.store(false, Ordering::Relaxed);
}

struct ChaosStateReset;

impl ChaosStateReset {
    fn new() -> Self {
        reset_chaos_state();
        Self
    }
}

impl Drop for ChaosStateReset {
    fn drop(&mut self) {
        reset_chaos_state();
    }
}

async fn test_app_state() -> AppState {
    let mut config = Config::for_test("removed-internal-backend".to_owned());
    config.https_only = false;
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

async fn login(app: &axum::Router) -> String {
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

#[tokio::test]
async fn parity_test_user_onboarding_and_auth_flows() {
    let _suite_lock = PARITY_SUITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login(&app).await;

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
                        "username": "alice",
                        "email": "alice@example.com",
                        "password": "AlicePassword123!",
                        "role": "user"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());

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
                        "username": "alice2",
                        "email": "alice@example.com",
                        "password": "AlicePassword123!",
                        "role": "user"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn parity_test_graphql_validation_and_introspection_policy() {
    let _suite_lock = PARITY_SUITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let state = test_app_state().await;
    let app = build_router(state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/graphql/demo")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "query": "query { items { id name } }"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_client_error() || response.status().is_success());
}

#[tokio::test]
async fn parity_test_developer_tools_chaos_and_simulator() {
    let _suite_lock = PARITY_SUITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let _chaos_reset = ChaosStateReset::new();
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/tools/chaos/toggle")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "backend": "redis",
                        "enabled": true,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/tools/chaos/stats")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["redis_outage"], true);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/platform/tools/rate-limit-simulator")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "max_requests": 50,
                        "duration_seconds": 60,
                        "simulated_requests": 100
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
    assert_eq!(body["allowed_requests"], 50);
    assert_eq!(body["blocked_requests"], 50);
    assert_eq!(body["would_exceed"], true);
}

#[tokio::test]
async fn parity_test_analytics_timeseries_endpoints() {
    let _suite_lock = PARITY_SUITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let state = test_app_state().await;
    let app = build_router(state);
    let token = login(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/analytics/timeseries")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/platform/analytics/top-apis")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
