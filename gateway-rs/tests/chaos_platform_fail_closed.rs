// Own test binary: the chaos outage flags are process-global, so toggling them
// here must not race the platform suites that share a process.
use std::sync::{Arc, atomic::Ordering};

use axum::body::{Body, to_bytes};
use doorman_gateway::{
    AppState, Config, build_router, middleware::chaos::CHAOS_MONGO_OUTAGE,
    storage::runtime::SharedStorage,
};
use http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASSWORD: &str = "fail-closed-password-123";

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn login_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/platform/authorization")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"email": "admin@doorman.dev", "password": PASSWORD}).to_string(),
        ))
        .unwrap()
}

fn me_request(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/platform/user/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Approved security divergence: while storage is unavailable the Rust
/// platform cannot evaluate the persisted IP/security policy, so every
/// platform request -- including login and cached-user reads that Python's
/// in-memory cache would still serve -- fails closed with 503 SEC012, and
/// recovers as soon as storage returns.
#[tokio::test]
async fn storage_outage_fails_platform_requests_closed_and_recovers() {
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one("roles", json!({"role_name": "admin", "manage_users": true}))
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": "admin", "email": "admin@doorman.dev",
                "password": bcrypt::hash(PASSWORD, 4).unwrap(),
                "role": "admin", "groups": ["ALL", "admin"], "active": true, "ui_access": true
            }),
        )
        .await
        .unwrap();
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(Arc::new(storage));
    let app = build_router(state);

    let (status, body) = send(&app, login_request()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_owned();

    CHAOS_MONGO_OUTAGE.store(true, Ordering::Relaxed);
    let during_me = send(&app, me_request(&token)).await;
    let during_login = send(&app, login_request()).await;
    CHAOS_MONGO_OUTAGE.store(false, Ordering::Relaxed);

    for (status, body) in [during_me, during_login] {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error_code"], "SEC012");
    }
    let (status, body) = send(&app, me_request(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
