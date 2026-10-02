use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    response::Response,
};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn test_app() -> Router {
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
    build_router(state)
}

async fn response_json(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn json_request(
    app: &Router,
    token: Option<&str>,
    method: Method,
    uri: &str,
    payload: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match payload {
        Some(payload) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(payload.to_string())
        }
        None => Body::empty(),
    };
    response_json(
        app.clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap(),
    )
    .await
}

async fn login_admin(app: &Router) -> String {
    login_as(app, "admin@doorman.dev", "AdminPassword123!").await
}

async fn login_as(app: &Router, email: &str, password: &str) -> String {
    let (status, body) = json_request(
        app,
        None,
        Method::POST,
        "/platform/authorization",
        Some(json!({
            "email": email,
            "password": password
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn self_service_updates_cannot_escalate_privileges() {
    let app = test_app().await;
    let admin = login_admin(&app).await;
    let (status, role) = json_request(
        &app,
        Some(&admin),
        Method::POST,
        "/platform/role",
        Some(json!({"role_name": "limited", "manage_users": false})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{role}");
    let password = "LimitedPassword123!";
    let (status, user) = json_request(
        &app,
        Some(&admin),
        Method::POST,
        "/platform/user",
        Some(json!({
            "username": "limited_user",
            "email": "limited@example.com",
            "password": password,
            "role": "limited",
            "groups": ["ALL"],
            "active": true,
            "ui_access": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    let limited = login_as(&app, "limited@example.com", password).await;
    let (status, users) = json_request(
        &app,
        Some(&limited),
        Method::GET,
        "/platform/user/all?page=1&page_size=100",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{users}");
    assert!(
        users["users"]
            .as_array()
            .unwrap()
            .iter()
            .all(|user| user["role"] != "admin")
    );
    for payload in [
        json!({"role": "admin"}),
        json!({"groups": ["ALL", "admin"]}),
        json!({"active": false}),
        json!({"username": "escalated"}),
    ] {
        let (status, body) = json_request(
            &app,
            Some(&limited),
            Method::PUT,
            "/platform/user/limited_user",
            Some(payload),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error_code"], "USR023");
    }
    let (status, body) = json_request(
        &app,
        Some(&limited),
        Method::PUT,
        "/platform/user/limited_user",
        Some(json!({"email": "updated@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = json_request(
        &app,
        Some(&admin),
        Method::PUT,
        "/platform/user/limited_user",
        Some(json!({"role": "admin"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// Python source: backend-services/tests/test_user_endpoints.py::test_user_me_and_crud
#[tokio::test]
async fn python_test_user_me_and_crud() {
    let app = test_app().await;
    let token = login_admin(&app).await;

    let (status, me) =
        json_request(&app, Some(&token), Method::GET, "/platform/user/me", None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["username"], "admin");

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::POST,
        "/platform/user",
        Some(json!({
            "username": "testuser1",
            "email": "testuser1@example.com",
            "password": "ThisIsAStrongPwd!123",
            "role": "admin",
            "groups": ["ALL"],
            "active": true,
            "ui_access": false
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{body}"
    );

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/user/testuser1",
        Some(json!({"email": "new@mail.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/user/testuser1/update-password",
        Some(json!({"new_password": "ThisIsANewPwd!456"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::DELETE,
        "/platform/user/testuser1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn admin_can_read_list_update_and_delete_administrator_resources() {
    let app = test_app().await;
    let token = login_admin(&app).await;

    let (status, role) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/role/admin",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{role}");
    assert_eq!(role["role_name"], "admin");

    let (status, roles) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/role/all?page=1&page_size=50",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{roles}");
    assert!(
        roles["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|role| role["role_name"] == "admin")
    );

    let (status, users) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/user/all?page=1&page_size=100",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{users}");
    assert!(
        users["users"]
            .as_array()
            .unwrap()
            .iter()
            .any(|user| user["username"] == "admin")
    );

    let description = "Administrator role parity description";
    let (status, updated_role) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/role/admin",
        Some(json!({"role_description": description})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated_role}");
    let (status, role) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/role/admin",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{role}");
    assert_eq!(role["role_description"], description);

    let (status, admin_by_email) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/user/email/admin@doorman.dev",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admin_by_email}");
    assert_eq!(admin_by_email["username"], "admin");
    let (status, update) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/user/admin",
        Some(json!({"email": "new-email@example.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{update}");
    assert_eq!(update["error_code"], "USR020");
    let (status, deleted_admin) = json_request(
        &app,
        Some(&token),
        Method::DELETE,
        "/platform/user/admin",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{deleted_admin}");
    assert_eq!(deleted_admin["error_code"], "USR021");
    let (status, password) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/user/admin/update-password",
        Some(json!({"current_password": "anything", "new_password": "NewPassword!123"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{password}");
    assert_eq!(password["error_code"], "USR022");

    let username = "parity_admin";
    let (status, created) = json_request(
        &app,
        Some(&token),
        Method::POST,
        "/platform/user",
        Some(json!({
            "username": username,
            "email": "parity_admin@example.com",
            "password": "ParityAdminPassword123!",
            "role": "admin",
            "groups": ["ALL", "admin"],
            "active": true,
            "ui_access": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, user) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/user/parity_admin",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["username"], username);
    let (status, deleted) = json_request(
        &app,
        Some(&token),
        Method::DELETE,
        "/platform/user/parity_admin",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (status, _) = json_request(
        &app,
        Some(&token),
        Method::GET,
        "/platform/user/parity_admin",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// Python source:
// backend-services/tests/test_user_permissions_negative.py::test_update_other_user_denied_without_permission
#[tokio::test]
async fn python_test_update_other_user_denied_without_permission() {
    let app = test_app().await;
    let token = login_admin(&app).await;

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::POST,
        "/platform/role",
        Some(json!({
            "role_name": "user",
            "role_description": "Standard user"
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{body}"
    );

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::POST,
        "/platform/user",
        Some(json!({
            "username": "qa_user",
            "email": "qa@doorman.dev",
            "password": "QaPass123_ValidLen!!",
            "role": "user"
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{body}"
    );

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/role/admin",
        Some(json!({"manage_users": false})),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{body}"
    );

    let (status, _) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/user/qa_user",
        Some(json!({"email": "qa2@doorman.dev"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/role/admin",
        Some(json!({"manage_users": true})),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{body}"
    );

    let (status, body) = json_request(
        &app,
        Some(&token),
        Method::PUT,
        "/platform/user/qa_user",
        Some(json!({"email": "qa3@doorman.dev"})),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{body}"
    );
}
