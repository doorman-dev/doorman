use std::sync::{Arc, OnceLock};

use axum::body::{Body, to_bytes};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
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

async fn app() -> axum::Router {
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one(
            "roles",
            json!({
                "role_name": "admin",
                "manage_users": true, "manage_apis": true, "manage_endpoints": true,
                "manage_groups": true, "manage_roles": true, "manage_routings": true,
                "manage_gateway": true, "manage_subscriptions": true, "manage_credits": true,
                "manage_auth": true, "manage_security": true, "manage_tiers": true,
                "manage_rate_limits": true, "view_analytics": true, "view_logs": true,
                "export_logs": true
            }),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({
                "username": "admin", "email": "admin@doorman.dev",
                "password": bcrypt::hash(fixture_password(), bcrypt::DEFAULT_COST).unwrap(),
                "role": "admin", "groups": ["ALL", "admin"], "active": true, "ui_access": true
            }),
        )
        .await
        .unwrap();
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(Arc::new(storage));
    build_router(state)
}

async fn request(
    app: &axum::Router,
    method: Method,
    path: &str,
    auth: Option<&(String, String)>,
    payload: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some((cookie, csrf)) = auth {
        builder = builder
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf);
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

async fn login(app: &axum::Router, email: &str, password: &str) -> (String, String) {
    let response = request(
        app,
        Method::POST,
        "/platform/authorization",
        None,
        Some(json!({"email": email, "password": password})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    let csrf = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("csrf_token="))
        .unwrap()
        .to_owned();
    (cookies.join("; "), csrf)
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

async fn create_user(
    app: &axum::Router,
    admin: &(String, String),
    username: &str,
    role: &str,
) -> (String, String) {
    let email = format!("{username}@example.com");
    let password = fixture_password();
    let response = request(
        app,
        Method::POST,
        "/platform/user",
        Some(admin),
        Some(json!({
            "username": username, "email": email, "password": password, "role": role,
            "groups": ["ALL"], "ui_access": true
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    login(app, &email, password).await
}

async fn management_attempt(
    app: &axum::Router,
    auth: &(String, String),
    permission: &str,
    index: usize,
    role: &str,
) -> axum::response::Response {
    let (path, payload) = match permission {
        "manage_apis" => (
            "/platform/api",
            json!({
                "api_name": format!("managed-api-{index}"), "api_version": "v1",
                "api_description": "managed", "api_allowed_roles": ["admin"],
                "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"],
                "api_type": "REST"
            }),
        ),
        "manage_endpoints" => (
            "/platform/endpoint",
            json!({
                "api_name": "permission-matrix-api", "api_version": "v1",
                "endpoint_method": "GET", "endpoint_uri": format!("/managed-{index}"),
                "endpoint_description": "managed"
            }),
        ),
        "manage_users" => (
            "/platform/user",
            json!({
                "username": format!("managed-user-{index}"),
                "email": format!("managed-user-{index}@example.com"),
                "password": fixture_password(), "role": role,
                "groups": ["ALL"], "ui_access": false
            }),
        ),
        "manage_groups" => (
            "/platform/group",
            json!({
                "group_name": format!("managed-group-{index}"), "group_description": "x"
            }),
        ),
        "manage_roles" => (
            "/platform/role",
            json!({
                "role_name": format!("managed-role-{index}"), "role_description": "x"
            }),
        ),
        _ => unreachable!(),
    };
    request(app, Method::POST, path, Some(auth), Some(payload)).await
}

#[tokio::test]
async fn live_role_permission_matrix_blocks_then_allows_each_management_operation() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let api = request(
        &app,
        Method::POST,
        "/platform/api",
        Some(&admin),
        Some(json!({
            "api_name": "permission-matrix-api", "api_version": "v1",
            "api_description": "permission matrix fixture", "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"], "api_servers": ["http://127.0.0.1:9"],
            "api_type": "REST", "active": true
        })),
    )
    .await;
    assert_eq!(api.status(), StatusCode::CREATED);
    let endpoint = request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&admin),
        Some(json!({
            "api_name": "permission-matrix-api", "api_version": "v1",
            "endpoint_method": "GET", "endpoint_uri": "/visible",
            "endpoint_description": "pinned Python authorization boundary"
        })),
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::CREATED);

    for (index, (permission, expected_code)) in [
        ("manage_apis", "API007"),
        ("manage_endpoints", "END010"),
        ("manage_users", "USR006"),
        ("manage_groups", "GRP008"),
        ("manage_roles", "ROLE009"),
    ]
    .into_iter()
    .enumerate()
    {
        let role = format!("matrix-{index}");
        let mut role_payload = json!({"role_name": role});
        role_payload[permission] = json!(false);
        let created = request(
            &app,
            Method::POST,
            "/platform/role",
            Some(&admin),
            Some(role_payload),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED, "{permission}");
        let user = create_user(&app, &admin, &format!("matrix-user-{index}"), &role).await;

        let attempt = management_attempt(&app, &user, permission, index, &role).await;
        assert_eq!(attempt.status(), StatusCode::FORBIDDEN, "{permission}");
        assert_eq!(
            json_body(attempt).await["error_code"],
            expected_code,
            "{permission}"
        );

        let mut update = json!({});
        update[permission] = json!(true);
        let enabled = request(
            &app,
            Method::PUT,
            &format!("/platform/role/{role}"),
            Some(&admin),
            Some(update),
        )
        .await;
        assert_eq!(enabled.status(), StatusCode::OK, "{permission}");
        let allowed = management_attempt(&app, &user, permission, index + 10, &role).await;
        assert_ne!(allowed.status(), StatusCode::FORBIDDEN, "{permission}");
    }
}

#[tokio::test]
async fn least_privilege_role_cannot_create_apis_or_read_logs() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let role = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({
            "role_name": "viewer",
            "manage_users": false,
            "manage_apis": false,
            "manage_endpoints": false,
            "manage_groups": false,
            "manage_roles": false,
            "manage_routings": false,
            "manage_gateway": false,
            "manage_subscriptions": false,
            "manage_security": false,
            "view_logs": false,
            "export_logs": false
        })),
    )
    .await;
    assert_eq!(role.status(), StatusCode::CREATED);
    let group = request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&admin),
        Some(json!({"group_name": "team1", "group_description": "team one"})),
    )
    .await;
    assert_eq!(group.status(), StatusCode::CREATED);
    let viewer = request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&admin),
        Some(json!({
            "username": "viewer1",
            "email": "viewer1@example.com",
            "password": fixture_password(),
            "role": "viewer",
            "groups": ["team1"],
            "active": true,
            "ui_access": true
        })),
    )
    .await;
    assert_eq!(viewer.status(), StatusCode::CREATED);
    let viewer = login(&app, "viewer1@example.com", fixture_password()).await;
    let api = request(
        &app,
        Method::POST,
        "/platform/api",
        Some(&admin),
        Some(json!({
            "api_name": "legacy-open-management", "api_version": "v1",
            "api_description": "pinned Python authorization boundary",
            "api_allowed_roles": ["admin"], "api_allowed_groups": ["ALL"],
            "api_servers": ["http://127.0.0.1:9"], "api_type": "REST"
        })),
    )
    .await;
    assert_eq!(api.status(), StatusCode::CREATED);
    let endpoint = request(
        &app,
        Method::POST,
        "/platform/endpoint",
        Some(&admin),
        Some(json!({
            "api_name": "legacy-open-management", "api_version": "v1",
            "endpoint_method": "GET", "endpoint_uri": "/visible",
            "endpoint_description": "pinned Python authorization boundary"
        })),
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::CREATED);
    let create_api = request(
        &app,
        Method::POST,
        "/platform/api",
        Some(&viewer),
        Some(json!({
            "api_name": "blocked",
            "api_version": "v1",
            "api_description": "blocked",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["ALL"],
            "api_servers": ["http://127.0.0.1:9"],
            "api_type": "REST"
        })),
    )
    .await;
    assert_eq!(create_api.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(create_api).await["error_code"], "API007");
    for path in [
        "/platform/api/all?page=1&page_size=100",
        "/platform/api/legacy-open-management/v1",
        "/platform/endpoint/legacy-open-management/v1?page=1&page_size=100",
    ] {
        let response = request(&app, Method::GET, path, Some(&viewer), None).await;
        let status = response.status();
        let body = json_body(response).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    let update_endpoint = request(
        &app,
        Method::PUT,
        "/platform/endpoint/GET/legacy-open-management/v1/visible",
        Some(&viewer),
        Some(json!({"endpoint_description": "blocked"})),
    )
    .await;
    assert_eq!(update_endpoint.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(update_endpoint).await["error_code"], "END011");
    let delete_endpoint = request(
        &app,
        Method::DELETE,
        "/platform/endpoint/GET/legacy-open-management/v1/visible",
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(delete_endpoint.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(delete_endpoint).await["error_code"], "END012");
    for (method, path, payload, code) in [
        (
            Method::POST,
            "/platform/endpoint/endpoint/validation",
            Some(json!({
                "endpoint_id": "missing", "validation_enabled": true,
                "validation_schema": {"validation_schema": {}}
            })),
            "END013",
        ),
        (
            Method::PUT,
            "/platform/endpoint/endpoint/validation/missing",
            Some(json!({
                "validation_enabled": true,
                "validation_schema": {"validation_schema": {}}
            })),
            "END014",
        ),
        (
            Method::DELETE,
            "/platform/endpoint/endpoint/validation/missing",
            None,
            "END015",
        ),
    ] {
        let response = request(&app, method, path, Some(&viewer), payload).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(json_body(response).await["error_code"], code, "{path}");
    }
    let deleted = request(
        &app,
        Method::DELETE,
        "/platform/api/legacy-open-management/v1",
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(
        json_body(deleted).await,
        json!({"message": "API deleted successfully"})
    );
    for (path, code) in [
        ("/platform/logging/logs", "LOG001"),
        ("/platform/logging/logs/files", "LOG001"),
        ("/platform/logging/logs/statistics", "LOG001"),
        ("/platform/logging/logs/export", "LOG003"),
        ("/platform/logging/logs/download", "LOG004"),
    ] {
        let response = request(&app, Method::GET, path, Some(&viewer), None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(json_body(response).await["error_code"], code, "{path}");
    }

    let enable_log_reading = request(
        &app,
        Method::PUT,
        "/platform/role/viewer",
        Some(&admin),
        Some(json!({"view_logs": true})),
    )
    .await;
    assert_eq!(enable_log_reading.status(), StatusCode::OK);
    for path in [
        "/platform/logging/logs",
        "/platform/logging/logs/files",
        "/platform/logging/logs/statistics",
    ] {
        let response = request(&app, Method::GET, path, Some(&viewer), None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    for (path, code) in [
        ("/platform/logging/logs/export", "LOG003"),
        ("/platform/logging/logs/download", "LOG004"),
    ] {
        let response = request(&app, Method::GET, path, Some(&viewer), None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(json_body(response).await["error_code"], code, "{path}");
    }

    let enable_log_export = request(
        &app,
        Method::PUT,
        "/platform/role/viewer",
        Some(&admin),
        Some(json!({"export_logs": true})),
    )
    .await;
    assert_eq!(enable_log_export.status(), StatusCode::OK);
    for path in [
        "/platform/logging/logs/export",
        "/platform/logging/logs/download",
    ] {
        let response = request(&app, Method::GET, path, Some(&viewer), None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn non_admin_managers_cannot_discover_or_manage_bootstrap_admin() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let manager_role = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({
            "role_name": "manager",
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
            "view_logs": true,
            "export_logs": true
        })),
    )
    .await;
    assert_eq!(manager_role.status(), StatusCode::CREATED);
    let manager = request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&admin),
        Some(json!({
            "username": "manager1",
            "email": "manager1@example.com",
            "password": fixture_password(),
            "role": "manager",
            "groups": ["ALL"],
            "active": true,
            "ui_access": true
        })),
    )
    .await;
    assert_eq!(manager.status(), StatusCode::CREATED);
    let manager = login(&app, "manager1@example.com", fixture_password()).await;

    let roles = request(
        &app,
        Method::GET,
        "/platform/role/all?page=1&page_size=50",
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(roles.status(), StatusCode::OK);
    assert!(
        json_body(roles).await["roles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|role| role["role_name"] != "admin")
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/role/admin",
            Some(&manager),
            None,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    let users = request(
        &app,
        Method::GET,
        "/platform/user/all?page=1&page_size=100",
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(users.status(), StatusCode::OK);
    assert!(
        json_body(users).await["response"]["users"]
            .as_array()
            .unwrap()
            .iter()
            .all(|user| user["role"] != "admin")
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/user/admin",
            Some(&manager),
            None,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    for method in [Method::PUT, Method::DELETE] {
        let response = request(
            &app,
            method,
            "/platform/user/admin",
            Some(&manager),
            Some(json!({"ui_access": true})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let assign_admin = request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&manager),
        Some(json!({
            "username": "forbidden_admin",
            "email": "forbidden_admin@example.com",
            "password": fixture_password(),
            "role": "admin",
            "groups": ["ALL"],
            "active": true,
            "ui_access": true
        })),
    )
    .await;
    assert_eq!(assign_admin.status(), StatusCode::FORBIDDEN);
    for (method, path) in [
        (Method::GET, "/platform/authorization/admin/status/admin"),
        (Method::POST, "/platform/authorization/admin/revoke/admin"),
        (Method::POST, "/platform/authorization/admin/unrevoke/admin"),
        (Method::POST, "/platform/authorization/admin/disable/admin"),
        (Method::POST, "/platform/authorization/admin/enable/admin"),
    ] {
        let response = request(&app, method, path, Some(&manager), Some(json!({}))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let body = json_body(response).await;
        assert_eq!(body, json!({"error_message": "User not found"}), "{path}");
    }
}

#[tokio::test]
async fn group_crud_requires_manage_groups_and_allows_group_manager() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    for (role, manage_groups) in [("limited", false), ("group-manager", true)] {
        let response = request(
            &app,
            Method::POST,
            "/platform/role",
            Some(&admin),
            Some(json!({
                "role_name": role, "manage_groups": manage_groups
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let limited = create_user(&app, &admin, "limited-user", "limited").await;
    let manager = create_user(&app, &admin, "group-manager-user", "group-manager").await;

    let forbidden = request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&limited),
        Some(json!({
            "group_name": "parity-group", "group_description": "x"
        })),
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(forbidden).await["error_code"], "GRP008");

    let created = request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&manager),
        Some(json!({
            "group_name": "parity-group", "group_description": "x"
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let fetched = request(
        &app,
        Method::GET,
        "/platform/group/parity-group",
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);
    assert_eq!(json_body(fetched).await["group_description"], "x");
    let updated = request(
        &app,
        Method::PUT,
        "/platform/group/parity-group",
        Some(&manager),
        Some(json!({"group_description": "y"})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let deleted = request(
        &app,
        Method::DELETE,
        "/platform/group/parity-group",
        Some(&manager),
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
}

#[tokio::test]
async fn python_test_roles_and_groups_crud() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;

    let role = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({
            "role_name": "qa",
            "role_description": "QA Role",
            "manage_users": false,
            "manage_apis": true,
            "manage_endpoints": true,
            "manage_groups": false,
            "manage_roles": false,
            "manage_routings": false,
            "manage_gateway": false,
            "manage_subscriptions": true,
            "manage_security": false,
            "view_logs": true,
            "export_logs": false
        })),
    )
    .await;
    assert!(matches!(
        role.status(),
        StatusCode::OK | StatusCode::CREATED
    ));
    assert_eq!(
        request(&app, Method::GET, "/platform/role/qa", Some(&admin), None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/role/all?page=1&page_size=50",
            Some(&admin),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::PUT,
            "/platform/role/qa",
            Some(&admin),
            Some(json!({"manage_groups": true}))
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::DELETE,
            "/platform/role/qa",
            Some(&admin),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );

    let group = request(
        &app,
        Method::POST,
        "/platform/group",
        Some(&admin),
        Some(json!({
            "group_name": "qa-group",
            "group_description": "QA",
            "api_access": []
        })),
    )
    .await;
    assert!(matches!(
        group.status(),
        StatusCode::OK | StatusCode::CREATED
    ));
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/group/qa-group",
            Some(&admin),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/group/all?page=1&page_size=50",
            Some(&admin),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::PUT,
            "/platform/group/qa-group",
            Some(&admin),
            Some(json!({"group_description": "Quality Group"}))
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::DELETE,
            "/platform/group/qa-group",
            Some(&admin),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn subscription_target_requires_the_python_group_access_gate() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let api = request(
        &app,
        Method::POST,
        "/platform/api",
        Some(&admin),
        Some(json!({
            "api_name": "group-restricted",
            "api_version": "v1",
            "api_description": "restricted subscription fixture",
            "api_allowed_roles": ["admin"],
            "api_allowed_groups": ["team1"],
            "api_servers": ["http://127.0.0.1:9"],
            "api_type": "REST"
        })),
    )
    .await;
    assert_eq!(api.status(), StatusCode::CREATED);
    let bob = request(
        &app,
        Method::POST,
        "/platform/user",
        Some(&admin),
        Some(json!({
            "username": "bob",
            "email": "bob@example.com",
            "password": fixture_password(),
            "role": "admin",
            "groups": ["team2"],
            "active": true,
            "ui_access": true
        })),
    )
    .await;
    assert_eq!(bob.status(), StatusCode::CREATED);

    let response = request(
        &app,
        Method::POST,
        "/platform/subscription/subscribe",
        Some(&admin),
        Some(json!({
            "username": "bob",
            "api_name": "group-restricted",
            "api_version": "v1"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response).await["error_code"], "SUB007");
}

#[tokio::test]
async fn routing_crud_requires_manage_routings_and_allows_routing_manager() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    for (role_name, manage_routings) in [("routing-limited", false), ("routing-manager", true)] {
        let role = request(
            &app,
            Method::POST,
            "/platform/role",
            Some(&admin),
            Some(json!({
                "role_name": role_name,
                "manage_routings": manage_routings
            })),
        )
        .await;
        assert_eq!(role.status(), StatusCode::CREATED);
    }
    let limited = create_user(&app, &admin, "routing-limited-user", "routing-limited").await;
    let manager = create_user(&app, &admin, "routing-manager-user", "routing-manager").await;
    let payload = json!({
        "client_key": "routing-parity-client",
        "routing_name": "routing parity",
        "routing_servers": ["http://upstream.local"]
    });

    let denied = request(
        &app,
        Method::POST,
        "/platform/routing",
        Some(&limited),
        Some(payload.clone()),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let created = request(
        &app,
        Method::POST,
        "/platform/routing",
        Some(&manager),
        Some(payload),
    )
    .await;
    assert!(matches!(
        created.status(),
        StatusCode::OK | StatusCode::CREATED
    ));
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/routing/all",
            Some(&manager),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::PUT,
            "/platform/routing/routing-parity-client",
            Some(&manager),
            Some(json!({"routing_description": "updated"}))
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            Method::DELETE,
            "/platform/routing/routing-parity-client",
            Some(&manager),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn missing_group_and_role_contracts_match_python_service_codes() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    for (method, path, code) in [
        (Method::GET, "/platform/group/not-a-group", "GRP002"),
        (Method::GET, "/platform/role/not-a-role", "ROLE004"),
        (Method::DELETE, "/platform/group/not-a-group", "GRP002"),
        (Method::DELETE, "/platform/role/not-a-role", "ROLE004"),
    ] {
        let expected = if method == Method::DELETE && path.contains("/role/") {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::NOT_FOUND
        };
        let response = request(&app, method, path, Some(&admin), None).await;
        assert_eq!(response.status(), expected, "{path}");
        assert_eq!(json_body(response).await["error_code"], code, "{path}");
    }
}

#[tokio::test]
async fn non_admin_role_manager_cannot_create_admin_role() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let role = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({
            "role_name": "role-manager", "manage_roles": true
        })),
    )
    .await;
    assert_eq!(role.status(), StatusCode::CREATED);
    let manager = create_user(&app, &admin, "role-manager-user", "role-manager").await;
    let response = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&manager),
        Some(json!({
            "role_name": "admin", "manage_roles": true
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response).await["error_code"], "ROLE013");
}

#[tokio::test]
async fn role_route_permissions_visibility_and_admin_codes_match_python() {
    let app = app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    for (name, manage_roles) in [("role-viewer", false), ("role-manager", true)] {
        let response = request(
            &app,
            Method::POST,
            "/platform/role",
            Some(&admin),
            Some(json!({"role_name": name, "manage_roles": manage_roles})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let viewer = create_user(&app, &admin, "role-viewer-user", "role-viewer").await;
    let manager = create_user(&app, &admin, "role-manager-2", "role-manager").await;

    let listed = request(
        &app,
        Method::GET,
        "/platform/role?page=1&page_size=10",
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed).await;
    assert!(listed["roles"].is_array());
    assert_eq!(listed["page"], 1);
    assert_eq!(listed["page_size"], 10);
    assert!(
        listed["roles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|role| role["role_name"] != "admin")
    );
    assert_eq!(
        request(
            &app,
            Method::GET,
            "/platform/role/role-viewer",
            Some(&viewer),
            None,
        )
        .await
        .status(),
        StatusCode::OK
    );

    for (method, path, payload, code) in [
        (
            Method::POST,
            "/platform/role",
            Some(json!({"role_name": "denied-role"})),
            "ROLE009",
        ),
        (
            Method::PUT,
            "/platform/role/role-viewer",
            Some(json!({"view_logs": true})),
            "ROLE010",
        ),
        (
            Method::DELETE,
            "/platform/role/role-viewer",
            None,
            "ROLE011",
        ),
    ] {
        let response = request(&app, method, path, Some(&viewer), payload).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(response).await["error_code"], code);
    }

    for (method, code) in [(Method::PUT, "ROLE014"), (Method::DELETE, "ROLE016")] {
        let response = request(
            &app,
            method,
            "/platform/role/admin",
            Some(&manager),
            Some(json!({"view_logs": true})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(response).await["error_code"], code);
    }
}
