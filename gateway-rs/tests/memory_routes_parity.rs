use std::{process::Command, sync::Arc};

use axum::body::{Body, to_bytes};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const PASSWORD: &str = "MemoryRouteTestPassword123!";

async fn request(
    app: &axum::Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    payload: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
        .unwrap();
    (status, body)
}

async fn login(app: &axum::Router, username: &str) -> String {
    let (status, body) = request(
        app,
        Method::POST,
        "/platform/authorization",
        None,
        json!({"email": format!("{username}@example.test"), "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn python_memory_route_contracts_in_isolated_processes() {
    // Production reads snapshot settings from the process environment. Separate
    // processes exercise those same routes without racing other tests' env vars.
    let Ok(mode) = std::env::var("DOORMAN_MEMORY_ROUTE_TEST_MODE") else {
        for mode in ["configured", "missing-key", "short-key"] {
            let directory =
                std::env::temp_dir().join(format!("doorman-memory-routes-{}", Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "python_memory_route_contracts_in_isolated_processes",
                    "--nocapture",
                ])
                .env("DOORMAN_MEMORY_ROUTE_TEST_MODE", mode)
                .env("MEM_DUMP_PATH", directory.join("default/memory_dump.bin"))
                .current_dir(&directory);
            if mode == "configured" {
                command.env("MEM_ENCRYPTION_KEY", "memory-route-fixture-key");
            } else if mode == "short-key" {
                command.env("MEM_ENCRYPTION_KEY", "short");
            } else {
                command.env_remove("MEM_ENCRYPTION_KEY");
            }
            let output = command.output().unwrap();
            std::fs::remove_dir_all(&directory).unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };

    let config = Config::for_test("unused".to_owned());
    let storage = Arc::new(
        SharedStorage::connect(&config.shared_storage)
            .await
            .unwrap(),
    );
    storage
        .insert_one(
            "roles",
            json!({"role_name": "admin", "manage_users": true,
        "manage_roles": true, "manage_security": true}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "roles",
            json!({"role_name": "user", "manage_security": false}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({"username": "admin", "email": "admin@example.test",
        "password": bcrypt::hash(PASSWORD, 4).unwrap(), "role": "admin", "groups": ["ALL"],
        "active": true, "ui_access": true}),
        )
        .await
        .unwrap();
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(storage.clone());
    let app = build_router(state);
    let admin = login(&app, "admin").await;

    if mode == "missing-key" || mode == "short-key" {
        for path in ["/platform/memory/dump", "/platform/memory/restore"] {
            let (status, body) = request(&app, Method::POST, path, Some(&admin), json!({})).await;
            if mode == "missing-key" {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(body["error_code"], "MEM002");
            } else {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(body["error_code"], "GTW999");
            }
        }
        return;
    }

    let (status, body) = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        json!({"role_name": "security-manager", "manage_security": true}),
    )
    .await;
    assert!(status.is_success(), "{body}");
    for (username, role) in [
        ("limited", "user"),
        ("manager", "security-manager"),
        ("e2euser", "admin"),
    ] {
        let (status, body) = request(
            &app,
            Method::POST,
            "/platform/user",
            Some(&admin),
            json!({"username": username, "email": format!("{username}@example.test"),
                "password": PASSWORD, "role": role, "groups": ["ALL"], "ui_access": true}),
        )
        .await;
        assert!(status.is_success(), "{body}");
    }
    let limited = login(&app, "limited").await;
    for (path, code) in [
        ("/platform/memory/dump", "SEC003"),
        ("/platform/memory/restore", "SEC004"),
    ] {
        let (status, body) = request(&app, Method::POST, path, Some(&limited), json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error_code"], code);
    }

    let manager = login(&app, "manager").await;
    let (status, body) = request(
        &app,
        Method::POST,
        "/platform/memory/dump",
        Some(&manager),
        json!({"path": []}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["detail"][0]["loc"], json!(["body", "path"]));

    let (status, body) = request(
        &app,
        Method::POST,
        "/platform/memory/dump",
        Some(&manager),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let dump_path = body["response"]["path"].as_str().unwrap();
    assert!(dump_path.ends_with(".bin") && std::path::Path::new(dump_path).is_file());

    let custom_hint = std::env::current_dir()
        .unwrap()
        .join("custom/permitted.bin");
    let (status, body) = request(
        &app,
        Method::POST,
        "/platform/memory/dump",
        Some(&manager),
        json!({"path": custom_hint}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let dump_path = body["response"]["path"].as_str().unwrap();
    assert!(std::path::Path::new(dump_path).is_file());
    assert_eq!(
        std::path::Path::new(dump_path).parent(),
        custom_hint.parent()
    );

    let (status, body) = request(
        &app,
        Method::DELETE,
        "/platform/user/e2euser",
        Some(&admin),
        json!({}),
    )
    .await;
    assert!(status.is_success(), "{body}");
    assert!(
        storage
            .find_one("users", &json!({"username": "e2euser"}))
            .await
            .unwrap()
            .is_none()
    );
    // A same-stem backup exists; an explicit nonexistent path must still be 404.
    let (status, body) = request(
        &app,
        Method::POST,
        "/platform/memory/restore",
        Some(&manager),
        json!({"path": std::env::var("MEM_DUMP_PATH").unwrap()}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error_code"], "MEM003");
    assert!(
        storage
            .find_one("users", &json!({"username": "e2euser"}))
            .await
            .unwrap()
            .is_none()
    );

    let (status, body) = request(
        &app,
        Method::POST,
        "/platform/memory/restore",
        Some(&manager),
        json!({"path": dump_path}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["response"]["version"], 1);
    let (status, body) = request(
        &app,
        Method::GET,
        "/platform/user/e2euser",
        Some(&admin),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["username"], "e2euser");
    login(&app, "e2euser").await;
}
