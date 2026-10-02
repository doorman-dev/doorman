use std::sync::{Arc, OnceLock};

use axum::body::{Body, to_bytes};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "admin@doorman.dev";
const LIMITED_EMAIL: &str = "limited@doorman.dev";
const MANAGER_EMAIL: &str = "security-manager@doorman.dev";
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

async fn parity_state() -> AppState {
    let mut config = Config::for_test("removed-internal-backend".to_owned());
    config.https_only = false;
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();

    for role in [
        json!({
            "role_name": "admin",
            "manage_gateway": true,
            "manage_security": true,
            "view_logs": true,
            "export_logs": true
        }),
        json!({
            "role_name": "limited",
            "manage_gateway": false,
            "manage_security": false,
            "view_logs": false,
            "export_logs": false
        }),
        json!({
            "role_name": "security-manager",
            "manage_gateway": false,
            "manage_security": true,
            "view_logs": false,
            "export_logs": false
        }),
    ] {
        storage.insert_one("roles", role).await.unwrap();
    }

    for (username, email, password, role) in [
        ("admin", ADMIN_EMAIL, fixture_password(), "admin"),
        ("limited", LIMITED_EMAIL, fixture_password(), "limited"),
        (
            "security-manager",
            MANAGER_EMAIL,
            fixture_password(),
            "security-manager",
        ),
    ] {
        storage
            .insert_one(
                "users",
                json!({
                    "username": username,
                    "email": email,
                    "password": bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap(),
                    "role": role,
                    "groups": [],
                    "active": true,
                    "ui_access": true
                }),
            )
            .await
            .unwrap();
    }

    let mut state = AppState::new(config).unwrap();
    state.storage = Some(Arc::new(storage));
    state
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

fn response_payload(body: &Value) -> &Value {
    body.get("response").unwrap_or(body)
}

#[tokio::test]
async fn security_settings_file_persistence_and_immediate_autosave() {
    if std::env::var_os("DOORMAN_SETTINGS_FILE_TEST_CHILD").is_none() {
        let directory =
            std::env::temp_dir().join(format!("doorman-settings-http-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security_settings_file_persistence_and_immediate_autosave",
                "--nocapture",
            ])
            .env("DOORMAN_SETTINGS_FILE_TEST_CHILD", "1")
            .env("MEM_ENCRYPTION_KEY", "settings-autosave-test-key")
            .env("MEM_AUTO_SAVE_ENABLED", "false")
            .current_dir(&directory)
            .output()
            .unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let directory = std::env::current_dir().unwrap();
    let file = directory.join("settings/security.json");
    let dump_directory = directory.join("dumps");
    let hint = dump_directory.join("wanted_dump.bin");
    let mut state = parity_state().await;
    state.config.security_settings_file = Some(file.clone());
    let storage = state.storage.as_ref().unwrap().clone();
    let settings = doorman_gateway::storage::security_settings::load(&storage, &state.config)
        .await
        .unwrap();
    state.runtime.update_memory_autosave_config(
        doorman_gateway::state::MemoryAutosaveConfig::from_settings(Some(&settings)),
    );
    let runtime = state.runtime.clone();
    let config = state.config.clone();
    let worker =
        doorman_gateway::storage::snapshot::spawn_autosave(storage.clone(), runtime.clone());
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let update = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({
            "enable_auto_save": true, "auto_save_frequency_seconds": 90, "dump_path": hint,
            "trust_x_forwarded_for": true, "xff_trusted_proxies": ["10.0.0.1/32"]
        })),
    )
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    let body = response_json(update).await;
    assert_eq!(response_payload(&body)["auto_save_frequency_seconds"], 90);
    assert_eq!(response_payload(&body)["enable_auto_save"], true);
    let bytes = std::fs::read(&file).unwrap();
    assert!(!bytes.is_empty());
    let persisted: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(persisted.get("_id").is_none());
    assert!(persisted.get("memory_only").is_none());
    assert_eq!(persisted["dump_path"], json!(hint));
    assert_eq!(persisted["auto_save_frequency_seconds"], 90);

    // A five-second deadline proves an immediate dump, not a 90-second wait.
    let dump = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(entries) = std::fs::read_dir(&dump_directory) {
                if let Some(path) = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| path.extension().is_some_and(|extension| extension == "bin"))
                {
                    break path;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("settings update must trigger an immediate encrypted dump");
    assert!(
        dump.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("wanted_dump-")
    );
    assert!(
        runtime
            .memory_snapshot_healthy
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    let restored = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    doorman_gateway::storage::snapshot::restore(&restored, dump.to_str())
        .await
        .unwrap();
    let saved_settings = restored
        .find_one("settings", &json!({"type": "security_settings"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved_settings["auto_save_frequency_seconds"], 90);

    // The file alone restores settings into a fresh memory database.
    let fresh = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    let loaded = doorman_gateway::storage::security_settings::load(&fresh, &config)
        .await
        .unwrap();
    assert_eq!(loaded, persisted);

    let invalid = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({"auto_save_frequency_seconds": 1})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    let limited = login(&app, LIMITED_EMAIL, fixture_password()).await;
    let denied = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &limited,
        Some(json!({"enable_auto_save": false})),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    let disabled_path = directory.join("disabled/unused.bin");
    let disabled = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({"enable_auto_save": false, "dump_path": disabled_path})),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert!(!runtime.memory_autosave_config().borrow().enabled);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!directory.join("disabled").exists());
    worker.abort();
    let _ = worker.await;
}

async fn login(app: &axum::Router, email: &str, password: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/platform/authorization")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    response_payload(&body)["access_token"]
        .as_str()
        .expect("login response access_token")
        .to_owned()
}

async fn request(
    app: &axum::Router,
    method: Method,
    path: &str,
    token: &str,
    payload: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match payload {
        Some(payload) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(payload.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

// Python: backend-services/live-tests/test_90_security_tools_logging.py::test_security_settings_get_put
#[tokio::test]
async fn live_security_settings_get_put_matches_python() {
    let app = build_router(parity_state().await);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;

    let get = request(
        &app,
        Method::GET,
        "/platform/security/settings",
        &token,
        None,
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    let get = response_json(get).await;
    let settings = response_payload(&get);
    assert!(settings.get("memory_only").is_some());

    let desired = !settings
        .get("enable_auto_save")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let put = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({"enable_auto_save": desired})),
    )
    .await;
    assert_eq!(put.status(), StatusCode::OK);
    let put = response_json(put).await;
    assert_eq!(
        response_payload(&put)["enable_auto_save"].as_bool(),
        Some(desired)
    );

    let get_again = request(
        &app,
        Method::GET,
        "/platform/security/settings",
        &token,
        None,
    )
    .await;
    let get_again = response_json(get_again).await;
    assert_eq!(
        response_payload(&get_again)["enable_auto_save"].as_bool(),
        Some(desired)
    );
}

#[tokio::test]
async fn security_settings_report_locked_policy_and_publish_autosave_updates() {
    let mut state = parity_state().await;
    state.config.shared_storage.local_host_ip_bypass = false;
    state.config.shared_storage.local_host_ip_bypass_locked = true;
    let storage = state.storage.as_ref().unwrap().clone();
    let mut autosave = state.runtime.memory_autosave_config();
    let app = build_router(state);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;
    let update = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({
            "allow_localhost_bypass": true,
            "trust_x_forwarded_for": true,
            "xff_trusted_proxies": [],
            "enable_auto_save": true,
            "auto_save_frequency_seconds": 120,
            "dump_path": "nested/security-backup.bin"
        })),
    )
    .await;
    assert_eq!(update.status(), StatusCode::OK);
    assert!(autosave.has_changed().unwrap());
    let applied = autosave.borrow_and_update().clone();
    assert!(applied.enabled);
    assert_eq!(applied.frequency_seconds, 120);
    assert_eq!(
        applied.dump_path.as_deref(),
        Some("nested/security-backup.bin")
    );

    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/platform/security/settings")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-forwarded-for", "203.0.113.9, 10.0.0.2")
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:43210".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let settings = response_payload(&body);
    assert_eq!(settings["allow_localhost_bypass_locked"], true);
    assert_eq!(settings["allow_localhost_bypass"], false);
    assert_eq!(settings["client_ip"], "127.0.0.1");
    assert_eq!(settings["client_ip_xff"], "203.0.113.9");
    assert_eq!(settings["security_warnings"].as_array().unwrap().len(), 1);
    assert!(settings.get("_id").is_none());

    let before = storage.find_one("settings", &json!({})).await.unwrap();
    let invalid = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({
            "auto_save_frequency_seconds": 1, "enable_auto_save": false
        })),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        storage.find_one("settings", &json!({})).await.unwrap(),
        before
    );
    assert!(!autosave.has_changed().unwrap());

    // A persisted bypass cannot defeat the environment lock on other routes.
    request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &token,
        Some(json!({
            "ip_blacklist": ["127.0.0.1"]
        })),
    )
    .await;
    let denied = app
        .oneshot(
            http::Request::builder()
                .uri("/platform/user/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:43210".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn security_settings_coerced_updates_persist_and_invalid_updates_are_atomic() {
    let state = parity_state().await;
    let storage = state.storage.as_ref().unwrap().clone();
    let runtime = state.runtime.clone();
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let path = "/platform/security/settings";
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({
            "enable_auto_save": "on", "auto_save_frequency_seconds": " 120 ",
            "trust_x_forwarded_for": 0, "allow_localhost_bypass": "no", "ignored": "value"
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let settings = response_payload(&body);
    assert_eq!(settings["enable_auto_save"], true);
    assert_eq!(settings["auto_save_frequency_seconds"], 120);
    assert_eq!(settings["trust_x_forwarded_for"], false);
    assert_eq!(settings["allow_localhost_bypass"], false);
    assert!(settings.get("ignored").is_none());
    let before = storage
        .find_one("settings", &json!({"type": "security_settings"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before["enable_auto_save"], true);
    assert_eq!(before["auto_save_frequency_seconds"], 120);
    assert!(runtime.memory_autosave_config().borrow().enabled);
    assert_eq!(
        runtime.memory_autosave_config().borrow().frequency_seconds,
        120
    );

    let response = request(&app, Method::PUT, path, &token, Some(json!({
        "enable_auto_save": "off", "auto_save_frequency_seconds": 59.9, "trust_x_forwarded_for": " true "
    }))).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let errors = response_json(response).await;
    // The pinned global handler returns VAL001; the Pydantic details are only logged.
    assert_eq!(response_payload(&errors)["error_code"], "VAL001");
    assert_eq!(
        storage
            .find_one("settings", &json!({"type": "security_settings"}))
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert!(runtime.memory_autosave_config().borrow().enabled);
    assert_eq!(
        runtime.memory_autosave_config().borrow().frequency_seconds,
        120
    );

    // Null and unknown fields are ignored, not persisted or reset to defaults.
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({
            "enable_auto_save": null, "auto_save_frequency_seconds": null, "ignored": true
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        storage
            .find_one("settings", &json!({"type": "security_settings"}))
            .await
            .unwrap()
            .unwrap(),
        before
    );
    let response = request(&app, Method::GET, path, &token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(response_payload(&body)["auto_save_frequency_seconds"], 120);
    assert_eq!(response_payload(&body)["enable_auto_save"], true);
}

#[tokio::test]
async fn security_settings_integer_length_limits_reject_atomically() {
    if std::env::var_os("DOORMAN_INTEGER_LIMIT_CHILD").is_none() {
        for (value, limit) in [("", 4300), ("640", 640), ("0", 0), ("5000", 5000)] {
            let directory =
                std::env::temp_dir().join(format!("doorman-integer-limits-{}", Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "security_settings_integer_length_limits_reject_atomically",
                    "--nocapture",
                ])
                .env("DOORMAN_INTEGER_LIMIT_CHILD", limit.to_string())
                .env("PYTHONINTMAXSTRDIGITS", value)
                .env("MEM_AUTO_SAVE_ENABLED", "false")
                .current_dir(&directory)
                .output()
                .unwrap();
            std::fs::remove_dir_all(&directory).unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }
    let limit: usize = std::env::var("DOORMAN_INTEGER_LIMIT_CHILD")
        .unwrap()
        .parse()
        .unwrap();
    let boundary = if limit == 0 { 4300 } else { limit.min(4300) };
    let file = std::env::current_dir().unwrap().join("security.json");
    let mut state = parity_state().await;
    state.config.security_settings_file = Some(file.clone());
    let storage = state.storage.as_ref().unwrap().clone();
    let runtime = state.runtime.clone();
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let path = "/platform/security/settings";
    let allowed = format!("{}120", "٠".repeat(boundary - 3));
    let mut updates = runtime.memory_autosave_config();
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({
            "auto_save_frequency_seconds":allowed,"enable_auto_save":false
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_payload(&response_json(response).await)["auto_save_frequency_seconds"],
        120
    );
    assert!(updates.has_changed().unwrap());
    assert_eq!(updates.borrow_and_update().frequency_seconds, 120);
    let before = storage
        .find_one("settings", &json!({"type":"security_settings"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before["auto_save_frequency_seconds"], 120);
    let bytes = std::fs::read(&file).unwrap();
    let persisted: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(persisted["auto_save_frequency_seconds"], 120);
    let read = request(&app, Method::GET, path, &token, None).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(
        response_payload(&response_json(read).await)["auto_save_frequency_seconds"],
        120
    );

    let padded = |digits: usize| format!("{}120", "0".repeat(digits - 3));
    let separated = padded(2151)
        .chars()
        .map(|character| character.to_string())
        .collect::<Vec<_>>()
        .join("_");
    let mut rejected = vec![
        padded(4301),
        format!("+{}", padded(4300)),
        format!(" {} ", padded(4299)),
        separated,
    ];
    if limit != 0 && limit < 4300 {
        rejected.push(padded(limit + 1));
    }
    for value in rejected {
        let updates = runtime.memory_autosave_config();
        let response = request(
            &app,
            Method::PUT,
            path,
            &token,
            Some(json!({
                "auto_save_frequency_seconds":value,"enable_auto_save":true
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response_payload(&response_json(response).await)["error_code"],
            "VAL001"
        );
        assert_eq!(
            storage
                .find_one("settings", &json!({"type":"security_settings"}))
                .await
                .unwrap()
                .unwrap(),
            before
        );
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(!updates.has_changed().unwrap());
        assert!(!updates.borrow().enabled);
    }
    let response = request(&app, Method::PUT, path, &token, Some(json!({
        "auto_save_frequency_seconds":format!("{}59","0".repeat(boundary-2)),"enable_auto_save":true
    }))).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_payload(&response_json(response).await)["error_code"],
        "VAL001"
    );
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert_eq!(
        storage
            .find_one("settings", &json!({"type":"security_settings"}))
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert!(!runtime.memory_autosave_config().borrow().enabled);
}

#[tokio::test]
async fn security_settings_lists_persist_and_enforce_python_patterns_atomically() {
    let directory = std::env::temp_dir().join(format!("doorman-list-settings-{}", Uuid::new_v4()));
    let file = directory.join("security.json");
    let mut state = parity_state().await;
    state.config.security_settings_file = Some(file.clone());
    let storage = state.storage.as_ref().unwrap().clone();
    let runtime = state.runtime.clone();
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let path = "/platform/security/settings";
    let response = request(&app, Method::PUT, path, &token, Some(json!({
        "ip_whitelist": [" 203.0.113.0/255.255.255.0 ", true, 120, 1.0, 1e-5, "invalid-ip", "203.0.113.0/+24"],
        "ip_blacklist": [false, "invalid-ip", "198.51.100.0/0.0.0.255"],
        "xff_trusted_proxies": [true, "invalid-ip", " 10.0.0.0/255.255.255.0 "],
        "trust_x_forwarded_for": true, "allow_localhost_bypass": false, "enable_auto_save": false
    }))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let expected = json!({
        "ip_whitelist": [" 203.0.113.0/255.255.255.0 ", "True", "120", "1.0", "1e-05", "invalid-ip", "203.0.113.0/+24"],
        "ip_blacklist": ["False", "invalid-ip", "198.51.100.0/0.0.0.255"],
        "xff_trusted_proxies": ["True", "invalid-ip", " 10.0.0.0/255.255.255.0 "]
    });
    let updated = response_json(response).await;
    let stored = storage
        .find_one("settings", &json!({"type":"security_settings"}))
        .await
        .unwrap()
        .unwrap();
    let persisted: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let read = request(&app, Method::GET, path, &token, None).await;
    assert_eq!(read.status(), StatusCode::OK);
    let read = response_json(read).await;
    for key in ["ip_whitelist", "ip_blacklist", "xff_trusted_proxies"] {
        assert_eq!(response_payload(&updated)[key], expected[key]);
        assert_eq!(stored[key], expected[key]);
        assert_eq!(persisted[key], expected[key]);
        assert_eq!(response_payload(&read)[key], expected[key]);
    }
    for (peer, forwarded, status, code) in [
        ("203.0.113.5", "198.51.100.9", StatusCode::OK, None),
        (
            "203.0.114.5",
            "203.0.113.5",
            StatusCode::FORBIDDEN,
            Some("SEC010"),
        ),
        ("10.0.0.5", "203.0.113.5", StatusCode::OK, None),
        (
            "10.0.0.5",
            "198.51.100.9",
            StatusCode::FORBIDDEN,
            Some("SEC011"),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/platform/monitor/liveness")
                    .header("x-forwarded-for", forwarded)
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                        peer.parse().unwrap(),
                        41000,
                    )))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{peer} -> {forwarded}");
        if let Some(code) = code {
            assert_eq!(response_json(response).await["error_code"], code);
        }
    }
    let before = stored;
    let bytes = std::fs::read(&file).unwrap();
    let updates = runtime.memory_autosave_config();
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({
            "enable_auto_save": true, "ip_whitelist": [null, [], {}],
            "ip_blacklist": "203.0.113.1", "xff_trusted_proxies": [null]
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_payload(&response_json(response).await)["error_code"],
        "VAL001"
    );
    assert_eq!(
        storage
            .find_one("settings", &json!({"type":"security_settings"}))
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert!(!updates.has_changed().unwrap());
    assert!(!updates.borrow().enabled);

    let junk = json!([true, 120, "invalid-ip", "203.0.113.0/+24"]);
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({
            "ip_whitelist": junk, "xff_trusted_proxies": junk
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/platform/monitor/liveness")
                .header("x-forwarded-for", "203.0.113.5")
                .extension(axum::extract::ConnectInfo(
                    "203.0.113.5:41000".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["error_code"], "SEC010");

    // Null fields preserve the existing lists; explicit empty lists clear them.
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({"ip_whitelist":null})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_payload(&response_json(response).await)["ip_whitelist"],
        json!(["True", "120", "invalid-ip", "203.0.113.0/+24"])
    );
    let response = request(
        &app,
        Method::PUT,
        path,
        &token,
        Some(json!({"ip_whitelist":[],"ip_blacklist":[],"xff_trusted_proxies":[]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = response_json(response).await;
    for key in ["ip_whitelist", "ip_blacklist", "xff_trusted_proxies"] {
        assert_eq!(response_payload(&response)[key], json!([]));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn security_settings_unicode_intervals_persist_and_invalid_updates_are_atomic() {
    let directory =
        std::env::temp_dir().join(format!("doorman-unicode-settings-{}", Uuid::new_v4()));
    let file = directory.join("security.json");
    let mut state = parity_state().await;
    state.config.security_settings_file = Some(file.clone());
    let storage = state.storage.as_ref().unwrap().clone();
    let runtime = state.runtime.clone();
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let path = "/platform/security/settings";
    for (value, expected) in [
        ("١٢٠", 120),
        ("１２０", 120),
        ("𝟙𝟚𝟘", 120),
        ("1_٢0", 120),
        ("\u{a0}+١_٢٠\u{3000}", 120),
        ("００６０", 60),
    ] {
        let mut updates = runtime.memory_autosave_config();
        let response = request(
            &app,
            Method::PUT,
            path,
            &token,
            Some(json!({"auto_save_frequency_seconds": value, "enable_auto_save": false})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{value:?}");
        assert_eq!(
            response_payload(&response_json(response).await)["auto_save_frequency_seconds"],
            expected
        );
        assert!(updates.has_changed().unwrap());
        assert_eq!(updates.borrow_and_update().frequency_seconds, expected);
        let stored = storage
            .find_one("settings", &json!({"type":"security_settings"}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored["auto_save_frequency_seconds"], expected);
        assert!(stored["auto_save_frequency_seconds"].is_number());
        let persisted: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(persisted["auto_save_frequency_seconds"], expected);
        let read = request(&app, Method::GET, path, &token, None).await;
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(
            response_payload(&response_json(read).await)["auto_save_frequency_seconds"],
            expected
        );
    }
    let before = storage
        .find_one("settings", &json!({"type":"security_settings"}))
        .await
        .unwrap()
        .unwrap();
    let bytes = std::fs::read(&file).unwrap();
    for (value, error_type) in [
        ("١__٢٠", "type_error.integer"),
        ("_١٢٠", "type_error.integer"),
        ("١٢٠_", "type_error.integer"),
        ("²⁶⁰", "type_error.integer"),
        ("①②⓪", "type_error.integer"),
        ("−١٢٠", "type_error.integer"),
        ("\u{1c}120\u{1f}", "type_error.integer"),
        ("\u{200b}120\u{200b}", "type_error.integer"),
        ("٥٩", "value_error.number.not_ge"),
        ("-١٢٠", "value_error.number.not_ge"),
    ] {
        let updates = runtime.memory_autosave_config();
        let response = request(
            &app,
            Method::PUT,
            path,
            &token,
            Some(json!({"auto_save_frequency_seconds": value, "enable_auto_save": true})),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{value:?}"
        );
        let body = response_json(response).await;
        assert_eq!(
            response_payload(&body)["error_code"],
            "VAL001",
            "{error_type}"
        );
        assert_eq!(
            storage
                .find_one("settings", &json!({"type":"security_settings"}))
                .await
                .unwrap()
                .unwrap(),
            before
        );
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(!updates.has_changed().unwrap());
        assert!(!updates.borrow().enabled);
        assert_eq!(updates.borrow().frequency_seconds, 60);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn security_settings_dump_path_coercion_persists_and_publishes_atomically() {
    let directory = std::env::temp_dir().join(format!("doorman-path-settings-{}", Uuid::new_v4()));
    let file = directory.join("security.json");
    let mut state = parity_state().await;
    state.config.security_settings_file = Some(file.clone());
    let storage = state.storage.as_ref().unwrap().clone();
    let runtime = state.runtime.clone();
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let path = "/platform/security/settings";
    for (value, expected) in [
        (json!(true), "True"),
        (json!(false), "False"),
        (json!(120), "120"),
        (json!(1.0), "1.0"),
        (json!(-0.0), "-0.0"),
        (json!(1e-5), "1e-05"),
        (json!(1e20), "1e+20"),
        (
            json!(f64::from_bits(4833791929896474481)),
            "1483282338825692.2",
        ),
    ] {
        let mut updates = runtime.memory_autosave_config();
        let response = request(
            &app,
            Method::PUT,
            path,
            &token,
            Some(json!({"dump_path": value, "enable_auto_save": false})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_payload(&response_json(response).await)["dump_path"],
            expected
        );
        assert!(updates.has_changed().unwrap());
        assert_eq!(
            updates.borrow_and_update().dump_path.as_deref(),
            Some(expected)
        );
        let document = storage
            .find_one("settings", &json!({"type": "security_settings"}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(document["dump_path"], expected);
        let persisted: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(persisted["dump_path"], expected);
        let read = request(&app, Method::GET, path, &token, None).await;
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(
            response_payload(&response_json(read).await)["dump_path"],
            expected
        );
    }
    let before = storage
        .find_one("settings", &json!({"type": "security_settings"}))
        .await
        .unwrap()
        .unwrap();
    let bytes = std::fs::read(&file).unwrap();
    for value in [json!([]), json!({})] {
        let updates = runtime.memory_autosave_config();
        let response = request(
            &app,
            Method::PUT,
            path,
            &token,
            Some(json!({"dump_path": value, "enable_auto_save": true})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response_payload(&response_json(response).await)["error_code"],
            "VAL001"
        );
        assert_eq!(
            storage
                .find_one("settings", &json!({"type": "security_settings"}))
                .await
                .unwrap()
                .unwrap(),
            before
        );
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(!updates.has_changed().unwrap());
        assert!(!updates.borrow().enabled);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn mixed_settings_records_are_preserved_by_security_reads_and_updates() {
    let state = parity_state().await;
    let storage = state.storage.as_ref().unwrap().clone();
    let runtime = state.runtime.clone();
    let app = build_router(state);
    let token = login(&app, MANAGER_EMAIL, fixture_password()).await;
    let path = "/platform/security/settings";
    // Snapshot/imported records can lack _id. Neither branch may replace the
    // collection or merge fields from another settings type into security data.
    for security in [
        json!({"type":"security_settings", "_id":"stable-security-id", "auto_save_frequency_seconds":120}),
        json!({"type":"security_settings", "auto_save_frequency_seconds":120}),
        Value::Null,
    ] {
        let unrelated = json!({"type":"email_settings", "_id":"mail", "mail_secret":"test-only-sentinel", "auto_save_frequency_seconds":999});
        let untyped = json!({"setting_name":"other", "value":42});
        let mut records = vec![unrelated.clone(), untyped.clone()];
        if !security.is_null() {
            if security.get("_id").is_none() {
                // This ordering exercises the former whole-collection
                // replacement branch, not just the wrong-record update.
                records.insert(0, security.clone());
            } else {
                records.push(security.clone());
            }
        }
        storage
            .replace_collection("settings", records)
            .await
            .unwrap();
        if !security.is_null() {
            let response = request(&app, Method::GET, path, &token, None).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = response_json(response).await;
            let settings = response_payload(&body);
            assert_eq!(settings["auto_save_frequency_seconds"], 120);
            assert!(settings.get("mail_secret").is_none());
        }
        let response = request(
            &app,
            Method::PUT,
            path,
            &token,
            Some(json!({
                "enable_auto_save":false, "auto_save_frequency_seconds":180
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let settings = response_payload(&body);
        assert_eq!(settings["type"], "security_settings");
        assert_eq!(settings["auto_save_frequency_seconds"], 180);
        assert!(settings.get("mail_secret").is_none());
        assert!(settings.get("_id").is_none());
        assert_eq!(
            runtime.memory_autosave_config().borrow().frequency_seconds,
            180
        );
        let records = storage.find_many("settings", &json!({})).await.unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.contains(&unrelated));
        assert!(records.contains(&untyped));
        let saved = records
            .iter()
            .find(|record| record["type"] == "security_settings")
            .unwrap();
        if !security.is_null() {
            assert_eq!(saved.get("_id"), security.get("_id"));
        }
        assert_eq!(saved["auto_save_frequency_seconds"], 180);
        assert!(saved.get("mail_secret").is_none());
    }
}

// Python: backend-services/live-tests/test_90_security_tools_logging.py::test_tools_cors_check
#[tokio::test]
async fn live_tools_cors_check_matches_python() {
    let app = build_router(parity_state().await);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;
    let response = request(
        &app,
        Method::POST,
        "/platform/tools/cors/check",
        &token,
        Some(json!({
            "origin": "http://localhost:3000",
            "method": "GET",
            "request_headers": ["Content-Type"]
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let payload = response_payload(&body);
    assert!(payload.get("config").is_some());
    assert!(payload.get("preflight").is_some());
}

// Python: backend-services/live-tests/test_90_security_tools_logging.py::test_logging_endpoints
#[tokio::test]
async fn live_logging_endpoints_match_python() {
    let app = build_router(parity_state().await);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;

    let logs = request(
        &app,
        Method::GET,
        "/platform/logging/logs?limit=10",
        &token,
        None,
    )
    .await;
    assert_eq!(logs.status(), StatusCode::OK);
    let logs = response_json(logs).await;
    assert!(response_payload(&logs).is_object() || response_payload(&logs).is_array());

    let files = request(
        &app,
        Method::GET,
        "/platform/logging/logs/files",
        &token,
        None,
    )
    .await;
    assert_eq!(files.status(), StatusCode::OK);
    let files = response_json(files).await;
    assert!(response_payload(&files).get("count").is_some());
}

// Python: backend-services/live-tests/test_90_security_tools_logging.py::test_clear_all_caches
#[tokio::test]
async fn live_clear_all_caches_matches_python() {
    let app = build_router(parity_state().await);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;
    let response = request(&app, Method::DELETE, "/api/caches", &token, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let payload = response_payload(&body);
    assert!(
        payload["message"]
            .as_str()
            .or_else(|| payload["error_message"].as_str())
            .unwrap_or("All caches cleared")
            .contains("All caches cleared")
    );
}

#[tokio::test]
async fn clear_caches_requires_manage_gateway_permission() {
    let state = parity_state().await;
    state
        .storage
        .as_ref()
        .unwrap()
        .update_one(
            "roles",
            &json!({"role_name": "admin"}),
            &json!({"manage_roles": true}),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;
    let disabled = request(
        &app,
        Method::PUT,
        "/platform/role/admin",
        &token,
        Some(json!({"manage_gateway": false})),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let denied = request(&app, Method::DELETE, "/api/caches", &token, None).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let enabled = request(
        &app,
        Method::PUT,
        "/platform/role/admin",
        &token,
        Some(json!({"manage_gateway": true})),
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);
    let cleared = request(&app, Method::DELETE, "/api/caches", &token, None).await;
    assert_eq!(cleared.status(), StatusCode::OK);
}

// Python:
// - backend-services/tests/test_security_permissions.py::test_security_settings_requires_permission
// - backend-services/tests/test_security_settings_permissions.py::test_security_settings_get_put_permissions
#[tokio::test]
async fn security_settings_require_manage_security_permission() {
    let app = build_router(parity_state().await);
    let limited = login(&app, LIMITED_EMAIL, fixture_password()).await;
    let manager = login(&app, MANAGER_EMAIL, fixture_password()).await;

    for method in [Method::GET, Method::PUT] {
        let payload = (method == Method::PUT).then(|| json!({"trust_x_forwarded_for": true}));
        let response = request(
            &app,
            method,
            "/platform/security/settings",
            &limited,
            payload,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let get = request(
        &app,
        Method::GET,
        "/platform/security/settings",
        &manager,
        None,
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);

    let put = request(
        &app,
        Method::PUT,
        "/platform/security/settings",
        &manager,
        Some(json!({"trust_x_forwarded_for": true})),
    )
    .await;
    assert_eq!(put.status(), StatusCode::OK);
    let put = response_json(put).await;
    assert_eq!(
        response_payload(&put)["trust_x_forwarded_for"].as_bool(),
        Some(true)
    );
}

#[tokio::test]
async fn log_export_filters_records_and_redacts_nested_credentials() {
    let directory = std::env::temp_dir().join(format!("doorman-log-export-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let mut state = parity_state().await;
    state.config.logs_dir = Some(directory.clone());
    let app = build_router(state);
    let token = login(&app, ADMIN_EMAIL, fixture_password()).await;
    let records = [
        json!({"time":"2026-09-13T12:00:00Z","name":"fixture","user":"fixture-user","level":"ERROR","message":"upstream failed","headers":{"authorization":"Bearer secret-auth"},"api_key":"secret-key","details":[{"password":"secret-password"}]}),
        json!({"time":"2026-09-12T12:00:00Z","name":"fixture","user":"fixture-user","level":"INFO","message":"earlier request"}),
    ];
    std::fs::write(
        directory.join("doorman.log"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let response = request(&app, Method::GET,
        "/platform/logging/logs/export?user=fixture-user&start_date=2026-09-13&end_date=2026-09-13&level=error",
        &token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let exported = response_payload(&body)["data"].as_str().unwrap();
    let records: Vec<Value> = serde_json::from_str(exported).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["message"], "upstream failed");
    for secret in ["secret-auth", "secret-key", "secret-password"] {
        assert!(!exported.contains(secret));
    }
    assert_eq!(records[0]["headers"]["authorization"], "[REDACTED]");
    assert_eq!(records[0]["api_key"], "[REDACTED]");
    let csv = request(
        &app,
        Method::GET,
        "/platform/logging/logs/download?user=fixture-user&format=csv",
        &token,
        None,
    )
    .await;
    assert_eq!(csv.status(), StatusCode::OK);
    assert!(
        csv.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    assert!(
        csv.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("attachment;")
    );
    let csv =
        String::from_utf8(to_bytes(csv.into_body(), 64 * 1024).await.unwrap().to_vec()).unwrap();
    assert!(csv.contains("upstream failed"));
    assert!(csv.contains("earlier request"));
    let limited = login(&app, LIMITED_EMAIL, fixture_password()).await;
    let denied = request(
        &app,
        Method::GET,
        "/platform/logging/logs/export",
        &limited,
        None,
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn unknown_path_404_is_written_to_the_gateway_activity_log() {
    let directory = std::env::temp_dir().join(format!("doorman-404-log-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();

    let mut state = parity_state().await;
    state.config.logs_dir = Some(directory.clone());
    let app = build_router(state);
    let path = "/some/random/path/that/does/not/exist";
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let log = std::fs::read_to_string(directory.join("doorman.log.rust")).unwrap();
    let record: Value = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(record["status_code"], StatusCode::NOT_FOUND.as_u16());
    assert_eq!(record["endpoint"], path);

    std::fs::remove_dir_all(directory).unwrap();
}
