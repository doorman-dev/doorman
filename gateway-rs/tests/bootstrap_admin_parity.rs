use doorman_gateway::{Config, storage::runtime::SharedStorage};
use serde_json::json;

#[tokio::test]
async fn bootstrap_admin_seed_matches_python_and_preserves_existing_credentials() {
    if std::env::var_os("DOORMAN_BOOTSTRAP_ADMIN_TEST_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bootstrap_admin_seed_matches_python_and_preserves_existing_credentials",
                "--nocapture",
            ])
            .env("DOORMAN_BOOTSTRAP_ADMIN_TEST_CHILD", "1")
            .env("DOORMAN_ADMIN_EMAIL", "first@doorman.dev")
            .env("DOORMAN_ADMIN_PASSWORD", "first-password-12chars")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage.initialize_core().await.unwrap();

    let admin = storage
        .find_one("users", &json!({"username": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin["email"], "first@doorman.dev");
    assert!(
        bcrypt::verify(
            "first-password-12chars",
            admin["password"].as_str().unwrap()
        )
        .unwrap()
    );
    for (field, expected) in [
        ("role", json!("admin")),
        ("groups", json!(["ALL", "admin"])),
        ("ui_access", json!(true)),
        ("active", json!(true)),
        ("rate_limit_duration", json!(1)),
        ("rate_limit_duration_type", json!("second")),
        ("throttle_duration", json!(1)),
        ("throttle_duration_type", json!("second")),
        ("throttle_wait_duration", json!(0)),
        ("throttle_wait_duration_type", json!("second")),
        ("throttle_queue_limit", json!(1)),
    ] {
        assert_eq!(admin[field], expected, "{field}");
    }
    let role = storage
        .find_one("roles", &json!({"role_name": "admin"}))
        .await
        .unwrap()
        .unwrap();
    for field in [
        "manage_users",
        "manage_apis",
        "manage_endpoints",
        "manage_groups",
        "manage_roles",
        "manage_routings",
        "manage_gateway",
        "manage_subscriptions",
        "manage_credits",
        "manage_auth",
        "manage_security",
        "view_logs",
    ] {
        assert_eq!(role[field], true, "{field}");
    }
    for group_name in ["admin", "ALL"] {
        assert!(
            storage
                .find_one("groups", &json!({"group_name": group_name}))
                .await
                .unwrap()
                .is_some(),
            "{group_name} group is seeded"
        );
    }

    // A later process configuration must not replace an existing bootstrap account.
    unsafe {
        std::env::set_var("DOORMAN_ADMIN_EMAIL", "second@doorman.dev");
        std::env::set_var("DOORMAN_ADMIN_PASSWORD", "second-password-12chars");
    }
    storage.initialize_core().await.unwrap();
    let preserved = storage
        .find_one("users", &json!({"username": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved["email"], "first@doorman.dev");
    assert!(
        bcrypt::verify(
            "first-password-12chars",
            preserved["password"].as_str().unwrap()
        )
        .unwrap()
    );
}

#[tokio::test]
async fn bootstrap_repairs_missing_admin_fields_like_python_mongo_mode() {
    if std::env::var_os("DOORMAN_BOOTSTRAP_REPAIR_TEST_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bootstrap_repairs_missing_admin_fields_like_python_mongo_mode",
                "--nocapture",
            ])
            .env("DOORMAN_BOOTSTRAP_REPAIR_TEST_CHILD", "1")
            .env("DOORMAN_ADMIN_EMAIL", "repair@doorman.dev")
            .env("DOORMAN_ADMIN_PASSWORD", "repair-password-12chars")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({"username": "admin", "ui_access": false, "email": ""}),
        )
        .await
        .unwrap();
    storage.initialize_core().await.unwrap();
    let admin = storage
        .find_one("users", &json!({"username": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin["ui_access"], true);
    assert_eq!(admin["email"], "repair@doorman.dev");
    assert!(
        bcrypt::verify(
            "repair-password-12chars",
            admin["password"].as_str().unwrap()
        )
        .unwrap()
    );
}
