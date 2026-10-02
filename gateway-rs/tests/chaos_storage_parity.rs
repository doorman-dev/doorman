use doorman_gateway::{
    Config,
    middleware::chaos::{CHAOS_ERROR_BUDGET_BURN, CHAOS_MONGO_OUTAGE, CHAOS_REDIS_OUTAGE},
    storage::runtime::SharedStorage,
};
use serde_json::json;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn chaos_outage_flags_fail_storage_operations_and_burn_error_budget_like_python() {
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one("apis", json!({"api_name": "a"}))
        .await
        .unwrap();
    let burn_before = CHAOS_ERROR_BUDGET_BURN.load(Ordering::Relaxed);

    CHAOS_MONGO_OUTAGE.store(true, Ordering::Relaxed);
    let err = storage.find_one("apis", &json!({})).await.unwrap_err();
    assert!(err.to_string().contains("chaos: simulated mongo outage"));
    assert!(storage.insert_one("apis", json!({})).await.is_err());
    assert!(storage.delete_one("apis", &json!({})).await.is_err());
    CHAOS_MONGO_OUTAGE.store(false, Ordering::Relaxed);
    assert!(
        storage
            .find_one("apis", &json!({}))
            .await
            .unwrap()
            .is_some()
    );

    CHAOS_REDIS_OUTAGE.store(true, Ordering::Relaxed);
    let err = storage.set_ephemeral("k", json!(1), 60).await.unwrap_err();
    assert!(err.to_string().contains("chaos: simulated redis outage"));
    assert!(storage.get_ephemeral("k").await.is_err());
    CHAOS_REDIS_OUTAGE.store(false, Ordering::Relaxed);
    storage.set_ephemeral("k", json!(1), 60).await.unwrap();
    assert_eq!(storage.get_ephemeral("k").await.unwrap(), Some(json!(1)));

    assert_eq!(
        CHAOS_ERROR_BUDGET_BURN.load(Ordering::Relaxed) - burn_before,
        5
    );
}
