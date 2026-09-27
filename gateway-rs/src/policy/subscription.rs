use http::StatusCode;
use serde_json::Value;

use super::{PolicyFailure, PolicyStage, roles::is_admin_user};
use crate::storage::models::{object_field, string_field};

pub fn enforce_subscription(
    api_name_version: &str,
    user: &Value,
    roles: &[Value],
    subscriptions: &[Value],
    enforce_admin_subscription: bool,
) -> Result<(), PolicyFailure> {
    if is_admin_user(user, roles) && !enforce_admin_subscription {
        return Ok(());
    }

    let username = string_field(user, "username").unwrap_or_default();
    let subscription = subscriptions
        .iter()
        .find(|item| string_field(item, "username") == Some(username));
    let Some(subscription) = subscription else {
        return Err(not_subscribed());
    };
    let apis = object_field(subscription, "apis");
    let subscribed = subscription
        .get("apis")
        .and_then(Value::as_array)
        .map(|apis| {
            apis.iter()
                .any(|api| api.as_str() == Some(api_name_version))
        })
        .or_else(|| apis.map(|apis| apis.contains_key(api_name_version)))
        .unwrap_or(false);

    if subscribed {
        Ok(())
    } else {
        Err(not_subscribed())
    }
}

fn not_subscribed() -> PolicyFailure {
    PolicyFailure::new(
        PolicyStage::Subscription,
        StatusCode::FORBIDDEN,
        "You are not subscribed to this resource",
        "You are not subscribed to this resource",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn admin_bypasses_subscription_unless_enforced() {
        let user = json!({ "username": "admin", "role": "admin" });
        assert!(enforce_subscription("demo/v1", &user, &[], &[], true).is_err());
        assert!(enforce_subscription("demo/v1", &user, &[], &[], false).is_ok());
    }

    #[test]
    fn checks_user_subscription_list() {
        let user = json!({ "username": "alice", "role": "viewer" });
        let subscriptions = vec![json!({ "username": "alice", "apis": ["demo/v1"] })];
        assert!(enforce_subscription("demo/v1", &user, &[], &subscriptions, false).is_ok());
        let failure =
            enforce_subscription("other/v1", &user, &[], &subscriptions, false).unwrap_err();
        assert_eq!(failure.status, StatusCode::FORBIDDEN);
        assert_eq!(
            failure.error_code,
            "You are not subscribed to this resource"
        );
    }
}
