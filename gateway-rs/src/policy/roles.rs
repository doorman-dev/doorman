use http::StatusCode;
use serde_json::Value;

use super::{PolicyFailure, PolicyStage};
use crate::storage::models::{bool_field_default, string_field, string_list_field};

/// The pinned `is_admin_role`: a role flagged `platform_admin`, or one named
/// "admin" / "platform admin" (case-insensitive).
pub fn is_admin_user(user: &Value, roles: &[Value]) -> bool {
    let role_name = string_field(user, "role").unwrap_or_default();
    let admin_name = |name: &str| {
        matches!(
            name.trim().to_lowercase().as_str(),
            "admin" | "platform admin"
        )
    };
    match roles
        .iter()
        .find(|role| string_field(role, "role_name") == Some(role_name))
    {
        Some(role) => {
            bool_field_default(role, "platform_admin", false)
                || admin_name(string_field(role, "role_name").unwrap_or_default())
        }
        None => admin_name(role_name),
    }
}

pub fn enforce_allowed_roles(api: &Value, user: &Value) -> Result<(), PolicyFailure> {
    let allowed_roles = string_list_field(api, "api_allowed_roles");
    if allowed_roles.is_empty() {
        return Ok(());
    }
    let role_name = string_field(user, "role").unwrap_or_default();
    if allowed_roles.iter().any(|role| role == role_name) {
        Ok(())
    } else {
        Err(PolicyFailure::new(
            PolicyStage::Role,
            StatusCode::FORBIDDEN,
            "GTW014",
            "Forbidden: role not allowed for this API",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allows_configured_api_roles() {
        let api = json!({ "api_allowed_roles": ["developer"] });
        let user = json!({ "role": "developer" });
        assert!(enforce_allowed_roles(&api, &user).is_ok());
    }

    #[test]
    fn rejects_unconfigured_api_roles() {
        let api = json!({ "api_allowed_roles": ["admin"] });
        let user = json!({ "role": "viewer" });
        assert_eq!(
            enforce_allowed_roles(&api, &user).unwrap_err().error_code,
            "GTW014"
        );
    }
}
