use http::StatusCode;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{PolicyFailure, PolicyStage};
use crate::storage::{
    field_encryption::decrypt_value,
    models::{bool_field_default, object_field, string_field, u64_field},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreditDecision {
    pub required: bool,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub user_header_value: Option<String>,
}

pub fn credit_header_values(
    definition: &Value,
    now: OffsetDateTime,
) -> Option<(String, Vec<String>)> {
    let header = string_field(definition, "api_key_header")?.to_owned();
    let old_encrypted = string_field(definition, "api_key");
    let old = decrypt_value(old_encrypted).or_else(|| old_encrypted.map(str::to_owned));
    let new_encrypted = string_field(definition, "api_key_new");
    let new = decrypt_value(new_encrypted).or_else(|| new_encrypted.map(str::to_owned));
    let expires = string_field(definition, "api_key_rotation_expires")
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
    let values = match (old, new, expires) {
        (Some(old), Some(new), Some(expires)) if now < expires => vec![old, new],
        (_, Some(new), Some(expires)) if now >= expires => vec![new],
        (Some(old), _, _) => vec![old],
        (_, Some(new), _) => vec![new],
        _ => return None,
    };
    Some((header, values))
}
pub fn evaluate_credits(
    api: &Value,
    username: Option<&str>,
    credit_defs: &[Value],
    user_credits: &[Value],
) -> Result<CreditDecision, PolicyFailure> {
    let enabled = bool_field_default(api, "api_credits_enabled", false);
    let public = bool_field_default(api, "api_public", false);
    if !enabled || public {
        return Ok(CreditDecision::default());
    }

    let Some(username) = username else {
        return Ok(CreditDecision {
            required: true,
            ..Default::default()
        });
    };
    let group = string_field(api, "api_credit_group").unwrap_or_default();
    if group.is_empty() {
        return Ok(CreditDecision {
            required: true,
            ..Default::default()
        });
    }
    let user_credit = user_credits
        .iter()
        .find(|doc| string_field(doc, "username") == Some(username));
    let available = user_credit
        .and_then(|doc| object_field(doc, "users_credits"))
        .and_then(|credits| credits.get(group))
        .and_then(|credit| u64_field(credit, "available_credits"))
        .unwrap_or(0);
    if available == 0 {
        return Err(PolicyFailure::new(
            PolicyStage::Credits,
            StatusCode::UNAUTHORIZED,
            "GTW008",
            "User does not have any credits",
        ));
    }

    let credit_def = credit_defs
        .iter()
        .find(|doc| string_field(doc, "api_credit_group") == Some(group));
    let header = credit_def.and_then(|doc| credit_header_values(doc, OffsetDateTime::now_utc()));
    let header_name = header.as_ref().map(|(name, _)| name.clone());
    let header_value = header.and_then(|(_, mut values)| values.pop());
    let user_header_value = user_credit
        .and_then(|doc| object_field(doc, "users_credits"))
        .and_then(|credits| credits.get(group))
        .and_then(|credit| string_field(credit, "user_api_key"))
        .and_then(|value| decrypt_value(Some(value)).or_else(|| Some(value.to_owned())));

    Ok(CreditDecision {
        required: true,
        header_name,
        header_value,
        user_header_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_credit_enabled_api_without_available_credits() {
        let api = json!({
            "api_credits_enabled": true,
            "api_credit_group": "ai",
        });
        let user_credits = vec![json!({
            "username": "alice",
            "users_credits": { "ai": { "available_credits": 0 } },
        })];
        assert_eq!(
            evaluate_credits(&api, Some("alice"), &[], &user_credits)
                .unwrap_err()
                .error_code,
            "GTW008"
        );
    }

    #[test]
    fn reports_credit_headers_without_deducting() {
        let api = json!({
            "api_credits_enabled": true,
            "api_credit_group": "ai",
        });
        let credit_defs = vec![json!({
            "api_credit_group": "ai",
            "api_key_header": "X-API-Key",
            "api_key": "system-key",
        })];
        let user_credits = vec![json!({
            "username": "alice",
            "users_credits": { "ai": { "available_credits": 2, "user_api_key": "user-key" } },
        })];
        let decision = evaluate_credits(&api, Some("alice"), &credit_defs, &user_credits).unwrap();
        assert!(decision.required);
        assert_eq!(decision.header_name, Some("X-API-Key".to_owned()));
        assert_eq!(decision.header_value, Some("system-key".to_owned()));
        assert_eq!(decision.user_header_value, Some("user-key".to_owned()));
    }

    #[test]
    fn public_credit_enabled_api_bypasses_credit_requirement_like_python() {
        let api = json!({
            "api_public": true,
            "api_credits_enabled": true,
            "api_credit_group": "public-ai",
        });
        let decision = evaluate_credits(&api, None, &[], &[]).unwrap();
        assert_eq!(decision, CreditDecision::default());
    }
}

#[test]
fn credit_key_rotation_returns_both_keys_before_expiry_and_new_key_after() {
    let definition = serde_json::json!({
        "api_credit_group": "rotgrp",
        "api_key_header": "x-api-key",
        "api_key": "old-key",
        "api_key_new": "new-key",
        "api_key_rotation_expires": "2030-01-01T01:00:00Z"
    });
    let before = OffsetDateTime::parse("2030-01-01T00:00:00Z", &Rfc3339).unwrap();
    assert_eq!(
        credit_header_values(&definition, before),
        Some((
            "x-api-key".to_owned(),
            vec!["old-key".to_owned(), "new-key".to_owned()]
        ))
    );
    let after = OffsetDateTime::parse("2030-01-01T02:00:00Z", &Rfc3339).unwrap();
    assert_eq!(
        credit_header_values(&definition, after),
        Some(("x-api-key".to_owned(), vec!["new-key".to_owned()]))
    );
}
