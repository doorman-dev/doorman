//! AI access keys (`dk_…`): generation, hashing and inbound lookup (plan P1.3).
//!
//! Only `hex(sha256(pepper || key))` is stored. The pepper is derived with HKDF
//! from the field-encryption key material, so rotating `TOKEN_ENCRYPTION_KEY`
//! (or `MEM_ENCRYPTION_KEY`) invalidates every issued key.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use http::{HeaderMap, HeaderValue, StatusCode, header};
use rand::Rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    ai::adapter::INBOUND_CREDENTIAL_HEADERS,
    error_codes::ErrorCode,
    policy::{PolicyFailure, PolicyStage},
    storage::{field_encryption::key_material, models::PolicyDocuments},
};

pub const KEY_PREFIX: &str = "dk_";
const KEY_RANDOM_CHARS: usize = 40;
const DISPLAY_PREFIX_CHARS: usize = 10;
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const LAST_USED_INTERVAL_SECS: i64 = 60;

/// The authenticated owner of an AI access key, carried on `PolicyRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiPrincipal {
    pub username: String,
    pub key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundAuth {
    Key(AiPrincipal),
    /// Not a `dk_` key: normalised into `Authorization: Bearer` for JWT checks.
    Jwt,
}

pub fn generate_key() -> String {
    let mut rng = rand::rng();
    let random: String = (0..KEY_RANDOM_CHARS)
        .map(|_| char::from(BASE62[rng.random_range(0..BASE62.len())]))
        .collect();
    format!("{KEY_PREFIX}{random}")
}

pub fn key_prefix(key: &str) -> String {
    key.chars().take(DISPLAY_PREFIX_CHARS).collect()
}

pub fn hash_key(key: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(pepper());
    digest.update(key.as_bytes());
    hex(&digest.finalize())
}

/// HKDF-SHA256 over the field-encryption key material for `info`. Without key
/// material the derivation still works but is deployment-independent.
pub(crate) fn derive_secret(info: &[u8]) -> [u8; 32] {
    let material = key_material().unwrap_or_default();
    let mut output = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(None, material.as_bytes())
        .expand(info, &mut output)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    output
}

fn pepper() -> [u8; 32] {
    derive_secret(b"doorman-ai-key-v1")
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid_key(message: &str) -> PolicyFailure {
    PolicyFailure::new(
        PolicyStage::Authentication,
        StatusCode::UNAUTHORIZED,
        ErrorCode::AI_ACCESS_KEY_INVALID,
        message,
    )
}

/// Inbound credential, in SDK precedence order: `Authorization: Bearer`,
/// `x-api-key`, `x-goog-api-key`, `api-key`, then the `key` query param.
fn inbound_credential(headers: &HeaderMap, query: &[(String, String)]) -> Option<String> {
    let header_value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    header_value(header::AUTHORIZATION.as_str())
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| token.trim().to_owned())
                .filter(|token| !token.is_empty())
        })
        .or_else(|| header_value("x-api-key"))
        .or_else(|| header_value("x-goog-api-key"))
        .or_else(|| header_value("api-key"))
        .or_else(|| {
            query
                .iter()
                .find(|(name, value)| name == "key" && !value.trim().is_empty())
                .map(|(_, value)| value.trim().to_owned())
        })
}

/// Resolves the caller of an AI route. A `dk_` key must exist, be unrevoked and
/// unexpired, belong to an active user and (when scoped) cover `api` ("{name}/{ver}").
/// Any other credential is treated as a JWT and moved to `Authorization: Bearer`.
/// Provider-style credential headers never survive this call.
pub fn resolve_inbound(
    headers: &mut HeaderMap,
    query: &[(String, String)],
    docs: &PolicyDocuments,
    api: &str,
) -> Result<InboundAuth, PolicyFailure> {
    let credential = inbound_credential(headers, query);
    for name in INBOUND_CREDENTIAL_HEADERS {
        if *name != "cookie" {
            headers.remove(*name);
        }
    }
    let Some(credential) = credential else {
        // Browser sessions authenticate with the access-token cookie.
        if headers.contains_key(header::COOKIE) {
            return Ok(InboundAuth::Jwt);
        }
        return Err(invalid_key("AI access key required"));
    };
    if !credential.starts_with(KEY_PREFIX) {
        let bearer = HeaderValue::from_str(&format!("Bearer {credential}"))
            .map_err(|_| invalid_key("Invalid AI access key"))?;
        headers.insert(header::AUTHORIZATION, bearer);
        return Ok(InboundAuth::Jwt);
    }
    let hash = hash_key(&credential);
    let record = docs
        .ai_access_keys
        .iter()
        .find(|record| record.get("key_hash").and_then(Value::as_str) == Some(hash.as_str()))
        .ok_or_else(|| invalid_key("Invalid AI access key"))?;
    if record.get("revoked").and_then(Value::as_bool) == Some(true) {
        return Err(invalid_key("AI access key has been revoked"));
    }
    if let Some(expires_at) = record.get("expires_at").and_then(Value::as_str) {
        let expired = OffsetDateTime::parse(expires_at, &Rfc3339)
            .map(|expires_at| expires_at <= OffsetDateTime::now_utc())
            .unwrap_or(true);
        if expired {
            return Err(invalid_key("AI access key has expired"));
        }
    }
    let username = record
        .get("username")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_key("Invalid AI access key"))?;
    let user_active = docs.users.iter().any(|user| {
        user.get("username").and_then(Value::as_str) == Some(username)
            && user.get("active").and_then(Value::as_bool) != Some(false)
    });
    if !user_active {
        return Err(invalid_key("Invalid AI access key"));
    }
    if let Some(scope) = record.get("api_scope").and_then(Value::as_array) {
        if !scope.is_empty() && !scope.iter().any(|entry| entry.as_str() == Some(api)) {
            return Err(invalid_key("AI access key is not valid for this API"));
        }
    }
    let key_id = record
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_key("Invalid AI access key"))?;
    Ok(InboundAuth::Key(AiPrincipal {
        username: username.to_owned(),
        key_id: key_id.to_owned(),
    }))
}

/// True at most once a minute per key, so `last_used_at` writes stay cheap.
pub fn should_record_last_used(key_id: &str, now: OffsetDateTime) -> bool {
    static LAST_WRITE: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    let now = now.unix_timestamp();
    let mut last_write = LAST_WRITE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match last_write.get(key_id) {
        Some(previous) if now - previous < LAST_USED_INTERVAL_SECS => false,
        _ => {
            last_write.insert(key_id.to_owned(), now);
            true
        }
    }
}

/// Fire-and-forget `last_used_at` update (throttled per key).
pub fn record_last_used(
    storage: std::sync::Arc<crate::storage::runtime::SharedStorage>,
    key_id: &str,
) {
    let now = OffsetDateTime::now_utc();
    if !should_record_last_used(key_id, now) {
        return;
    }
    let key_id = key_id.to_owned();
    let Ok(at) = now.format(&Rfc3339) else {
        return;
    };
    tokio::spawn(async move {
        if let Err(error) = storage
            .update_one(
                "ai_access_keys",
                &serde_json::json!({"key_id": key_id}),
                &serde_json::json!({"last_used_at": at}),
            )
            .await
        {
            tracing::warn!(%error, "failed to record AI key last_used_at");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn docs_with_key(key: &str, record: Value, active: bool) -> PolicyDocuments {
        let mut record = record;
        record["key_hash"] = json!(hash_key(key));
        PolicyDocuments {
            ai_access_keys: vec![record],
            users: vec![json!({"username": "alice", "active": active})],
            ..Default::default()
        }
    }

    fn key_record() -> Value {
        json!({"key_id": "k1", "username": "alice", "revoked": false})
    }

    fn hdrs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn principal() -> InboundAuth {
        InboundAuth::Key(AiPrincipal {
            username: "alice".to_owned(),
            key_id: "k1".to_owned(),
        })
    }

    #[test]
    fn generated_keys_have_format_and_hash_is_not_plaintext() {
        let key = generate_key();
        assert!(key.starts_with("dk_"));
        assert_eq!(key.len(), 43);
        assert!(key[3..].bytes().all(|byte| BASE62.contains(&byte)));
        assert_eq!(key_prefix(&key), key[..10]);
        let hash = hash_key(&key);
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains(&key[3..]));
        assert_eq!(hash, hash_key(&key));
        assert_ne!(generate_key(), key);
    }

    #[test]
    fn ai_key_authenticates_through_x_api_key_header() {
        let key = generate_key();
        let docs = docs_with_key(&key, key_record(), true);
        let mut headers = hdrs(&[("x-api-key", &key), ("anthropic-version", "2023-06-01")]);
        assert_eq!(
            resolve_inbound(&mut headers, &[], &docs, "claude/v1").unwrap(),
            principal()
        );
        assert!(headers.get("x-api-key").is_none());
        assert!(headers.get("anthropic-version").is_some());
    }

    #[test]
    fn ai_key_authenticates_through_bearer() {
        let key = generate_key();
        let docs = docs_with_key(&key, key_record(), true);
        let mut headers = hdrs(&[("authorization", &format!("Bearer {key}"))]);
        assert_eq!(
            resolve_inbound(&mut headers, &[], &docs, "gpt/v1").unwrap(),
            principal()
        );
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn ai_key_authenticates_through_goog_header() {
        let key = generate_key();
        let docs = docs_with_key(&key, key_record(), true);
        let mut headers = hdrs(&[("x-goog-api-key", &key)]);
        assert_eq!(
            resolve_inbound(&mut headers, &[], &docs, "gem/v1").unwrap(),
            principal()
        );
        assert!(headers.get("x-goog-api-key").is_none());
        // `?key=` works too (google-genai REST style).
        let mut headers = HeaderMap::new();
        let query = vec![("key".to_owned(), key.clone())];
        assert_eq!(
            resolve_inbound(&mut headers, &query, &docs, "gem/v1").unwrap(),
            principal()
        );
    }

    #[test]
    fn revoked_ai_key_is_rejected() {
        let key = generate_key();
        let mut record = key_record();
        record["revoked"] = json!(true);
        let docs = docs_with_key(&key, record, true);
        let error =
            resolve_inbound(&mut hdrs(&[("x-api-key", &key)]), &[], &docs, "a/v1").unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.error_code, "AI007");

        let mut record = key_record();
        record["expires_at"] = json!("2020-01-01T00:00:00Z");
        let docs = docs_with_key(&key, record, true);
        let error =
            resolve_inbound(&mut hdrs(&[("x-api-key", &key)]), &[], &docs, "a/v1").unwrap_err();
        assert_eq!(error.error_code, "AI007");

        // Unknown key and missing credential.
        let error = resolve_inbound(
            &mut hdrs(&[("x-api-key", &generate_key())]),
            &[],
            &docs,
            "a/v1",
        )
        .unwrap_err();
        assert_eq!(error.error_code, "AI007");
        let error = resolve_inbound(&mut HeaderMap::new(), &[], &docs, "a/v1").unwrap_err();
        assert_eq!(error.error_code, "AI007");
    }

    #[test]
    fn ai_key_for_inactive_user_is_rejected() {
        let key = generate_key();
        let docs = docs_with_key(&key, key_record(), false);
        let error =
            resolve_inbound(&mut hdrs(&[("x-api-key", &key)]), &[], &docs, "a/v1").unwrap_err();
        assert_eq!(error.error_code, "AI007");
        let mut docs = docs_with_key(&key, key_record(), true);
        docs.users.clear();
        assert!(resolve_inbound(&mut hdrs(&[("x-api-key", &key)]), &[], &docs, "a/v1").is_err());
    }

    #[test]
    fn ai_key_scope_limits_apis() {
        let key = generate_key();
        let mut record = key_record();
        record["api_scope"] = json!(["claude/v1"]);
        let docs = docs_with_key(&key, record, true);
        assert_eq!(
            resolve_inbound(&mut hdrs(&[("x-api-key", &key)]), &[], &docs, "claude/v1").unwrap(),
            principal()
        );
        let error =
            resolve_inbound(&mut hdrs(&[("x-api-key", &key)]), &[], &docs, "gpt/v1").unwrap_err();
        assert_eq!(error.error_code, "AI007");
    }

    #[test]
    fn jwt_still_works_on_ai_routes() {
        let docs = PolicyDocuments::default();
        // A JWT sent the Anthropic-SDK way is normalised into Authorization.
        let mut headers = hdrs(&[("x-api-key", "eyJ.jwt.token")]);
        assert_eq!(
            resolve_inbound(&mut headers, &[], &docs, "a/v1").unwrap(),
            InboundAuth::Jwt
        );
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer eyJ.jwt.token"
        );
        assert!(headers.get("x-api-key").is_none());
        // Cookie sessions fall through to JWT verification.
        let mut headers = hdrs(&[("cookie", "access_token_cookie=abc")]);
        assert_eq!(
            resolve_inbound(&mut headers, &[], &docs, "a/v1").unwrap(),
            InboundAuth::Jwt
        );
    }

    #[test]
    fn last_used_is_throttled_per_key() {
        let now = OffsetDateTime::now_utc();
        assert!(should_record_last_used("throttle-a", now));
        assert!(!should_record_last_used(
            "throttle-a",
            now + time::Duration::seconds(30)
        ));
        assert!(should_record_last_used("throttle-b", now));
        assert!(should_record_last_used(
            "throttle-a",
            now + time::Duration::seconds(61)
        ));
    }
}
