//! Doorman AI gateway: provider adapters, metering, budgets and guardrails.

pub mod adapter;
pub mod budgets;
pub mod config;
pub mod failover;
pub mod guardrails;
pub mod keys;
pub mod pricing;
pub mod providers;
pub mod sse;
pub mod usage;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Pseudonymous, deployment-stable user ID sent upstream (C4):
/// `hex(hmac_sha256(salt, username))[..32]`. The salt is `AI_USER_ID_SALT`, or
/// derived from the field-encryption key material when unset. Changing it breaks
/// the provider's per-user continuity.
pub fn hashed_user_id(username: &str) -> String {
    let salt = std::env::var("AI_USER_ID_SALT")
        .ok()
        .filter(|value| !value.is_empty())
        .map(String::into_bytes)
        .unwrap_or_else(|| keys::derive_secret(b"doorman-ai-user-id-v1").to_vec());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&salt).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(username.as_bytes());
    let mut id = keys::hex(&mac.finalize().into_bytes());
    id.truncate(32);
    id
}

/// True when `AI_USER_ID_SALT` is set explicitly (reported by the settings endpoint).
pub fn user_id_salt_set() -> bool {
    std::env::var("AI_USER_ID_SALT").is_ok_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_user_id_is_stable_and_not_username() {
        let first = hashed_user_id("alice@example.com");
        assert_eq!(first, hashed_user_id("alice@example.com"));
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!first.contains("alice"));
        assert_ne!(first, hashed_user_id("bob@example.com"));
        assert_ne!(first, hashed_user_id("Alice@example.com"));
    }
}
