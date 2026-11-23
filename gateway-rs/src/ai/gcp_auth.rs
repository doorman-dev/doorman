//! Google service-account sign-in for Vertex AI (pure: no network).

use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

#[derive(Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    pub project_id: String,
}

impl std::fmt::Debug for ServiceAccount {
    // Never print the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

pub fn parse(json: &str) -> Result<ServiceAccount, String> {
    #[derive(Deserialize)]
    struct Document {
        #[serde(rename = "type")]
        kind: String,
        client_email: String,
        private_key: String,
        token_uri: Option<String>,
        project_id: Option<String>,
    }

    let doc: Document = serde_json::from_str(json)
        .map_err(|_| "Invalid service-account JSON or missing required fields")?;
    if doc.kind != "service_account"
        || doc.client_email.trim().is_empty()
        || doc.private_key.trim().is_empty()
    {
        return Err("Invalid service-account type, email, or private key".into());
    }
    Ok(ServiceAccount {
        client_email: doc.client_email,
        private_key: doc.private_key,
        token_uri: doc.token_uri.unwrap_or_else(|| DEFAULT_TOKEN_URI.into()),
        project_id: doc.project_id.unwrap_or_default(),
    })
}

#[derive(Serialize, Deserialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

/// RS256 JWT for the OAuth 2.0 JWT-bearer grant.
pub fn assertion(sa: &ServiceAccount, scope: &str, now: OffsetDateTime) -> Result<String, String> {
    let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        .map_err(|_| "Invalid service-account RSA private key")?;
    let iat = now.unix_timestamp();
    let claims = Claims {
        iss: &sa.client_email,
        scope,
        aud: &sa.token_uri,
        iat,
        exp: iat + 3600,
    };
    encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|_| "Could not sign service-account assertion".into())
}

/// `(access_token, expires_in)` from the token endpoint's JSON reply.
pub fn parse_token_response(body: &[u8]) -> Result<(String, Duration), String> {
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        expires_in: u64,
    }

    let response: TokenResponse =
        serde_json::from_slice(body).map_err(|_| "Invalid service-account token response")?;
    if response.access_token.trim().is_empty() || response.expires_in == 0 {
        return Err("Invalid service-account access token or expiry".into());
    }
    Ok((
        response.access_token,
        Duration::from_secs(response.expires_in),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use serde_json::{Value, json};
    use time::macros::datetime;

    const PRIVATE_KEY: &str = include_str!("../../tests/fixtures/ai/vertex/private.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/ai/vertex/public.pem");

    #[test]
    fn verifies_assertion_and_claims() {
        let sa = parse(
            &json!({
                "type": "service_account",
                "client_email": "vertex-test@example.invalid",
                "private_key": PRIVATE_KEY,
            })
            .to_string(),
        )
        .unwrap();
        let now = datetime!(2024-01-01 00:00 UTC);
        assert_eq!(sa.token_uri, DEFAULT_TOKEN_URI);
        assert!(sa.project_id.is_empty());
        let jwt = assertion(&sa, CLOUD_PLATFORM_SCOPE, now).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_audience(&[DEFAULT_TOKEN_URI]);
        validation.set_issuer(&[&sa.client_email]);
        let key = DecodingKey::from_rsa_pem(PUBLIC_KEY).unwrap();
        let decoded = decode::<Value>(&jwt, &key, &validation).unwrap();
        assert_eq!(
            decoded.claims,
            json!({
                "iss": sa.client_email,
                "scope": CLOUD_PLATFORM_SCOPE,
                "aud": DEFAULT_TOKEN_URI,
                "iat": now.unix_timestamp(),
                "exp": now.unix_timestamp() + 3600,
            })
        );
    }

    #[test]
    fn rejects_missing_fields_without_echoing_key() {
        let complete = json!({
            "type": "service_account",
            "client_email": "vertex-test@example.invalid",
            "private_key": "throwaway-test-key-marker",
        });
        for field in ["type", "client_email", "private_key"] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(
                !parse(&incomplete.to_string())
                    .unwrap_err()
                    .contains("throwaway-test-key-marker")
            );
        }
        let sa = parse(&complete.to_string()).unwrap();
        let error = assertion(&sa, CLOUD_PLATFORM_SCOPE, OffsetDateTime::UNIX_EPOCH).unwrap_err();
        assert!(!error.contains("throwaway-test-key-marker"));
        assert!(!format!("{sa:?}").contains("throwaway-test-key-marker"));
    }

    #[test]
    fn parses_token_response() {
        assert_eq!(
            parse_token_response(br#"{"access_token":"mock-token","expires_in":3600}"#).unwrap(),
            ("mock-token".to_owned(), Duration::from_secs(3600))
        );
        assert!(parse_token_response(br#"{"access_token":"mock-token","expires_in":0}"#).is_err());
    }
}
