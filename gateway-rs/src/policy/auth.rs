use http::{HeaderMap, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::{PolicyFailure, PolicyStage};
use crate::config::SharedStorageConfig;

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        Option::<Audience>::deserialize(deserializer)?.map(|audience| match audience {
            Audience::One(value) => vec![value],
            Audience::Many(values) => values,
        }),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AuthClaims {
    pub sub: Option<String>,
    pub jti: Option<String>,
    pub role: Option<String>,
    pub exp: Option<usize>,
    pub iss: Option<String>,
    pub iat: Option<usize>,
    #[serde(deserialize_with = "deserialize_audience")]
    pub aud: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
struct JwtKeyConfig {
    kid: Option<String>,
    algorithm: Option<String>,
    secret: Option<String>,
    key: Option<String>,
    public_key: Option<String>,
    public_key_path: Option<String>,
    verification_key: Option<String>,
}

pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    extract_cookie(headers, "access_token_cookie").or_else(|| extract_authorization(headers))
}

pub fn verify_request_token(
    headers: &HeaderMap,
    config: &SharedStorageConfig,
) -> Result<AuthClaims, PolicyFailure> {
    let token = extract_token(headers).ok_or_else(|| unauthorized("Unauthorized"))?;
    let header = decode_header(&token).map_err(|_| unauthorized("Unauthorized"))?;
    let key = select_key(config, header.kid.as_deref())
        .ok_or_else(|| unauthorized("Invalid token signature"))?;
    let algorithm = key.algorithm();
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    // python-jose applies no clock leeway; an expired token is rejected at once.
    validation.leeway = 0;
    validation.set_issuer(&[config.jwt_issuer.as_str()]);
    validation.set_audience(&[config.jwt_audience.as_str()]);
    // A configured issuer/audience must be present, not merely valid if present.
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let data = decode::<AuthClaims>(&token, &key.decoding_key()?, &validation)
        .map_err(|_| unauthorized("Unauthorized"))?;
    if data.claims.sub.as_deref().unwrap_or_default().is_empty()
        || data.claims.jti.as_deref().unwrap_or_default().is_empty()
    {
        return Err(unauthorized("Invalid token"));
    }
    Ok(data.claims)
}

fn extract_authorization(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?
        .trim();
    if value.is_empty() {
        return None;
    }
    let parts: Vec<&str> = value.split_whitespace().collect();
    match parts.as_slice() {
        [scheme, token] if scheme.eq_ignore_ascii_case("bearer") => Some((*token).to_owned()),
        [token] => Some((*token).to_owned()),
        _ => None,
    }
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(cookie_name, cookie_value)| {
            (cookie_name == name && !cookie_value.trim().is_empty())
                .then(|| cookie_value.to_owned())
        })
}

#[derive(Clone, Debug)]
struct VerificationKey {
    kid: Option<String>,
    algorithm: String,
    secret: String,
    rsa: bool,
}

impl VerificationKey {
    fn algorithm(&self) -> Algorithm {
        match self.algorithm.to_ascii_uppercase().as_str() {
            "RS256" => Algorithm::RS256,
            _ => Algorithm::HS256,
        }
    }

    fn decoding_key(&self) -> Result<DecodingKey, PolicyFailure> {
        if self.rsa {
            DecodingKey::from_rsa_pem(self.secret.as_bytes())
                .map_err(|_| unauthorized("Invalid token signature"))
        } else {
            Ok(DecodingKey::from_secret(self.secret.as_bytes()))
        }
    }
}

fn select_key(config: &SharedStorageConfig, kid: Option<&str>) -> Option<VerificationKey> {
    if let Some(raw) = &config.jwt_keys_json {
        if let Some(key) = select_configured_key(raw, kid) {
            return Some(key);
        }
    }
    config.jwt_secret.as_ref().map(|secret| VerificationKey {
        kid: Some("legacy-key".to_owned()),
        algorithm: "HS256".to_owned(),
        secret: secret.clone(),
        rsa: false,
    })
}

fn select_configured_key(raw: &str, kid: Option<&str>) -> Option<VerificationKey> {
    let value: Value = serde_json::from_str(raw).ok()?;
    let configs = match value {
        Value::Array(items) => items,
        Value::Object(mut map) => match map.remove("keys") {
            Some(Value::Array(items)) => items,
            _ => vec![Value::Object(map)],
        },
        _ => return None,
    };

    let keys = configs
        .into_iter()
        .filter_map(|value| serde_json::from_value::<JwtKeyConfig>(value).ok())
        .filter_map(|config| {
            let algorithm = config.algorithm.unwrap_or_else(|| "HS256".to_owned());
            let secret = if algorithm.eq_ignore_ascii_case("RS256") {
                config
                    .public_key_path
                    .and_then(|path| std::fs::read_to_string(path).ok())
                    .or(config.public_key)
                    .or(config.verification_key)
            } else {
                config.secret.or(config.key).or(config.verification_key)
            }?;
            Some(VerificationKey {
                kid: config.kid,
                rsa: algorithm.eq_ignore_ascii_case("RS256"),
                algorithm,
                secret,
            })
        })
        .collect::<Vec<_>>();
    if let Some(kid) = kid {
        return keys.into_iter().find(|key| key.kid.as_deref() == Some(kid));
    }
    if keys.len() == 1 {
        return keys.into_iter().next();
    }
    keys.into_iter()
        .find(|key| key.kid.as_deref() == Some("legacy-key"))
}

pub fn unauthorized(message: &str) -> PolicyFailure {
    PolicyFailure::new(
        PolicyStage::Authentication,
        StatusCode::UNAUTHORIZED,
        message,
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn audience_deserializes_string_or_array() {
        let one: AuthClaims =
            serde_json::from_value(serde_json::json!({"sub":"user","jti":"id","aud":"doorman"}))
                .unwrap();
        let many: AuthClaims =
            serde_json::from_value(serde_json::json!({"sub":"user","jti":"id","aud":["doorman"]}))
                .unwrap();
        assert_eq!(one.aud, Some(vec!["doorman".to_owned()]));
        assert_eq!(many.aud, Some(vec!["doorman".to_owned()]));
    }

    #[test]
    fn extracts_cookie_before_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; access_token_cookie=cookie-token"),
        );
        assert_eq!(extract_token(&headers), Some("cookie-token".to_owned()));
    }

    #[test]
    fn accepts_bare_authorization_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("raw-token"));
        assert_eq!(extract_token(&headers), Some("raw-token".to_owned()));
    }

    #[test]
    fn tokens_missing_issuer_or_audience_are_rejected() {
        let config = SharedStorageConfig {
            jwt_secret: Some("unit-test-secret".to_owned()),
            ..SharedStorageConfig::default()
        };
        let exp = jsonwebtoken::get_current_timestamp() + 600;
        let full = serde_json::json!({
            "sub": "user", "jti": "id", "exp": exp,
            "iss": config.jwt_issuer, "aud": config.jwt_audience,
        });
        let verify = |claims: &serde_json::Value| {
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                claims,
                &jsonwebtoken::EncodingKey::from_secret(b"unit-test-secret"),
            )
            .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
            verify_request_token(&headers, &config)
        };
        assert!(verify(&full).is_ok());
        for claim in ["iss", "aud"] {
            let mut partial = full.clone();
            partial.as_object_mut().unwrap().remove(claim);
            assert!(verify(&partial).is_err(), "token without {claim} accepted");
        }
    }

    #[test]
    fn configured_verification_key_selection_matches_legacy_kid_rules() {
        let keys = r#"[
            {"kid":"one","algorithm":"HS256","secret":"first","active":false},
            {"kid":"two","algorithm":"HS256","secret":"second"}
        ]"#;
        assert!(select_configured_key(keys, None).is_none());
        assert_eq!(
            select_configured_key(keys, Some("one")).unwrap().secret,
            "first"
        );

        let legacy = r#"[
            {"kid":"one","algorithm":"HS256","secret":"first"},
            {"kid":"legacy-key","algorithm":"HS256","secret":"legacy"}
        ]"#;
        assert_eq!(
            select_configured_key(legacy, None).unwrap().secret,
            "legacy"
        );
    }
}
