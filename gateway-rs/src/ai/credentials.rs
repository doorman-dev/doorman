//! Turns a stored provider key into what goes on the wire (step 4, B1).
//!
//! Most providers send the key as a header. Bedrock takes a Bedrock API key
//! (bearer) or IAM keys stored as JSON (SigV4). Vertex exchanges a
//! service-account JSON for a short-lived access token, cached per key.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use http::{HeaderMap, Method};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::ai::{
    adapter::{AiProvider, INBOUND_CREDENTIAL_HEADERS, ProviderAdapter},
    gcp_auth, sigv4,
};

/// Refresh a cached Vertex token this long before it expires.
const REFRESH_EARLY: Duration = Duration::from_secs(300);
/// Upper bound on the token exchange round trip.
const TOKEN_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Test-only: lets the service account's `token_uri` point at a loopback host.
pub const LOOPBACK_TOKEN_URI_ENV: &str = "AI_VERTEX_ALLOW_LOOPBACK_TOKEN_URI";

#[derive(Clone, Debug)]
pub enum PreparedCredential {
    /// Existing providers: the adapter formats `key` for its header.
    Header(String),
    /// Bedrock API key or Vertex access token, sent as `Authorization: Bearer`.
    Bearer(String),
    /// Bedrock IAM keys; the request is signed last, over its final form.
    SigV4(sigv4::Credentials),
}

#[derive(Clone, Debug)]
pub struct Prepared {
    pub credential: PreparedCredential,
    /// Vertex: the service account's project, used when config has none.
    pub project_id: Option<String>,
}

/// Never contains key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialError(pub String);

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub async fn prepare(
    provider: AiProvider,
    raw: &str,
    client: &reqwest::Client,
) -> Result<Prepared, CredentialError> {
    let credential = match provider {
        AiProvider::Bedrock => bedrock_credential(raw)?,
        AiProvider::Vertex => {
            let account = gcp_auth::parse(raw)
                .map_err(|_| CredentialError("Vertex service-account JSON is invalid".into()))?;
            let token = vertex_token(&account, raw, client).await?;
            let project_id = Some(account.project_id.clone()).filter(|id| !id.is_empty());
            return Ok(Prepared {
                credential: PreparedCredential::Bearer(token),
                project_id,
            });
        }
        _ => PreparedCredential::Header(raw.to_owned()),
    };
    Ok(Prepared {
        credential,
        project_id: None,
    })
}

/// IAM keys are stored as `{"access_key_id","secret_access_key","session_token"?}`;
/// anything else is a Bedrock API key.
fn bedrock_credential(raw: &str) -> Result<PreparedCredential, CredentialError> {
    let raw = raw.trim();
    if !raw.starts_with('{') {
        return Ok(PreparedCredential::Bearer(raw.to_owned()));
    }
    let malformed = || CredentialError("Bedrock IAM key JSON is invalid".into());
    let value: Value = serde_json::from_str(raw).map_err(|_| malformed())?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    Ok(PreparedCredential::SigV4(sigv4::Credentials {
        access_key_id: field("access_key_id").ok_or_else(malformed)?,
        secret_access_key: field("secret_access_key").ok_or_else(malformed)?,
        session_token: field("session_token"),
    }))
}

/// The parts of one outbound request that SigV4 signs.
pub struct OutboundRequest<'a> {
    pub method: &'a Method,
    pub url: &'a str,
    pub body: &'a [u8],
    pub region: Option<&'a str>,
}

/// Puts the credential on `headers`. SigV4 must run after every other header is set.
pub fn apply(
    prepared: &PreparedCredential,
    adapter: &dyn ProviderAdapter,
    header_override: Option<&str>,
    request: &OutboundRequest,
    headers: &mut HeaderMap,
) -> Result<(), CredentialError> {
    if adapter.provider() == AiProvider::Bedrock {
        // Client-sent AWS auth headers (x-amz-date, x-amz-security-token, ...)
        // must never reach AWS next to Doorman's own credential.
        let client_aws: Vec<_> = headers
            .keys()
            .filter(|name| name.as_str().starts_with("x-amz-"))
            .cloned()
            .collect();
        for name in client_aws {
            headers.remove(name);
        }
    }
    match prepared {
        PreparedCredential::Header(value) => {
            adapter.apply_credential(headers, value, header_override);
        }
        PreparedCredential::Bearer(token) => adapter.apply_credential(headers, token, None),
        PreparedCredential::SigV4(credentials) => {
            for name in INBOUND_CREDENTIAL_HEADERS {
                headers.remove(*name);
            }
            let region = request.region.ok_or_else(|| {
                CredentialError("Bedrock region is unknown; set it on the API".into())
            })?;
            let url = url::Url::parse(request.url)
                .map_err(|_| CredentialError("Bedrock upstream URL is invalid".into()))?;
            sigv4::sign(
                credentials,
                region,
                "bedrock",
                request.method,
                &url,
                headers,
                request.body,
                time::OffsetDateTime::now_utc(),
            );
        }
    }
    Ok(())
}

/// Bedrock region or Vertex location from the server host, else `configured`.
/// The host wins so a backup in another region is signed for that region.
pub fn region_for(provider: AiProvider, server: &str, configured: Option<&str>) -> Option<String> {
    let host = url::Url::parse(server)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
    let from_host = host.and_then(|host| match provider {
        AiProvider::Bedrock => host_region_bedrock(&host),
        AiProvider::Vertex => host_location_vertex(&host),
        _ => None,
    });
    from_host.or_else(|| {
        configured
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

/// `bedrock-runtime.{region}.amazonaws.com`, `bedrock-runtime-fips.{region}…`,
/// and VPC endpoints `…bedrock-runtime.{region}.vpce.amazonaws.com`.
fn host_region_bedrock(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    let at = labels
        .iter()
        .position(|label| label.starts_with("bedrock-runtime"))?;
    let region = labels.get(at + 1)?;
    (host.ends_with(".amazonaws.com") && region.contains('-')).then(|| (*region).to_owned())
}

/// `{location}-aiplatform.googleapis.com`; `aiplatform.googleapis.com` is global.
fn host_location_vertex(host: &str) -> Option<String> {
    if host == "aiplatform.googleapis.com" {
        return Some("global".into());
    }
    host.strip_suffix("-aiplatform.googleapis.com")
        .filter(|location| !location.is_empty() && !location.contains('.'))
        .map(str::to_owned)
}

struct CachedToken {
    token: String,
    expires_at: Instant,
}

type TokenSlot = Arc<tokio::sync::Mutex<Option<CachedToken>>>;

fn token_slots() -> &'static Mutex<HashMap<[u8; 32], TokenSlot>> {
    static SLOTS: OnceLock<Mutex<HashMap<[u8; 32], TokenSlot>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fresh(expires_at: Instant, now: Instant) -> bool {
    expires_at
        .checked_sub(REFRESH_EARLY)
        .is_some_and(|refresh_at| now < refresh_at)
}

fn token_uri_allowed(uri: &str) -> bool {
    if uri == gcp_auth::DEFAULT_TOKEN_URI {
        return true;
    }
    let loopback_allowed =
        std::env::var(LOOPBACK_TOKEN_URI_ENV).is_ok_and(|value| value.eq_ignore_ascii_case("true"));
    loopback_allowed
        && url::Url::parse(uri)
            .is_ok_and(|url| matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")))
}

/// One exchange per service account at a time; failures are never cached.
async fn vertex_token(
    account: &gcp_auth::ServiceAccount,
    raw: &str,
    client: &reqwest::Client,
) -> Result<String, CredentialError> {
    let key: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let slot = token_slots()
        .lock()
        .map_err(|_| CredentialError("Vertex token cache unavailable".into()))?
        .entry(key)
        .or_default()
        .clone();
    let mut cached = slot.lock().await;
    if let Some(token) = cached.as_ref()
        && fresh(token.expires_at, Instant::now())
    {
        return Ok(token.token.clone());
    }
    if !token_uri_allowed(&account.token_uri) {
        return Err(CredentialError(
            "Vertex service-account token_uri must be https://oauth2.googleapis.com/token".into(),
        ));
    }
    let assertion = gcp_auth::assertion(
        account,
        gcp_auth::CLOUD_PLATFORM_SCOPE,
        time::OffsetDateTime::now_utc(),
    )
    .map_err(|_| CredentialError("Vertex service-account key could not sign".into()))?;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", &assertion)
        .finish();
    let started = Instant::now();
    let response = client
        .post(&account.token_uri)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form)
        .timeout(TOKEN_EXCHANGE_TIMEOUT)
        .send()
        .await
        .map_err(|_| CredentialError("Google token endpoint unreachable".into()))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|_| CredentialError("Google token endpoint unreachable".into()))?;
    if !status.is_success() {
        return Err(CredentialError(format!(
            "Google token exchange failed with HTTP {}",
            status.as_u16()
        )));
    }
    let (token, lifetime) = gcp_auth::parse_token_response(&body)
        .map_err(|_| CredentialError("Google token response is invalid".into()))?;
    *cached = Some(CachedToken {
        token: token.clone(),
        expires_at: started + lifetime,
    });
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_comes_from_host_then_config() {
        let bedrock = |server, configured| region_for(AiProvider::Bedrock, server, configured);
        assert_eq!(
            bedrock(
                "https://bedrock-runtime.us-west-2.amazonaws.com",
                Some("eu-west-1")
            )
            .as_deref(),
            Some("us-west-2")
        );
        assert_eq!(
            bedrock("https://bedrock-runtime-fips.us-east-1.amazonaws.com", None).as_deref(),
            Some("us-east-1")
        );
        assert_eq!(
            bedrock(
                "https://vpce-0a1.bedrock-runtime.eu-central-1.vpce.amazonaws.com",
                None
            )
            .as_deref(),
            Some("eu-central-1")
        );
        assert_eq!(
            bedrock("http://127.0.0.1:9", Some(" us-east-1 ")).as_deref(),
            Some("us-east-1")
        );
        assert_eq!(bedrock("http://127.0.0.1:9", None), None);
        let vertex = |server| region_for(AiProvider::Vertex, server, None);
        assert_eq!(
            vertex("https://us-east5-aiplatform.googleapis.com").as_deref(),
            Some("us-east5")
        );
        assert_eq!(
            vertex("https://aiplatform.googleapis.com").as_deref(),
            Some("global")
        );
        assert_eq!(
            region_for(AiProvider::Openai, "https://api.openai.com", None),
            None
        );
    }

    #[test]
    fn bedrock_key_is_bearer_or_iam_json() {
        assert!(matches!(
            bedrock_credential(" bedrock-api-key ").unwrap(),
            PreparedCredential::Bearer(key) if key == "bedrock-api-key"
        ));
        let PreparedCredential::SigV4(iam) = bedrock_credential(
            r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}"#,
        )
        .unwrap() else {
            panic!("expected SigV4");
        };
        assert_eq!(iam.access_key_id, "AKIDEXAMPLE");
        assert_eq!(iam.session_token, None);
        let error = bedrock_credential(r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"#)
            .unwrap_err();
        assert!(!error.0.contains("AKIDEXAMPLE"));
        assert!(bedrock_credential(r#"{"access_key_id":"AKIDEXAMPLE"}"#).is_err());
    }

    #[test]
    fn token_is_refreshed_five_minutes_early() {
        let now = Instant::now();
        assert!(fresh(now + Duration::from_secs(301), now));
        assert!(!fresh(now + Duration::from_secs(300), now));
        assert!(!fresh(now, now));
    }

    #[test]
    fn only_googles_token_uri_without_the_test_flag() {
        assert!(token_uri_allowed("https://oauth2.googleapis.com/token"));
        assert!(!token_uri_allowed("https://evil.example/token"));
        // The flag is unset in unit tests; loopback stays refused.
        if std::env::var(LOOPBACK_TOKEN_URI_ENV).is_err() {
            assert!(!token_uri_allowed("http://127.0.0.1:9/token"));
        }
    }
}
