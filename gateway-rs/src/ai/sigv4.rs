//! AWS Signature Version 4 for Bedrock.

use std::fmt::Write;

use hmac::{Hmac, Mac};
use http::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use http::{HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::format_description;
use url::Url;

#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    // Never print the secret or the session token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// Adds `host`, `x-amz-date`, `x-amz-content-sha256`, `x-amz-security-token`
/// (when set) and `authorization` to `headers`.
#[allow(clippy::too_many_arguments)] // frozen step 4 contract
pub fn sign(
    credentials: &Credentials,
    region: &str,
    service: &str,
    method: &Method,
    url: &Url,
    headers: &mut HeaderMap,
    body: &[u8],
    now: OffsetDateTime,
) {
    headers.remove(AUTHORIZATION);
    headers.remove("x-amz-security-token");
    let Some(host) = url.host_str() else { return };
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let Ok(host) = HeaderValue::from_str(&host) else {
        return;
    };
    let Ok(date) = now
        .to_offset(time::UtcOffset::UTC)
        .format(format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
    else {
        return;
    };
    let body_hash = format!("{:x}", Sha256::digest(body));
    headers.insert(HOST, host);
    headers.insert(
        "x-amz-date",
        HeaderValue::from_str(&date).expect("formatted UTC date"),
    );
    headers.insert(
        "x-amz-content-sha256",
        HeaderValue::from_str(&body_hash).expect("hex digest"),
    );
    if let Some(token) = &credentials.session_token {
        let Ok(mut token) = HeaderValue::from_str(token) else {
            return;
        };
        token.set_sensitive(true);
        headers.insert("x-amz-security-token", token);
    }

    let mut names: Vec<_> = headers
        .keys()
        .filter(|name| {
            **name == HOST || **name == CONTENT_TYPE || name.as_str().starts_with("x-amz-")
        })
        .collect();
    names.sort_unstable_by_key(|name| name.as_str());
    let signed_headers = names
        .iter()
        .map(|name| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical_headers = String::new();
    for name in names {
        let mut values = Vec::new();
        for value in headers.get_all(name) {
            let Ok(value) = value.to_str() else { return };
            values.push(value.split_ascii_whitespace().collect::<Vec<_>>().join(" "));
        }
        writeln!(canonical_headers, "{name}:{}", values.join(",")).expect("writing to String");
    }

    // The URL path already contains any wire escapes. Escape the percent signs
    // too when signing non-S3 requests, while preserving path delimiters.
    let mut path = String::new();
    for segment in url.path().split('/').filter(|segment| !segment.is_empty()) {
        path.push('/');
        path.push_str(&uri_encode(segment.as_bytes()));
    }
    if path.is_empty() || url.path().ends_with('/') {
        path.push('/');
    }
    let mut pairs: Vec<_> = url
        .query()
        .filter(|query| !query.is_empty())
        .into_iter()
        .flat_map(|query| query.split('&'))
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (encode_query_component(key), encode_query_component(value))
        })
        .collect();
    pairs.sort_unstable();
    let query = pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{body_hash}");
    let day = &date[..date.find('T').expect("formatted UTC date")];
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let request_hash = Sha256::digest(canonical.as_bytes());
    let to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{request_hash:x}");
    let mut seed = b"AWS4".to_vec();
    seed.extend_from_slice(credentials.secret_access_key.as_bytes());
    let date_key = hmac(&seed, day);
    let region_key = hmac(&date_key, region);
    let service_key = hmac(&region_key, service);
    let signing_key = hmac(&service_key, "aws4_request");
    let signature = hmac(&signing_key, &to_sign);
    let value = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature:x}",
        credentials.access_key_id
    );
    if let Ok(mut value) = HeaderValue::from_str(&value) {
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
}

fn hmac(key: &[u8], data: &str) -> hmac::digest::Output<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC permits any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes()
}

fn uri_encode(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to String");
        }
    }
    encoded
}

fn encode_query_component(raw: &str) -> String {
    let mut bytes = Vec::new();
    let mut rest = raw.as_bytes();
    while let [byte, tail @ ..] = rest {
        if let [b'%', high, low, remaining @ ..] = rest {
            if let (Some(high), Some(low)) = (
                char::from(*high).to_digit(16),
                char::from(*low).to_digit(16),
            ) {
                bytes.push((high * 16 + low) as u8);
                rest = remaining;
                continue;
            }
        }
        bytes.push(*byte);
        rest = tail;
    }
    uri_encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use time::macros::datetime;

    #[derive(Deserialize)]
    struct Case {
        name: String,
        method: String,
        url: String,
        service: String,
        body: String,
        token: Option<String>,
        authorization: String,
    }

    #[test]
    fn matches_botocore_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/ai/bedrock/sigv4.json"))
                .unwrap();
        let cases: Vec<Case> = serde_json::from_value(fixture["cases"].clone()).unwrap();
        for case in cases {
            let credentials = Credentials {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
                session_token: case.token,
            };
            let mut headers = HeaderMap::new();
            if !case.body.is_empty() {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            sign(
                &credentials,
                "us-east-1",
                &case.service,
                &case.method.parse().unwrap(),
                &Url::parse(&case.url).unwrap(),
                &mut headers,
                case.body.as_bytes(),
                datetime!(2015-08-30 12:36 UTC),
            );
            assert_eq!(headers[AUTHORIZATION], case.authorization, "{}", case.name);
            assert!(headers[AUTHORIZATION].is_sensitive());
            if credentials.session_token.is_some() {
                assert!(headers["x-amz-security-token"].is_sensitive());
            }
        }
    }
}
