use std::collections::BTreeMap;
use std::sync::LazyLock;

use http::HeaderMap;

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub action: String,
    pub target: String,
    pub status: String,
}

const REDACTED: &str = "[REDACTED]";

static SENSITIVE_LOG_HEADER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api_key|x-csrf-token)\s*:\s*[^;\r\n]*",
    )
    .expect("sensitive header expression is valid")
});
static SENSITIVE_LOG_ASSIGNMENT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)\b(access[_-]?token|refresh[_-]?token|password|api[_-]?key)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s;,]+)"#,
    )
    .expect("sensitive assignment expression is valid")
});
static SENSITIVE_LOG_AUTH_SCHEME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]+={0,2}")
        .expect("sensitive authorization scheme expression is valid")
});
static SENSITIVE_VALUE: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    [
        r"^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$",
        r"(?i)^Bearer\s+",
        r"(?i)^Basic\s+[a-zA-Z0-9+/=]+$",
        r"^sk-[a-zA-Z0-9]{32,}$",
        r"^[a-fA-F0-9]{32,}$",
        r"(?s)^-----BEGIN[A-Z\s]+PRIVATE KEY-----",
    ]
    .into_iter()
    .map(|pattern| regex::Regex::new(pattern).expect("sensitive value expression is valid"))
    .collect()
});

/// Sanitize a free-form log message before it reaches a non-structured sink.
/// Structured audit records should use `redacted_headers` or `redacted_value` instead.
pub fn redacted_log_message(raw: &str) -> String {
    let headers = SENSITIVE_LOG_HEADER.replace_all(raw, "$1: [REDACTED]");
    let assignments = SENSITIVE_LOG_ASSIGNMENT.replace_all(&headers, "$1=[REDACTED]");
    SENSITIVE_LOG_AUTH_SCHEME
        .replace_all(&assignments, "$1 [REDACTED]")
        .into_owned()
}

/// Apply the same secret-name policy to nested structured log exports.
pub fn redact_record(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if is_sensitive_name(name) {
                    *value = serde_json::Value::String(REDACTED.to_owned());
                } else if name == "message" {
                    if let Some(message) = value.as_str() {
                        *value = serde_json::Value::String(redacted_log_message(message));
                    }
                } else {
                    redact_record(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_record),
        serde_json::Value::String(raw) if is_sensitive_value(raw) => {
            *raw = REDACTED.to_owned();
        }
        _ => {}
    }
}

pub fn redacted_upstream(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return REDACTED.to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Return a structured header view that is safe to attach to an audit record.
/// Audit callers must use this instead of logging a `HeaderMap` directly.
pub fn redacted_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            let value = if is_sensitive_name(&name) {
                REDACTED.to_owned()
            } else {
                value.to_str().unwrap_or("[BINARY]").to_owned()
            };
            (name, value)
        })
        .collect()
}

/// Redact a user-provided value before including it in an audit record.
pub fn redacted_value(field: &str, value: &str) -> String {
    if is_sensitive_name(field) {
        REDACTED.to_owned()
    } else {
        value.to_owned()
    }
}

pub fn management_mutation(actor: &str, action: &str, target: &str, status: &str) {
    tracing::info!(
        actor = %redacted_value("actor", actor),
        action,
        target = %redacted_value("target", target),
        status,
        "platform audit event"
    );
}

pub fn global_ip_deny(target: &str, reason: &str, source_ip: Option<&str>) {
    tracing::info!(
        action = "ip.global_deny",
        target,
        status = "blocked",
        reason,
        source_ip,
        "platform audit event"
    );
}

pub fn config_export(actor: &str, section: Option<&str>) {
    management_mutation(actor, "config.export", section.unwrap_or("all"), "success");
}

fn is_sensitive_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('-', "_");
    if matches!(
        normalized.as_str(),
        "api_authorization_field_swap" | "authorization_field_swap"
    ) {
        return false;
    }
    matches!(
        normalized.as_str(),
        "authorization" | "proxy_authorization" | "cookie" | "set_cookie"
    ) || normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("key")
        || normalized.contains("apikey")
        || normalized.contains("auth")
}

fn is_sensitive_value(value: &str) -> bool {
    SENSITIVE_VALUE
        .iter()
        .any(|pattern| pattern.is_match(value))
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header};

    use super::{REDACTED, redact_record, redacted_headers, redacted_log_message, redacted_value};

    #[test]
    fn audit_header_redaction_never_exposes_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("access_token_cookie=secret"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("secret-api-key"));
        headers.insert("x-password", HeaderValue::from_static("secret-password"));
        headers.insert("x-request-id", HeaderValue::from_static("safe-id"));

        let redacted = redacted_headers(&headers);
        assert_eq!(redacted["authorization"], REDACTED);
        assert_eq!(redacted["cookie"], REDACTED);
        assert_eq!(redacted["x-api-key"], REDACTED);
        assert_eq!(redacted["x-password"], REDACTED);
        assert_eq!(redacted["x-request-id"], "safe-id");
        assert_eq!(redacted_value("token", "secret"), REDACTED);
    }

    #[test]
    fn free_form_log_messages_redact_headers_and_assignments() {
        let secret = "very-secret-value";
        let message = format!(
            "Authorization: Bearer {secret}; cookie: session={secret}; Set-Cookie: access_token_cookie={secret}; X-API-Key: {secret}; X-CSRF-Token: {secret}; password=\"{secret}\" access_token=\"{secret}\" refresh_token={secret}; Bearer {secret}; Basic {secret}"
        );
        let redacted = redacted_log_message(&message);
        assert!(!redacted.contains(secret));
        for expected in [
            "Authorization: [REDACTED]",
            "cookie: [REDACTED]",
            "Set-Cookie: [REDACTED]",
            "X-API-Key: [REDACTED]",
            "X-CSRF-Token: [REDACTED]",
            "password=[REDACTED]",
            "access_token=[REDACTED]",
            "refresh_token=[REDACTED]",
            "Bearer [REDACTED]",
            "Basic [REDACTED]",
        ] {
            assert!(redacted.contains(expected), "{redacted}");
        }
    }

    #[test]
    fn structured_records_match_python_key_and_value_redaction() {
        let mut record = serde_json::json!({
            "signing_key": "secret",
            "api_authorization_field_swap": "x-auth",
            "nested": ["Bearer secret", "safe"]
        });
        redact_record(&mut record);
        assert_eq!(record["signing_key"], REDACTED);
        assert_eq!(record["api_authorization_field_swap"], "x-auth");
        assert_eq!(record["nested"][0], REDACTED);
        assert_eq!(record["nested"][1], "safe");
    }
}
