use crate::ai::adapter::{
    AiRequestInfo, Dialect, INBOUND_CREDENTIAL_HEADERS, INBOUND_CREDENTIAL_QUERY,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};

pub(super) const TEXT_CAP: usize = 256 * 1024;

pub(super) fn request_info(
    operation: &'static str,
    model: Option<String>,
    stream: bool,
) -> AiRequestInfo {
    AiRequestInfo {
        operation,
        model,
        stream: stream && is_generation(operation),
        metered: !matches!(operation, "models" | "count_tokens"),
        local: operation == "models",
        generation: is_generation(operation),
        dialect: Dialect::for_operation(operation),
    }
}

fn is_generation(operation: &str) -> bool {
    matches!(
        operation,
        "chat" | "responses" | "messages" | "generate" | "converse" | "invoke"
    )
}

pub(super) fn body_model(body: &Value) -> Option<String> {
    body.get("model").and_then(Value::as_str).map(str::to_owned)
}

pub(super) fn set_body_model(
    info: &AiRequestInfo,
    path: &str,
    body: &mut Value,
    model: &str,
) -> String {
    if !info.local {
        if let Some(object) = body.as_object_mut() {
            object.insert("model".into(), json!(model));
        }
    }
    path.to_owned()
}

pub(super) fn clamp(body: &mut Value, field: &str, cap: u64) {
    if let Some(object) = body.as_object_mut() {
        let value = object
            .get(field)
            .and_then(Value::as_u64)
            .unwrap_or(cap)
            .min(cap);
        object.insert(field.into(), json!(value));
    }
}

pub(super) fn strip_query(query: Vec<(String, String)>) -> Vec<(String, String)> {
    query
        .into_iter()
        .filter(|(name, _)| !INBOUND_CREDENTIAL_QUERY.contains(&name.as_str()))
        .collect()
}

pub(super) fn credential(
    headers: &mut HeaderMap,
    key: &str,
    default_header: &str,
    header_override: Option<&str>,
) {
    for name in INBOUND_CREDENTIAL_HEADERS {
        headers.remove(*name);
    }
    let Ok(name) = HeaderName::from_bytes(header_override.unwrap_or(default_header).as_bytes())
    else {
        return;
    };
    // Never turn a provider credential into an outbound session cookie.
    if name == http::header::COOKIE {
        return;
    }
    let value = if name == http::header::AUTHORIZATION {
        format!("Bearer {key}")
    } else {
        key.to_owned()
    };
    if let Ok(mut value) = HeaderValue::from_str(&value) {
        value.set_sensitive(true);
        headers.insert(name, value);
    }
}

pub(super) fn append_text(target: &mut String, text: &str) {
    let mut length = text.len().min(TEXT_CAP.saturating_sub(target.len()));
    while !text.is_char_boundary(length) {
        length -= 1;
    }
    target.push_str(&text[..length]);
}

pub(super) fn text_part(target: &mut String, text: &str) {
    if !target.is_empty() && !text.is_empty() {
        append_text(target, "\n");
    }
    append_text(target, text);
}

pub(super) fn content_text(value: &Value, target: &mut String) {
    if let Some(text) = value.as_str() {
        text_part(target, text);
    } else if let Some(parts) = value.as_array() {
        for part in parts {
            if matches!(
                part.get("type").and_then(Value::as_str),
                Some("text" | "input_text" | "output_text")
            ) {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    text_part(target, text);
                }
            }
        }
    }
}

pub(super) fn messages_text(body: &Value, target: &mut String) {
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            if matches!(
                message.get("role").and_then(Value::as_str),
                Some("system" | "developer" | "user" | "assistant")
            ) {
                content_text(&message["content"], target);
            }
        }
    }
}

#[cfg(test)]
pub(super) fn feed_stream(parser: &mut dyn crate::ai::usage::StreamUsageParser, transcript: &str) {
    let mut sse = crate::ai::sse::SseParser::new(1024 * 1024);
    for chunk in transcript.as_bytes().chunks(7) {
        for event in sse.push(chunk) {
            parser.on_event(&event);
        }
    }
}

/// Decode a model path segment without interpreting a literal plus as a space.
pub(super) fn decode_segment(segment: &str) -> Option<String> {
    let escaped = segment
        .replace('+', "%2B")
        .replace('&', "%26")
        .replace('=', "%3D");
    url::form_urlencoded::parse(escaped.as_bytes())
        .next()
        .map(|(name, _)| name.into_owned())
}

/// Encode a single URL path segment, including delimiters inside model IDs.
pub(super) fn encode_segment(segment: &str) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~@".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to String");
        }
    }
    encoded
}
