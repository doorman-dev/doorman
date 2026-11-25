//! OpenAI side shared by every target: validation, errors, chunk/usage builders,
//! and pass-through for OpenAI / Azure / OpenAI-compatible.

use http::StatusCode;
use serde_json::{Value, json};

use super::{ChunkTranslator, NativeRequest, TranslateError};
use crate::ai::{adapter::AiProvider, sse::SseEvent};

/// Identity of the chunks one stream emits. Shared with the target modules.
#[derive(Clone, Debug)]
pub(super) struct ChunkMeta {
    pub id: String,
    pub model: String,
    pub created: i64,
    pub include_usage: bool,
}

impl ChunkMeta {
    pub(super) fn chunk(&self, delta: Value, finish_reason: Option<&str>) -> Value {
        let mut chunk = self.envelope(json!([{
            "index": 0,
            "delta": delta,
            "finish_reason": finish_reason,
        }]));
        if self.include_usage {
            chunk["usage"] = Value::Null;
        }
        chunk
    }

    pub(super) fn usage_chunk(&self, usage: Value) -> Value {
        let mut chunk = self.envelope(json!([]));
        chunk["usage"] = usage;
        chunk
    }

    fn envelope(&self, choices: Value) -> Value {
        json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": choices,
        })
    }
}

pub(super) fn usage(prompt: u64, completion: u64, cached: u64) -> Value {
    json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt.saturating_add(completion),
        "prompt_tokens_details": {"cached_tokens": cached},
    })
}

pub(super) fn completion(
    model: &str,
    id: Option<&str>,
    content: String,
    tool_calls: Vec<Value>,
    finish_reason: &str,
    usage: Value,
) -> Value {
    let id = id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("chatcmpl-{}", uuid::Uuid::new_v4()));
    let content = if content.is_empty() && !tool_calls.is_empty() {
        Value::Null
    } else {
        Value::String(content)
    };
    let mut message = json!({"role": "assistant", "content": content});
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
    }
    json!({
        "id": id,
        "object": "chat.completion",
        "created": time::OffsetDateTime::now_utc().unix_timestamp(),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": usage,
    })
}

pub(super) fn finish_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("max_tokens" | "MAX_TOKENS") => "length",
        Some("tool_use") => "tool_calls",
        Some(
            "refusal"
            | "guardrail_intervened"
            | "content_filtered"
            | "SAFETY"
            | "RECITATION"
            | "BLOCKLIST"
            | "PROHIBITED_CONTENT",
        ) => "content_filter",
        _ => "stop",
    }
}

pub(super) const JSON_OBJECT_INSTRUCTION: &str =
    "Respond with a single valid JSON object and no other text.";

pub(super) enum ResponseFormat<'a> {
    Text,
    JsonObject,
    JsonSchema {
        name: Option<&'a str>,
        description: Option<&'a str>,
        schema: &'a Value,
    },
}

pub(super) fn response_format(chat: &Value) -> Result<ResponseFormat<'_>, TranslateError> {
    let format = &chat["response_format"];
    match format["type"].as_str() {
        _ if format.is_null() => Ok(ResponseFormat::Text),
        Some("text") => Ok(ResponseFormat::Text),
        Some("json_object") => Ok(ResponseFormat::JsonObject),
        Some("json_schema") => {
            let definition = &format["json_schema"];
            let schema = &definition["schema"];
            if !schema.is_object() {
                return Err(TranslateError(
                    "response_format.json_schema.schema must be an object".into(),
                ));
            }
            Ok(ResponseFormat::JsonSchema {
                name: definition["name"].as_str(),
                description: definition["description"].as_str(),
                schema,
            })
        }
        _ => Err(TranslateError(
            "response_format.type must be text, json_object, or json_schema".into(),
        )),
    }
}

pub(super) fn output_token_limit(chat: &Value) -> Result<Option<u64>, TranslateError> {
    for field in ["max_completion_tokens", "max_tokens"] {
        if !chat[field].is_null() {
            return chat[field]
                .as_u64()
                .filter(|limit| *limit > 0)
                .map(Some)
                .ok_or_else(|| TranslateError(format!("{field} must be a positive integer")));
        }
    }
    Ok(None)
}

pub(super) fn stop_sequences(chat: &Value) -> Result<Option<Value>, TranslateError> {
    match &chat["stop"] {
        Value::Null => Ok(None),
        Value::String(stop) => Ok(Some(json!([stop]))),
        Value::Array(stops) if stops.iter().all(Value::is_string) => Ok(Some(json!(stops))),
        _ => Err(TranslateError(
            "stop must be a string or an array of strings".into(),
        )),
    }
}

pub(super) fn reasoning_effort(chat: &Value) -> Result<Option<&str>, TranslateError> {
    let value = &chat["reasoning_effort"];
    match value.as_str() {
        None if value.is_null() => Ok(None),
        effort @ Some("none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max") => {
            Ok(effort)
        }
        _ => Err(TranslateError("Unsupported reasoning_effort".into())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolChoice<'a> {
    Default,
    Auto,
    None,
    Required,
    Named(&'a str),
}

pub(super) fn tool_choice(chat: &Value) -> Result<ToolChoice<'_>, TranslateError> {
    let choice = &chat["tool_choice"];
    match choice {
        Value::Null => Ok(ToolChoice::Default),
        Value::String(choice) if choice == "auto" => Ok(ToolChoice::Auto),
        Value::String(choice) if choice == "none" => Ok(ToolChoice::None),
        Value::String(choice) if choice == "required" => Ok(ToolChoice::Required),
        Value::Object(_) if choice["type"] == "function" => choice["function"]["name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(ToolChoice::Named)
            .ok_or_else(|| TranslateError("Named tool_choice requires a function name".into())),
        _ => Err(TranslateError(
            "tool_choice must be auto, none, required, or a named function".into(),
        )),
    }
}

pub(super) fn array_field<'a>(body: &'a Value, field: &str) -> Result<&'a [Value], TranslateError> {
    match &body[field] {
        Value::Null => Ok(&[]),
        Value::Array(items) => Ok(items),
        _ => Err(TranslateError(format!("{field} must be an array"))),
    }
}

pub(super) fn tool_definition(tool: &Value) -> Result<(&str, &Value), TranslateError> {
    let function = &tool["function"];
    let name = function["name"].as_str().filter(|name| !name.is_empty());
    match name {
        Some(name) if tool["type"] == "function" => Ok((name, function)),
        _ => Err(TranslateError(
            "Tools must be function definitions with a name".into(),
        )),
    }
}

pub(super) fn tool_parameters(function: &Value) -> Value {
    if function["parameters"].is_null() {
        json!({"type": "object", "properties": {}})
    } else {
        function["parameters"].clone()
    }
}

pub(super) fn tool_use(call: &Value) -> Result<(&str, &str, Value), TranslateError> {
    let function = &call["function"];
    let id = call["id"].as_str().filter(|id| !id.is_empty());
    let name = function["name"].as_str().filter(|name| !name.is_empty());
    let (Some(id), Some(name)) = (id, name) else {
        return Err(TranslateError(
            "Tool calls require an id and function name".into(),
        ));
    };
    if !call["type"].is_null() && call["type"] != "function" {
        return Err(TranslateError("Tool calls must be function calls".into()));
    }
    let input = function["arguments"]
        .as_str()
        .and_then(|arguments| serde_json::from_str::<Value>(arguments).ok())
        .filter(Value::is_object)
        .ok_or_else(|| TranslateError("Tool call arguments must be a JSON object string".into()))?;
    Ok((id, name, input))
}

pub(super) fn tool_result_id(message: &Value) -> Result<&str, TranslateError> {
    message["tool_call_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| TranslateError("Tool messages require a tool_call_id".into()))
}

pub(super) fn tool_call(id: &str, name: &str, arguments: &Value) -> Value {
    let arguments = if arguments.is_null() {
        "{}".into()
    } else {
        arguments.to_string()
    };
    json!({
        "id": id, "type": "function", "function": {"name": name, "arguments": arguments},
    })
}

pub(super) fn tool_arguments_delta(index: usize, arguments: &str) -> Value {
    json!({"tool_calls": [{"index": index, "function": {"arguments": arguments}}]})
}

pub(super) fn image_url(part: &Value) -> Result<&str, TranslateError> {
    part["image_url"]["url"]
        .as_str()
        .filter(|url| !url.is_empty())
        .ok_or_else(|| TranslateError("image_url content parts require a URL".into()))
}

pub(super) fn base64_image(url: &str) -> Result<(&str, &str), TranslateError> {
    url.strip_prefix("data:")
        .and_then(|url| url.split_once(";base64,"))
        .filter(|(media_type, data)| {
            media_type.starts_with("image/")
                && !data.is_empty()
                && data
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
        })
        .ok_or_else(|| TranslateError("Inline images require a base64 image data URL".into()))
}

pub(super) fn https_image(url: &str) -> Result<url::Url, TranslateError> {
    url::Url::parse(url)
        .ok()
        .filter(|url| url.scheme() == "https" && url.has_host())
        .ok_or_else(|| {
            TranslateError("Image URLs must use HTTPS or a base64 image data URL".into())
        })
}

pub(super) fn path_segment(segment: &str) -> String {
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

/// Checks shared by all targets (messages, roles, `n`).
pub(super) fn validate(chat: &Value) -> Result<(), TranslateError> {
    let messages = chat["messages"]
        .as_array()
        .filter(|messages| !messages.is_empty())
        .ok_or_else(|| TranslateError("messages must be a non-empty array".into()))?;
    if chat.get("n").is_some_and(|n| n.as_u64() != Some(1)) {
        return Err(TranslateError("n must be 1 when supplied".into()));
    }
    for (index, message) in messages.iter().enumerate() {
        if !matches!(
            message["role"].as_str(),
            Some("system" | "developer" | "user" | "assistant" | "tool")
        ) {
            return Err(TranslateError(format!(
                "messages[{index}].role must be system, developer, user, assistant, or tool"
            )));
        }
    }
    Ok(())
}

pub(super) fn to_native(
    provider: AiProvider,
    model: &str,
    chat: &Value,
) -> Result<NativeRequest, TranslateError> {
    let mut body = chat.clone();
    let rest_path = match provider {
        AiProvider::AzureOpenai => format!("openai/deployments/{model}/chat/completions"),
        _ => {
            body["model"] = json!(model);
            "v1/chat/completions".into()
        }
    };
    Ok(NativeRequest {
        rest_path,
        query: Vec::new(),
        body,
        stream: chat["stream"].as_bool().unwrap_or_default(),
    })
}

pub(super) fn from_native(requested_model: &str, native: &Value) -> Value {
    let mut body = native.clone();
    if let Some(object) = body.as_object_mut() {
        object.insert("model".into(), json!(requested_model));
    }
    body
}

pub(super) fn error_to_openai(status: StatusCode, body: &[u8]) -> Value {
    let kind = match status {
        StatusCode::UNAUTHORIZED => "authentication_error",
        StatusCode::FORBIDDEN => "permission_error",
        StatusCode::NOT_FOUND => "not_found_error",
        StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
        status if status.is_client_error() => "invalid_request_error",
        _ => "api_error",
    };
    let body: Value = serde_json::from_slice(body).unwrap_or_default();
    let message = body["error_message"]
        .as_str()
        .or_else(|| {
            [
                &body["error"]["message"],
                &body["message"],
                &body["Message"],
            ]
            .into_iter()
            .filter_map(Value::as_str)
            .find(|message| !message.trim().is_empty())
        })
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("Error"));
    let code = body
        .get("error_code")
        .or_else(|| body["error"].get("code"))
        .and_then(|code| match code {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        });
    json!({"error": {
        "message": message,
        "type": kind,
        "code": code,
        "param": null,
    }})
}

pub(super) struct PassthroughChunks {
    meta: ChunkMeta,
}

impl PassthroughChunks {
    pub(super) fn new(meta: ChunkMeta) -> Self {
        Self { meta }
    }
}

impl ChunkTranslator for PassthroughChunks {
    fn on_event(&mut self, event: &SseEvent) -> Vec<Value> {
        let Ok(mut chunk) = serde_json::from_str::<Value>(&event.data) else {
            // The gateway emits its own [DONE] after the upstream stream ends.
            return Vec::new();
        };
        let Some(object) = chunk.as_object_mut() else {
            return Vec::new();
        };
        object.insert("model".into(), json!(self.meta.model));
        vec![chunk]
    }

    fn finish(&mut self) -> Vec<Value> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::translate::{self, Target};

    #[test]
    fn validates_shared_chat_fields() {
        for chat in [
            json!({}),
            json!({"messages": {}}),
            json!({"messages": []}),
            json!({"messages": [{}]}),
            json!({"messages": [{"role": "invalid"}]}),
            json!({"messages": [{"role": "user"}], "n": 2}),
            json!({"messages": [{"role": "user"}], "n": "1"}),
        ] {
            assert!(validate(&chat).is_err(), "{chat}");
        }
        let chat = json!({"messages": [
            {"role": "system"}, {"role": "developer"}, {"role": "user"},
            {"role": "assistant"}, {"role": "tool"}
        ], "n": 1, "logprobs": true});
        assert_eq!(validate(&chat), Ok(()));
        assert_eq!(
            translate::to_native(AiProvider::Anthropic, "claude", &chat),
            Err(TranslateError(
                "logprobs is only supported on OpenAI-compatible targets".into()
            )),
        );
    }

    #[test]
    fn maps_provider_and_doorman_errors() {
        let cases = [
            (
                400,
                r#"{"type":"error","error":{"type":"invalid_request_error","message":"Anthropic"}}"#,
                "Anthropic",
                "invalid_request_error",
                Value::Null,
            ),
            (
                401,
                r#"{"error":{"code":"invalid_api_key","message":"OpenAI"}}"#,
                "OpenAI",
                "authentication_error",
                json!("invalid_api_key"),
            ),
            (
                403,
                r#"{"error":{"code":403,"message":"Google","status":"PERMISSION_DENIED"}}"#,
                "Google",
                "permission_error",
                json!("403"),
            ),
            (
                404,
                r#"{"error_code":"AI013","error_message":"Doorman"}"#,
                "Doorman",
                "not_found_error",
                json!("AI013"),
            ),
            (
                429,
                r#"{"message":"Bedrock"}"#,
                "Bedrock",
                "rate_limit_error",
                Value::Null,
            ),
            (502, r#"{"Message":"AWS"}"#, "AWS", "api_error", Value::Null),
            (
                503,
                r#"{"messages":[{"content":"request text"}]}"#,
                "Service Unavailable",
                "api_error",
                Value::Null,
            ),
        ];
        for (status, body, message, kind, code) in cases {
            assert_eq!(
                error_to_openai(StatusCode::from_u16(status).unwrap(), body.as_bytes()),
                json!({"error":{"message": message, "type": kind, "code": code, "param": null}}),
            );
        }
    }

    #[test]
    fn preserves_passthrough_paths_bodies_and_chunks() {
        let chat = json!({"model":"alias","messages":[{"role":"user","content":"hi"}],
            "logprobs": true, "stream": true});
        for (provider, path, upstream_model) in [
            (AiProvider::Openai, "v1/chat/completions", "deployment"),
            (
                AiProvider::OpenaiCompatible,
                "v1/chat/completions",
                "deployment",
            ),
            (
                AiProvider::AzureOpenai,
                "openai/deployments/deployment/chat/completions",
                "alias",
            ),
        ] {
            let native = translate::to_native(provider, "deployment", &chat).unwrap();
            assert_eq!(native.rest_path, path);
            let mut expected = chat.clone();
            expected["model"] = json!(upstream_model);
            assert_eq!(native.body, expected);
            assert!(native.stream && native.query.is_empty());
        }

        let native = json!({"id":"upstream","model":"native","choices":[]});
        let expected = json!({"id":"upstream","model":"alias","choices":[]});
        assert_eq!(from_native("alias", &native), expected);
        let mut stream = translate::stream_translator(Target::Passthrough, "alias", "id", 0, false);
        assert_eq!(
            stream.on_event(&SseEvent {
                event: None,
                data: native.to_string()
            }),
            vec![expected],
        );
        assert!(
            stream
                .on_event(&SseEvent {
                    event: None,
                    data: "[DONE]".into()
                })
                .is_empty()
        );
        assert!(stream.finish().is_empty());
    }
}
