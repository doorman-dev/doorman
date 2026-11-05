use super::common;
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, ProviderAdapter},
    sse::SseEvent,
    usage::{AiUsage, StreamUsageParser},
};
use http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};

pub struct AnthropicAdapter;
impl ProviderAdapter for AnthropicAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::Anthropic
    }
    fn classify(
        &self,
        method: &Method,
        path: &str,
        _query: &[(String, String)],
        body: &Value,
    ) -> Option<AiRequestInfo> {
        let operation = match (method, path) {
            (&Method::POST, "v1/messages") => "messages",
            (&Method::POST, "v1/messages/count_tokens") => "count_tokens",
            (&Method::GET, "v1/models") => "models",
            _ => return None,
        };
        Some(common::request_info(
            operation,
            common::body_model(body),
            body["stream"] == true,
        ))
    }
    fn set_model(&self, info: &AiRequestInfo, path: &str, body: &mut Value, model: &str) -> String {
        common::set_body_model(info, path, body, model)
    }
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut Value, cap: u64) {
        if info.generation {
            common::clamp(body, "max_tokens", cap);
        }
    }
    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut Value, user: &str) {
        if info.generation {
            if let Some(object) = body.as_object_mut() {
                let metadata = object.entry("metadata").or_insert(json!({}));
                if metadata.is_null() {
                    *metadata = json!({});
                }
                if let Some(metadata) = metadata.as_object_mut() {
                    metadata.entry("user_id").or_insert(json!(user));
                }
            }
        }
    }
    fn ensure_stream_usage(&self, _info: &AiRequestInfo, _body: &mut Value) {}
    fn upstream_query(
        &self,
        _info: &AiRequestInfo,
        query: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        common::strip_query(query)
    }
    fn apply_credential(&self, headers: &mut HeaderMap, key: &str, header_override: Option<&str>) {
        common::credential(headers, key, "x-api-key", header_override);
    }
    fn default_headers(&self, headers: &mut HeaderMap) {
        headers
            .entry("anthropic-version")
            .or_insert(http::HeaderValue::from_static("2023-06-01"));
    }
    fn local_response(
        &self,
        info: &AiRequestInfo,
        models: &[String],
    ) -> Option<(StatusCode, Value)> {
        (info.operation == "models").then(|| (StatusCode::OK, json!({"data":models.iter().map(|id| json!({"type":"model","id":id,"display_name":id})).collect::<Vec<_>>(),"has_more":false,"first_id":models.first(),"last_id":models.last()})))
    }
    fn extract_usage(&self, info: &AiRequestInfo, body: &Value) -> Option<AiUsage> {
        if !info.metered {
            return None;
        }
        let mut usage = AiUsage::default();
        if !body["usage"].is_object()
            || body["usage"]["input_tokens"].as_u64().is_none()
            || body["usage"]["output_tokens"].as_u64().is_none()
        {
            return None;
        }
        update_usage(&mut usage, &body["usage"]);
        usage.refusal = self.is_refusal(body);
        Some(usage)
    }
    fn stream_usage(&self, _info: &AiRequestInfo) -> Box<dyn StreamUsageParser> {
        Box::<AnthropicStream>::default()
    }
    fn prompt_text(&self, info: &AiRequestInfo, body: &Value) -> String {
        let mut text = String::new();
        if info.generation {
            common::content_text(&body["system"], &mut text);
            common::messages_text(body, &mut text);
        }
        text
    }
    fn response_text(&self, info: &AiRequestInfo, body: &Value) -> Option<String> {
        if !info.generation {
            return None;
        }
        let mut text = String::new();
        common::content_text(&body["content"], &mut text);
        (!text.is_empty()).then_some(text)
    }
    fn is_refusal(&self, body: &Value) -> bool {
        body["stop_reason"] == "refusal" || body["stop_details"]["type"] == "refusal"
    }
}

fn update_usage(usage: &mut AiUsage, value: &Value) {
    for (field, destination) in [
        ("input_tokens", &mut usage.input_tokens),
        ("output_tokens", &mut usage.output_tokens),
        ("cache_read_input_tokens", &mut usage.cache_read_tokens),
        ("cache_creation_input_tokens", &mut usage.cache_write_tokens),
    ] {
        if let Some(count) = value[field].as_u64() {
            *destination = count;
        }
    }
}

#[derive(Default)]
struct AnthropicStream {
    usage: Option<AiUsage>,
    text: String,
    refusal: bool,
}
impl StreamUsageParser for AnthropicStream {
    fn on_event(&mut self, event: &SseEvent) {
        let Ok(body) = serde_json::from_str::<Value>(&event.data) else {
            return;
        };
        match body["type"].as_str().or(event.event.as_deref()) {
            Some("message_start") => {
                if body["message"]["usage"]["input_tokens"].as_u64().is_some() {
                    let mut usage = AiUsage::default();
                    update_usage(&mut usage, &body["message"]["usage"]);
                    self.usage = Some(usage);
                }
            }
            Some("message_delta") => {
                if let Some(usage) = self.usage.as_mut() {
                    update_usage(usage, &body["usage"]);
                }
                self.refusal |= body["delta"]["stop_reason"] == "refusal"
                    || body["delta"]["stop_details"]["type"] == "refusal";
            }
            Some("content_block_start") if body["content_block"]["type"] == "text" => {
                if let Some(text) = body["content_block"]["text"].as_str() {
                    common::append_text(&mut self.text, text);
                }
            }
            Some("content_block_delta") if body["delta"]["type"] == "text_delta" => {
                if let Some(text) = body["delta"]["text"].as_str() {
                    common::append_text(&mut self.text, text);
                }
            }
            _ => {}
        }
    }
    fn completion_text(&self) -> Option<&str> {
        (!self.text.is_empty()).then_some(self.text.as_str())
    }
    fn finish(self: Box<Self>) -> Option<AiUsage> {
        self.usage.map(|mut usage| {
            usage.refusal |= self.refusal;
            usage
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anthropic_sets_default_version_and_metadata_user_id() {
        let info = common::request_info("messages", None, false);
        let mut headers = HeaderMap::new();
        headers.insert("anthropic-beta", "feature-placeholder".parse().unwrap());
        AnthropicAdapter.default_headers(&mut headers);
        assert_eq!(headers["anthropic-version"], "2023-06-01");
        headers.insert("anthropic-version", "client-version".parse().unwrap());
        AnthropicAdapter.default_headers(&mut headers);
        assert_eq!(headers["anthropic-version"], "client-version");
        assert_eq!(headers["anthropic-beta"], "feature-placeholder");
        let mut body = json!({"metadata":{"other":"keep"}});
        AnthropicAdapter.inject_user_id(&info, &mut body, "hash");
        AnthropicAdapter.inject_user_id(&info, &mut body, "new-hash");
        assert_eq!(body["metadata"], json!({"other":"keep","user_id":"hash"}));
        let mut body = json!({"metadata":null});
        AnthropicAdapter.inject_user_id(&info, &mut body, "hash");
        assert_eq!(body["metadata"], json!({"user_id":"hash"}));
        let mut body = json!({"metadata":{"user_id":null}});
        AnthropicAdapter.inject_user_id(&info, &mut body, "hash");
        assert!(body["metadata"]["user_id"].is_null());
    }
    #[test]
    fn anthropic_count_tokens_is_unmetered() {
        let info = AnthropicAdapter
            .classify(
                &Method::POST,
                "v1/messages/count_tokens",
                &[],
                &json!({"model":"claude-haiku-5-5"}),
            )
            .unwrap();
        assert!(!info.metered && !info.generation && !info.stream);
        assert_eq!(
            AnthropicAdapter.extract_usage(&info, &json!({"input_tokens":42})),
            None
        );
        assert!(
            AnthropicAdapter
                .classify(&Method::POST, "v1/messages/batches", &[], &json!({}))
                .is_none()
        );
    }
    #[test]
    fn anthropic_stream_usage_message_start_plus_delta() {
        let info = common::request_info("messages", None, true);
        let mut parser = AnthropicAdapter.stream_usage(&info);
        common::feed_stream(
            parser.as_mut(),
            include_str!("../../../tests/fixtures/ai/anthropic/messages_stream.sse"),
        );
        assert_eq!(parser.completion_text(), Some("Gateway ready."));
        let usage = parser.finish().unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.cache_write_tokens,
                usage.cache_read_tokens,
                usage.output_tokens
            ),
            (80, 20, 40, 24)
        );
        let body = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/anthropic/messages.json"
        ))
        .unwrap();
        assert_eq!(AnthropicAdapter.extract_usage(&info, &body), Some(usage));
    }
}
