use super::common;
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, ProviderAdapter},
    sse::SseEvent,
    usage::{AiUsage, StreamUsageParser},
};
use http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};

pub struct OpenaiAdapter;

impl ProviderAdapter for OpenaiAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::Openai
    }

    fn classify(
        &self,
        method: &Method,
        path: &str,
        _query: &[(String, String)],
        body: &Value,
    ) -> Option<AiRequestInfo> {
        let operation = match (method, path) {
            (&Method::POST, "v1/chat/completions") => "chat",
            (&Method::POST, "v1/responses") => "responses",
            (&Method::POST, "v1/embeddings") => "embed",
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
        if !info.generation {
            return;
        }
        if info.operation == "responses" {
            common::clamp(body, "max_output_tokens", cap);
        } else if body.get("max_completion_tokens").is_some() {
            common::clamp(body, "max_completion_tokens", cap);
        } else if body.get("max_tokens").is_some() {
            common::clamp(body, "max_tokens", cap);
        } else {
            common::clamp(body, "max_completion_tokens", cap);
        }
    }

    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut Value, user: &str) {
        if info.generation {
            if let Some(object) = body.as_object_mut() {
                object.entry("safety_identifier").or_insert(json!(user));
            }
        }
    }

    fn ensure_stream_usage(&self, info: &AiRequestInfo, body: &mut Value) {
        if info.operation == "chat" && info.stream {
            if let Some(object) = body.as_object_mut() {
                let options = object.entry("stream_options").or_insert(json!({}));
                if !options.is_object() {
                    *options = json!({});
                }
                options["include_usage"] = json!(true);
            }
        }
    }

    fn upstream_query(
        &self,
        _info: &AiRequestInfo,
        query: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        common::strip_query(query)
    }
    fn apply_credential(&self, headers: &mut HeaderMap, key: &str, header_override: Option<&str>) {
        common::credential(headers, key, "authorization", header_override);
    }
    fn default_headers(&self, _headers: &mut HeaderMap) {}

    fn local_response(
        &self,
        info: &AiRequestInfo,
        models: &[String],
    ) -> Option<(StatusCode, Value)> {
        (info.operation == "models").then(|| (StatusCode::OK, json!({"object":"list","data":models.iter().map(|id| json!({"id":id,"object":"model","owned_by":"doorman"})).collect::<Vec<_>>()})))
    }

    fn extract_usage(&self, info: &AiRequestInfo, body: &Value) -> Option<AiUsage> {
        extract_usage(info.operation, body)
    }
    fn stream_usage(&self, info: &AiRequestInfo) -> Box<dyn StreamUsageParser> {
        Box::new(OpenaiStream::new(info.operation))
    }

    fn prompt_text(&self, info: &AiRequestInfo, body: &Value) -> String {
        let mut text = String::new();
        if !info.generation {
            return text;
        }
        if info.operation == "responses" {
            common::content_text(&body["instructions"], &mut text);
            if let Some(input) = body["input"].as_str() {
                common::text_part(&mut text, input);
            } else if let Some(items) = body["input"].as_array() {
                for item in items {
                    if item
                        .get("type")
                        .and_then(Value::as_str)
                        .is_none_or(|kind| kind == "message")
                        && matches!(
                            item["role"].as_str(),
                            Some("user" | "assistant" | "system" | "developer")
                        )
                    {
                        common::content_text(&item["content"], &mut text);
                    }
                }
            }
        } else {
            common::messages_text(body, &mut text);
        }
        text
    }

    fn response_text(&self, info: &AiRequestInfo, body: &Value) -> Option<String> {
        if !info.generation {
            return None;
        }
        let mut text = String::new();
        if info.operation == "responses" {
            if let Some(items) = body["output"].as_array() {
                for item in items {
                    if item["type"] == "message" {
                        common::content_text(&item["content"], &mut text);
                    }
                }
            }
        } else if let Some(choices) = body["choices"].as_array() {
            for choice in choices {
                common::content_text(&choice["message"]["content"], &mut text);
            }
        }
        (!text.is_empty()).then_some(text)
    }

    fn is_refusal(&self, body: &Value) -> bool {
        is_refusal(body)
    }
}

pub(super) fn is_refusal(body: &Value) -> bool {
    let part_refusal = |parts: &Value| {
        parts
            .as_array()
            .is_some_and(|parts| parts.iter().any(|part| part["type"] == "refusal"))
    };
    body["choices"].as_array().is_some_and(|choices| {
        choices.iter().any(|choice| {
            choice["message"]["refusal"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
                || part_refusal(&choice["message"]["content"])
                || choice["finish_reason"] == "content_filter"
        })
    }) || body["output"]
        .as_array()
        .is_some_and(|output| output.iter().any(|item| part_refusal(&item["content"])))
}

pub(super) fn extract_usage(operation: &str, body: &Value) -> Option<AiUsage> {
    let usage = body.get("usage")?.as_object()?;
    let (input_field, output_field, detail_field) = if operation == "responses" {
        ("input_tokens", "output_tokens", "input_tokens_details")
    } else {
        (
            "prompt_tokens",
            "completion_tokens",
            "prompt_tokens_details",
        )
    };
    let input = usage.get(input_field)?.as_u64()?;
    let cached = usage
        .get(detail_field)
        .and_then(|v| v.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some(AiUsage {
        input_tokens: input.saturating_sub(cached),
        output_tokens: if operation == "embed" {
            0
        } else {
            usage.get(output_field)?.as_u64()?
        },
        cache_read_tokens: cached,
        reasoning_tokens: usage
            .get(if operation == "responses" {
                "output_tokens_details"
            } else {
                "completion_tokens_details"
            })
            .and_then(|v| v.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        refusal: is_refusal(body),
        ..AiUsage::default()
    })
}

pub(super) struct OpenaiStream {
    operation: &'static str,
    usage: Option<AiUsage>,
    text: String,
    refusal: bool,
}
impl OpenaiStream {
    pub(super) fn new(operation: &'static str) -> Self {
        Self {
            operation,
            usage: None,
            text: String::new(),
            refusal: false,
        }
    }
}
impl StreamUsageParser for OpenaiStream {
    fn on_event(&mut self, event: &SseEvent) {
        let Ok(body) = serde_json::from_str::<Value>(&event.data) else {
            return;
        };
        if self.operation == "responses" {
            match body["type"].as_str().or(event.event.as_deref()) {
                Some("response.completed") => {
                    if let Some(usage) = extract_usage("responses", &body["response"]) {
                        self.usage = Some(usage);
                    }
                }
                Some("response.output_text.delta") => {
                    if let Some(delta) = body["delta"].as_str() {
                        common::append_text(&mut self.text, delta);
                    }
                }
                Some("response.refusal.delta" | "response.refusal.done") => self.refusal = true,
                _ => {}
            }
        } else {
            if let Some(usage) = extract_usage("chat", &body) {
                self.usage = Some(usage);
            }
            if let Some(choices) = body["choices"].as_array() {
                for choice in choices {
                    if let Some(text) = choice["delta"]["content"].as_str() {
                        common::append_text(&mut self.text, text);
                    }
                    self.refusal |= choice["delta"]["refusal"]
                        .as_str()
                        .is_some_and(|v| !v.is_empty())
                        || choice["finish_reason"] == "content_filter";
                }
            }
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
    const CHAT: &str = include_str!("../../../tests/fixtures/ai/openai/chat.json");
    fn info(operation: &'static str) -> AiRequestInfo {
        common::request_info(operation, None, true)
    }

    #[test]
    fn openai_classifies_chat_responses_embeddings_and_rejects_files() {
        for (path, operation) in [
            ("v1/chat/completions", "chat"),
            ("v1/responses", "responses"),
            ("v1/embeddings", "embed"),
        ] {
            let info = OpenaiAdapter
                .classify(
                    &Method::POST,
                    path,
                    &[],
                    &json!({"model":"gpt-example","stream":true}),
                )
                .unwrap();
            assert_eq!(info.operation, operation);
            assert_eq!(info.generation, operation != "embed");
            assert_eq!(info.stream, operation != "embed");
        }
        assert!(
            OpenaiAdapter
                .classify(&Method::POST, "v1/files", &[], &json!({}))
                .is_none()
        );
        let info = OpenaiAdapter
            .classify(&Method::GET, "v1/models", &[], &Value::Null)
            .unwrap();
        assert!(info.local && !info.metered);
        assert_eq!(
            OpenaiAdapter
                .local_response(&info, &["allowed".into()])
                .unwrap()
                .1["data"][0]["id"],
            "allowed"
        );
    }
    #[test]
    fn openai_injects_include_usage_preserving_stream_options() {
        let mut body = json!({"stream_options":{"include_usage":false,"include_obfuscation":false},"user":"client","max_tokens":500});
        OpenaiAdapter.ensure_stream_usage(&info("chat"), &mut body);
        OpenaiAdapter.clamp_max_output(&info("chat"), &mut body, 100);
        OpenaiAdapter.inject_user_id(&info("chat"), &mut body, "hash");
        assert_eq!(
            body["stream_options"],
            json!({"include_usage":true,"include_obfuscation":false})
        );
        assert_eq!(body["max_tokens"], 100);
        assert!(body.get("max_completion_tokens").is_none());
        assert_eq!(body["user"], "client");
        OpenaiAdapter.inject_user_id(&info("chat"), &mut body, "other");
        assert_eq!(body["safety_identifier"], "hash");
        let mut responses = json!({"max_output_tokens":50});
        OpenaiAdapter.clamp_max_output(&info("responses"), &mut responses, 100);
        assert_eq!(responses["max_output_tokens"], 50);
    }
    #[test]
    fn openai_extracts_usage_chat_and_responses_shapes() {
        let chat: Value = serde_json::from_str(CHAT).unwrap();
        let usage = OpenaiAdapter.extract_usage(&info("chat"), &chat).unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.cache_read_tokens,
                usage.output_tokens,
                usage.reasoning_tokens
            ),
            (60, 40, 24, 8)
        );
        let response = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/openai/responses.json"
        ))
        .unwrap();
        let usage = OpenaiAdapter
            .extract_usage(&info("responses"), &response)
            .unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.cache_read_tokens,
                usage.output_tokens
            ),
            (72, 48, 30)
        );
        let embed = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/openai/embeddings.json"
        ))
        .unwrap();
        assert_eq!(
            OpenaiAdapter
                .extract_usage(&info("embed"), &embed)
                .unwrap()
                .input_tokens,
            12
        );
        assert_eq!(
            OpenaiAdapter.response_text(&info("chat"), &chat).unwrap(),
            "Gateway ready."
        );
    }
    #[test]
    fn openai_chat_stream_usage_from_final_chunk() {
        let mut parser = OpenaiAdapter.stream_usage(&info("chat"));
        common::feed_stream(
            parser.as_mut(),
            include_str!("../../../tests/fixtures/ai/openai/chat_stream.sse"),
        );
        assert_eq!(parser.completion_text(), Some("Gateway ready."));
        assert_eq!(parser.finish().unwrap().input_tokens, 60);
    }
    #[test]
    fn openai_responses_stream_usage_from_completed_event() {
        let mut parser = OpenaiAdapter.stream_usage(&info("responses"));
        common::feed_stream(
            parser.as_mut(),
            include_str!("../../../tests/fixtures/ai/openai/responses_stream.sse"),
        );
        assert_eq!(parser.completion_text(), Some("Gateway ready."));
        assert_eq!(parser.finish().unwrap().output_tokens, 30);
    }
    #[test]
    fn missing_stream_usage_returns_none() {
        let mut parser = OpenaiAdapter.stream_usage(&info("chat"));
        common::feed_stream(
            parser.as_mut(),
            include_str!("../../../tests/fixtures/ai/openai/chat_stream_no_usage.sse"),
        );
        assert_eq!(parser.completion_text(), Some("Gateway ready."));
        assert_eq!(parser.finish(), None);
    }
    #[test]
    fn refusal_detected_but_body_untouched() {
        for (adapter, source) in [
            (
                &OpenaiAdapter as &dyn ProviderAdapter,
                include_str!("../../../tests/fixtures/ai/openai/refusal.json"),
            ),
            (
                &super::super::anthropic::AnthropicAdapter as &dyn ProviderAdapter,
                include_str!("../../../tests/fixtures/ai/anthropic/refusal.json"),
            ),
        ] {
            let body: Value = serde_json::from_str(source).unwrap();
            let original = body.clone();
            assert!(adapter.is_refusal(&body));
            assert_eq!(body, original);
        }
    }
    #[test]
    fn user_id_injected_only_on_generation_operations() {
        for (adapter, path) in [
            (&OpenaiAdapter as &dyn ProviderAdapter, "v1/embeddings"),
            (
                &super::super::anthropic::AnthropicAdapter as &dyn ProviderAdapter,
                "v1/messages/count_tokens",
            ),
        ] {
            let mut body = json!({"model":"example","input":"hello"});
            let original = body.clone();
            let info = adapter.classify(&Method::POST, path, &[], &body).unwrap();
            adapter.inject_user_id(&info, &mut body, "hash");
            adapter.clamp_max_output(&info, &mut body, 10);
            assert_eq!(body, original);
        }
    }
    #[test]
    fn apply_credential_strips_all_inbound_credentials() {
        for provider in [AiProvider::Openai, AiProvider::Anthropic] {
            let adapter = super::super::adapter_for(provider);
            let mut headers = HeaderMap::new();
            for name in crate::ai::adapter::INBOUND_CREDENTIAL_HEADERS {
                headers.insert(*name, "inbound-placeholder".parse().unwrap());
            }
            adapter.apply_credential(&mut headers, "fixture-placeholder", None);
            let expected = crate::ai::adapter::preset(provider).credential_header;
            for name in crate::ai::adapter::INBOUND_CREDENTIAL_HEADERS {
                assert_eq!(headers.contains_key(*name), *name == expected);
            }
            let info = info("chat");
            assert_eq!(
                adapter.upstream_query(
                    &info,
                    vec![
                        ("key".into(), "inbound".into()),
                        ("api-key".into(), "inbound".into()),
                        ("alt".into(), "sse".into())
                    ]
                ),
                vec![("alt".into(), "sse".into())]
            );
        }
    }
    #[test]
    fn prompt_text_skips_tools_images_and_respects_utf8_cap() {
        let body = json!({"messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image_url","image_url":{"url":"secret-image"}}]},{"role":"tool","content":"secret-tool"}]});
        assert_eq!(OpenaiAdapter.prompt_text(&info("chat"), &body), "hello");
        let body = json!({"messages":[{"role":"user","content":"é".repeat(common::TEXT_CAP)}]});
        assert_eq!(
            OpenaiAdapter.prompt_text(&info("chat"), &body).len(),
            common::TEXT_CAP
        );
    }
}
