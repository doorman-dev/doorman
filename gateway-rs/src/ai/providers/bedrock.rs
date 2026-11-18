use super::{anthropic::AnthropicAdapter, common};
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, Dialect, ProviderAdapter, StreamFraming},
    sse::SseEvent,
    usage::{AiUsage, StreamUsageParser},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, Method};
use serde_json::{Value, json};

pub struct BedrockAdapter;

fn base_model(model: &str) -> &str {
    let model = if model.starts_with("arn:") {
        model.rsplit_once('/').map_or(model, |(_, id)| id)
    } else {
        model
    };
    match model.split_once('.') {
        Some(("us" | "eu" | "apac" | "global", base)) => base,
        _ => model,
    }
}

fn converse_usage(body: &Value) -> Option<AiUsage> {
    let usage = &body["usage"];
    Some(AiUsage {
        input_tokens: usage["inputTokens"].as_u64()?,
        output_tokens: usage["outputTokens"].as_u64()?,
        cache_read_tokens: usage["cacheReadInputTokens"].as_u64().unwrap_or_default(),
        cache_write_tokens: usage["cacheWriteInputTokens"].as_u64().unwrap_or_default(),
        refusal: converse_refusal(body),
        ..AiUsage::default()
    })
}

fn converse_refusal(body: &Value) -> bool {
    matches!(
        body["stopReason"].as_str(),
        Some("guardrail_intervened" | "content_filtered")
    )
}

fn converse_text(content: &Value, text: &mut String) {
    if let Some(parts) = content.as_array() {
        for part in parts {
            if let Some(value) = part["text"].as_str() {
                common::text_part(text, value);
            }
        }
    }
}

impl ProviderAdapter for BedrockAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::Bedrock
    }
    fn classify(
        &self,
        method: &Method,
        rest_path: &str,
        _query: &[(String, String)],
        _body: &Value,
    ) -> Option<AiRequestInfo> {
        if *method != Method::POST {
            return None;
        }
        let (segment, action) = rest_path.strip_prefix("model/")?.split_once('/')?;
        let model = common::decode_segment(segment)?;
        if matches!(model.as_str(), "" | "." | "..") {
            return None;
        }
        let (op, stream) = match action {
            "converse" => ("converse", false),
            "converse-stream" => ("converse", true),
            "count-tokens" => ("count_tokens", false),
            "invoke" | "invoke-with-response-stream"
                if base_model(&model).starts_with("anthropic.") =>
            {
                ("invoke", action == "invoke-with-response-stream")
            }
            _ => return None,
        };
        Some(common::request_info(op, Some(model), stream))
    }
    fn set_model(
        &self,
        info: &AiRequestInfo,
        rest_path: &str,
        body: &mut Value,
        model: &str,
    ) -> String {
        if info.dialect == Dialect::Anthropic {
            if let Some(object) = body.as_object_mut() {
                object
                    .entry("anthropic_version")
                    .or_insert(json!("bedrock-2023-05-31"));
                object.remove("model");
            }
        }
        if info.model.as_deref() == Some(model) {
            return rest_path.to_owned();
        }
        let Some((_, action)) = rest_path.rsplit_once('/') else {
            return rest_path.to_owned();
        };
        format!("model/{}/{action}", common::encode_segment(model))
    }
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut Value, cap: u64) {
        match info.dialect {
            Dialect::Anthropic => AnthropicAdapter.clamp_max_output(info, body, cap),
            Dialect::BedrockConverse => {
                if let Some(object) = body.as_object_mut() {
                    let config = object.entry("inferenceConfig").or_insert(json!({}));
                    if !config.is_object() {
                        *config = json!({});
                    }
                    common::clamp(config, "maxTokens", cap);
                }
            }
            _ => {}
        }
    }
    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut Value, user: &str) {
        match info.dialect {
            Dialect::Anthropic => AnthropicAdapter.inject_user_id(info, body, user),
            Dialect::BedrockConverse => {
                if let Some(object) = body.as_object_mut() {
                    let metadata = object.entry("requestMetadata").or_insert(json!({}));
                    if metadata.is_null() {
                        *metadata = json!({});
                    }
                    if let Some(metadata) = metadata.as_object_mut() {
                        metadata.entry("doorman_user").or_insert(json!(user));
                    }
                }
            }
            _ => {}
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
    fn apply_credential(&self, headers: &mut HeaderMap, key: &str, _header_override: Option<&str>) {
        common::credential(headers, key, "authorization", None);
    }
    fn default_headers(&self, _headers: &mut HeaderMap) {}
    fn local_response(
        &self,
        _info: &AiRequestInfo,
        _allowed_models: &[String],
    ) -> Option<(http::StatusCode, Value)> {
        None
    }
    fn extract_usage(&self, info: &AiRequestInfo, body: &Value) -> Option<AiUsage> {
        match info.dialect {
            Dialect::BedrockConverse => converse_usage(body),
            Dialect::Anthropic => AnthropicAdapter.extract_usage(info, body),
            _ => None,
        }
    }
    fn stream_usage(&self, info: &AiRequestInfo) -> Box<dyn StreamUsageParser> {
        if info.dialect == Dialect::Anthropic {
            Box::new(InvokeStream {
                parser: AnthropicAdapter.stream_usage(info),
                metrics: None,
            })
        } else {
            Box::<ConverseStream>::default()
        }
    }
    fn prompt_text(&self, info: &AiRequestInfo, body: &Value) -> String {
        if info.dialect == Dialect::Anthropic {
            return AnthropicAdapter.prompt_text(info, body);
        }
        let mut text = String::new();
        if info.dialect == Dialect::BedrockConverse {
            converse_text(&body["system"], &mut text);
            if let Some(messages) = body["messages"].as_array() {
                for message in messages {
                    converse_text(&message["content"], &mut text);
                }
            }
        }
        text
    }
    fn response_text(&self, info: &AiRequestInfo, body: &Value) -> Option<String> {
        match info.dialect {
            Dialect::Anthropic => AnthropicAdapter.response_text(info, body),
            Dialect::BedrockConverse => {
                let mut text = String::new();
                converse_text(&body["output"]["message"]["content"], &mut text);
                (!text.is_empty()).then_some(text)
            }
            _ => None,
        }
    }
    fn is_refusal(&self, body: &Value) -> bool {
        converse_refusal(body) || AnthropicAdapter.is_refusal(body)
    }
    fn stream_framing(&self, info: &AiRequestInfo) -> StreamFraming {
        if info.stream {
            StreamFraming::AwsEventStream
        } else {
            StreamFraming::Sse
        }
    }
    fn pricing_model(&self, model: &str) -> String {
        let model = base_model(model);
        if let Some((base, version)) = model.rsplit_once("-v")
            && let Some((major, minor)) = version.split_once(':')
            && !major.is_empty()
            && major.bytes().all(|byte| byte.is_ascii_digit())
            && !minor.is_empty()
            && minor.bytes().all(|byte| byte.is_ascii_digit())
            && !base.rsplit('-').next().is_some_and(|segment| {
                segment.len() == 8 && segment.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return base.to_owned();
        }
        model.to_owned()
    }
}

#[derive(Default)]
struct ConverseStream {
    usage: Option<AiUsage>,
    text: String,
    refusal: bool,
}

impl StreamUsageParser for ConverseStream {
    fn on_event(&mut self, event: &SseEvent) {
        let Ok(body) = serde_json::from_str::<Value>(&event.data) else {
            return;
        };
        match event.event.as_deref() {
            Some("metadata") => {
                if let Some(usage) = converse_usage(&body) {
                    self.usage = Some(usage);
                }
            }
            Some("messageStop") => self.refusal |= converse_refusal(&body),
            Some("contentBlockDelta") => {
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

struct InvokeStream {
    parser: Box<dyn StreamUsageParser>,
    metrics: Option<AiUsage>,
}

impl StreamUsageParser for InvokeStream {
    fn on_event(&mut self, event: &SseEvent) {
        if event.event.as_deref() != Some("chunk") {
            return;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(&event.data) else {
            return;
        };
        let Some(encoded) = chunk["bytes"].as_str() else {
            return;
        };
        let Ok(bytes) = STANDARD.decode(encoded) else {
            return;
        };
        let Ok(data) = String::from_utf8(bytes) else {
            return;
        };
        if let Ok(body) = serde_json::from_str::<Value>(&data) {
            let metrics = &body["amazon-bedrock-invocationMetrics"];
            if let (Some(input_tokens), Some(output_tokens)) = (
                metrics["inputTokenCount"].as_u64(),
                metrics["outputTokenCount"].as_u64(),
            ) {
                self.metrics = Some(AiUsage {
                    input_tokens,
                    output_tokens,
                    ..AiUsage::default()
                });
            }
        }
        self.parser.on_event(&SseEvent { event: None, data });
    }
    fn completion_text(&self) -> Option<&str> {
        self.parser.completion_text()
    }
    fn finish(self: Box<Self>) -> Option<AiUsage> {
        self.parser.finish().or(self.metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::eventstream::Decoder;

    #[test]
    fn classifies_five_paths() {
        for (action, op, dialect, stream) in [
            ("converse", "converse", Dialect::BedrockConverse, false),
            (
                "converse-stream",
                "converse",
                Dialect::BedrockConverse,
                true,
            ),
            ("invoke", "invoke", Dialect::Anthropic, false),
            (
                "invoke-with-response-stream",
                "invoke",
                Dialect::Anthropic,
                true,
            ),
            ("count-tokens", "count_tokens", Dialect::Opaque, false),
        ] {
            let path = format!("model/us.anthropic.claude-v1:0/{action}");
            let info = BedrockAdapter
                .classify(&Method::POST, &path, &[], &Value::Null)
                .unwrap();
            assert_eq!(
                (info.operation, info.dialect, info.stream),
                (op, dialect, stream)
            );
            assert_eq!(info.generation, op != "count_tokens");
            assert_eq!(info.metered, info.generation);
            assert!(
                matches!(
                    BedrockAdapter.stream_framing(&info),
                    StreamFraming::AwsEventStream
                ) == stream
            );
        }
        for path in [
            "model/us.amazon.nova/invoke",
            "model/meta.llama/invoke-with-response-stream",
            "model/m/models",
        ] {
            assert!(
                BedrockAdapter
                    .classify(&Method::POST, path, &[], &Value::Null)
                    .is_none()
            );
        }
    }

    #[test]
    fn encodes_arns_and_normalizes_pricing_models() {
        let arn =
            "arn:aws:bedrock:us-east-1:111122223333:inference-profile/eu.anthropic.claude-v1:0";
        let info = common::request_info("invoke", Some("old".into()), true);
        let mut body = json!({"model":"ignored"});
        let path = BedrockAdapter.set_model(&info, "model/old/invoke", &mut body, arn);
        assert_eq!(
            path,
            "model/arn%3Aaws%3Abedrock%3Aus-east-1%3A111122223333%3Ainference-profile%2Feu.anthropic.claude-v1%3A0/invoke"
        );
        assert_eq!(
            BedrockAdapter
                .classify(&Method::POST, &path, &[], &body)
                .unwrap()
                .model
                .as_deref(),
            Some(arn)
        );
        assert_eq!(body, json!({"anthropic_version":"bedrock-2023-05-31"}));
        for model in [
            arn,
            "us.anthropic.claude-v1:0",
            "global.anthropic.claude-v1:0",
            "apac.anthropic.claude-v1:0",
            "anthropic.claude-v1:0",
        ] {
            assert_eq!(BedrockAdapter.pricing_model(model), "anthropic.claude");
        }
    }

    #[test]
    fn prices_undated_versioned_models_without_the_suffix() {
        assert_eq!(
            BedrockAdapter.pricing_model("us.anthropic.claude-sonnet-5-5-v1:0"),
            "anthropic.claude-sonnet-5-5"
        );
        assert_eq!(
            BedrockAdapter.pricing_model("eu.anthropic.claude-sonnet-4-5-20250929-v1:0"),
            "anthropic.claude-sonnet-4-5-20250929-v1:0"
        );
    }

    #[test]
    fn extracts_usage_and_text_from_both_response_formats() {
        let info = common::request_info("converse", None, false);
        let mut request = json!({"system":[{"text":"System"}],"messages":[{"content":[{"text":"User"}]}],
            "requestMetadata":{"doorman_user":"client"}});
        BedrockAdapter.inject_user_id(&info, &mut request, "hashed");
        BedrockAdapter.clamp_max_output(&info, &mut request, 20);
        assert_eq!(request["requestMetadata"]["doorman_user"], "client");
        assert_eq!(request["inferenceConfig"]["maxTokens"], 20);
        assert_eq!(BedrockAdapter.prompt_text(&info, &request), "System\nUser");

        let body = json!({"usage":{"inputTokens":8,"outputTokens":3,"cacheReadInputTokens":2,"cacheWriteInputTokens":1},
            "output":{"message":{"content":[{"text":"Hi"}]}},"stopReason":"content_filtered"});
        let usage = BedrockAdapter.extract_usage(&info, &body).unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_tokens,
                usage.cache_write_tokens
            ),
            (8, 3, 2, 1)
        );
        assert!(usage.refusal);
        assert_eq!(
            BedrockAdapter.response_text(&info, &body).as_deref(),
            Some("Hi")
        );

        let info = common::request_info("invoke", None, false);
        let body = json!({"usage":{"input_tokens":8,"output_tokens":3,"cache_read_input_tokens":2,"cache_creation_input_tokens":1},
            "content":[{"type":"text","text":"Hi"}]});
        let usage = BedrockAdapter.extract_usage(&info, &body).unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.output_tokens,
                usage.cache_read_tokens,
                usage.cache_write_tokens
            ),
            (8, 3, 2, 1)
        );
        assert_eq!(
            BedrockAdapter.response_text(&info, &body).as_deref(),
            Some("Hi")
        );
    }

    #[test]
    fn reads_both_stream_transcripts_and_metrics_fallback() {
        let converse = include_bytes!("../../../tests/fixtures/ai/bedrock/converse-stream.bin");
        let invoke =
            include_bytes!("../../../tests/fixtures/ai/bedrock/invoke-with-response-stream.bin");
        for (op, transcript) in [
            ("converse", converse.as_slice()),
            ("invoke", invoke.as_slice()),
        ] {
            let info = common::request_info(op, None, true);
            let mut parser = BedrockAdapter.stream_usage(&info);
            let frames = Decoder::new(2048).push(transcript);
            for frame in &frames {
                parser.on_event(&frame.as_ref().unwrap().to_sse_event());
            }
            assert_eq!(parser.completion_text(), Some("Hi"));
            let usage = parser.finish().unwrap();
            assert_eq!((usage.input_tokens, usage.output_tokens), (8, 3));
            if op == "converse" {
                assert_eq!((usage.cache_read_tokens, usage.cache_write_tokens), (2, 1));
            } else {
                let mut fallback = BedrockAdapter.stream_usage(&info);
                fallback.on_event(&frames.last().unwrap().as_ref().unwrap().to_sse_event());
                assert_eq!(fallback.finish().unwrap().output_tokens, 3);
            }
        }
    }
}
