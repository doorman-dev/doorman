use super::common;
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, ProviderAdapter},
    sse::SseEvent,
    usage::{AiUsage, StreamUsageParser},
};
use http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};

pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::Gemini
    }
    fn classify(
        &self,
        method: &Method,
        path: &str,
        query: &[(String, String)],
        _body: &Value,
    ) -> Option<AiRequestInfo> {
        if method == Method::GET && path == "v1beta/models" {
            return Some(common::request_info("models", None, false));
        }
        if method != Method::POST {
            return None;
        }
        let segments: Vec<_> = path.split('/').collect();
        let [version, "models", model_method] = segments.as_slice() else {
            return None;
        };
        if !matches!(*version, "v1" | "v1beta") {
            return None;
        }
        let (model, method) = model_method.split_once(':')?;
        if model.is_empty() {
            return None;
        }
        let operation = match method {
            "generateContent" | "streamGenerateContent" => "generate",
            "countTokens" => "count_tokens",
            "embedContent" | "batchEmbedContents" => "embed",
            _ => return None,
        };
        Some(common::request_info(
            operation,
            Some(model.to_owned()),
            method == "streamGenerateContent"
                && query
                    .iter()
                    .any(|(name, value)| name == "alt" && value == "sse"),
        ))
    }
    fn set_model(
        &self,
        info: &AiRequestInfo,
        path: &str,
        _body: &mut Value,
        model: &str,
    ) -> String {
        if info.local {
            return path.to_owned();
        }
        let Some((prefix, model_method)) = path.rsplit_once('/') else {
            return path.to_owned();
        };
        let Some((_, method)) = model_method.split_once(':') else {
            return path.to_owned();
        };
        format!("{prefix}/{model}:{method}")
    }
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut Value, cap: u64) {
        if info.generation {
            if let Some(object) = body.as_object_mut() {
                let config = object.entry("generationConfig").or_insert(json!({}));
                if !config.is_object() {
                    *config = json!({});
                }
                common::clamp(config, "maxOutputTokens", cap);
            }
        }
    }
    fn inject_user_id(&self, _info: &AiRequestInfo, _body: &mut Value, _user: &str) {}
    fn ensure_stream_usage(&self, _info: &AiRequestInfo, _body: &mut Value) {}
    fn upstream_query(
        &self,
        _info: &AiRequestInfo,
        query: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        common::strip_query(query)
    }
    fn apply_credential(&self, headers: &mut HeaderMap, key: &str, header_override: Option<&str>) {
        common::credential(headers, key, "x-goog-api-key", header_override);
    }
    fn default_headers(&self, _headers: &mut HeaderMap) {}
    fn local_response(
        &self,
        info: &AiRequestInfo,
        models: &[String],
    ) -> Option<(StatusCode, Value)> {
        (info.operation == "models").then(|| (StatusCode::OK, json!({"models": models.iter().map(|model| json!({"name":format!("models/{model}"),"displayName":model,"supportedGenerationMethods":["generateContent","streamGenerateContent","countTokens","embedContent","batchEmbedContents"]})).collect::<Vec<_>>()})))
    }
    fn extract_usage(&self, info: &AiRequestInfo, body: &Value) -> Option<AiUsage> {
        if !info.metered {
            return None;
        }
        extract_usage(body)
    }
    fn stream_usage(&self, _info: &AiRequestInfo) -> Box<dyn StreamUsageParser> {
        Box::<GeminiStream>::default()
    }
    fn prompt_text(&self, info: &AiRequestInfo, body: &Value) -> String {
        let mut text = String::new();
        if info.generation {
            parts_text(&body["systemInstruction"], &mut text);
            if let Some(contents) = body["contents"].as_array() {
                for content in contents {
                    parts_text(content, &mut text);
                }
            }
        }
        text
    }
    fn response_text(&self, info: &AiRequestInfo, body: &Value) -> Option<String> {
        if !info.generation {
            return None;
        }
        let mut text = String::new();
        if let Some(chunks) = body.as_array() {
            for chunk in chunks {
                response_text(chunk, &mut text);
            }
        } else {
            response_text(body, &mut text);
        }
        (!text.is_empty()).then_some(text)
    }
    fn is_refusal(&self, body: &Value) -> bool {
        if let Some(chunks) = body.as_array() {
            chunks.iter().any(refusal)
        } else {
            refusal(body)
        }
    }
}

fn parts_text(content: &Value, target: &mut String) {
    if let Some(parts) = content["parts"].as_array() {
        for part in parts {
            if part["thought"] != true {
                if let Some(text) = part["text"].as_str() {
                    common::append_text(target, text);
                }
            }
        }
    }
}
fn response_text(body: &Value, target: &mut String) {
    if let Some(candidates) = body["candidates"].as_array() {
        for candidate in candidates {
            parts_text(&candidate["content"], target);
        }
    }
}
fn refusal(body: &Value) -> bool {
    body["promptFeedback"]["blockReason"]
        .as_str()
        .is_some_and(|reason| reason != "BLOCK_REASON_UNSPECIFIED" && !reason.is_empty())
        || body["candidates"].as_array().is_some_and(|candidates| {
            candidates
                .iter()
                .any(|candidate| candidate["finishReason"] == "SAFETY")
        })
}
fn extract_usage(body: &Value) -> Option<AiUsage> {
    let body = if let Some(chunks) = body.as_array() {
        chunks.last()?
    } else {
        body
    };
    let usage = body.get("usageMetadata")?.as_object()?;
    let input = usage.get("promptTokenCount")?.as_u64()?;
    let cached = usage
        .get("cachedContentTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let thoughts = usage
        .get("thoughtsTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some(AiUsage {
        input_tokens: input.saturating_sub(cached),
        output_tokens: usage
            .get("candidatesTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(thoughts),
        cache_read_tokens: cached,
        reasoning_tokens: thoughts,
        refusal: refusal(body),
        ..AiUsage::default()
    })
}
#[derive(Default)]
struct GeminiStream {
    usage: Option<AiUsage>,
    text: String,
    refusal: bool,
}
impl StreamUsageParser for GeminiStream {
    fn on_event(&mut self, event: &SseEvent) {
        let Ok(body) = serde_json::from_str::<Value>(&event.data) else {
            return;
        };
        if let Some(usage) = extract_usage(&body) {
            self.usage = Some(usage);
        }
        self.refusal |= refusal(&body);
        response_text(&body, &mut self.text);
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
    fn info() -> AiRequestInfo {
        common::request_info("generate", Some("gemini-example-flash".into()), true)
    }
    #[test]
    fn gemini_rewrites_model_path_segment() {
        let path = "v1beta/models/gemini-example-flash:streamGenerateContent";
        let mut body = json!({"generationConfig":{"temperature":0.2,"maxOutputTokens":200}});
        let info = GeminiAdapter
            .classify(&Method::POST, path, &[("alt".into(), "sse".into())], &body)
            .unwrap();
        assert!(info.stream && info.generation);
        assert_eq!(
            GeminiAdapter.set_model(&info, path, &mut body, "other-model"),
            "v1beta/models/other-model:streamGenerateContent"
        );
        GeminiAdapter.clamp_max_output(&info, &mut body, 100);
        assert_eq!(
            body["generationConfig"],
            json!({"temperature":0.2,"maxOutputTokens":100})
        );
        assert!(
            GeminiAdapter
                .classify(
                    &Method::POST,
                    "v1beta/files/model:generateContent",
                    &[],
                    &body
                )
                .is_none()
        );
        assert!(
            GeminiAdapter
                .classify(&Method::POST, "v1beta/models/model:delete", &[], &body)
                .is_none()
        );
    }
    #[test]
    fn gemini_non_sse_stream_array_usage_from_last_element() {
        let body = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/gemini/generate_stream_array.json"
        ))
        .unwrap();
        let info = GeminiAdapter
            .classify(
                &Method::POST,
                "v1/models/gemini-example-flash:streamGenerateContent",
                &[],
                &json!({}),
            )
            .unwrap();
        assert!(!info.stream);
        let usage = GeminiAdapter.extract_usage(&info, &body).unwrap();
        assert_eq!((usage.input_tokens, usage.output_tokens), (60, 32));
        assert_eq!(
            GeminiAdapter.response_text(&info, &body).unwrap(),
            "Gateway ready."
        );
        assert_eq!(
            GeminiAdapter.upstream_query(
                &info,
                vec![
                    ("key".into(), "placeholder".into()),
                    ("alt".into(), "json".into())
                ]
            ),
            vec![("alt".into(), "json".into())]
        );
    }
    #[test]
    fn gemini_extracts_usage_metadata() {
        let body = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/gemini/generate.json"
        ))
        .unwrap();
        let usage = GeminiAdapter.extract_usage(&info(), &body).unwrap();
        assert_eq!(
            (
                usage.input_tokens,
                usage.cache_read_tokens,
                usage.output_tokens,
                usage.reasoning_tokens
            ),
            (60, 40, 32, 8)
        );
        let blocked = serde_json::from_str(include_str!(
            "../../../tests/fixtures/ai/gemini/safety_block.json"
        ))
        .unwrap();
        assert!(GeminiAdapter.is_refusal(&blocked));
    }
    #[test]
    fn gemini_stream_usage_last_chunk_wins() {
        let mut parser = GeminiAdapter.stream_usage(&info());
        common::feed_stream(
            parser.as_mut(),
            include_str!("../../../tests/fixtures/ai/gemini/generate_stream.sse"),
        );
        assert_eq!(parser.completion_text(), Some("Gateway ready."));
        assert_eq!(parser.finish().unwrap().output_tokens, 32);
    }
    #[test]
    fn usage_normalises_cached_input_per_provider() {
        for (provider, source, operation, expected) in [
            (
                AiProvider::Openai,
                include_str!("../../../tests/fixtures/ai/openai/chat.json"),
                "chat",
                (60, 40, 0, 24),
            ),
            (
                AiProvider::Anthropic,
                include_str!("../../../tests/fixtures/ai/anthropic/messages.json"),
                "messages",
                (80, 40, 20, 24),
            ),
            (
                AiProvider::Gemini,
                include_str!("../../../tests/fixtures/ai/gemini/generate.json"),
                "generate",
                (60, 40, 0, 32),
            ),
            (
                AiProvider::AzureOpenai,
                include_str!("../../../tests/fixtures/ai/azure_openai/chat.json"),
                "chat",
                (60, 40, 0, 24),
            ),
        ] {
            let adapter = super::super::adapter_for(provider);
            let body = serde_json::from_str(source).unwrap();
            let usage = adapter
                .extract_usage(&common::request_info(operation, None, false), &body)
                .unwrap();
            assert_eq!(
                (
                    usage.input_tokens,
                    usage.cache_read_tokens,
                    usage.cache_write_tokens,
                    usage.output_tokens
                ),
                expected
            );
        }
    }
}
