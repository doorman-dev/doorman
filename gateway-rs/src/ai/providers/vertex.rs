use super::{anthropic::AnthropicAdapter, common, gemini::GeminiAdapter};
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, Dialect, ProviderAdapter, UpstreamCtx},
    usage::{AiUsage, StreamUsageParser},
};
use http::{HeaderMap, Method};
use serde_json::{Value, json};

pub struct VertexAdapter;

struct VertexPath<'a> {
    version: &'a str,
    project: &'a str,
    location: &'a str,
    publisher: &'a str,
    model: &'a str,
    method: &'a str,
}

impl<'a> VertexPath<'a> {
    fn parse(path: &'a str) -> Option<Self> {
        let segments: Vec<_> = path.split('/').collect();
        let [
            version @ ("v1" | "v1beta1"),
            "projects",
            project,
            "locations",
            location,
            "publishers",
            publisher,
            "models",
            tail,
        ] = segments.as_slice()
        else {
            return None;
        };
        let (model, method) = tail.rsplit_once(':')?;
        if project.is_empty() || location.is_empty() || model.is_empty() {
            return None;
        }
        Some(Self {
            version,
            project,
            location,
            publisher,
            model,
            method,
        })
    }

    fn format(&self, project: &str, location: &str, model: &str) -> String {
        format!(
            "{}/projects/{project}/locations/{location}/publishers/{}/models/{model}:{}",
            self.version, self.publisher, self.method
        )
    }
}

fn delegate(info: &AiRequestInfo) -> &'static dyn ProviderAdapter {
    match info.dialect {
        Dialect::Anthropic => &AnthropicAdapter,
        _ => &GeminiAdapter,
    }
}

impl ProviderAdapter for VertexAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::Vertex
    }
    fn classify(
        &self,
        method: &Method,
        rest_path: &str,
        _query: &[(String, String)],
        body: &Value,
    ) -> Option<AiRequestInfo> {
        if *method != Method::POST {
            return None;
        }
        let path = VertexPath::parse(rest_path)?;
        let (op, stream) = match (path.publisher, path.model, path.method) {
            ("google", _, "generateContent") => ("generate", false),
            ("google", _, "streamGenerateContent") => ("generate", true),
            ("google", _, "countTokens") => ("count_tokens", false),
            ("anthropic", "count-tokens", "rawPredict") => {
                return Some(common::request_info(
                    "count_tokens",
                    common::body_model(body),
                    false,
                ));
            }
            ("anthropic", _, "rawPredict") => ("messages", false),
            ("anthropic", _, "streamRawPredict") => ("messages", true),
            _ => return None,
        };
        Some(common::request_info(
            op,
            common::decode_segment(path.model),
            stream,
        ))
    }
    fn set_model(
        &self,
        info: &AiRequestInfo,
        rest_path: &str,
        body: &mut Value,
        model: &str,
    ) -> String {
        let Some(path) = VertexPath::parse(rest_path) else {
            return rest_path.to_owned();
        };
        if path.publisher == "anthropic" {
            if let Some(object) = body.as_object_mut() {
                object
                    .entry("anthropic_version")
                    .or_insert(json!("vertex-2023-10-16"));
                if path.method == "streamRawPredict" {
                    object.insert("stream".into(), json!(true));
                }
                if info.operation == "count_tokens" {
                    if let Some(value) = object.get_mut("model") {
                        *value = json!(model);
                    }
                } else {
                    object.remove("model");
                }
            }
            if info.operation == "count_tokens" {
                return rest_path.to_owned();
            }
        }
        if info.model.as_deref() == Some(model) {
            return rest_path.to_owned();
        }
        path.format(path.project, path.location, &common::encode_segment(model))
    }
    fn upstream_path(&self, _info: &AiRequestInfo, rest_path: &str, ctx: &UpstreamCtx) -> String {
        let Some(path) = VertexPath::parse(rest_path) else {
            return rest_path.to_owned();
        };
        let project = ctx.project_id.map(common::encode_segment);
        let location = ctx.region.map(common::encode_segment);
        path.format(
            project.as_deref().unwrap_or(path.project),
            location.as_deref().unwrap_or(path.location),
            path.model,
        )
    }
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut Value, cap: u64) {
        delegate(info).clamp_max_output(info, body, cap);
    }
    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut Value, user: &str) {
        delegate(info).inject_user_id(info, body, user);
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
        delegate(info).extract_usage(info, body)
    }
    fn stream_usage(&self, info: &AiRequestInfo) -> Box<dyn StreamUsageParser> {
        delegate(info).stream_usage(info)
    }
    fn prompt_text(&self, info: &AiRequestInfo, body: &Value) -> String {
        delegate(info).prompt_text(info, body)
    }
    fn response_text(&self, info: &AiRequestInfo, body: &Value) -> Option<String> {
        delegate(info).response_text(info, body)
    }
    fn is_refusal(&self, body: &Value) -> bool {
        AnthropicAdapter.is_refusal(body) || GeminiAdapter.is_refusal(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::sse::SseParser;

    #[test]
    fn classifies_publisher_paths() {
        let cases = [
            (
                "v1",
                "global",
                "google",
                "gemini-3",
                "generateContent",
                Dialect::Gemini,
                "generate",
                false,
            ),
            (
                "v1beta1",
                "us-central1",
                "google",
                "gemini-3",
                "streamGenerateContent",
                Dialect::Gemini,
                "generate",
                true,
            ),
            (
                "v1",
                "global",
                "anthropic",
                "claude%40date",
                "rawPredict",
                Dialect::Anthropic,
                "messages",
                false,
            ),
            (
                "v1",
                "us-east5",
                "anthropic",
                "claude@date",
                "streamRawPredict",
                Dialect::Anthropic,
                "messages",
                true,
            ),
            (
                "v1",
                "global",
                "anthropic",
                "count-tokens",
                "rawPredict",
                Dialect::Opaque,
                "count_tokens",
                false,
            ),
            (
                "v1",
                "global",
                "google",
                "gemini-3",
                "countTokens",
                Dialect::Opaque,
                "count_tokens",
                false,
            ),
        ];
        for (version, location, publisher, model, method, dialect, op, stream) in cases {
            let path = format!(
                "{version}/projects/sample/locations/{location}/publishers/{publisher}/models/{model}:{method}"
            );
            let body = json!({"model":"claude@date"});
            let info = VertexAdapter
                .classify(&Method::POST, &path, &[], &body)
                .unwrap();
            assert_eq!(
                (info.dialect, info.operation, info.stream),
                (dialect, op, stream)
            );
            assert_eq!(
                info.model.as_deref(),
                Some(if publisher == "anthropic" {
                    "claude@date"
                } else {
                    model
                })
            );
        }
        assert!(
            VertexAdapter
                .classify(
                    &Method::POST,
                    "v1/projects/p/locations/global/publishers/other/models/m:rawPredict",
                    &[],
                    &Value::Null
                )
                .is_none()
        );
    }

    #[test]
    fn rewrites_model_and_target_and_preserves_count_route() {
        let mut body = json!({"anthropic_version":"client-version", "model":"ignored"});
        let path =
            "v1/projects/client/locations/global/publishers/anthropic/models/old:streamRawPredict";
        let info = VertexAdapter
            .classify(&Method::POST, path, &[], &body)
            .unwrap();
        let path = VertexAdapter.set_model(&info, path, &mut body, "new@2026");
        let target = UpstreamCtx {
            project_id: Some("upstream"),
            region: Some("us-east5"),
        };
        assert_eq!(
            VertexAdapter.upstream_path(&info, &path, &target),
            "v1/projects/upstream/locations/us-east5/publishers/anthropic/models/new@2026:streamRawPredict"
        );
        VertexAdapter.inject_user_id(&info, &mut body, "hashed");
        assert_eq!(
            body,
            json!({"anthropic_version":"client-version", "stream":true, "metadata":{"user_id":"hashed"}})
        );

        let path = "v1/projects/client/locations/global/publishers/anthropic/models/count-tokens:rawPredict";
        let mut body = json!({"model":"old"});
        let info = VertexAdapter
            .classify(&Method::POST, path, &[], &body)
            .unwrap();
        assert_eq!(VertexAdapter.set_model(&info, path, &mut body, "new"), path);
        assert_eq!(
            body,
            json!({"model":"new","anthropic_version":"vertex-2023-10-16"})
        );
    }

    #[test]
    fn reads_both_publisher_sse_transcripts() {
        for (op, transcript) in [
            (
                "generate",
                include_bytes!("../../../tests/fixtures/ai/vertex/gemini.sse").as_slice(),
            ),
            (
                "messages",
                include_bytes!("../../../tests/fixtures/ai/vertex/anthropic.sse").as_slice(),
            ),
        ] {
            let info = common::request_info(op, None, true);
            let mut stream = VertexAdapter.stream_usage(&info);
            for event in SseParser::new(2048).push(transcript) {
                stream.on_event(&event);
            }
            assert_eq!(stream.completion_text(), Some("Hi"));
            let usage = stream.finish().unwrap();
            assert_eq!((usage.input_tokens, usage.output_tokens), (8, 3));
        }
    }
}
