use super::openai::OpenaiAdapter;
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, ProviderAdapter},
    usage::{AiUsage, StreamUsageParser},
};
use http::{HeaderMap, Method, StatusCode};
use serde_json::Value;

pub struct OpenaiCompatibleAdapter;
impl ProviderAdapter for OpenaiCompatibleAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::OpenaiCompatible
    }
    fn classify(
        &self,
        method: &Method,
        path: &str,
        query: &[(String, String)],
        body: &Value,
    ) -> Option<AiRequestInfo> {
        OpenaiAdapter.classify(method, path, query, body)
    }
    fn set_model(&self, info: &AiRequestInfo, path: &str, body: &mut Value, model: &str) -> String {
        OpenaiAdapter.set_model(info, path, body, model)
    }
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut Value, cap: u64) {
        OpenaiAdapter.clamp_max_output(info, body, cap);
    }
    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut Value, user: &str) {
        OpenaiAdapter.inject_user_id(info, body, user);
    }
    fn ensure_stream_usage(&self, info: &AiRequestInfo, body: &mut Value) {
        OpenaiAdapter.ensure_stream_usage(info, body);
    }
    fn upstream_query(
        &self,
        info: &AiRequestInfo,
        query: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        OpenaiAdapter.upstream_query(info, query)
    }
    fn apply_credential(&self, headers: &mut HeaderMap, key: &str, header_override: Option<&str>) {
        OpenaiAdapter.apply_credential(headers, key, header_override);
    }
    fn default_headers(&self, _headers: &mut HeaderMap) {}
    fn local_response(
        &self,
        info: &AiRequestInfo,
        models: &[String],
    ) -> Option<(StatusCode, Value)> {
        OpenaiAdapter.local_response(info, models)
    }
    fn extract_usage(&self, info: &AiRequestInfo, body: &Value) -> Option<AiUsage> {
        OpenaiAdapter.extract_usage(info, body)
    }
    fn stream_usage(&self, info: &AiRequestInfo) -> Box<dyn StreamUsageParser> {
        OpenaiAdapter.stream_usage(info)
    }
    fn prompt_text(&self, info: &AiRequestInfo, body: &Value) -> String {
        OpenaiAdapter.prompt_text(info, body)
    }
    fn response_text(&self, info: &AiRequestInfo, body: &Value) -> Option<String> {
        OpenaiAdapter.response_text(info, body)
    }
    fn is_refusal(&self, body: &Value) -> bool {
        OpenaiAdapter.is_refusal(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatible_uses_header_override() {
        for (header, expected) in [
            ("X-Internal-Token", "placeholder"),
            ("Authorization", "Bearer placeholder"),
        ] {
            let mut headers = HeaderMap::new();
            for name in crate::ai::adapter::INBOUND_CREDENTIAL_HEADERS {
                headers.insert(*name, "inbound".parse().unwrap());
            }
            OpenaiCompatibleAdapter.apply_credential(&mut headers, "placeholder", Some(header));
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[header], expected);
        }
    }
}
