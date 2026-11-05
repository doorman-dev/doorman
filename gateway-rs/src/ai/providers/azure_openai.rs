use super::{common, openai::OpenaiAdapter};
use crate::ai::{
    adapter::{AiProvider, AiRequestInfo, ProviderAdapter},
    usage::{AiUsage, StreamUsageParser},
};
use http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};

pub struct AzureOpenaiAdapter;
impl ProviderAdapter for AzureOpenaiAdapter {
    fn provider(&self) -> AiProvider {
        AiProvider::AzureOpenai
    }
    fn classify(
        &self,
        method: &Method,
        path: &str,
        _query: &[(String, String)],
        body: &Value,
    ) -> Option<AiRequestInfo> {
        if method != Method::POST {
            return None;
        }
        let segments: Vec<_> = path.split('/').collect();
        let (deployment, operation) = match segments.as_slice() {
            ["openai", "deployments", deployment, "chat", "completions"] => (*deployment, "chat"),
            ["openai", "deployments", deployment, "embeddings"] => (*deployment, "embed"),
            _ => return None,
        };
        if deployment.is_empty() {
            return None;
        }
        Some(common::request_info(
            operation,
            Some(deployment.into()),
            body["stream"] == true,
        ))
    }
    fn set_model(
        &self,
        _info: &AiRequestInfo,
        path: &str,
        _body: &mut Value,
        model: &str,
    ) -> String {
        let mut segments: Vec<_> = path.split('/').collect();
        if segments.len() >= 4 && segments[0] == "openai" && segments[1] == "deployments" {
            segments[2] = model;
        }
        segments.join("/")
    }
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut Value, cap: u64) {
        OpenaiAdapter.clamp_max_output(info, body, cap);
    }
    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut Value, user: &str) {
        if info.generation {
            if let Some(object) = body.as_object_mut() {
                object.entry("user").or_insert(json!(user));
            }
        }
    }
    fn ensure_stream_usage(&self, info: &AiRequestInfo, body: &mut Value) {
        OpenaiAdapter.ensure_stream_usage(info, body);
    }
    fn upstream_query(
        &self,
        _info: &AiRequestInfo,
        query: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        common::strip_query(query)
    }
    fn apply_credential(&self, headers: &mut HeaderMap, key: &str, header_override: Option<&str>) {
        common::credential(headers, key, "api-key", header_override);
    }
    fn default_headers(&self, _headers: &mut HeaderMap) {}
    fn local_response(
        &self,
        _info: &AiRequestInfo,
        _models: &[String],
    ) -> Option<(StatusCode, Value)> {
        None
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
    fn azure_uses_deployment_as_model() {
        let path = "openai/deployments/corp-chat/chat/completions";
        let mut body = json!({"model":"ignored","user":"client","stream":true});
        let info = AzureOpenaiAdapter
            .classify(&Method::POST, path, &[], &body)
            .unwrap();
        assert_eq!(info.model.as_deref(), Some("corp-chat"));
        assert_eq!(
            AzureOpenaiAdapter.set_model(&info, path, &mut body, "fallback"),
            "openai/deployments/fallback/chat/completions"
        );
        AzureOpenaiAdapter.inject_user_id(&info, &mut body, "hash");
        assert_eq!(body["user"], "client");
        assert!(body.get("safety_identifier").is_none());
        body.as_object_mut().unwrap().remove("user");
        AzureOpenaiAdapter.inject_user_id(&info, &mut body, "hash");
        assert_eq!(body["user"], "hash");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "inbound".parse().unwrap());
        AzureOpenaiAdapter.apply_credential(&mut headers, "placeholder", None);
        assert_eq!(headers["api-key"], "placeholder");
        assert!(!headers.contains_key("authorization"));
        assert_eq!(
            AzureOpenaiAdapter.upstream_query(
                &info,
                vec![
                    ("api-version".into(), "2024-10-21".into()),
                    ("api-key".into(), "inbound".into())
                ]
            ),
            vec![("api-version".into(), "2024-10-21".into())]
        );
    }
}
