//! Provider adapter contract (plan §5.10). Adapters live in `ai::providers`.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    Openai,
    Anthropic,
    Gemini,
    AzureOpenai,
    OpenaiCompatible,
}

impl AiProvider {
    pub const ALL: [AiProvider; 5] = [
        AiProvider::Openai,
        AiProvider::Anthropic,
        AiProvider::Gemini,
        AiProvider::AzureOpenai,
        AiProvider::OpenaiCompatible,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AiProvider::Openai => "openai",
            AiProvider::Anthropic => "anthropic",
            AiProvider::Gemini => "gemini",
            AiProvider::AzureOpenai => "azure_openai",
            AiProvider::OpenaiCompatible => "openai_compatible",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AiRequestInfo {
    /// "chat" | "responses" | "messages" | "count_tokens" | "generate" | "embed" | "models"
    pub operation: &'static str,
    /// As requested, before alias resolution.
    pub model: Option<String>,
    /// True only when the upstream reply will be `text/event-stream`.
    pub stream: bool,
    /// False for count_tokens / models.
    pub metered: bool,
    /// Answered by the gateway (models list).
    pub local: bool,
    /// True for chat/responses/messages/generate: user-id, clamp and guardrails apply.
    pub generation: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ProviderPreset {
    pub id: &'static str,
    pub label: &'static str,
    pub default_server: Option<&'static str>,
    pub credential_header: &'static str,
    /// "bearer" | "raw"
    pub credential_format: &'static str,
    /// Appended to `{gw}/api/ai/{name}/{ver}`; "/v1" for OpenAI-style SDKs, "" otherwise.
    pub sdk_base_url_suffix: &'static str,
    pub supports_user_id: bool,
    pub operations: &'static [&'static str],
}

/// Owned by Claude so contract validation and the catalog endpoint never wait on adapters.
/// Order matches `AiProvider::ALL`.
pub static PRESETS: &[ProviderPreset] = &[
    ProviderPreset {
        id: "openai",
        label: "OpenAI",
        default_server: Some("https://api.openai.com"),
        credential_header: "authorization",
        credential_format: "bearer",
        sdk_base_url_suffix: "/v1",
        supports_user_id: true,
        operations: &["chat", "responses", "embed", "models"],
    },
    ProviderPreset {
        id: "anthropic",
        label: "Anthropic",
        default_server: Some("https://api.anthropic.com"),
        credential_header: "x-api-key",
        credential_format: "raw",
        sdk_base_url_suffix: "",
        supports_user_id: true,
        operations: &["messages", "count_tokens", "models"],
    },
    ProviderPreset {
        id: "gemini",
        label: "Google Gemini",
        default_server: Some("https://generativelanguage.googleapis.com"),
        credential_header: "x-goog-api-key",
        credential_format: "raw",
        sdk_base_url_suffix: "",
        supports_user_id: false,
        operations: &["generate", "count_tokens", "embed", "models"],
    },
    ProviderPreset {
        id: "azure_openai",
        label: "Azure OpenAI",
        default_server: None,
        credential_header: "api-key",
        credential_format: "raw",
        sdk_base_url_suffix: "",
        supports_user_id: true,
        operations: &["chat", "embed"],
    },
    ProviderPreset {
        id: "openai_compatible",
        label: "OpenAI-compatible",
        default_server: None,
        credential_header: "authorization",
        credential_format: "bearer",
        sdk_base_url_suffix: "/v1",
        supports_user_id: true,
        operations: &["chat", "responses", "embed", "models"],
    },
];

pub fn preset(provider: AiProvider) -> &'static ProviderPreset {
    let index = AiProvider::ALL
        .iter()
        .position(|candidate| *candidate == provider)
        .unwrap_or_default();
    &PRESETS[index]
}

/// Credentials removed from every inbound request before it goes upstream. The handler strips
/// these; `apply_credential` must ALSO remove them first (defense in depth), then insert the provider key.
pub const INBOUND_CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-goog-api-key",
    "api-key",
    "cookie",
];
pub const INBOUND_CREDENTIAL_QUERY: &[&str] = &["key", "api-key"];

pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> AiProvider;
    /// Match method + rest path (no leading slash) against §8. None → AI001.
    fn classify(
        &self,
        method: &http::Method,
        rest_path: &str,
        query: &[(String, String)],
        body: &serde_json::Value,
    ) -> Option<AiRequestInfo>;
    /// Rewrite the model in body or path (alias / downgrade). Returns the (possibly new) rest_path.
    fn set_model(
        &self,
        info: &AiRequestInfo,
        rest_path: &str,
        body: &mut serde_json::Value,
        model: &str,
    ) -> String;
    /// No-op unless info.generation.
    fn clamp_max_output(&self, info: &AiRequestInfo, body: &mut serde_json::Value, cap: u64);
    /// No-op unless info.generation; never overwrites a client value.
    fn inject_user_id(&self, info: &AiRequestInfo, body: &mut serde_json::Value, hashed_user: &str);
    /// OpenAI-style chat streams only.
    fn ensure_stream_usage(&self, info: &AiRequestInfo, body: &mut serde_json::Value);
    /// Remove INBOUND_CREDENTIAL_QUERY params. Never changes the response format the client asked for.
    fn upstream_query(
        &self,
        info: &AiRequestInfo,
        query: Vec<(String, String)>,
    ) -> Vec<(String, String)>;
    fn apply_credential(
        &self,
        headers: &mut http::HeaderMap,
        key: &str,
        header_override: Option<&str>,
    );
    /// e.g. anthropic-version if absent.
    fn default_headers(&self, headers: &mut http::HeaderMap);
    fn local_response(
        &self,
        info: &AiRequestInfo,
        allowed_models: &[String],
    ) -> Option<(http::StatusCode, serde_json::Value)>;
    /// Non-stream body; for Gemini this may be a JSON array (take the last element's usageMetadata).
    fn extract_usage(
        &self,
        info: &AiRequestInfo,
        body: &serde_json::Value,
    ) -> Option<crate::ai::usage::AiUsage>;
    fn stream_usage(&self, info: &AiRequestInfo) -> Box<dyn crate::ai::usage::StreamUsageParser>;
    /// Plain text of the prompt (system + user/assistant text parts) for prompt logging; capped at 256 KiB.
    fn prompt_text(&self, info: &AiRequestInfo, body: &serde_json::Value) -> String;
    /// Plain text of a non-stream completion for prompt logging; capped at 256 KiB.
    fn response_text(&self, info: &AiRequestInfo, body: &serde_json::Value) -> Option<String>;
    /// Analytics only; never alters the response.
    fn is_refusal(&self, body: &serde_json::Value) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_follow_provider_order() {
        for provider in AiProvider::ALL {
            assert_eq!(preset(provider).id, provider.as_str());
            assert_eq!(AiProvider::parse(provider.as_str()), Some(provider));
        }
        assert_eq!(PRESETS.len(), AiProvider::ALL.len());
        assert_eq!(AiProvider::parse("vertex"), None);
    }
}
