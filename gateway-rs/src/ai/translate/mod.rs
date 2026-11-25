//! OpenAI chat-completions ⇄ native provider formats for the unified endpoint
//! (`/api/ai/v1`, step 5). Pure: no I/O, no config, no logging of bodies.
//!
//! Contract frozen at `s5-contract` (spec `~/mds/doorman_step5-unified-endpoint-plan.md`).
//! Signatures in this file are Claude's; bodies in the target modules are Codex's.

mod anthropic;
mod converse;
mod gemini;
mod openai;

use http::StatusCode;
use serde_json::Value;

use crate::ai::{adapter::AiProvider, sse::SseEvent};

/// The native format a provider/model pair is translated to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// OpenAI, Azure OpenAI, OpenAI-compatible: the body already is OpenAI chat.
    Passthrough,
    /// Anthropic Messages (Anthropic API and Vertex `publishers/anthropic`).
    Anthropic,
    /// Gemini generateContent (Gemini API and Vertex `publishers/google`).
    Gemini,
    /// Bedrock Converse / ConverseStream.
    Converse,
}

/// Vertex: `claude*` → Anthropic, else Gemini. OpenAI / Azure / OpenAI-compatible → Passthrough.
pub fn target_for(provider: AiProvider, model: &str) -> Target {
    match provider {
        AiProvider::Openai | AiProvider::AzureOpenai | AiProvider::OpenaiCompatible => {
            Target::Passthrough
        }
        AiProvider::Anthropic => Target::Anthropic,
        AiProvider::Gemini => Target::Gemini,
        AiProvider::Vertex if model.starts_with("claude") => Target::Anthropic,
        AiProvider::Vertex => Target::Gemini,
        AiProvider::Bedrock => Target::Converse,
    }
}

/// A translated request, ready for the normal AI pipeline.
#[derive(Clone, Debug, PartialEq)]
pub struct NativeRequest {
    /// Provider path after `/api/ai/{name}/{ver}/`, exactly what the adapter's `classify` accepts:
    /// openai/openai_compatible `v1/chat/completions`; azure `openai/deployments/{model}/chat/completions`;
    /// anthropic `v1/messages`; gemini `v1beta/models/{m}:generateContent` | `:streamGenerateContent` (+ alt=sse);
    /// vertex `v1/projects/-/locations/-/publishers/{google|anthropic}/models/{m}:{generateContent|streamGenerateContent|rawPredict|streamRawPredict}`
    /// (`-` placeholders are replaced by the handler's `UpstreamCtx`); bedrock `model/{id}/converse` | `converse-stream`.
    pub rest_path: String,
    pub query: Vec<(String, String)>,
    pub body: Value,
    pub stream: bool,
}

/// Why a request can't be translated. Becomes 400 AI012; the message is shown to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslateError(pub String);

/// OpenAI chat request → the provider's native request.
pub fn to_native(
    provider: AiProvider,
    model: &str,
    chat: &Value,
) -> Result<NativeRequest, TranslateError> {
    openai::validate(chat)?;
    let target = target_for(provider, model);
    if target != Target::Passthrough && !chat["logprobs"].is_null() {
        return Err(TranslateError(
            "logprobs is only supported on OpenAI-compatible targets".into(),
        ));
    }
    match target {
        Target::Passthrough => openai::to_native(provider, model, chat),
        Target::Anthropic => anthropic::to_native(provider, model, chat),
        Target::Gemini => gemini::to_native(provider, model, chat),
        Target::Converse => converse::to_native(model, chat),
    }
}

/// Native non-stream success body → OpenAI `chat.completion` (id, object, created, model = requested name,
/// choices[0].message {role, content, tool_calls}, finish_reason, usage {prompt_tokens, completion_tokens,
/// total_tokens, prompt_tokens_details.cached_tokens}).
pub fn from_native(target: Target, requested_model: &str, native: &Value) -> Value {
    match target {
        Target::Passthrough => openai::from_native(requested_model, native),
        Target::Anthropic => anthropic::from_native(requested_model, native),
        Target::Gemini => gemini::from_native(requested_model, native),
        Target::Converse => converse::from_native(requested_model, native),
    }
}

/// Any native error body (or none) → `{"error":{"message","type","code","param":null}}`.
/// Doorman's own errors (`error_code`/`error_message`) keep their code in `code`.
pub fn error_to_openai(status: StatusCode, body: &[u8]) -> Value {
    openai::error_to_openai(status, body)
}

/// Native stream events (SSE events, or AWS frames already turned into `SseEvent` by
/// `Frame::to_sse_event`) → `chat.completion.chunk` objects. The handler serialises each
/// as `data: {json}\n\n` and appends `data: [DONE]\n\n`.
pub trait ChunkTranslator: Send {
    fn on_event(&mut self, event: &SseEvent) -> Vec<Value>;
    /// Final chunks: the finish_reason chunk if not yet sent, then the usage chunk
    /// (`choices: []`) when include_usage.
    fn finish(&mut self) -> Vec<Value>;
}

pub fn stream_translator(
    target: Target,
    requested_model: &str,
    id: &str,
    created: i64,
    include_usage: bool,
) -> Box<dyn ChunkTranslator> {
    let chunk = openai::ChunkMeta {
        id: id.to_owned(),
        model: requested_model.to_owned(),
        created,
        include_usage,
    };
    match target {
        Target::Passthrough => Box::new(openai::PassthroughChunks::new(chunk)),
        Target::Anthropic => Box::new(anthropic::Chunks::new(chunk)),
        Target::Gemini => Box::new(gemini::Chunks::new(chunk)),
        Target::Converse => Box::new(converse::Chunks::new(chunk)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertex_routes_claude_models_to_anthropic() {
        assert_eq!(
            target_for(AiProvider::Vertex, "claude-sonnet-5-5"),
            Target::Anthropic
        );
        assert_eq!(
            target_for(AiProvider::Vertex, "gemini-3-pro"),
            Target::Gemini
        );
        assert_eq!(
            target_for(AiProvider::AzureOpenai, "gpt-5"),
            Target::Passthrough
        );
        assert_eq!(
            target_for(AiProvider::Bedrock, "us.anthropic.x"),
            Target::Converse
        );
    }
}
