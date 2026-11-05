//! Provider adapters selected by the frozen provider catalog.

pub mod anthropic;
pub mod azure_openai;
mod common;
pub mod gemini;
pub mod openai;
pub mod openai_compatible;

use crate::ai::adapter::{AiProvider, ProviderAdapter};

pub fn adapter_for(provider: AiProvider) -> &'static dyn ProviderAdapter {
    static OPENAI: openai::OpenaiAdapter = openai::OpenaiAdapter;
    static ANTHROPIC: anthropic::AnthropicAdapter = anthropic::AnthropicAdapter;
    static GEMINI: gemini::GeminiAdapter = gemini::GeminiAdapter;
    static AZURE: azure_openai::AzureOpenaiAdapter = azure_openai::AzureOpenaiAdapter;
    static COMPATIBLE: openai_compatible::OpenaiCompatibleAdapter =
        openai_compatible::OpenaiCompatibleAdapter;
    match provider {
        AiProvider::Openai => &OPENAI,
        AiProvider::Anthropic => &ANTHROPIC,
        AiProvider::Gemini => &GEMINI,
        AiProvider::AzureOpenai => &AZURE,
        AiProvider::OpenaiCompatible => &COMPATIBLE,
    }
}
