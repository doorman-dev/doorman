//! OpenTelemetry spans and metrics for AI requests (GenAI conventions v0.1.0).
//!
//! Prompt and response text, keys and headers are never recorded. The SERVER
//! span (see `middleware::otel`) carries Doorman's own decisions; a CLIENT span
//! is opened only for each upstream attempt; provider inference metrics are
//! recorded only when an upstream model answered.

use std::sync::OnceLock;

use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use tracing::{Span, field::Empty};

use crate::{
    ai::{
        adapter::AiProvider,
        usage::{AiUsage, FinalizeCtx},
    },
    observability::otel,
};

/// What `execute_ai` learned about the request, for the request counter and
/// the SERVER span (filled in as each fact becomes known).
#[derive(Default)]
pub struct RequestMeta {
    pub provider: Option<AiProvider>,
    pub api: Option<String>,
    pub operation: Option<&'static str>,
    pub model: Option<String>,
    pub username: Option<String>,
    pub unified_model: Option<String>,
}

/// `gen_ai.provider.name` (registry values; custom value for compatible APIs).
pub fn provider_name(provider: AiProvider) -> &'static str {
    match provider {
        AiProvider::Openai => "openai",
        AiProvider::Anthropic => "anthropic",
        AiProvider::Gemini => "gcp.gemini",
        AiProvider::Vertex => "gcp.vertex_ai",
        AiProvider::Bedrock => "aws.bedrock",
        AiProvider::AzureOpenai => "azure.ai.openai",
        AiProvider::OpenaiCompatible => "openai_compatible",
    }
}

/// `gen_ai.operation.name` for inference operations; None for calls that are
/// not inference (model lists, token counting).
pub fn operation_name(operation: &str) -> Option<&'static str> {
    match operation {
        "chat" | "messages" | "converse" | "invoke" | "responses" => Some("chat"),
        "generate" => Some("generate_content"),
        "completions" => Some("text_completion"),
        "embeddings" => Some("embeddings"),
        _ => None,
    }
}

/// A CLIENT span for one upstream attempt, or None when tracing is off or the
/// call is not inference.
pub fn client_span(
    provider: AiProvider,
    operation: &str,
    model: &str,
    url: &str,
    stream: bool,
) -> Option<Span> {
    if !otel::traces_on() {
        return None;
    }
    let operation = operation_name(operation)?;
    let span = tracing::info_span!(
        target: otel::TARGET,
        "gen_ai.client",
        otel.name = %format!("{operation} {model}"),
        otel.kind = "client",
        otel.status_code = Empty,
        gen_ai.operation.name = operation,
        gen_ai.provider.name = provider_name(provider),
        gen_ai.request.model = model,
        gen_ai.request.stream = stream,
        gen_ai.usage.input_tokens = Empty,
        gen_ai.usage.output_tokens = Empty,
        gen_ai.response.time_to_first_chunk = Empty,
        server.address = Empty,
        server.port = Empty,
        "error.type" = Empty,
    );
    if let Ok(url) = url::Url::parse(url)
        && let Some(host) = url.host_str()
    {
        span.record("server.address", host);
        if let Some(port) = url.port_or_known_default() {
            span.record("server.port", i64::from(port));
        }
    }
    Some(span)
}

/// Marks an attempt as failed (`error.type`: a status code or a short reason).
pub fn fail(span: &Option<Span>, error_type: &str) {
    if let Some(span) = span {
        span.record("otel.status_code", "error");
        span.record("error.type", error_type);
    }
}

fn status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

/// Every AI request, including cache hits and policy blocks: records the
/// SERVER span's Doorman attributes and counts `doorman.ai.requests`.
pub fn request_done(span: Option<&Span>, meta: &RequestMeta, status: u16, cache: &str) {
    if let Some(span) = span {
        if let Some(api) = &meta.api {
            span.record("doorman.api", api.as_str());
        }
        span.record("doorman.cache", cache);
        if let Some(model) = &meta.unified_model {
            span.record("doorman.unified_model", model.as_str());
        }
        if otel::config().include_user
            && let Some(user) = &meta.username
        {
            span.record("enduser.id", user.as_str());
        }
    }
    let Some(metrics) = metrics() else {
        return;
    };
    let mut attributes = vec![
        KeyValue::new("doorman.status_class", status_class(status)),
        KeyValue::new("doorman.cache", cache.to_owned()),
    ];
    if let Some(api) = &meta.api {
        attributes.push(KeyValue::new("doorman.api", api.clone()));
    }
    if let Some(provider) = meta.provider {
        attributes.push(KeyValue::new(
            "gen_ai.provider.name",
            provider_name(provider),
        ));
    }
    if let Some(operation) = meta.operation {
        attributes.push(KeyValue::new(
            "gen_ai.operation.name",
            operation_name(operation).unwrap_or(operation),
        ));
    }
    if let Some(model) = &meta.model {
        attributes.push(KeyValue::new("gen_ai.request.model", model.clone()));
    }
    metrics.requests.add(1, &attributes);
}

/// Called once usage is known (after the reply, including streams). Ends the
/// CLIENT span and releases the SERVER span.
pub fn finish(ctx: &mut FinalizeCtx, usage: &AiUsage, cost_nanos: Option<u64>, saved_nanos: u64) {
    let server = ctx.server_span.take();
    let client = ctx.client_span.take();
    let input = usage
        .input_tokens
        .saturating_add(usage.cache_read_tokens)
        .saturating_add(usage.cache_write_tokens);
    let as_i64 = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    let usd = |nanos: u64| nanos as f64 / 1e9;
    let failed = ctx.status >= 400;
    if let Some(span) = &server {
        if let Some(nanos) = cost_nanos {
            span.record("doorman.cost_usd", usd(nanos));
        }
        span.record("doorman.fallbacks", i64::from(ctx.fallbacks));
        span.record("doorman.guardrail.redactions", i64::from(ctx.redactions));
    }
    if let Some(span) = &client {
        if failed {
            span.record("otel.status_code", "error");
            span.record("error.type", ctx.status.to_string().as_str());
        } else {
            span.record("gen_ai.usage.input_tokens", as_i64(input));
            span.record("gen_ai.usage.output_tokens", as_i64(usage.output_tokens));
        }
        if let Some(ms) = ctx.first_chunk_ms {
            span.record("gen_ai.response.time_to_first_chunk", ms as f64 / 1e3);
        }
    }
    let Some(metrics) = metrics() else {
        return;
    };
    let mut attributes = vec![
        KeyValue::new("gen_ai.provider.name", provider_name(ctx.provider)),
        KeyValue::new("gen_ai.request.model", ctx.model.clone()),
        KeyValue::new("doorman.api", ctx.api.clone()),
    ];
    if let Some(operation) = operation_name(ctx.operation) {
        attributes.push(KeyValue::new("gen_ai.operation.name", operation));
    }
    if ctx.cache_saved.is_some() {
        metrics.cache_hits.add(1, &attributes);
        metrics.cache_saved_cost.add(usd(saved_nanos), &attributes);
        return;
    }
    if let Some(nanos) = cost_nanos.filter(|nanos| *nanos > 0) {
        metrics.cost.add(usd(nanos), &attributes);
    }
    let Some(operation) = operation_name(ctx.operation) else {
        return;
    };
    if failed {
        attributes.push(KeyValue::new("error.type", ctx.status.to_string()));
    }
    let seconds = ctx.started.elapsed().as_secs_f64();
    if operation == "embeddings" {
        metrics.embeddings_duration.record(seconds, &attributes);
        if !failed {
            metrics.embeddings_input.record(input, &attributes);
        }
        return;
    }
    metrics.inference_duration.record(seconds, &attributes);
    if !failed {
        metrics.inference_input.record(input, &attributes);
        metrics
            .inference_output
            .record(usage.output_tokens, &attributes);
    }
    if let Some(ms) = ctx.first_chunk_ms {
        metrics
            .time_to_first_chunk
            .record(ms as f64 / 1e3, &attributes);
    }
}

struct Metrics {
    requests: Counter<u64>,
    cost: Counter<f64>,
    cache_hits: Counter<u64>,
    cache_saved_cost: Counter<f64>,
    inference_duration: Histogram<f64>,
    inference_input: Histogram<u64>,
    inference_output: Histogram<u64>,
    time_to_first_chunk: Histogram<f64>,
    embeddings_duration: Histogram<f64>,
    embeddings_input: Histogram<u64>,
}

const SECONDS: [f64; 14] = [
    0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92,
];
const TOKENS: [f64; 14] = [
    1.0, 4.0, 16.0, 64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0,
    16777216.0, 67108864.0,
];

/// Instruments, created once metric export has started (None otherwise).
fn metrics() -> Option<&'static Metrics> {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    if !otel::metrics_on() {
        return None;
    }
    Some(METRICS.get_or_init(|| {
        let meter = global::meter("doorman-gateway");
        let seconds = |name: &'static str, description: &'static str| {
            meter
                .f64_histogram(name)
                .with_unit("s")
                .with_description(description)
                .with_boundaries(SECONDS.to_vec())
                .build()
        };
        let tokens = |name: &'static str, description: &'static str| {
            meter
                .u64_histogram(name)
                .with_unit("{token}")
                .with_description(description)
                .with_boundaries(TOKENS.to_vec())
                .build()
        };
        Metrics {
            requests: meter
                .u64_counter("doorman.ai.requests")
                .with_unit("{request}")
                .with_description("AI requests handled by Doorman, including cache hits and blocks")
                .build(),
            cost: meter
                .f64_counter("doorman.ai.cost")
                .with_unit("USD")
                .with_description("Provider cost of AI requests")
                .build(),
            cache_hits: meter
                .u64_counter("doorman.ai.cache.hits")
                .with_unit("{request}")
                .with_description("AI requests answered from Doorman's response cache")
                .build(),
            cache_saved_cost: meter
                .f64_counter("doorman.ai.cache.saved_cost")
                .with_unit("USD")
                .with_description("Provider cost avoided by the response cache")
                .build(),
            inference_duration: seconds(
                "gen_ai.client.inference.duration",
                "Duration of GenAI inference calls",
            ),
            inference_input: tokens(
                "gen_ai.client.inference.operation.input_tokens",
                "Input tokens per inference call",
            ),
            inference_output: tokens(
                "gen_ai.client.inference.operation.output_tokens",
                "Output tokens per inference call",
            ),
            time_to_first_chunk: seconds(
                "gen_ai.client.inference.time_to_first_chunk",
                "Time to the first streamed output chunk",
            ),
            embeddings_duration: seconds(
                "gen_ai.client.embeddings.duration",
                "Duration of GenAI embeddings calls",
            ),
            embeddings_input: tokens(
                "gen_ai.client.embeddings.operation.input_tokens",
                "Input tokens per embeddings call",
            ),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_and_operation_names() {
        assert_eq!(provider_name(AiProvider::Gemini), "gcp.gemini");
        assert_eq!(
            provider_name(AiProvider::OpenaiCompatible),
            "openai_compatible"
        );
        assert_eq!(operation_name("messages"), Some("chat"));
        assert_eq!(operation_name("generate"), Some("generate_content"));
        assert_eq!(operation_name("embeddings"), Some("embeddings"));
        assert_eq!(operation_name("models"), None);
        assert_eq!(operation_name("count_tokens"), None);
    }
}
