//! Step 7: OpenTelemetry export of AI traffic, received by an in-process
//! OTLP/HTTP collector. One test: the SDK, propagator and subscriber are
//! process-wide.
//! Run: `cargo test -p doorman-gateway --test ai_otel`.

#[path = "common/ai.rs"]
mod ai_common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use ai_common::{FakeProvider, Reply, body_bytes, harness, send};
use axum::{Router, body::Bytes, extract::State, routing::post};
use http::{Method, StatusCode};
use opentelemetry_proto::tonic::{
    collector::{metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest},
    common::v1::{AnyValue, KeyValue, any_value::Value as Any},
    trace::v1::{Span, span::SpanKind},
};
use prost::Message;
use serde_json::{Value, json};

const CHAT: &str = "/api/ai/gpt/v1/v1/chat/completions";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT_ID: &str = "00f067aa0ba902b7";
const SECRET_PROMPT: &str = "SENTINEL-PROMPT-7f3a";
const SECRET_REPLY: &str = "SENTINEL-REPLY-91c2";

#[derive(Clone, Default)]
struct Collected {
    traces: Arc<Mutex<Vec<Bytes>>>,
    metrics: Arc<Mutex<Vec<Bytes>>>,
}

async fn start_collector() -> (String, Collected) {
    let collected = Collected::default();
    let app = Router::new()
        .route(
            "/v1/traces",
            post(|State(c): State<Collected>, body: Bytes| async move {
                c.traces.lock().unwrap().push(body);
                StatusCode::OK
            }),
        )
        .route(
            "/v1/metrics",
            post(|State(c): State<Collected>, body: Bytes| async move {
                c.metrics.lock().unwrap().push(body);
                StatusCode::OK
            }),
        )
        .with_state(collected.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, collected)
}

fn attr<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a Any> {
    attributes
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| kv.value.as_ref())
        .and_then(|value: &AnyValue| value.value.as_ref())
}

fn text(span: &Span, key: &str) -> Option<String> {
    match attr(&span.attributes, key)? {
        Any::StringValue(value) => Some(value.clone()),
        other => Some(format!("{other:?}")),
    }
}

fn int(span: &Span, key: &str) -> Option<i64> {
    match attr(&span.attributes, key)? {
        Any::IntValue(value) => Some(*value),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn reply() -> Value {
    json!({
        "id": "chatcmpl-up", "object": "chat.completion", "created": 1, "model": "gpt-x",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": SECRET_REPLY}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
    })
}

const SSE: [&str; 3] = [
    "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n\n",
    "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n",
    "data: [DONE]\n\n",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ai_requests_export_genai_spans_and_metrics() {
    let (collector, collected) = start_collector().await;
    // SAFETY: set before any thread reads the environment for telemetry.
    unsafe {
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", &collector);
        std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");
        std::env::remove_var("DOORMAN_OTEL_INCLUDE_USER");
    }
    doorman_gateway::observability::init();
    assert!(doorman_gateway::observability::otel::traces_on());

    // Non-stream, cached: a miss carrying the caller's trace context, then a hit.
    let fake = FakeProvider::start(vec![Reply::ok(reply())]).await;
    let h = harness(
        "gpt",
        "openai",
        &fake.url,
        json!({"api_ai_config": {"credential_group": "prov-cred", "allowed_models": ["gpt-x"],
            "cache": {"enabled": true, "ttl_seconds": 3600, "scope": "user"}}}),
    )
    .await;
    let auth = format!("Bearer {}", h.key);
    let traceparent = format!("00-{TRACE_ID}-{PARENT_ID}-01");
    let ask = json!({"model": "gpt-x", "messages": [{"role": "user", "content": SECRET_PROMPT}]});
    let headers = [
        ("authorization", auth.as_str()),
        ("traceparent", traceparent.as_str()),
        ("tracestate", "vendor=secret"),
        ("baggage", "tenant=acme"),
    ];
    let miss = send(&h.app, Method::POST, CHAT, &headers, Some(ask.clone())).await;
    assert_eq!(miss.headers()["x-doorman-cache"], "miss");
    body_bytes(miss).await;
    // Trace context never reaches the AI provider.
    let upstream = fake.last();
    for name in ["traceparent", "tracestate", "baggage"] {
        assert!(!upstream.headers.contains_key(name), "{name} was forwarded");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let hit = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", auth.as_str())],
        Some(ask),
    )
    .await;
    assert_eq!(hit.headers()["x-doorman-cache"], "hit");
    body_bytes(hit).await;
    assert_eq!(fake.calls().len(), 1);

    // Stream, uncached: the CLIENT span lasts until the stream ends.
    let stream_fake = FakeProvider::start(vec![Reply::Sse(
        SSE.iter()
            .map(|chunk| (Duration::from_millis(40), *chunk))
            .collect(),
    )])
    .await;
    let hs = harness("gpt", "openai", &stream_fake.url, json!({})).await;
    let stream_auth = format!("Bearer {}", hs.key);
    let response = send(
        &hs.app,
        Method::POST,
        CHAT,
        &[("authorization", stream_auth.as_str())],
        Some(
            json!({"model": "gpt-x", "stream": true, "stream_options": {"include_usage": true},
            "messages": [{"role": "user", "content": SECRET_PROMPT}]}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_bytes(response).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    tokio::task::spawn_blocking(doorman_gateway::observability::otel::shutdown)
        .await
        .unwrap();

    let traces = collected.traces.lock().unwrap().clone();
    let metrics = collected.metrics.lock().unwrap().clone();
    assert!(!traces.is_empty(), "no traces exported");
    assert!(!metrics.is_empty(), "no metrics exported");
    for bytes in traces.iter().chain(&metrics) {
        let raw = String::from_utf8_lossy(bytes);
        for (index, secret) in [SECRET_PROMPT, SECRET_REPLY, "tenant=acme", &h.key, &hs.key]
            .into_iter()
            .enumerate()
        {
            assert!(!raw.contains(secret), "secret #{index} was exported");
        }
        assert!(
            !raw.contains("enduser.id"),
            "user identity exported without opt-in"
        );
    }
    let spans: Vec<Span> = traces
        .iter()
        .flat_map(|bytes| {
            ExportTraceServiceRequest::decode(bytes.as_ref())
                .unwrap()
                .resource_spans
        })
        .flat_map(|resource| resource.scope_spans)
        .flat_map(|scope| scope.spans)
        .collect();
    let servers: Vec<&Span> = spans
        .iter()
        .filter(|span| span.kind == SpanKind::Server as i32)
        .collect();
    let clients: Vec<&Span> = spans
        .iter()
        .filter(|span| span.kind == SpanKind::Client as i32)
        .collect();
    assert_eq!(servers.len(), 3, "{spans:#?}");
    assert_eq!(
        clients.len(),
        2,
        "one per upstream call, none for the hit: {spans:#?}"
    );

    // The caller's trace context parents Doorman's SERVER span.
    let miss_server = servers
        .iter()
        .find(|span| hex(&span.trace_id) == TRACE_ID)
        .expect("server span joined the caller's trace");
    assert_eq!(hex(&miss_server.parent_span_id), PARENT_ID);
    // W3C tracestate travels with the trace (to the collector, not upstream).
    assert_eq!(miss_server.trace_state, "vendor=secret");
    assert_eq!(miss_server.name, "POST /api/ai/gpt/v1");
    assert_eq!(text(miss_server, "doorman.cache").as_deref(), Some("miss"));
    assert_eq!(text(miss_server, "doorman.api").as_deref(), Some("gpt/v1"));
    assert_eq!(int(miss_server, "http.response.status_code"), Some(200));
    assert!(text(miss_server, "doorman.cost_usd").is_some());

    let miss_client = clients
        .iter()
        .find(|span| span.parent_span_id == miss_server.span_id)
        .expect("CLIENT span under the SERVER span");
    assert_eq!(miss_client.name, "chat gpt-x");
    assert_eq!(
        text(miss_client, "gen_ai.provider.name").as_deref(),
        Some("openai")
    );
    assert_eq!(
        text(miss_client, "gen_ai.operation.name").as_deref(),
        Some("chat")
    );
    assert_eq!(
        text(miss_client, "gen_ai.request.model").as_deref(),
        Some("gpt-x")
    );
    assert_eq!(int(miss_client, "gen_ai.usage.input_tokens"), Some(7));
    assert_eq!(int(miss_client, "gen_ai.usage.output_tokens"), Some(3));
    assert_eq!(
        text(miss_client, "server.address").as_deref(),
        Some("127.0.0.1")
    );
    assert!(int(miss_client, "server.port").is_some());

    let hit_server = servers
        .iter()
        .find(|span| text(span, "doorman.cache").as_deref() == Some("hit"))
        .expect("hit recorded on its SERVER span");
    assert!(
        clients
            .iter()
            .all(|span| span.parent_span_id != hit_server.span_id)
    );

    let stream_client = clients
        .iter()
        .find(|span| text(span, "gen_ai.request.stream").as_deref() == Some("BoolValue(true)"))
        .expect("stream CLIENT span");
    assert_eq!(int(stream_client, "gen_ai.usage.input_tokens"), Some(5));
    assert_eq!(int(stream_client, "gen_ai.usage.output_tokens"), Some(2));
    assert!(
        attr(
            &stream_client.attributes,
            "gen_ai.response.time_to_first_chunk"
        )
        .is_some()
    );
    let lasted = stream_client.end_time_unix_nano - stream_client.start_time_unix_nano;
    assert!(
        lasted >= 120_000_000,
        "stream span ended early: {lasted} ns"
    );

    let names: Vec<(String, Vec<String>)> = metrics
        .iter()
        .flat_map(|bytes| {
            ExportMetricsServiceRequest::decode(bytes.as_ref())
                .unwrap()
                .resource_metrics
        })
        .flat_map(|resource| resource.scope_metrics)
        .flat_map(|scope| scope.metrics)
        .map(|metric| {
            let keys = format!("{:?}", metric.data);
            (metric.name, vec![keys])
        })
        .collect();
    for expected in [
        "doorman.ai.requests",
        "doorman.ai.cache.hits",
        "gen_ai.client.inference.duration",
        "gen_ai.client.inference.operation.input_tokens",
        "gen_ai.client.inference.operation.output_tokens",
        "gen_ai.client.inference.time_to_first_chunk",
    ] {
        assert!(
            names.iter().any(|(name, _)| name == expected),
            "missing metric {expected}"
        );
    }
    for (name, data) in &names {
        assert!(!data[0].contains("alice"), "{name} carries the username");
    }
}
