//! Long-running fake AI provider for local UI work and the joint walkthrough.
//! Never runs in normal test passes (`#[ignore]`). Start it with:
//!
//! ```text
//! DOORMAN_FAKE_PROVIDER_PORT=18080 cargo test -p doorman-gateway --test ai_fake_provider \
//!     ai_fake_provider_server -- --exact --ignored --nocapture
//! ```
//!
//! It answers OpenAI chat/responses/embeddings, Anthropic messages and Gemini
//! generateContent (stream and non-stream) with fixed text and usage, and logs
//! which credential header arrived (never its value).

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::Request,
    response::{IntoResponse, Response},
};
use http::{StatusCode, header};
use serde_json::{Value, json};

fn sse(events: Vec<String>) -> Response {
    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(events.concat()))
        .unwrap()
}

async fn handle(request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 64 << 20)
        .await
        .unwrap_or_else(|_| Bytes::new());
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let path = parts.uri.path().to_owned();
    let credential = ["authorization", "x-api-key", "x-goog-api-key", "api-key"]
        .into_iter()
        .find(|name| parts.headers.contains_key(*name))
        .unwrap_or("none");
    let model = json["model"].as_str().unwrap_or("fake-model").to_owned();
    let stream = json["stream"] == true || parts.uri.query().is_some_and(|q| q.contains("alt=sse"));
    println!(
        "fake provider: {} {path} credential={credential} model={model} stream={stream}",
        parts.method
    );
    match path.as_str() {
        "/v1/chat/completions" | "/openai/deployments/fake/chat/completions" if stream => sse(vec![
            format!("data: {}\n\n", json!({"id":"chatcmpl-fake","object":"chat.completion.chunk","model":model,"choices":[{"index":0,"delta":{"role":"assistant","content":"Hello from the "}}]})),
            format!("data: {}\n\n", json!({"id":"chatcmpl-fake","object":"chat.completion.chunk","model":model,"choices":[{"index":0,"delta":{"content":"fake provider."},"finish_reason":"stop"}]})),
            format!("data: {}\n\n", json!({"id":"chatcmpl-fake","object":"chat.completion.chunk","model":model,"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":6,"total_tokens":18}})),
            "data: [DONE]\n\n".to_owned(),
        ]),
        "/v1/chat/completions" | "/openai/deployments/fake/chat/completions" => Json(json!({
            "id": "chatcmpl-fake", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello from the fake provider."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}
        })).into_response(),
        "/v1/responses" => Json(json!({
            "id": "resp_fake", "object": "response", "model": model,
            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Hello from the fake provider."}]}],
            "usage": {"input_tokens": 12, "output_tokens": 6}
        })).into_response(),
        "/v1/embeddings" => Json(json!({
            "object": "list", "model": model,
            "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
            "usage": {"prompt_tokens": 4, "total_tokens": 4}
        })).into_response(),
        "/v1/messages" if stream => sse(vec![
            format!("event: message_start\ndata: {}\n\n", json!({"type":"message_start","message":{"id":"msg_fake","type":"message","role":"assistant","model":model,"content":[],"usage":{"input_tokens":12,"output_tokens":1}}})),
            format!("event: content_block_start\ndata: {}\n\n", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
            format!("event: content_block_delta\ndata: {}\n\n", json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello from the fake provider."}})),
            format!("event: content_block_stop\ndata: {}\n\n", json!({"type":"content_block_stop","index":0})),
            format!("event: message_delta\ndata: {}\n\n", json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":6}})),
            format!("event: message_stop\ndata: {}\n\n", json!({"type":"message_stop"})),
        ]),
        "/v1/messages" => Json(json!({
            "id": "msg_fake", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": "Hello from the fake provider."}],
            "stop_reason": "end_turn", "usage": {"input_tokens": 12, "output_tokens": 6}
        })).into_response(),
        "/v1/messages/count_tokens" => Json(json!({"input_tokens": 12})).into_response(),
        _ if path.contains(":generateContent") || path.contains(":streamGenerateContent") => {
            let chunk = json!({
                "candidates": [{"content": {"role": "model", "parts": [{"text": "Hello from the fake provider."}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 6, "totalTokenCount": 18}
            });
            if stream {
                sse(vec![format!("data: {chunk}\n\n")])
            } else if path.contains(":streamGenerateContent") {
                Json(json!([chunk])).into_response()
            } else {
                Json(chunk).into_response()
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": {"message": "fake provider: unknown path"}}))).into_response(),
    }
}

#[tokio::test]
#[ignore = "long-running fake provider for manual runs"]
async fn ai_fake_provider_server() {
    let port: u16 = std::env::var("DOORMAN_FAKE_PROVIDER_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(18080);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    println!("fake provider listening on http://127.0.0.1:{port}");
    axum::serve(listener, Router::new().fallback(handle))
        .await
        .unwrap();
}
