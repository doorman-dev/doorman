//! Step 5: the unified OpenAI-style endpoint `/api/ai/v1`.
//! Run one at a time: `cargo test -p doorman-gateway --test ai_unified <name> -- --exact`.

#[path = "common/ai.rs"]
mod ai_common;

use std::time::Duration;

use ai_common::{FakeProvider, Reply, UPSTREAM_KEY, body_bytes, body_json, harness, send};
use doorman_gateway::ai::keys;
use http::{Method, StatusCode};
use serde_json::{Value, json};

const NO_UPSTREAM: &str = "http://127.0.0.1:9";

async fn set_unified(storage: &doorman_gateway::storage::runtime::SharedStorage, unified: Value) {
    storage
        .insert_one(
            "settings",
            json!({"type": "ai_settings", "unified": unified}),
        )
        .await
        .unwrap();
}

fn bearer(key: &str) -> String {
    format!("Bearer {key}")
}

fn model_ids(body: &Value) -> Vec<String> {
    body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|model| model["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn unified_models_lists_routes_models_and_aliases() {
    let h = harness("gpt", "openai", NO_UPSTREAM, json!({})).await;
    set_unified(
        &h.storage,
        json!({"enabled": true, "routes": [
            {"model": "quick", "targets": [{"api": "gpt/v1", "model": "gpt-x-mini"}]},
            {"model": "nowhere", "targets": [{"api": "other/v1", "model": "x"}]}
        ]}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::GET,
        "/api/ai/v1/models",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["object"], "list");
    let ids = model_ids(&body);
    for expected in ["claude-opus-5-5", "fast", "gemini-x", "gpt-x", "quick"] {
        assert!(
            ids.contains(&expected.to_owned()),
            "{expected} missing from {ids:?}"
        );
    }
    assert!(
        !ids.iter().any(|id| id.ends_with('*') || id == "nowhere"),
        "{ids:?}"
    );
}

#[tokio::test]
async fn unified_requires_a_doorman_key() {
    let h = harness("gpt", "openai", NO_UPSTREAM, json!({})).await;
    let body = json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]});
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x")],
        Some(body.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(body_json(response).await["error"]["message"].is_string());
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", "Bearer dk_not_a_real_key")],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unified_unknown_model_is_404_and_missing_model_is_400() {
    let h = harness("gpt", "openai", NO_UPSTREAM, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(json!({"model": "not-allowed", "messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        body_json(response).await["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not-allowed")
    );
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(json!({"messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unified_turned_off_is_404() {
    let h = harness("gpt", "openai", NO_UPSTREAM, json!({})).await;
    set_unified(&h.storage, json!({"enabled": false, "routes": []})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::GET,
        "/api/ai/v1/models",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        body_json(response).await["error"]["message"]
            .as_str()
            .unwrap()
            .contains("turned off")
    );
}

#[tokio::test]
async fn unified_respects_key_scope() {
    let h = harness("gpt", "openai", NO_UPSTREAM, json!({})).await;
    let scoped = keys::generate_key();
    h.storage
        .insert_one(
            "ai_access_keys",
            json!({"key_id": "key-scoped", "username": "alice", "name": "scoped",
                "key_prefix": keys::key_prefix(&scoped), "key_hash": keys::hash_key(&scoped),
                "revoked": false, "api_scope": ["other/v1"]}),
        )
        .await
        .unwrap();
    let auth = bearer(&scoped);
    let response = send(
        &h.app,
        Method::GET,
        "/api/ai/v1/models",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(model_ids(&body_json(response).await).is_empty());
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unified_rejects_other_paths() {
    let h = harness("gpt", "openai", NO_UPSTREAM, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/embeddings",
        &[("authorization", &auth)],
        Some(json!({"model": "gpt-x", "input": "hi"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(body_json(response).await["error"].is_object());
}

fn chat_reply(model: &str, text: &str) -> Value {
    json!({
        "id": "chatcmpl-up", "object": "chat.completion", "created": 1, "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
    })
}

#[tokio::test]
async fn unified_openai_route_passes_through_and_echoes_the_route_name() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply("gpt-x-mini", "hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, json!({})).await;
    set_unified(
        &h.storage,
        json!({"enabled": true, "routes": [
            {"model": "quick", "targets": [{"api": "gpt/v1", "model": "gpt-x-mini"}]}
        ]}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(json!({"model": "quick", "messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["model"], "quick");
    assert_eq!(body["choices"][0]["message"]["content"], "hello");
    let upstream = fake.last();
    assert_eq!(upstream.path_and_query, "/v1/chat/completions");
    assert_eq!(upstream.json()["model"], "gpt-x-mini");
    assert_eq!(
        upstream.headers["authorization"],
        format!("Bearer {UPSTREAM_KEY}").as_str()
    );
    assert!(!format!("{:?}", upstream.headers).contains(&h.key));
}

#[tokio::test]
async fn unified_openai_stream_ends_with_one_done() {
    let fake = FakeProvider::start(vec![Reply::Sse(vec![
        (Duration::ZERO, "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"he\"}}]}\n\n"),
        (Duration::ZERO, "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n"),
        (Duration::ZERO, "data: [DONE]\n\n"),
    ])])
    .await;
    let h = harness("gpt", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(
            json!({"model": "gpt-x", "stream": true, "stream_options": {"include_usage": true},
            "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let text = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert_eq!(text.matches("data: [DONE]").count(), 1, "{text}");
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    assert_eq!(text.matches("\"content\":\"he\"").count(), 1, "{text}");
    assert!(text.contains("\"completion_tokens\":2"), "{text}");
}

#[tokio::test]
async fn unified_route_fails_over_to_the_next_provider() {
    let down = FakeProvider::start(vec![Reply::status(
        503,
        json!({"error": {"message": "overloaded"}}),
    )])
    .await;
    let up = FakeProvider::start(vec![Reply::ok(chat_reply("gpt-x", "from backup"))]).await;
    let h = harness("gpt", "openai", &down.url, json!({})).await;
    h.storage
        .insert_one(
            "apis",
            json!({
                "api_id": uuid::Uuid::new_v4().to_string(),
                "api_name": "backup", "api_version": "v1", "api_type": "AI",
                "api_ai_provider": "openai", "api_servers": [up.url],
                "api_public": false, "api_auth_required": true,
                "api_allowed_groups": ["ALL"], "api_allowed_roles": [],
                "api_allowed_retry_count": 0, "active": true,
                "api_ai_config": {"credential_group": "prov-cred", "allowed_models": ["gpt-x"],
                    "require_subscription": false}
            }),
        )
        .await
        .unwrap();
    set_unified(
        &h.storage,
        json!({"enabled": true, "routes": [{"model": "best", "targets": [
            {"api": "gpt/v1", "model": "gpt-x"}, {"api": "backup/v1", "model": "gpt-x"}
        ]}]}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(json!({"model": "best", "messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["choices"][0]["message"]["content"], "from backup");
    assert_eq!(body["model"], "best");
    assert_eq!(down.calls().len(), 1);
    assert_eq!(up.calls().len(), 1);
}

#[tokio::test]
async fn unified_client_errors_do_not_fail_over() {
    let refusing = FakeProvider::start(vec![Reply::status(
        400,
        json!({"error": {"message": "bad tool schema", "code": "invalid_value"}}),
    )])
    .await;
    let h = harness("gpt", "openai", &refusing.url, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"]["message"], "bad tool schema");
    assert_eq!(body["error"]["type"], "invalid_request_error");
}

// ── Anthropic and Vertex Claude (translate-anthropic) ──────────────────────

const ANTHROPIC_SSE: [&str; 4] = [
    "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
    "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n",
    "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
];

fn anthropic_message(content: Value, stop_reason: &str) -> Value {
    json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
        "content": content, "stop_reason": stop_reason,
        "usage": {"input_tokens": 12, "output_tokens": 5}})
}

async fn wait_for_usage(
    storage: &doorman_gateway::storage::runtime::SharedStorage,
    requests: i64,
) -> Value {
    for _ in 0..100 {
        let rows = storage
            .find_many("ai_usage_daily", &json!({}))
            .await
            .unwrap();
        let total: i64 = rows.iter().filter_map(|row| row["requests"].as_i64()).sum();
        if total >= requests {
            return rows[0].clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("AI usage was not recorded");
}

async fn chat(h: &ai_common::Harness, body: Value) -> http::Response<axum::body::Body> {
    let auth = bearer(&h.key);
    send(
        &h.app,
        Method::POST,
        "/api/ai/v1/chat/completions",
        &[("authorization", &auth)],
        Some(body),
    )
    .await
}

#[tokio::test]
async fn unified_anthropic_text_round_trip_records_native_usage() {
    let fake = FakeProvider::start(vec![Reply::ok(anthropic_message(
        json!([{"type": "text", "text": "Hello there"}]),
        "end_turn",
    ))])
    .await;
    let h = harness("claude", "anthropic", &fake.url, json!({})).await;
    let response = chat(
        &h,
        json!({"model": "claude-opus-5-5", "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "hi"}
        ]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["object"], "chat.completion");
    assert_eq!(body["model"], "claude-opus-5-5");
    assert_eq!(body["choices"][0]["message"]["content"], "Hello there");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 12);
    assert_eq!(body["usage"]["completion_tokens"], 5);
    let upstream = fake.last();
    assert_eq!(upstream.path_and_query, "/v1/messages");
    assert_eq!(upstream.headers["x-api-key"], UPSTREAM_KEY);
    let sent = upstream.json();
    assert_eq!(sent["model"], "claude-opus-5-5");
    assert!(sent["max_tokens"].as_u64().is_some_and(|max| max > 0));
    assert!(sent["system"].to_string().contains("Be brief."));
    assert_eq!(sent["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        sent["metadata"]["user_id"],
        doorman_gateway::ai::hashed_user_id("alice")
    );
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["provider"], "anthropic");
    assert_eq!(row["input_tokens"], 12);
    assert_eq!(row["output_tokens"], 5);
}

#[tokio::test]
async fn unified_anthropic_stream_becomes_openai_chunks_with_usage() {
    let fake = FakeProvider::start(vec![Reply::Sse(
        ANTHROPIC_SSE
            .iter()
            .map(|chunk| (Duration::from_millis(5), *chunk))
            .collect(),
    )])
    .await;
    let h = harness("claude", "anthropic", &fake.url, json!({})).await;
    let response = chat(
        &h,
        json!({"model": "claude-opus-5-5", "stream": true, "stream_options": {"include_usage": true},
            "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let text = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    assert_eq!(text.matches("data: [DONE]").count(), 1, "{text}");
    let chunks: Vec<Value> = text
        .split("\n\n")
        .filter_map(|event| event.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    assert!(
        chunks
            .iter()
            .all(|c| c["object"] == "chat.completion.chunk")
    );
    assert!(chunks.iter().all(|c| c["model"] == "claude-opus-5-5"));
    let ids: std::collections::HashSet<_> = chunks.iter().map(|c| c["id"].clone()).collect();
    assert_eq!(ids.len(), 1, "one id per stream");
    let content: String = chunks
        .iter()
        .filter_map(|c| c["choices"][0]["delta"]["content"].as_str())
        .collect();
    assert_eq!(content, "Hi");
    assert!(
        chunks
            .iter()
            .any(|c| c["choices"][0]["finish_reason"] == "stop")
    );
    let usage = chunks
        .iter()
        .rev()
        .find(|c| c["usage"].is_object())
        .unwrap();
    assert_eq!(usage["choices"], json!([]));
    assert_eq!(usage["usage"]["prompt_tokens"], 12);
    assert_eq!(usage["usage"]["completion_tokens"], 5);
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["output_tokens"], 5);
}

#[tokio::test]
async fn unified_anthropic_tool_calls_round_trip() {
    let fake = FakeProvider::start(vec![
        Reply::ok(anthropic_message(
            json!([{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Oslo"}}]),
            "tool_use",
        )),
        Reply::ok(anthropic_message(
            json!([{"type": "text", "text": "It is 3°C."}]),
            "end_turn",
        )),
    ])
    .await;
    let h = harness("claude", "anthropic", &fake.url, json!({})).await;
    let tools = json!([{"type": "function", "function": {"name": "get_weather",
        "description": "Weather by city",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]);
    let response = chat(
        &h,
        json!({"model": "claude-opus-5-5", "tools": tools,
            "messages": [{"role": "user", "content": "Weather in Oslo?"}]}),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["choices"][0]["finish_reason"], "tool_calls", "{body}");
    let call = &body["choices"][0]["message"]["tool_calls"][0];
    assert_eq!(call["id"], "toolu_1");
    assert_eq!(call["type"], "function");
    assert_eq!(call["function"]["name"], "get_weather");
    let arguments: Value =
        serde_json::from_str(call["function"]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(arguments, json!({"city": "Oslo"}));
    assert_eq!(
        fake.last().json()["tools"][0]["input_schema"]["required"],
        json!(["city"])
    );

    let response = chat(
        &h,
        json!({"model": "claude-opus-5-5", "tools": tools, "messages": [
            {"role": "user", "content": "Weather in Oslo?"},
            {"role": "assistant", "content": null, "tool_calls": [call]},
            {"role": "tool", "tool_call_id": "toolu_1", "content": "3°C"}
        ]}),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["choices"][0]["message"]["content"], "It is 3°C.",
        "{body}"
    );
    let sent = fake.last().json();
    let sent_text = sent["messages"].to_string();
    assert!(
        sent_text.contains("\"tool_use\"") && sent_text.contains("\"tool_result\""),
        "{sent}"
    );
    assert!(sent_text.contains("toolu_1"), "{sent}");
}

#[tokio::test]
async fn unified_guardrails_redact_the_translated_request() {
    let fake = FakeProvider::start(vec![Reply::ok(anthropic_message(
        json!([{"type": "text", "text": "ok"}]),
        "end_turn",
    ))])
    .await;
    let h = harness("claude", "anthropic", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_guardrails",
            json!({"guardrail_id": "pii", "name": "rail-pii", "enabled": true,
                "applies_to": {"apis": ["*"], "groups": ["*"]}, "direction": "input",
                "detectors": [{"type": "builtin", "id": "email"}], "action": "redact", "mode": "enforce"}),
        )
        .await
        .unwrap();
    let response = chat(
        &h,
        json!({"model": "claude-opus-5-5", "messages": [{"role": "user", "content": "mail jane@example.com"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-doorman-ai-redactions"], "1");
    assert!(!fake.last().json().to_string().contains("jane@example.com"));
}

#[tokio::test]
async fn unified_vertex_alias_for_claude_uses_the_anthropic_publisher() {
    let fake = FakeProvider::start(vec![Reply::ok(anthropic_message(
        json!([{"type": "text", "text": "from vertex"}]),
        "end_turn",
    ))])
    .await;
    let h = ai_common::harness_with_key(
        "corp-vertex",
        "vertex",
        &fake.url,
        json!({"api_ai_config": {
            "credential_group": "prov-cred",
            "allowed_models": ["claude-opus-5-5", "gemini-x"],
            "model_aliases": {"smart": "claude-opus-5-5"},
            "region": "us-east5",
        }}),
        &ai_common::vertex_service_account(&fake, "acme-ai"),
        |_| {},
    )
    .await;
    let response = chat(
        &h,
        json!({"model": "smart", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["model"], "smart");
    assert_eq!(body["choices"][0]["message"]["content"], "from vertex");
    let call = fake.last();
    assert_eq!(
        call.path_and_query,
        "/v1/projects/acme-ai/locations/us-east5/publishers/anthropic/models/claude-opus-5-5:rawPredict"
    );
    assert!(call.json().get("model").is_none(), "{}", call.json());
    assert!(call.json()["anthropic_version"].is_string());
}

#[tokio::test]
async fn unified_budget_block_is_final_and_does_not_fail_over() {
    let primary = FakeProvider::start(vec![Reply::ok(chat_reply("gpt-x", "first"))]).await;
    let backup = FakeProvider::start(vec![Reply::ok(chat_reply("gpt-x", "backup"))]).await;
    let h = harness("gpt", "openai", &primary.url, json!({})).await;
    h.storage
        .insert_one(
            "apis",
            json!({
                "api_id": uuid::Uuid::new_v4().to_string(),
                "api_name": "backup", "api_version": "v1", "api_type": "AI",
                "api_ai_provider": "openai", "api_servers": [backup.url],
                "api_public": false, "api_auth_required": true,
                "api_allowed_groups": ["ALL"], "api_allowed_roles": [],
                "api_allowed_retry_count": 0, "active": true,
                "api_ai_config": {"credential_group": "prov-cred", "allowed_models": ["gpt-x"],
                    "require_subscription": false}
            }),
        )
        .await
        .unwrap();
    h.storage
        .insert_one(
            "ai_budgets",
            json!({"budget_id": "one", "name": "one", "scope": "api", "target": "gpt/v1",
                "period": "month", "limit_type": "requests", "limit_value": 1,
                "action": "block", "enabled": true}),
        )
        .await
        .unwrap();
    set_unified(
        &h.storage,
        json!({"enabled": true, "routes": [{"model": "best", "targets": [
            {"api": "gpt/v1", "model": "gpt-x"}, {"api": "backup/v1", "model": "gpt-x"}
        ]}]}),
    )
    .await;
    let body = json!({"model": "best", "messages": [{"role": "user", "content": "hi"}]});
    assert_eq!(chat(&h, body.clone()).await.status(), StatusCode::OK);
    wait_for_usage(&h.storage, 1).await;
    let mut blocked = None;
    for _ in 0..50 {
        let response = chat(&h, body.clone()).await;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            blocked = Some(body_json(response).await);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let blocked = blocked.expect("the second request should hit the allowance");
    assert_eq!(blocked["error"]["type"], "rate_limit_error", "{blocked}");
    assert!(blocked["error"]["code"].is_string(), "{blocked}");
    assert!(
        backup.calls().is_empty(),
        "a budget block must not fall through"
    );
}

#[tokio::test]
async fn unified_azure_uses_the_deployment_path() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply("gpt-x", "from azure"))]).await;
    let h = harness("az", "azure_openai", &fake.url, json!({})).await;
    let response = chat(
        &h,
        json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["choices"][0]["message"]["content"], "from azure");
    let call = fake.last();
    assert!(
        call.path_and_query
            .starts_with("/openai/deployments/gpt-x/chat/completions"),
        "{}",
        call.path_and_query
    );
    assert_eq!(call.headers["api-key"], UPSTREAM_KEY);
}

// ── Gemini and Vertex Gemini (translate-gemini) ─────────────────────────────

fn gemini_reply(parts: Value, finish: &str) -> Value {
    json!({
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish, "index": 0}],
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3, "totalTokenCount": 10}
    })
}

#[tokio::test]
async fn unified_gemini_text_round_trip() {
    let fake = FakeProvider::start(vec![Reply::ok(gemini_reply(
        json!([{"text": "Hello from Gemini"}]),
        "STOP",
    ))])
    .await;
    let h = harness("gem", "gemini", &fake.url, json!({})).await;
    let response = chat(
        &h,
        json!({"model": "gemini-x", "max_tokens": 50, "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "again"}
        ]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "Hello from Gemini"
    );
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 7);
    assert_eq!(body["usage"]["completion_tokens"], 3);
    let call = fake.last();
    assert_eq!(
        call.path_and_query,
        "/v1beta/models/gemini-x:generateContent"
    );
    assert_eq!(call.headers["x-goog-api-key"], UPSTREAM_KEY);
    let sent = call.json();
    assert!(sent["systemInstruction"].to_string().contains("Be brief."));
    assert_eq!(sent["contents"][1]["role"], "model");
    assert_eq!(sent["generationConfig"]["maxOutputTokens"], 50);
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["provider"], "gemini");
    assert_eq!(row["input_tokens"], 7);
}

#[tokio::test]
async fn unified_gemini_stream_uses_sse_and_reports_usage() {
    let fake = FakeProvider::start(vec![Reply::Sse(vec![
        (Duration::from_millis(5), "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hel\"}]},\"index\":0}]}\n\n"),
        (Duration::from_millis(5), "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"lo\"}]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":7,\"candidatesTokenCount\":2,\"totalTokenCount\":9}}\n\n"),
    ])])
    .await;
    let h = harness("gem", "gemini", &fake.url, json!({})).await;
    let response = chat(
        &h,
        json!({"model": "gemini-x", "stream": true, "stream_options": {"include_usage": true},
            "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let text = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert_eq!(text.matches("data: [DONE]").count(), 1, "{text}");
    let chunks: Vec<Value> = text
        .split("\n\n")
        .filter_map(|event| event.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    let content: String = chunks
        .iter()
        .filter_map(|c| c["choices"][0]["delta"]["content"].as_str())
        .collect();
    assert_eq!(content, "Hello");
    assert!(
        chunks
            .iter()
            .any(|c| c["choices"][0]["finish_reason"] == "stop")
    );
    let usage = chunks
        .iter()
        .rev()
        .find(|c| c["usage"].is_object())
        .unwrap();
    assert_eq!(usage["usage"]["completion_tokens"], 2);
    assert_eq!(
        fake.last().path_and_query,
        "/v1beta/models/gemini-x:streamGenerateContent?alt=sse"
    );
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["output_tokens"], 2);
}

#[tokio::test]
async fn unified_gemini_function_call_becomes_tool_call() {
    let fake = FakeProvider::start(vec![Reply::ok(gemini_reply(
        json!([{"functionCall": {"name": "get_weather", "args": {"city": "Oslo"}}}]),
        "STOP",
    ))])
    .await;
    let h = harness("gem", "gemini", &fake.url, json!({})).await;
    let response = chat(
        &h,
        json!({"model": "gemini-x", "messages": [{"role": "user", "content": "Weather in Oslo?"}],
            "tools": [{"type": "function", "function": {"name": "get_weather",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}},
                    "additionalProperties": false}}}]}),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["choices"][0]["finish_reason"], "tool_calls", "{body}");
    let call = &body["choices"][0]["message"]["tool_calls"][0];
    assert_eq!(call["function"]["name"], "get_weather");
    let arguments: Value =
        serde_json::from_str(call["function"]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(arguments, json!({"city": "Oslo"}));
    let sent = fake.last().json();
    let declaration = &sent["tools"][0]["functionDeclarations"][0];
    assert_eq!(declaration["name"], "get_weather");
    assert!(
        !declaration.to_string().contains("additionalProperties"),
        "{declaration}"
    );
}

#[tokio::test]
async fn unified_vertex_gemini_uses_the_google_publisher() {
    let fake = FakeProvider::start(vec![Reply::ok(gemini_reply(
        json!([{"text": "from vertex gemini"}]),
        "STOP",
    ))])
    .await;
    let h = ai_common::harness_with_key(
        "corp-vertex",
        "vertex",
        &fake.url,
        json!({"api_ai_config": {
            "credential_group": "prov-cred",
            "allowed_models": ["claude-opus-5-5", "gemini-x"],
            "region": "us-east5",
        }}),
        &ai_common::vertex_service_account(&fake, "acme-ai"),
        |_| {},
    )
    .await;
    let response = chat(
        &h,
        json!({"model": "gemini-x", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "from vertex gemini"
    );
    assert_eq!(
        fake.last().path_and_query,
        "/v1/projects/acme-ai/locations/us-east5/publishers/google/models/gemini-x:generateContent"
    );
    assert_eq!(
        fake.last().headers["authorization"],
        "Bearer ya29.fake-token-1"
    );
}

// ── Bedrock Converse (translate-converse) ───────────────────────────────────

const BEDROCK_MODEL: &str = "us.anthropic.claude-sonnet-5-5";

async fn bedrock_harness(fake: &FakeProvider) -> ai_common::Harness {
    ai_common::harness_with_key(
        "corp-bedrock",
        "bedrock",
        &fake.url,
        json!({"api_ai_config": {
            "credential_group": "prov-cred",
            "allowed_models": ["us.anthropic.*"],
            "region": "us-west-2",
        }}),
        ai_common::BEDROCK_IAM_KEY,
        |_| {},
    )
    .await
}

fn bedrock_frame(headers: &[(&str, &str)], payload: Value) -> Vec<u8> {
    doorman_gateway::ai::eventstream::encode(headers, payload.to_string().as_bytes())
}

fn bedrock_event(event_type: &str, payload: Value) -> Vec<u8> {
    bedrock_frame(
        &[
            (":event-type", event_type),
            (":content-type", "application/json"),
            (":message-type", "event"),
        ],
        payload,
    )
}

fn stream_chunks(text: &str) -> Vec<Value> {
    text.split("\n\n")
        .filter_map(|event| event.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

#[tokio::test]
async fn unified_bedrock_converse_is_signed_and_translated() {
    let fake = FakeProvider::start(vec![Reply::ok(json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "Hello"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 9, "outputTokens": 4, "totalTokens": 13},
        "metrics": {"latencyMs": 100}
    }))])
    .await;
    let h = bedrock_harness(&fake).await;
    let response = chat(
        &h,
        json!({"model": BEDROCK_MODEL, "max_tokens": 64, "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "hi"}
        ]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["choices"][0]["message"]["content"], "Hello");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    assert_eq!(body["usage"]["prompt_tokens"], 9);
    let call = fake.last();
    assert_eq!(
        call.path_and_query,
        format!("/model/{BEDROCK_MODEL}/converse")
    );
    assert!(
        call.headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    );
    let sent = call.json();
    assert_eq!(sent["system"][0]["text"], "Be brief.");
    assert_eq!(sent["messages"][0]["content"][0]["text"], "hi");
    assert_eq!(sent["inferenceConfig"]["maxTokens"], 64);
    assert!(sent.get("model").is_none());
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["provider"], "bedrock");
    assert_eq!(row["input_tokens"], 9);
}

#[tokio::test]
async fn unified_bedrock_stream_frames_become_openai_chunks() {
    let mut stream = Vec::new();
    stream.extend(bedrock_event("messageStart", json!({"role": "assistant"})));
    stream.extend(bedrock_event(
        "contentBlockDelta",
        json!({"contentBlockIndex": 0, "delta": {"text": "Hel"}}),
    ));
    stream.extend(bedrock_event(
        "contentBlockDelta",
        json!({"contentBlockIndex": 0, "delta": {"text": "lo"}}),
    ));
    stream.extend(bedrock_event(
        "messageStop",
        json!({"stopReason": "end_turn"}),
    ));
    stream.extend(bedrock_event(
        "metadata",
        json!({"usage": {"inputTokens": 11, "outputTokens": 6, "totalTokens": 17},
            "metrics": {"latencyMs": 90}}),
    ));
    let fake = FakeProvider::start(vec![Reply::Binary {
        content_type: "application/vnd.amazon.eventstream",
        chunks: stream.chunks(7).map(<[u8]>::to_vec).collect(),
    }])
    .await;
    let h = bedrock_harness(&fake).await;
    let response = chat(
        &h,
        json!({"model": BEDROCK_MODEL, "stream": true, "stream_options": {"include_usage": true},
            "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let text = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert_eq!(text.matches("data: [DONE]").count(), 1, "{text}");
    let chunks = stream_chunks(&text);
    let content: String = chunks
        .iter()
        .filter_map(|c| c["choices"][0]["delta"]["content"].as_str())
        .collect();
    assert_eq!(content, "Hello");
    assert!(
        chunks
            .iter()
            .any(|c| c["choices"][0]["finish_reason"] == "stop")
    );
    let usage = chunks
        .iter()
        .rev()
        .find(|c| c["usage"].is_object())
        .unwrap();
    assert_eq!(usage["usage"]["prompt_tokens"], 11);
    assert_eq!(usage["usage"]["completion_tokens"], 6);
    assert_eq!(
        fake.last().path_and_query,
        format!("/model/{BEDROCK_MODEL}/converse-stream")
    );
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["output_tokens"], 6);
}

#[tokio::test]
async fn unified_bedrock_exception_mid_stream_becomes_an_error_line() {
    let mut stream = Vec::new();
    stream.extend(bedrock_event("messageStart", json!({"role": "assistant"})));
    stream.extend(bedrock_event(
        "contentBlockDelta",
        json!({"contentBlockIndex": 0, "delta": {"text": "Hel"}}),
    ));
    stream.extend(bedrock_frame(
        &[
            (":exception-type", "throttlingException"),
            (":content-type", "application/json"),
            (":message-type", "exception"),
        ],
        json!({"message": "Too many tokens, please wait"}),
    ));
    let fake = FakeProvider::start(vec![Reply::Binary {
        content_type: "application/vnd.amazon.eventstream",
        chunks: vec![stream],
    }])
    .await;
    let h = bedrock_harness(&fake).await;
    let response = chat(
        &h,
        json!({"model": BEDROCK_MODEL, "stream": true,
            "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let text = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    let chunks = stream_chunks(&text);
    let error = chunks
        .iter()
        .find(|c| c["error"].is_object())
        .expect("an error line");
    assert_eq!(error["error"]["message"], "Too many tokens, please wait");
    assert!(text.contains("\"content\":\"Hel\""), "{text}");
}
