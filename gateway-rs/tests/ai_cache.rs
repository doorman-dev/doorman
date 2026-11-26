//! Step 6: exact-match AI response caching.
//! Run one at a time: `cargo test -p doorman-gateway --test ai_cache <name> -- --exact`.

#[path = "common/ai.rs"]
mod ai_common;

use std::time::Duration;

use ai_common::{FakeProvider, Harness, Reply, body_bytes, body_json, harness, send};
use axum::{body::Body, http::Response};
use doorman_gateway::ai::keys;
use http::{Method, StatusCode};
use serde_json::{Value, json};

const CHAT: &str = "/api/ai/gpt/v1/v1/chat/completions";

fn cached(scope: &str) -> Value {
    json!({"api_ai_config": {
        "credential_group": "prov-cred",
        "allowed_models": ["gpt-x", "gpt-x-mini*", "claude-opus-5-5", "gemini-x"],
        "cache": {"enabled": true, "ttl_seconds": 3600, "scope": scope},
    }})
}

fn reply(text: &str) -> Value {
    json!({
        "id": "chatcmpl-up", "object": "chat.completion", "created": 1, "model": "gpt-x",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
    })
}

fn ask(content: &str) -> Value {
    json!({"model": "gpt-x", "messages": [{"role": "user", "content": content}]})
}

async fn post(h: &Harness, key: &str, body: Value, extra: &[(&str, &str)]) -> Response<Body> {
    let auth = format!("Bearer {key}");
    let mut headers = vec![("authorization", auth.as_str())];
    headers.extend_from_slice(extra);
    send(&h.app, Method::POST, CHAT, &headers, Some(body)).await
}

fn cache_header(response: &Response<Body>) -> String {
    response
        .headers()
        .get("x-doorman-cache")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

/// Sums the daily rollup once `requests` have been recorded.
async fn usage_totals(h: &Harness, requests: i64) -> Value {
    for _ in 0..100 {
        let rows = h
            .storage
            .find_many("ai_usage_daily", &json!({}))
            .await
            .unwrap();
        let sum = |field: &str| -> i64 { rows.iter().filter_map(|row| row[field].as_i64()).sum() };
        if sum("requests") >= requests {
            return json!({
                "requests": sum("requests"), "cache_hits": sum("cache_hits"),
                "input_tokens": sum("input_tokens"), "output_tokens": sum("output_tokens"),
                "saved_input_tokens": sum("saved_input_tokens"),
                "saved_output_tokens": sum("saved_output_tokens"),
            });
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("AI usage was not recorded");
}

/// Waits for the background cache write after a miss.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn add_user(h: &Harness, username: &str) -> String {
    add_user_in(h, username, &["ALL", "eng"]).await
}

async fn add_user_in(h: &Harness, username: &str, groups: &[&str]) -> String {
    h.storage
        .insert_one(
            "users",
            json!({"username": username, "email": format!("{username}@example.com"), "password": "unused",
                "role": "developer", "groups": groups, "active": true}),
        )
        .await
        .unwrap();
    h.storage
        .insert_one(
            "subscriptions",
            json!({"username": username, "apis": ["gpt/v1"]}),
        )
        .await
        .unwrap();
    let key = keys::generate_key();
    h.storage
        .insert_one(
            "ai_access_keys",
            json!({"key_id": format!("key-{username}"), "username": username, "name": "test",
                "key_prefix": keys::key_prefix(&key), "key_hash": keys::hash_key(&key), "revoked": false}),
        )
        .await
        .unwrap();
    key
}

#[tokio::test]
async fn cache_is_off_by_default() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, json!({})).await;
    for _ in 0..2 {
        let response = post(&h, &h.key, ask("hi"), &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(cache_header(&response), "off");
        settle().await;
    }
    assert_eq!(fake.calls().len(), 2);
}

#[tokio::test]
async fn second_identical_request_is_a_free_hit() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    let first = post(&h, &h.key, ask("hi"), &[]).await;
    assert_eq!(cache_header(&first), "miss");
    let first_body = body_bytes(first).await;
    settle().await;
    // Same request with keys in another order.
    let reordered: Value =
        serde_json::from_str(r#"{"messages":[{"content":"hi","role":"user"}],"model":"gpt-x"}"#)
            .unwrap();
    let second = post(&h, &h.key, reordered, &[]).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(cache_header(&second), "hit");
    assert_eq!(second.headers()["x-doorman-ai-model"], "gpt-x");
    assert_eq!(body_bytes(second).await, first_body);
    assert_eq!(fake.calls().len(), 1, "the provider is called once");
    let totals = usage_totals(&h, 2).await;
    assert_eq!(totals["requests"], 2);
    assert_eq!(totals["cache_hits"], 1);
    assert_eq!(totals["input_tokens"], 7, "only the miss used tokens");
    assert_eq!(totals["saved_input_tokens"], 7);
    assert_eq!(totals["saved_output_tokens"], 3);
    // A different prompt is a miss.
    let third = post(&h, &h.key, ask("something else"), &[]).await;
    assert_eq!(cache_header(&third), "miss");
    assert_eq!(fake.calls().len(), 2);
}

#[tokio::test]
async fn user_scope_keeps_answers_per_person_and_shared_scope_does_not() {
    for (scope, bob_hits) in [("user", false), ("shared", true)] {
        let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
        let h = harness("gpt", "openai", &fake.url, cached(scope)).await;
        let bob = add_user(&h, "bob").await;
        assert_eq!(
            cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
            "miss"
        );
        settle().await;
        let response = post(&h, &bob, ask("hi"), &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        let expected = if bob_hits { "hit" } else { "miss" };
        assert_eq!(cache_header(&response), expected, "scope {scope}");
        assert_eq!(
            fake.calls().len(),
            if bob_hits { 1 } else { 2 },
            "scope {scope}"
        );
    }
}

#[tokio::test]
async fn clients_can_bypass_the_cache() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    for header in [
        ("cache-control", "no-store"),
        ("cache-control", "no-cache"),
        ("x-doorman-cache", "bypass"),
    ] {
        let response = post(&h, &h.key, ask("hi"), &[header]).await;
        assert_eq!(cache_header(&response), "bypass", "{header:?}");
    }
    assert_eq!(fake.calls().len(), 4);
    assert_eq!(cache_header(&post(&h, &h.key, ask("hi"), &[]).await), "hit");
}

#[tokio::test]
async fn errors_are_never_cached() {
    let fake = FakeProvider::start(vec![
        Reply::status(500, json!({"error": {"message": "boom"}})),
        Reply::status(400, json!({"error": {"message": "bad"}})),
        Reply::ok(reply("hello")),
    ])
    .await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    let first = post(&h, &h.key, ask("hi"), &[]).await;
    assert!(first.status().is_server_error());
    settle().await;
    let second = post(&h, &h.key, ask("hi"), &[]).await;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    settle().await;
    let third = post(&h, &h.key, ask("hi"), &[]).await;
    assert_eq!(third.status(), StatusCode::OK);
    assert_eq!(cache_header(&third), "miss");
    settle().await;
    assert_eq!(cache_header(&post(&h, &h.key, ask("hi"), &[]).await), "hit");
    assert_eq!(fake.calls().len(), 3);
}

const SSE: [&str; 3] = [
    "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n\n",
    "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n",
    "data: [DONE]\n\n",
];

fn ask_stream(content: &str) -> Value {
    json!({"model": "gpt-x", "stream": true, "stream_options": {"include_usage": true},
        "messages": [{"role": "user", "content": content}]})
}

#[tokio::test]
async fn streams_are_recorded_and_replayed_byte_for_byte() {
    let fake = FakeProvider::start(vec![Reply::Sse(
        SSE.iter()
            .map(|chunk| (Duration::from_millis(5), *chunk))
            .collect(),
    )])
    .await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    let first = post(&h, &h.key, ask_stream("hi"), &[]).await;
    assert_eq!(cache_header(&first), "miss");
    let first_bytes = body_bytes(first).await;
    assert_eq!(first_bytes, SSE.concat().as_bytes());
    settle().await;
    let second = post(&h, &h.key, ask_stream("hi"), &[]).await;
    assert_eq!(cache_header(&second), "hit");
    assert!(
        second.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    assert_eq!(body_bytes(second).await, first_bytes);
    assert_eq!(fake.calls().len(), 1);
    // A streamed and a non-streamed request are cached separately.
    fake.set_replies(vec![Reply::ok(reply("hello"))]);
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
    let totals = usage_totals(&h, 3).await;
    assert_eq!(totals["cache_hits"], 1);
    assert_eq!(totals["saved_output_tokens"], 2);
}

#[tokio::test]
async fn streams_with_an_error_event_are_not_cached() {
    let fake = FakeProvider::start(vec![Reply::Sse(vec![
        (Duration::from_millis(5), SSE[0]),
        (
            Duration::from_millis(5),
            "data: {\"error\":{\"message\":\"overloaded\",\"type\":\"server_error\"}}\n\n",
        ),
    ])])
    .await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    body_bytes(post(&h, &h.key, ask_stream("hi"), &[]).await).await;
    settle().await;
    let second = post(&h, &h.key, ask_stream("hi"), &[]).await;
    assert_eq!(cache_header(&second), "miss");
    body_bytes(second).await;
    assert_eq!(fake.calls().len(), 2);
}

#[tokio::test]
async fn hits_count_request_allowances_but_not_tokens() {
    // Request allowance: a hit is still a request (decision 8, revised).
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    h.storage
        .insert_one(
            "ai_budgets",
            json!({"budget_id": "one", "name": "one", "scope": "api", "target": "gpt/v1",
                "period": "month", "limit_type": "requests", "limit_value": 1,
                "action": "block", "enabled": true}),
        )
        .await
        .unwrap();
    assert_eq!(
        post(&h, &h.key, ask("hi"), &[]).await.status(),
        StatusCode::OK
    );
    usage_totals(&h, 1).await;
    settle().await;
    let mut blocked = false;
    for _ in 0..50 {
        if post(&h, &h.key, ask("hi"), &[]).await.status() == StatusCode::TOO_MANY_REQUESTS {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(blocked, "the request allowance applies to hits");
    assert_eq!(fake.calls().len(), 1);

    // Token allowance: used up by the miss, yet hits are still served free.
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    h.storage
        .insert_one(
            "ai_budgets",
            json!({"budget_id": "tok", "name": "tok", "scope": "api", "target": "gpt/v1",
                "period": "month", "limit_type": "tokens", "limit_value": 5,
                "action": "block", "enabled": true}),
        )
        .await
        .unwrap();
    post(&h, &h.key, ask("hi"), &[]).await;
    usage_totals(&h, 1).await;
    settle().await;
    for _ in 0..3 {
        let hit = post(&h, &h.key, ask("hi"), &[]).await;
        assert_eq!(hit.status(), StatusCode::OK);
        assert_eq!(cache_header(&hit), "hit");
    }
    let mut blocked = false;
    for _ in 0..50 {
        if post(&h, &h.key, ask("new question"), &[]).await.status()
            == StatusCode::TOO_MANY_REQUESTS
        {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(blocked, "a new question still hits the token allowance");
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn forwarded_headers_and_query_order_are_part_of_the_key() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    let beta = [("openai-beta", "assistants=v2")];
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &beta).await),
        "miss"
    );
    settle().await;
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &beta).await),
        "hit"
    );
    // A response-changing header differs: not the same request.
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
    settle().await;
    // SDK telemetry headers do not change the answer.
    let sdk = [
        ("x-stainless-package-version", "9.9.9"),
        ("user-agent", "other/1"),
    ];
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &sdk).await),
        "hit"
    );
    let auth = format!("Bearer {}", h.key);
    let mut seen = Vec::new();
    for path in [
        "/api/ai/gpt/v1/v1/chat/completions?a=1&a=2",
        "/api/ai/gpt/v1/v1/chat/completions?a=2&a=1",
    ] {
        let response = send(
            &h.app,
            Method::POST,
            path,
            &[("authorization", &auth)],
            Some(ask("q")),
        )
        .await;
        seen.push(cache_header(&response));
        settle().await;
    }
    assert_eq!(
        seen,
        ["miss", "miss"],
        "repeated query values keep their order"
    );
}

#[tokio::test]
async fn a_replaced_api_never_replays_the_old_apis_answers() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("shared")).await;
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
    settle().await;
    h.storage
        .update_one(
            "apis",
            &json!({"api_name": "gpt"}),
            &json!({"api_id": "replacement-id"}),
        )
        .await
        .unwrap();
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
    settle().await;
    // A tighter output cap is a different request too.
    h.storage
        .update_one(
            "apis",
            &json!({"api_name": "gpt"}),
            &json!({"api_ai_config": {
                "credential_group": "prov-cred", "allowed_models": ["gpt-x"], "max_output_tokens": 16,
                "cache": {"enabled": true, "ttl_seconds": 3600, "scope": "shared"}}}),
        )
        .await
        .unwrap();
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
    assert_eq!(fake.calls().len(), 3);
}

#[tokio::test]
async fn shared_answers_are_partitioned_by_upstream_credential() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let mut config = cached("shared");
    config["api_ai_config"]["credential_overrides"] =
        json!([{"group": "eng", "credential_group": "other-cred"}]);
    let h = harness("gpt", "openai", &fake.url, config).await;
    h.storage
        .insert_one(
            "credit_defs",
            json!({"api_credit_group": "other-cred", "api_key": "other-upstream-key",
                "api_key_header": "authorization", "credit_tiers": []}),
        )
        .await
        .unwrap();
    let outsider = add_user_in(&h, "olga", &["ALL"]).await;
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
    settle().await;
    assert_eq!(
        cache_header(&post(&h, &outsider, ask("hi"), &[]).await),
        "miss"
    );
    settle().await;
    let bob = add_user(&h, "bob").await;
    assert_eq!(
        cache_header(&post(&h, &bob, ask("hi"), &[]).await),
        "hit",
        "same account"
    );
    assert_eq!(fake.calls().len(), 2);
}

#[tokio::test]
async fn a_reused_username_starts_with_an_empty_cache() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    assert_eq!(cache_header(&post(&h, &h.key, ask("hi"), &[]).await), "hit");
    // What deleting and re-creating "alice" does.
    doorman_gateway::ai::cache::forget_user(Some(&h.storage), "alice").await;
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
}

#[tokio::test]
async fn current_output_guardrails_apply_to_cached_answers() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("write to jane@example.com"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("shared")).await;
    assert_eq!(
        post(&h, &h.key, ask("hi"), &[]).await.status(),
        StatusCode::OK
    );
    settle().await;
    h.storage
        .insert_one(
            "ai_guardrails",
            json!({"guardrail_id": "pii-out", "name": "rail-pii-out", "enabled": true,
                "applies_to": {"apis": ["*"], "groups": ["*"]}, "direction": "output",
                "detectors": [{"type": "builtin", "id": "email"}], "action": "block", "mode": "enforce"}),
        )
        .await
        .unwrap();
    let response = post(&h, &h.key, ask("hi"), &[]).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "never replayed past the new rule"
    );
    assert_eq!(cache_header(&response), "miss");
}

#[tokio::test]
async fn streams_cut_off_before_the_end_marker_are_not_cached() {
    let fake = FakeProvider::start(vec![Reply::Sse(vec![
        (Duration::from_millis(5), SSE[0]),
        (Duration::from_millis(5), SSE[1]),
    ])])
    .await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    body_bytes(post(&h, &h.key, ask_stream("hi"), &[]).await).await;
    settle().await;
    let second = post(&h, &h.key, ask_stream("hi"), &[]).await;
    assert_eq!(cache_header(&second), "miss");
    body_bytes(second).await;
    assert_eq!(fake.calls().len(), 2);
}

#[tokio::test]
async fn error_envelopes_with_status_200_are_not_cached() {
    let fake = FakeProvider::start(vec![Reply::ok(json!({
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
        "error": {"message": "partial failure"}
    }))])
    .await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
}

#[tokio::test]
async fn replies_without_usage_are_cached_with_estimated_savings() {
    let mut body = reply("hello");
    body.as_object_mut().unwrap().remove("usage");
    let fake = FakeProvider::start(vec![Reply::ok(body)]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    assert_eq!(cache_header(&post(&h, &h.key, ask("hi"), &[]).await), "hit");
    let totals = usage_totals(&h, 2).await;
    assert_eq!(totals["cache_hits"], 1);
    assert!(totals["saved_output_tokens"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn saved_input_includes_the_providers_own_cache_reads() {
    let mut body = reply("hello");
    body["usage"] = json!({"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10,
        "prompt_tokens_details": {"cached_tokens": 4}});
    let fake = FakeProvider::start(vec![Reply::ok(body)]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    post(&h, &h.key, ask("hi"), &[]).await;
    let totals = usage_totals(&h, 2).await;
    assert_eq!(totals["saved_input_tokens"], 7);
}

#[tokio::test]
async fn hits_use_bandwidth_allowances() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    let used_by_one = 2 * 400;
    h.storage
        .update_one(
            "users",
            &json!({"username": "alice"}),
            &json!({"bandwidth_limit_bytes": used_by_one, "bandwidth_limit_window": "day"}),
        )
        .await
        .unwrap();
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(post(&h, &h.key, ask("hi"), &[]).await.status());
        settle().await;
    }
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "hits count bandwidth: {statuses:?}"
    );
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn purging_an_api_makes_its_entries_unreachable() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("shared")).await;
    post(&h, &h.key, ask("hi"), &[]).await;
    settle().await;
    let api = h
        .storage
        .find_one("apis", &json!({"api_name": "gpt"}))
        .await
        .unwrap()
        .unwrap();
    let namespace = doorman_gateway::ai::cache::api_namespace(api["api_id"].as_str().unwrap());
    let purged = doorman_gateway::ai::cache::purge(Some(&h.storage), &namespace)
        .await
        .unwrap();
    assert_eq!(purged, 1);
    assert_eq!(
        cache_header(&post(&h, &h.key, ask("hi"), &[]).await),
        "miss"
    );
}

#[tokio::test]
async fn guardrail_blocks_still_apply_before_the_cache() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("shared")).await;
    post(&h, &h.key, ask("my email is jane@example.com"), &[]).await;
    settle().await;
    h.storage
        .insert_one(
            "ai_guardrails",
            json!({"guardrail_id": "pii", "name": "rail-pii", "enabled": true,
                "applies_to": {"apis": ["*"], "groups": ["*"]}, "direction": "input",
                "detectors": [{"type": "builtin", "id": "email"}], "action": "block", "mode": "enforce"}),
        )
        .await
        .unwrap();
    let response = post(&h, &h.key, ask("my email is jane@example.com"), &[]).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "blocked, not replayed"
    );
    assert_eq!(
        cache_header(&response),
        "miss",
        "local responses carry the header too"
    );
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn unified_endpoint_requests_hit_the_cache() {
    let fake = FakeProvider::start(vec![Reply::ok(reply("hello"))]).await;
    let h = harness("gpt", "openai", &fake.url, cached("user")).await;
    let auth = format!("Bearer {}", h.key);
    let mut headers_seen = Vec::new();
    for _ in 0..2 {
        let response = send(
            &h.app,
            Method::POST,
            "/api/ai/v1/chat/completions",
            &[("authorization", &auth)],
            Some(ask("hi")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        headers_seen.push(cache_header(&response));
        let body = body_json(response).await;
        assert_eq!(body["choices"][0]["message"]["content"], "hello");
        settle().await;
    }
    assert_eq!(headers_seen, ["miss", "hit"]);
    assert_eq!(fake.calls().len(), 1);
}
