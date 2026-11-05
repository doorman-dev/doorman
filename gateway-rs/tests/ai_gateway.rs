use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "common/ai.rs"]
mod ai_common;
use ai_common::{
    FakeProvider, Reply, UPSTREAM_KEY, body_bytes, body_json, harness, harness_with, send,
};
use std::time::Duration;

fn fixture_password() -> &'static str {
    static PASSWORD: OnceLock<String> = OnceLock::new();
    PASSWORD.get_or_init(|| {
        let bytes = Uuid::new_v4().into_bytes();
        format!(
            "{}{}{}!{}",
            char::from(bytes[0] % 26 + b'A'),
            char::from(bytes[1] % 26 + b'a'),
            char::from(bytes[2] % 10 + b'0'),
            Uuid::new_v4()
        )
    })
}

async fn memory_storage() -> SharedStorage {
    let config = Config::for_test("removed-internal-backend".to_owned());
    SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap()
}

async fn insert_admin_user(storage: &SharedStorage) {
    storage
        .insert_one(
            "users",
            json!({
                "username": "admin", "email": "admin@doorman.dev",
                "password": bcrypt::hash(fixture_password(), 4).unwrap(),
                "role": "admin", "groups": ["ALL", "admin"], "active": true, "ui_access": true
            }),
        )
        .await
        .unwrap();
}

/// Memory-mode gateway with the bootstrap admin role and user.
async fn platform_app() -> (axum::Router, Arc<SharedStorage>) {
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    insert_admin_user(&storage).await;
    storage.initialize_core().await.unwrap();
    let storage = Arc::new(storage);
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(storage.clone());
    (build_router(state), storage)
}

async fn request(
    app: &axum::Router,
    method: Method,
    path: &str,
    auth: Option<&(String, String)>,
    payload: Option<Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .extension(loopback());
    if let Some((cookie, csrf)) = auth {
        builder = builder
            .header(header::COOKIE, cookie)
            .header("x-csrf-token", csrf);
    }
    let body = if let Some(payload) = payload {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(payload.to_string())
    } else {
        Body::empty()
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

async fn login(app: &axum::Router, email: &str, password: &str) -> (String, String) {
    let response = request(
        app,
        Method::POST,
        "/platform/authorization",
        None,
        Some(json!({"email": email, "password": password})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    let csrf = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("csrf_token="))
        .unwrap()
        .to_owned();
    (cookies.join("; "), csrf)
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

fn loopback() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000)))
}

#[tokio::test]
async fn ai_route_is_registered_and_bypasses_envelope() {
    let mut config = Config::for_test("http://127.0.0.1:9".to_owned());
    config.strict_response_envelope = true;
    let app = build_router(AppState::new(config).unwrap());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/ai/corp-openai/v1/v1/chat/completions")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(loopback())
                .body(Body::from(
                    json!({"model": "gpt-x", "messages": []}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // Reaches the AI handler (not the data-plane 404/405 guard).
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    // Native shape: the strict response envelope never wraps AI routes.
    assert!(body.get("status_code").is_none(), "enveloped: {body}");
    assert!(body.get("error_code").is_some(), "unexpected body: {body}");

    // Methods outside GET/POST/OPTIONS are rejected by the route guard.
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/ai/corp-openai/v1/v1/chat/completions")
                .extension(loopback())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn admin_role_has_manage_ai() {
    // Fresh bootstrap creates the admin role with manage_ai.
    let storage = memory_storage().await;
    insert_admin_user(&storage).await;
    storage.initialize_core().await.unwrap();
    let role = storage
        .find_one("roles", &json!({"role_name": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(role["manage_ai"], true);

    // An admin role from before manage_ai existed is backfilled once...
    let storage = memory_storage().await;
    insert_admin_user(&storage).await;
    storage
        .insert_one("roles", json!({"role_name": "admin", "manage_users": true}))
        .await
        .unwrap();
    storage.initialize_core().await.unwrap();
    let role = storage
        .find_one("roles", &json!({"role_name": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(role["manage_ai"], true);
    assert_eq!(role["manage_users"], true);

    // ...but an explicit value set by an operator is respected.
    storage
        .update_one(
            "roles",
            &json!({"role_name": "admin"}),
            &json!({"manage_ai": false}),
        )
        .await
        .unwrap();
    storage.initialize_core().await.unwrap();
    let role = storage
        .find_one("roles", &json!({"role_name": "admin"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(role["manage_ai"], false);
}

#[tokio::test]
async fn role_payload_includes_manage_ai() {
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;

    // The UI reads permissions from GET /platform/role/{name}.
    let role = json_body(
        request(
            &app,
            Method::GET,
            "/platform/role/admin",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(role["manage_ai"], true, "{role}");

    let created = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({"role_name": "ai-admin", "manage_ai": "true"})),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let role = json_body(
        request(
            &app,
            Method::GET,
            "/platform/role/ai-admin",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(role["manage_ai"], true, "{role}");

    let updated = request(
        &app,
        Method::PUT,
        "/platform/role/ai-admin",
        Some(&admin),
        Some(json!({"manage_ai": false})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let role = json_body(
        request(
            &app,
            Method::GET,
            "/platform/role/ai-admin",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(role["manage_ai"], false, "{role}");

    // Roles created without it keep the pinned Python shape (no default materialized).
    let created = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({"role_name": "plain"})),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let role = json_body(
        request(
            &app,
            Method::GET,
            "/platform/role/plain",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert!(role.get("manage_ai").is_none(), "{role}");
    assert_eq!(role["manage_users"], false);

    let invalid = request(
        &app,
        Method::POST,
        "/platform/role",
        Some(&admin),
        Some(json!({"role_name": "bad", "manage_ai": "maybe"})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

const CHAT: &str = "/api/ai/corp-openai/v1/v1/chat/completions";

fn chat_body(model: &str) -> Value {
    json!({"model": model, "messages": [{"role": "user", "content": "hi"}]})
}

fn chat_reply() -> Value {
    json!({"id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-x",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11}})
}

fn bearer(key: &str) -> String {
    format!("Bearer {key}")
}

#[tokio::test]
async fn ai_openai_non_stream_roundtrip_injects_key_and_identifier() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-doorman-ai-model"], "gpt-x");
    assert_eq!(body_json(response).await, chat_reply());
    let call = fake.last();
    assert_eq!(call.method, Method::POST);
    assert_eq!(call.path_and_query, "/v1/chat/completions");
    assert_eq!(
        call.headers["authorization"],
        format!("Bearer {UPSTREAM_KEY}")
    );
    let body = call.json();
    assert_eq!(body["model"], "gpt-x");
    assert_eq!(
        body["safety_identifier"],
        doorman_gateway::ai::hashed_user_id("alice")
    );
    assert_eq!(body["messages"], chat_body("gpt-x")["messages"]);
}

const OPENAI_SSE: [&str; 3] = [
    "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n\n",
    "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\ndata: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2}}\n\n",
    "data: [DONE]\n\n",
];

#[tokio::test]
async fn ai_openai_stream_passes_sse_bytes_verbatim() {
    let fake = FakeProvider::start(vec![Reply::Sse(
        OPENAI_SSE
            .iter()
            .map(|chunk| (Duration::from_millis(5), *chunk))
            .collect(),
    )])
    .await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let mut body = chat_body("gpt-x");
    body["stream"] = json!(true);
    body["stream_options"] = json!({"custom": 1});
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
    assert_eq!(body_bytes(response).await, OPENAI_SSE.concat().as_bytes());
    let upstream = fake.last().json();
    assert_eq!(
        upstream["stream_options"],
        json!({"custom": 1, "include_usage": true})
    );
}

const ANTHROPIC_SSE: [&str; 4] = [
    "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
    "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n",
    "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
];

fn messages_body(stream: bool) -> Value {
    json!({"model": "claude-opus-5-5", "max_tokens": 64, "stream": stream,
        "messages": [{"role": "user", "content": "hi"}]})
}

#[tokio::test]
async fn ai_anthropic_stream_passes_sse_bytes_verbatim() {
    let fake = FakeProvider::start(vec![Reply::Sse(
        ANTHROPIC_SSE
            .iter()
            .map(|chunk| (Duration::from_millis(5), *chunk))
            .collect(),
    )])
    .await;
    let h = harness("corp-claude", "anthropic", &fake.url, json!({})).await;
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/corp-claude/v1/v1/messages",
        &[("x-api-key", &h.key), ("anthropic-beta", "test-beta")],
        Some(messages_body(true)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert_eq!(
        body_bytes(response).await,
        ANTHROPIC_SSE.concat().as_bytes()
    );
    let call = fake.last();
    assert_eq!(call.path_and_query, "/v1/messages");
    assert_eq!(call.headers["x-api-key"], UPSTREAM_KEY);
    assert_eq!(call.headers["anthropic-version"], "2023-06-01");
    assert_eq!(call.headers["anthropic-beta"], "test-beta");
    assert!(call.headers.get("authorization").is_none());
    assert_eq!(
        call.json()["metadata"]["user_id"],
        doorman_gateway::ai::hashed_user_id("alice")
    );
}

#[tokio::test]
async fn ai_rejects_disallowed_model() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-y")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["error_code"], "AI002");
    // Prefix patterns allow a family.
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x-mini-2026")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fake.calls().len(), 1);
    // A body without a model and no default is AI003.
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(json!({"messages": []})),
    )
    .await;
    assert_eq!(body_json(response).await["error_code"], "AI003");
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(CHAT)
                .header("authorization", &auth)
                .extension(loopback())
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error_code"], "AI003");
}

#[tokio::test]
async fn ai_alias_rewrites_model() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("fast")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-doorman-ai-model"], "gpt-x-mini");
    assert_eq!(fake.last().json()["model"], "gpt-x-mini");
}

#[tokio::test]
async fn ai_unknown_operation_is_ai001() {
    let fake = FakeProvider::start(vec![Reply::ok(json!({}))]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    for path in [
        "/api/ai/corp-openai/v1/v1/files",
        "/api/ai/corp-openai/v1/v1/fine_tuning/jobs",
    ] {
        let response = send(
            &h.app,
            Method::POST,
            path,
            &[("authorization", &auth)],
            Some(json!({"model": "gpt-x"})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body_json(response).await["error_code"], "AI001");
    }
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn ai_missing_credential_is_rejected_not_defaulted() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_ai_config": {"credential_group": "nonexistent", "allowed_models": ["gpt-x"]}}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_json(response).await["error_code"], "AI006");
    // An undecryptable stored key is never sent upstream either.
    h.storage
        .insert_one(
            "credit_defs",
            json!({"api_credit_group": "nonexistent", "api_key": "enc:gAAAAA-not-decryptable",
                "api_key_header": "authorization", "credit_tiers": []}),
        )
        .await
        .unwrap();
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(body_json(response).await["error_code"], "AI006");
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn ai_provider_429_is_passed_through_not_rotated() {
    let error = json!({"error": {"message": "Rate limit reached", "type": "requests", "code": "rate_limit_exceeded"}});
    let fake = FakeProvider::start(vec![Reply::Json {
        status: 429,
        body: error.clone(),
        headers: vec![
            ("retry-after", "7"),
            ("x-ratelimit-remaining-requests", "0"),
            ("set-cookie", "upstream=1"),
        ],
    }])
    .await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_allowed_retry_count": 3}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "7");
    assert_eq!(response.headers()["x-ratelimit-remaining-requests"], "0");
    assert!(response.headers().get("set-cookie").is_none());
    assert_eq!(body_json(response).await, error);
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn ai_does_not_retry_500() {
    let fake = FakeProvider::start(vec![Reply::status(
        500,
        json!({"error": {"message": "boom"}}),
    )])
    .await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_allowed_retry_count": 3}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(response).await,
        json!({"error": {"message": "boom"}})
    );
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn ai_retries_502_before_first_byte() {
    let fake = FakeProvider::start(vec![
        Reply::status(502, json!({"error": "bad gateway"})),
        Reply::ok(chat_reply()),
    ])
    .await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_allowed_retry_count": 1}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, chat_reply());
    assert_eq!(fake.calls().len(), 2);
}

#[tokio::test]
async fn ai_first_byte_timeout_is_ai010() {
    let fake = FakeProvider::start(vec![Reply::Delayed(
        Duration::from_millis(1500),
        Box::new(Reply::ok(chat_reply())),
    )])
    .await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_ai_config": {"credential_group": "prov-cred", "allowed_models": ["gpt-x"],
            "first_byte_timeout_ms": 150}}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body_json(response).await["error_code"], "AI010");
}

#[tokio::test]
async fn ai_stream_survives_past_total_timeout() {
    let chunks: Vec<(Duration, &'static str)> = (0..6)
        .map(|_| (Duration::from_millis(150), "data: {\"choices\":[]}\n\n"))
        .collect();
    let fake = FakeProvider::start(vec![Reply::Sse(chunks)]).await;
    // REST would cut this off at 200 ms; the stream lasts ~900 ms.
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_read_timeout": 0.2}),
    )
    .await;
    let auth = bearer(&h.key);
    let mut body = chat_body("gpt-x");
    body["stream"] = json!(true);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(response).await,
        "data: {\"choices\":[]}\n\n".repeat(6).as_bytes()
    );
}

#[tokio::test]
async fn ai_refusal_passes_through_unmodified() {
    let refusal = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
        "content": [], "stop_reason": "refusal", "stop_details": {"type": "refusal"},
        "usage": {"input_tokens": 10, "output_tokens": 0}});
    let fake = FakeProvider::start(vec![Reply::ok(refusal.clone())]).await;
    let h = harness("corp-claude", "anthropic", &fake.url, json!({})).await;
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/corp-claude/v1/v1/messages",
        &[("x-api-key", &h.key)],
        Some(messages_body(false)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, refusal.to_string().as_bytes());
}

#[tokio::test]
async fn ai_requires_subscription_like_rest() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .delete_one("subscriptions", &json!({"username": "alice"}))
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(fake.calls().is_empty());
    // No credential at all is AI007.
    let response = send(&h.app, Method::POST, CHAT, &[], Some(chat_body("gpt-x"))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error_code"], "AI007");
}

#[tokio::test]
async fn ai_group_access_without_subscription_when_configured() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let config = json!({"credential_group": "prov-cred", "allowed_models": ["gpt-x"],
        "require_subscription": false});
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_allowed_groups": ["eng"], "api_ai_config": config}),
    )
    .await;
    h.storage
        .delete_one("subscriptions", &json!({"username": "alice"}))
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let headers = [("authorization", auth.as_str())];
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &headers,
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "alice is in eng");
    // Group membership is still enforced.
    h.storage
        .update_one(
            "apis",
            &json!({"api_name": "corp-openai"}),
            &json!({"api_allowed_groups": ["finance"]}),
        )
        .await
        .unwrap();
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &headers,
        Some(chat_body("gpt-x")),
    )
    .await;
    // Group denial is 401, the same as REST APIs (Python parity).
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ai_retired_version_returns_410() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_lifecycle_status": "retired"}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn ai_response_is_not_enveloped_or_gzipped_when_streaming() {
    let fake = FakeProvider::start(vec![
        Reply::Sse(
            OPENAI_SSE
                .iter()
                .map(|chunk| (Duration::ZERO, *chunk))
                .collect(),
        ),
        Reply::ok(chat_reply()),
    ])
    .await;
    let h = harness_with("corp-openai", "openai", &fake.url, json!({}), |config| {
        config.strict_response_envelope = true;
        config.compression_enabled = true;
    })
    .await;
    let auth = bearer(&h.key);
    let mut body = chat_body("gpt-x");
    body["stream"] = json!(true);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth), ("accept-encoding", "gzip")],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(body_bytes(response).await, OPENAI_SSE.concat().as_bytes());
    // Non-stream JSON keeps the provider's native shape too.
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(body_json(response).await, chat_reply());
}

#[tokio::test]
async fn ai_local_models_list_shows_only_allowed_models() {
    let fake = FakeProvider::start(vec![Reply::ok(json!({}))]).await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        json!({"api_ai_config": {"credential_group": "prov-cred", "allowed_models": ["gpt-x", "gpt-x-mini", "o-*"]}}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::GET,
        "/api/ai/corp-openai/v1/v1/models",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["gpt-x", "gpt-x-mini"]);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn ai_never_forwards_cookies_or_inbound_provider_keys() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        &format!("{CHAT}?key=inbound-query-key&api-key=inbound2&keep=1"),
        &[
            ("authorization", &auth),
            ("cookie", "session=inbound-cookie"),
            ("x-api-key", "inbound-x-api-key"),
            ("x-goog-api-key", "inbound-goog"),
            ("api-key", "inbound-azure"),
            ("x-doorman-user", "mallory"),
        ],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let call = fake.last();
    assert_eq!(call.path_and_query, "/v1/chat/completions?keep=1");
    assert_eq!(
        call.headers["authorization"],
        format!("Bearer {UPSTREAM_KEY}")
    );
    for name in [
        "cookie",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
        "x-doorman-user",
    ] {
        assert!(call.headers.get(name).is_none(), "{name} forwarded");
    }
    let all_headers = format!("{:?}", call.headers);
    assert!(!all_headers.contains(&h.key) && !all_headers.contains("inbound"));
}

#[tokio::test]
async fn ai_gemini_routes_model_path_and_buffers_non_sse_stream() {
    let array = json!([
        {"candidates": [{"content": {"parts": [{"text": "Hel"}]}}]},
        {"candidates": [{"content": {"parts": [{"text": "lo"}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 2}}
    ]);
    let fake = FakeProvider::start(vec![Reply::ok(array.clone())]).await;
    let h = harness("corp-gemini", "gemini", &fake.url, json!({})).await;
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]});
    let response = send(
        &h.app,
        Method::POST,
        &format!(
            "/api/ai/corp-gemini/v1/v1beta/models/gemini-x:streamGenerateContent?key={}",
            h.key
        ),
        &[],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, array);
    let call = fake.last();
    assert_eq!(
        call.path_and_query,
        "/v1beta/models/gemini-x:streamGenerateContent"
    );
    assert_eq!(call.headers["x-goog-api-key"], UPSTREAM_KEY);

    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/corp-gemini/v1/v1beta/models/gemini-y:generateContent",
        &[("x-goog-api-key", &h.key)],
        Some(json!({"contents": []})),
    )
    .await;
    assert_eq!(body_json(response).await["error_code"], "AI002");
}

#[tokio::test]
async fn ai_azure_uses_deployment_as_model_and_keeps_api_version() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-azure", "azure_openai", &fake.url, json!({})).await;
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/corp-azure/v1/openai/deployments/gpt-x/chat/completions?api-version=2024-10-21",
        &[("api-key", &h.key)],
        Some(json!({"messages": [{"role": "user", "content": "hi"}]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let call = fake.last();
    assert_eq!(
        call.path_and_query,
        "/openai/deployments/gpt-x/chat/completions?api-version=2024-10-21"
    );
    assert_eq!(call.headers["api-key"], UPSTREAM_KEY);
    assert!(call.headers.get("authorization").is_none());
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/corp-azure/v1/openai/deployments/other/chat/completions?api-version=2024-10-21",
        &[("api-key", &h.key)],
        Some(json!({"messages": []})),
    )
    .await;
    assert_eq!(body_json(response).await["error_code"], "AI002");
}

async fn create_platform_user(
    app: &axum::Router,
    admin: &(String, String),
    username: &str,
) -> (String, String) {
    let role = request(
        app,
        Method::POST,
        "/platform/role",
        Some(admin),
        Some(json!({"role_name": "ai-dev"})),
    )
    .await;
    assert!(matches!(
        role.status(),
        StatusCode::CREATED | StatusCode::OK | StatusCode::BAD_REQUEST
    ));
    let email = format!("{username}@example.com");
    let response = request(
        app,
        Method::POST,
        "/platform/user",
        Some(admin),
        Some(
            json!({"username": username, "email": email, "password": fixture_password(),
            "role": "ai-dev", "groups": ["ALL"], "ui_access": true}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    login(app, &email, fixture_password()).await
}

#[tokio::test]
async fn ai_providers_catalog_lists_all_providers() {
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/providers",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let providers = body["providers"].as_array().unwrap();
    let ids: Vec<&str> = providers
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "openai",
            "anthropic",
            "gemini",
            "azure_openai",
            "openai_compatible"
        ]
    );
    for provider in providers {
        for field in [
            "id",
            "label",
            "default_server",
            "credential_header",
            "credential_format",
            "sdk_base_url_suffix",
            "supports_user_id",
            "operations",
        ] {
            assert!(
                provider.get(field).is_some(),
                "{field} missing in {provider}"
            );
        }
    }
    assert_eq!(providers[0]["sdk_base_url_suffix"], "/v1");
    assert_eq!(providers[1]["credential_header"], "x-api-key");
    assert_eq!(providers[3]["default_server"], Value::Null);
    // Unauthenticated callers are rejected.
    let response = request(&app, Method::GET, "/platform/ai/providers", None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_list_revoke_ai_key_roundtrip() {
    let (app, storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let created = request(
        &app,
        Method::POST,
        "/platform/ai/keys",
        Some(&admin),
        Some(json!({"name": "laptop", "expires_in_days": 30, "api_scope": ["corp-claude/v1"]})),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    let key = created["key"].as_str().unwrap();
    assert!(key.starts_with("dk_") && key.len() == 43);
    assert_eq!(created["key_prefix"], &key[..10]);
    assert_eq!(created["name"], "laptop");
    assert!(created["expires_at"].as_str().unwrap().ends_with('Z'));
    let key_id = created["key_id"].as_str().unwrap().to_owned();

    let listed =
        json_body(request(&app, Method::GET, "/platform/ai/keys", Some(&admin), None).await).await;
    let keys = listed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["key_id"], key_id.as_str());
    assert_eq!(keys[0]["revoked"], false);
    assert_eq!(keys[0]["api_scope"], json!(["corp-claude/v1"]));
    assert!(keys[0].get("key_hash").is_none());
    let stored = storage
        .find_one("ai_access_keys", &json!({"key_id": key_id}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored["key_hash"], doorman_gateway::ai::keys::hash_key(key));
    assert!(!stored.to_string().contains(key));

    let revoked = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/keys/{key_id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    assert_eq!(
        json_body(revoked).await,
        json!({"message": "AI key revoked", "key_id": key_id})
    );
    let listed =
        json_body(request(&app, Method::GET, "/platform/ai/keys", Some(&admin), None).await).await;
    assert_eq!(listed["keys"][0]["revoked"], true);

    // Validation errors use AI009.
    for payload in [
        json!({"name": ""}),
        json!({"name": "x", "expires_in_days": 0}),
        json!({"name": "x", "expires_in_days": 366}),
        json!({"name": "x", "api_scope": ["no-version"]}),
    ] {
        let response = request(
            &app,
            Method::POST,
            "/platform/ai/keys",
            Some(&admin),
            Some(payload.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{payload}");
        assert_eq!(json_body(response).await["error_code"], "AI009");
    }
    let response = request(
        &app,
        Method::DELETE,
        "/platform/ai/keys/missing",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ai_key_plaintext_never_returned_twice() {
    let (app, storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let created = json_body(
        request(
            &app,
            Method::POST,
            "/platform/ai/keys",
            Some(&admin),
            Some(json!({"name": "ci"})),
        )
        .await,
    )
    .await;
    let key = created["key"].as_str().unwrap().to_owned();
    assert_eq!(created["expires_at"], Value::Null);
    for path in ["/platform/ai/keys", "/platform/ai/keys/user/admin"] {
        let response = request(&app, Method::GET, path, Some(&admin), None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let text = String::from_utf8(
            to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!text.contains(&key), "{path} leaked the key");
        assert!(!text.contains("key_hash"), "{path} leaked the hash");
    }
    let all = storage
        .find_many("ai_access_keys", &json!({}))
        .await
        .unwrap();
    assert!(!serde_json::to_string(&all).unwrap().contains(&key));
    // The 20-active-key limit.
    for index in 0..19 {
        let response = request(
            &app,
            Method::POST,
            "/platform/ai/keys",
            Some(&admin),
            Some(json!({"name": format!("k{index}")})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = request(
        &app,
        Method::POST,
        "/platform/ai/keys",
        Some(&admin),
        Some(json!({"name": "k21"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error_code"], "AI009");
}

#[tokio::test]
async fn user_cannot_revoke_others_key_without_manage_users() {
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let bob = create_platform_user(&app, &admin, "bob").await;
    let bob_key = json_body(
        request(
            &app,
            Method::POST,
            "/platform/ai/keys",
            Some(&bob),
            Some(json!({"name": "bob"})),
        )
        .await,
    )
    .await["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let admin_key = json_body(
        request(
            &app,
            Method::POST,
            "/platform/ai/keys",
            Some(&admin),
            Some(json!({"name": "adm"})),
        )
        .await,
    )
    .await["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Bob cannot revoke or list the admin's keys.
    let response = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/keys/{admin_key}"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/keys/user/admin",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Bob lists only his own keys.
    let mine =
        json_body(request(&app, Method::GET, "/platform/ai/keys", Some(&bob), None).await).await;
    assert_eq!(mine["keys"].as_array().unwrap().len(), 1);
    assert_eq!(mine["keys"][0]["key_id"], bob_key.as_str());
    // The admin (manage_users) can view and revoke Bob's key.
    let theirs = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/keys/user/bob",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(theirs["keys"][0]["key_id"], bob_key.as_str());
    let response = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/keys/{bob_key}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // Bob can revoke his own.
    let own = json_body(
        request(
            &app,
            Method::POST,
            "/platform/ai/keys",
            Some(&bob),
            Some(json!({"name": "bob2"})),
        )
        .await,
    )
    .await["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/keys/{own}"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn credit_def_allows_empty_tiers_over_http() {
    let (app, storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let response = request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&admin),
        Some(
            json!({"api_credit_group": "openai-prod", "api_key": "sk-test",
            "api_key_header": "Authorization", "credit_tiers": []}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let stored = storage
        .find_one("credit_defs", &json!({"api_credit_group": "openai-prod"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored["credit_tiers"], json!([]));
    let response = request(
        &app,
        Method::POST,
        "/platform/credit",
        Some(&admin),
        Some(json!({"api_credit_group": "basic", "api_key": "key",
            "api_key_header": "header", "credit_tiers": []})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

async fn wait_for_usage(storage: &SharedStorage, requests: i64) -> Value {
    for _ in 0..100 {
        let rows = storage
            .find_many("ai_usage_daily", &json!({}))
            .await
            .unwrap();
        let total: i64 = rows.iter().filter_map(|row| row["requests"].as_i64()).sum();
        if total >= requests {
            assert_eq!(rows.len(), 1, "{rows:?}");
            return rows[0].clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("AI usage was not recorded");
}

fn gpt_x_price() -> Value {
    json!({"pricing_id": "p1", "provider": "openai", "model_pattern": "gpt-x",
        "input_usd_per_mtok": 2.0, "output_usd_per_mtok": 8.0, "effective_from": "2026-01-01"})
}

#[tokio::test]
async fn record_usage_upserts_daily_rollup_memory_mode() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one("ai_pricing", gpt_x_price())
        .await
        .unwrap();
    let auth = bearer(&h.key);
    for _ in 0..2 {
        let response = send(
            &h.app,
            Method::POST,
            CHAT,
            &[("authorization", &auth)],
            Some(chat_body("gpt-x")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let row = wait_for_usage(&h.storage, 2).await;
    let day = time::OffsetDateTime::now_utc().date().to_string();
    assert_eq!(row["day"], day.as_str());
    assert_eq!(row["api"], "corp-openai/v1");
    assert_eq!(row["provider"], "openai");
    assert_eq!(row["model"], "gpt-x");
    assert_eq!(row["username"], "alice");
    assert_eq!(row["groups"], json!(["ALL", "eng"]));
    assert_eq!(row["role"], "developer");
    assert_eq!(row["tier"], Value::Null, "no tier assigned");
    assert_eq!(row["requests"], 2);
    assert_eq!(row["errors"], 0);
    assert_eq!(row["input_tokens"], 18);
    assert_eq!(row["output_tokens"], 4);
    // 9 in x $2/MTok (2_000 nanos) + 2 out x $8/MTok (8_000 nanos) per call.
    assert_eq!(row["cost_nanos"], 2 * (9 * 2_000 + 2 * 8_000));
    assert_eq!(row["unpriced_requests"], 0);
    assert_eq!(row["estimated_requests"], 0);
    // Provider errors count as errors with no tokens.
    fake.set_replies(vec![Reply::status(
        400,
        json!({"error": {"message": "bad"}}),
    )]);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let row = wait_for_usage(&h.storage, 3).await;
    assert_eq!(row["errors"], 1);
    assert_eq!(row["input_tokens"], 18);
}

#[tokio::test]
async fn client_disconnect_still_records_estimated_usage() {
    let mut chunks = vec![(Duration::ZERO, OPENAI_SSE[0])];
    chunks.extend((0..20).map(|_| (Duration::from_millis(100), "data: {\"choices\":[]}\n\n")));
    let fake = FakeProvider::start(vec![Reply::Sse(chunks)]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let auth = bearer(&h.key);
    let mut body = chat_body("gpt-x");
    body["stream"] = json!(true);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    use futures_util::StreamExt;
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(first, OPENAI_SSE[0].as_bytes());
    drop(stream); // client goes away mid-stream
    let row = wait_for_usage(&h.storage, 1).await;
    assert_eq!(row["requests"], 1);
    assert_eq!(row["estimated_requests"], 1);
    assert_eq!(row["unpriced_requests"], 1);
    assert!(row["output_tokens"].as_i64().unwrap() > 0, "{row}");
}

#[tokio::test]
async fn logs_endpoint_returns_ai_usage_records() {
    let logs_dir = std::env::temp_dir().join(format!("doorman-ai-logs-{}", Uuid::new_v4()));
    let fake = FakeProvider::start(vec![
        Reply::ok(chat_reply()),
        Reply::Sse(
            OPENAI_SSE
                .iter()
                .map(|chunk| (Duration::ZERO, *chunk))
                .collect(),
        ),
    ])
    .await;
    let dir = logs_dir.clone();
    let h = harness_with(
        "corp-openai",
        "openai",
        &fake.url,
        json!({}),
        move |config| {
            config.logs_enabled = true;
            config.logs_dir = Some(dir);
        },
    )
    .await;
    h.storage
        .insert_one("ai_pricing", gpt_x_price())
        .await
        .unwrap();
    insert_admin_user(&h.storage).await;
    h.storage.initialize_core().await.unwrap();
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = chat_body("gpt-x");
    body["stream"] = json!(true);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(body_bytes(response).await, OPENAI_SSE.concat().as_bytes());
    wait_for_usage(&h.storage, 2).await;

    let admin = login(&h.app, "admin@doorman.dev", fixture_password()).await;
    let mut usage_lines = Vec::new();
    for _ in 0..50 {
        let logs = json_body(
            request(
                &h.app,
                Method::GET,
                "/platform/logging/logs?type=ai_usage",
                Some(&admin),
                None,
            )
            .await,
        )
        .await;
        usage_lines = logs["logs"].as_array().cloned().unwrap_or_default();
        if !usage_lines.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(usage_lines.len(), 1, "{usage_lines:?}");
    let line = &usage_lines[0];
    assert_eq!(line["type"], "ai_usage");
    assert_eq!(line["stream"], true);
    assert_eq!(line["user"], "alice");
    assert_eq!(line["model"], "gpt-x");
    assert_eq!(line["input_tokens"], 9);
    assert_eq!(line["output_tokens"], 2);
    assert_eq!(line["cost_nanos"], 9 * 2_000 + 2 * 8_000);
    assert!(line["request_id"].as_str().is_some_and(|id| !id.is_empty()));

    let logs = json_body(
        request(
            &h.app,
            Method::GET,
            "/platform/logging/logs?api=ai:corp-openai",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let with_ai: Vec<&Value> = logs["logs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record.get("ai").is_some())
        .collect();
    assert_eq!(with_ai.len(), 1, "{logs}");
    let block = &with_ai[0]["ai"];
    assert_eq!(block["stream"], false);
    assert_eq!(block["provider"], "openai");
    assert_eq!(block["input_tokens"], 9);
    assert_eq!(block["cost_nanos"], 9 * 2_000 + 2 * 8_000);
    assert_eq!(with_ai[0]["endpoint"], "chat");
    let _ = std::fs::remove_dir_all(logs_dir);
}

#[allow(clippy::too_many_arguments)]
fn usage_row(
    day: &str,
    api: &str,
    model: &str,
    user: &str,
    groups: &[&str],
    requests: u64,
    input: u64,
    output: u64,
    cost: u64,
) -> Value {
    json!({"_id": format!("{day}|{api}|{model}|{user}"), "day": day, "api": api, "provider": "openai",
        "model": model, "username": user, "groups": groups, "requests": requests, "errors": 0,
        "input_tokens": input, "output_tokens": output, "cache_read_tokens": 0, "cache_write_tokens": 0,
        "cost_nanos": cost, "estimated_requests": 0, "unpriced_requests": 0,
        "latency_ms_total": 10, "ttft_ms_total": 5})
}

async fn seed_usage(storage: &SharedStorage) {
    for row in [
        usage_row(
            "2026-10-01",
            "corp-openai/v1",
            "gpt-x",
            "admin",
            &["ALL", "admin"],
            2,
            100,
            50,
            1_500_000,
        ),
        usage_row(
            "2026-10-02",
            "corp-openai/v1",
            "gpt-x",
            "bob",
            &["ALL", "eng"],
            1,
            10,
            5,
            250_000,
        ),
        usage_row(
            "2026-10-02",
            "corp-openai/v1",
            "gpt-x-mini",
            "bob",
            &["ALL", "eng"],
            4,
            40,
            20,
            4_000,
        ),
        usage_row(
            "2026-09-30",
            "corp-openai/v1",
            "gpt-x",
            "bob",
            &["ALL", "eng"],
            9,
            900,
            900,
            9_000_000,
        ),
    ] {
        storage.insert_one("ai_usage_daily", row).await.unwrap();
    }
}

#[tokio::test]
async fn ai_overview_sums_tokens_and_cost() {
    let (app, storage) = platform_app().await;
    seed_usage(&storage).await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let overview = json_body(
        request(
            &app,
            Method::GET,
            "/platform/analytics/ai/overview?start=2026-10-01&end=2026-10-31",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(overview["start"], "2026-10-01");
    assert_eq!(overview["end"], "2026-10-31");
    assert_eq!(overview["requests"], 7);
    assert_eq!(overview["input_tokens"], 150);
    assert_eq!(overview["output_tokens"], 75);
    assert_eq!(overview["cost_nanos"], 1_754_000);
    assert_eq!(overview["cost_usd"], "0.001754");
    assert_eq!(overview["active_users"], 2);
    assert_eq!(overview["top_models"][0]["model"], "gpt-x");
    assert_eq!(overview["top_models"][0]["cost_nanos"], 1_750_000);
    assert_eq!(overview["top_models"][1]["model"], "gpt-x-mini");
    let series = json_body(
        request(
            &app,
            Method::GET,
            "/platform/analytics/ai/timeseries?start=2026-10-01&end=2026-10-31&group_by=model",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(series["group_by"], "model");
    let points = series["points"].as_array().unwrap();
    assert_eq!(points.len(), 3);
    assert_eq!(points[0]["day"], "2026-10-01");
    assert_eq!(points[1]["key"], "gpt-x");
    let series = json_body(
        request(
            &app,
            Method::GET,
            "/platform/analytics/ai/timeseries?start=2026-10-01&end=2026-10-31",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(series["points"].as_array().unwrap().len(), 2);
    assert_eq!(series["points"][1]["key"], Value::Null);
    assert_eq!(series["points"][1]["requests"], 5);
    // Default range is the last 30 days; bad dates are AI009.
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/overview?start=2026-13-01",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error_code"], "AI009");
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/overview",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ai_breakdown_by_group_uses_snapshot_groups() {
    let (app, storage) = platform_app().await;
    seed_usage(&storage).await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let groups = json_body(
        request(
            &app,
            Method::GET,
            "/platform/analytics/ai/breakdown?dimension=group&start=2026-10-01&end=2026-10-31",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(groups["dimension"], "group");
    let rows = groups["rows"].as_array().unwrap();
    let by_key: HashMap<&str, &Value> = rows
        .iter()
        .map(|row| (row["key"].as_str().unwrap(), row))
        .collect();
    assert_eq!(by_key["ALL"]["requests"], 7);
    assert_eq!(by_key["admin"]["requests"], 2);
    assert_eq!(by_key["eng"]["requests"], 5);
    assert_eq!(by_key["eng"]["cost_nanos"], 254_000);
    assert!(rows.iter().all(|row| row.get("groups").is_none()));
    assert_eq!(rows[0]["key"], "ALL");
    let users = json_body(request(&app, Method::GET, "/platform/analytics/ai/breakdown?dimension=user&start=2026-10-01&end=2026-10-31&limit=1", Some(&admin), None).await).await;
    let rows = users["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["key"], "admin");
    assert_eq!(rows[0]["groups"], json!(["ALL", "admin"]));
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/breakdown?dimension=planet",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/breakdown?limit=501",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ai_export_csv_escapes_and_requires_permission() {
    let (app, storage) = platform_app().await;
    seed_usage(&storage).await;
    storage
        .insert_one(
            "ai_usage_daily",
            usage_row(
                "2026-10-03",
                "corp-openai/v1",
                "=cmd,\"x\"",
                "carol",
                &["sales, emea"],
                1,
                1,
                1,
                1,
            ),
        )
        .await
        .unwrap();
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/export.csv?dimension=group&month=2026-10",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    let csv = String::from_utf8(
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].starts_with("# "));
    assert_eq!(
        lines[1],
        "month,group,username,model,requests,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,cost_usd,estimated_requests,unpriced_requests,role,tier,provider"
    );
    assert!(
        // bob has no role/tier snapshot and no user record yet: "(none)".
        lines.contains(&"2026-10,eng,bob,gpt-x,1,10,5,0,0,0.000250,0,0,(none),(none),openai"),
        "{csv}"
    );
    assert!(
        lines.contains(&"2026-10,\"sales, emea\",carol,\"'=cmd,\"\"x\"\"\",1,1,1,0,0,0.000000,0,0,(none),(none),openai"),
        "{csv}"
    );
    // September rows are excluded; bob is listed under both of his groups.
    assert!(!csv.contains(",900,"));
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains(",bob,gpt-x,"))
            .count(),
        2
    );

    let bob = create_platform_user(&app, &admin, "bob").await;
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/export.csv?month=2026-10",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/overview",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = request(
        &app,
        Method::GET,
        "/platform/analytics/ai/export.csv?month=2026-1",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn usage_me_only_returns_own_rows() {
    let (app, storage) = platform_app().await;
    let today = time::OffsetDateTime::now_utc().date().to_string();
    storage
        .insert_one(
            "ai_usage_daily",
            usage_row(&today, "a/v1", "gpt-x", "admin", &["ALL"], 3, 30, 10, 7_000),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "ai_usage_daily",
            usage_row(&today, "a/v1", "gpt-x", "bob", &["ALL"], 5, 50, 50, 9_000),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "ai_usage_daily",
            usage_row(
                "2020-01-01",
                "a/v1",
                "gpt-x",
                "admin",
                &["ALL"],
                100,
                1,
                1,
                1,
            ),
        )
        .await
        .unwrap();
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let me = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/usage/me?period=month",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(me["username"], "admin");
    assert_eq!(me["period"], "month");
    assert_eq!(me["period_key"], format!("m{}", &today[..7]));
    assert_eq!(
        me["usage"],
        json!({"requests": 3, "input_tokens": 30, "output_tokens": 10, "cost_nanos": 7_000, "cost_usd": "0.000007"})
    );
    assert_eq!(me["budgets"], json!([]));
    let bob = create_platform_user(&app, &admin, "bob").await;
    let me = json_body(request(&app, Method::GET, "/platform/ai/usage/me", Some(&bob), None).await)
        .await;
    assert_eq!(me["usage"]["requests"], 5);
    assert_eq!(me["apis"], json!([]));
    // AI APIs the caller can use: group access alone, or a subscription.
    for (name, require_subscription) in [("open-ai", false), ("sub-ai", true)] {
        storage
            .insert_one(
                "apis",
                json!({"api_name": name, "api_version": "v1", "api_type": "AI",
                    "api_ai_provider": "anthropic", "api_servers": ["http://127.0.0.1:9"],
                    "api_allowed_groups": ["ALL"], "active": true,
                    "api_ai_config": {"credential_group": "c", "allowed_models": ["claude-opus-5-5", "claude-*"],
                        "model_aliases": {"best": "claude-opus-5-5"},
                        "require_subscription": require_subscription}}),
            )
            .await
            .unwrap();
    }
    let me = json_body(request(&app, Method::GET, "/platform/ai/usage/me", Some(&bob), None).await)
        .await;
    assert_eq!(
        me["apis"],
        json!([{"api_name": "open-ai", "api_version": "v1", "provider": "anthropic",
            "sdk_base_url_suffix": "", "default_model": null, "models": ["claude-opus-5-5", "best"],
            "model_patterns": ["claude-opus-5-5", "claude-*"]}])
    );
}

#[tokio::test]
async fn pricing_put_rejects_invalid_rows() {
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let empty = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/pricing",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(empty, json!({"pricing": [], "updated_at": null}));
    for bad in [
        json!({"pricing": [{"provider": "openai", "model_pattern": "gpt-x", "input_usd_per_mtok": -1, "output_usd_per_mtok": 1, "effective_from": "2026-01-01"}]}),
        json!({"pricing": [{"provider": "nope", "model_pattern": "gpt-x", "input_usd_per_mtok": 1, "output_usd_per_mtok": 1, "effective_from": "2026-01-01"}]}),
        json!({"pricing": [{"provider": "openai", "model_pattern": "gpt-x", "input_usd_per_mtok": 1.1234567, "output_usd_per_mtok": 1, "effective_from": "2026-01-01"}]}),
        json!({"rows": []}),
    ] {
        let response = request(
            &app,
            Method::PUT,
            "/platform/ai/pricing",
            Some(&admin),
            Some(bad.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(json_body(response).await["error_code"], "AI009");
    }
    let table = json!({"pricing": [
        {"provider": "anthropic", "model_pattern": "claude-opus-5-5", "input_usd_per_mtok": 4.0, "output_usd_per_mtok": 20.0, "cache_read_usd_per_mtok": 0.2, "effective_from": "2026-10-06", "note": "verify"},
        {"provider": "openai", "model_pattern": "gpt-x*", "input_usd_per_mtok": 1, "output_usd_per_mtok": 2, "effective_from": "2026-01-01"}
    ]});
    let saved = json_body(
        request(
            &app,
            Method::PUT,
            "/platform/ai/pricing",
            Some(&admin),
            Some(table),
        )
        .await,
    )
    .await;
    assert_eq!(saved["pricing"].as_array().unwrap().len(), 2);
    assert!(
        saved["pricing"][0]["pricing_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(saved["pricing"][1]["cache_write_usd_per_mtok"], Value::Null);
    assert!(saved["updated_at"].as_str().is_some());
    // PUT replaces the whole table.
    let replaced = json!({"pricing": [{"provider": "gemini", "model_pattern": "gemini-x", "input_usd_per_mtok": 1, "output_usd_per_mtok": 1, "effective_from": "2026-01-01"}]});
    request(
        &app,
        Method::PUT,
        "/platform/ai/pricing",
        Some(&admin),
        Some(replaced),
    )
    .await;
    let listed = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/pricing",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(listed["pricing"].as_array().unwrap().len(), 1);
    assert_eq!(listed["pricing"][0]["provider"], "gemini");
    // Writing needs manage_ai; reading needs view_analytics.
    let bob = create_platform_user(&app, &admin, "bob").await;
    let response = request(
        &app,
        Method::PUT,
        "/platform/ai/pricing",
        Some(&bob),
        Some(json!({"pricing": []})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = request(&app, Method::GET, "/platform/ai/pricing", Some(&bob), None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

fn budget(
    id: &str,
    scope: &str,
    target: &str,
    limit_type: &str,
    limit: u64,
    action: &str,
) -> Value {
    json!({"budget_id": id, "name": format!("budget-{id}"), "scope": scope, "target": target,
        "period": "month", "limit_type": limit_type, "limit_value": limit, "action": action,
        "downgrade_model": null, "warn_at_percent": 80, "enabled": true})
}

async fn set_budget_used(storage: &SharedStorage, id: &str, used: u64) {
    let key = format!(
        "ai_budget:{id}:{}",
        doorman_gateway::ai::budgets::period_key(time::OffsetDateTime::now_utc(), "month")
    );
    storage.incr_by(&key, used, 3600).await.unwrap();
}

fn member_key(id: &str, username: &str) -> String {
    format!(
        "ai_budget:{id}:{}:u:{username}",
        doorman_gateway::ai::budgets::period_key(time::OffsetDateTime::now_utc(), "month")
    )
}

async fn set_member_used(storage: &SharedStorage, id: &str, username: &str, used: u64) {
    storage
        .incr_by(&member_key(id, username), used, 3600)
        .await
        .unwrap();
}

async fn member_used(storage: &SharedStorage, id: &str, username: &str) -> u64 {
    storage
        .current_counter(&member_key(id, username))
        .await
        .unwrap()
}

async fn budget_used(storage: &SharedStorage, id: &str) -> u64 {
    let key = format!(
        "ai_budget:{id}:{}",
        doorman_gateway::ai::budgets::period_key(time::OffsetDateTime::now_utc(), "month")
    );
    storage.current_counter(&key).await.unwrap()
}

#[tokio::test]
async fn budget_block_returns_ai004_with_reset() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_budgets",
            budget("b1", "user", "alice", "tokens", 10, "block"),
        )
        .await
        .unwrap();
    set_budget_used(&h.storage, "b1", 10).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_after > 0 && retry_after <= 31 * 86_400);
    let body = body_json(response).await;
    assert_eq!(body["error_code"], "AI004");
    assert_eq!(body["budget"], "budget-b1");
    let resets = time::OffsetDateTime::parse(
        body["period_resets_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(resets.day(), 1);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn budget_downgrade_switches_model_and_sets_header() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let mut downgrade = budget("b1", "global", "", "cost", 1_000, "downgrade");
    downgrade["downgrade_model"] = json!("gpt-x-mini");
    h.storage.insert_one("ai_budgets", downgrade).await.unwrap();
    set_budget_used(&h.storage, "b1", 1_000).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["x-doorman-ai-model-downgraded"],
        "gpt-x->gpt-x-mini"
    );
    assert_eq!(response.headers()["x-doorman-ai-model"], "gpt-x-mini");
    assert_eq!(fake.last().json()["model"], "gpt-x-mini");
}

#[tokio::test]
async fn budget_warn_header_at_threshold() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_budgets",
            budget("b1", "api", "corp-openai/v1", "tokens", 100, "warn"),
        )
        .await
        .unwrap();
    h.storage
        .insert_one(
            "ai_budgets",
            budget("b2", "user", "alice", "tokens", 1_000, "block"),
        )
        .await
        .unwrap();
    set_budget_used(&h.storage, "b1", 85).await;
    set_budget_used(&h.storage, "b2", 100).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["x-doorman-ai-budget-warning"],
        "budget-b1;85"
    );
    // Below the threshold there is no warning.
    let fake2 = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h2 = harness("corp-openai", "openai", &fake2.url, json!({})).await;
    h2.storage
        .insert_one(
            "ai_budgets",
            budget("b1", "global", "", "tokens", 100, "warn"),
        )
        .await
        .unwrap();
    set_budget_used(&h2.storage, "b1", 79).await;
    let auth = bearer(&h2.key);
    let response = send(
        &h2.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert!(
        response
            .headers()
            .get("x-doorman-ai-budget-warning")
            .is_none()
    );
}

#[tokio::test]
async fn group_budget_applies_to_members_only() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_budgets",
            budget("sales", "group", "sales", "tokens", 1, "block"),
        )
        .await
        .unwrap();
    set_budget_used(&h.storage, "sales", 5).await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "alice is not in sales");
    h.storage
        .insert_one(
            "ai_budgets",
            budget("eng", "group", "eng", "tokens", 1, "block"),
        )
        .await
        .unwrap();
    set_budget_used(&h.storage, "eng", 5).await;
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(response).await["budget"], "budget-eng");
}

#[tokio::test]
async fn per_employee_provider_allowance_is_enforced_per_user() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply()), Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    let mut claude = budget("each-claude", "global", "", "tokens", 1, "block");
    claude["provider"] = json!("anthropic");
    claude["per_user"] = json!(true);
    let mut openai = budget("each-openai", "global", "", "tokens", 1, "block");
    openai["provider"] = json!("openai");
    openai["per_user"] = json!(true);
    h.storage.insert_one("ai_budgets", claude).await.unwrap();
    h.storage.insert_one("ai_budgets", openai).await.unwrap();
    // Another provider's exhausted allowance and a large company-wide total
    // for this one don't block alice: only her own OpenAI allowance does.
    set_member_used(&h.storage, "each-claude", "alice", 5).await;
    set_budget_used(&h.storage, "each-openai", 1_000).await;
    let auth = bearer(&h.key);
    let headers = [("authorization", auth.as_str())];
    let call = || {
        send(
            &h.app,
            Method::POST,
            CHAT,
            &headers,
            Some(chat_body("gpt-x")),
        )
    };
    let first = call().await;
    assert_eq!(first.status(), StatusCode::OK);
    body_bytes(first).await;
    for _ in 0..50 {
        if member_used(&h.storage, "each-openai", "alice").await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        member_used(&h.storage, "each-openai", "alice").await > 0,
        "member counter charged"
    );
    assert!(
        budget_used(&h.storage, "each-openai").await > 1_000,
        "total counter charged"
    );
    let response = call().await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(response).await["budget"], "budget-each-openai");
}

#[tokio::test]
async fn tier_token_allowance_acts_as_user_budget() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "tiers",
            json!({"tier_id": "t-ai", "name": "pro", "display_name": "Pro", "is_default": true,
                "enabled": true, "limits": {"ai_monthly_token_allowance": 5}}),
        )
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // 9 input + 2 output tokens are charged to the implicit monthly budget.
    for _ in 0..100 {
        if budget_used(&h.storage, "tier-t-ai-alice").await >= 11 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(budget_used(&h.storage, "tier-t-ai-alice").await, 11);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(response).await["error_code"], "AI004");
}

#[tokio::test]
async fn budget_charge_after_stream_end() {
    let fake = FakeProvider::start(vec![Reply::Sse(
        OPENAI_SSE
            .iter()
            .map(|chunk| (Duration::from_millis(5), *chunk))
            .collect(),
    )])
    .await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_budgets",
            budget("b1", "user", "alice", "tokens", 1_000, "block"),
        )
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let mut body = chat_body("gpt-x");
    body["stream"] = json!(true);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(
        budget_used(&h.storage, "b1").await,
        0,
        "charged before the stream ended"
    );
    body_bytes(response).await;
    for _ in 0..100 {
        if budget_used(&h.storage, "b1").await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(budget_used(&h.storage, "b1").await, 11);
}

#[tokio::test]
async fn budget_endpoints_validate_targets() {
    let (app, storage) = platform_app().await;
    storage
        .insert_one(
            "apis",
            json!({"api_id": "ai1", "api_name": "corp-openai", "api_version": "v1", "api_type": "AI",
                "api_ai_provider": "openai", "api_servers": ["http://127.0.0.1:9"],
                "api_ai_config": {"credential_group": "c", "allowed_models": ["gpt-x", "gpt-x-mini"]}}),
        )
        .await
        .unwrap();
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let base = json!({"name": "Team cap", "scope": "user", "target": "admin", "period": "month",
        "limit_type": "cost", "limit_value": 5_000_000_000u64, "action": "block"});
    let with = |patch: Value| {
        let mut body = base.clone();
        for (key, value) in patch.as_object().unwrap() {
            body[key] = value.clone();
        }
        body
    };
    for (patch, field) in [
        (json!({"target": "ghost"}), "target"),
        (json!({"scope": "group", "target": "nope"}), "target"),
        (json!({"scope": "api", "target": "missing/v1"}), "target"),
        (json!({"scope": "planet"}), "scope"),
        (json!({"limit_value": 0}), "limit_value"),
        (json!({"action": "downgrade"}), "downgrade_model"),
        (
            json!({"action": "downgrade", "downgrade_model": "gpt-z"}),
            "downgrade_model",
        ),
        (json!({"warn_at_percent": 0}), "warn_at_percent"),
        (json!({"warn_at_percent": 100}), "warn_at_percent"),
        (json!({"period": "year"}), "period"),
    ] {
        let response = request(
            &app,
            Method::POST,
            "/platform/ai/budgets",
            Some(&admin),
            Some(with(patch.clone())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{patch}");
        let body = json_body(response).await;
        assert_eq!(body["error_code"], "AI009");
        assert!(
            body["error_message"].as_str().unwrap().starts_with(field),
            "{body}"
        );
    }
    let created = request(&app, Method::POST, "/platform/ai/budgets", Some(&admin), Some(with(json!({"scope": "group", "target": "ALL", "action": "downgrade", "downgrade_model": "gpt-x-mini"})))).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    let id = created["budget_id"].as_str().unwrap().to_owned();
    assert_eq!(created["warn_at_percent"], 80);
    assert_eq!(created["enabled"], true);
    let api_budget = request(
        &app,
        Method::POST,
        "/platform/ai/budgets",
        Some(&admin),
        Some(with(json!({"scope": "api", "target": "corp-openai/v1"}))),
    )
    .await;
    assert_eq!(api_budget.status(), StatusCode::CREATED);
    let listed = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/budgets",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let row = listed["budgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["budget_id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["used"], 0);
    assert_eq!(row["percent"], 0);
    assert!(row["resets_at"].as_str().unwrap().ends_with('Z'));
    let updated = request(
        &app,
        Method::PUT,
        &format!("/platform/ai/budgets/{id}"),
        Some(&admin),
        Some(json!({"limit_value": 7})),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(json_body(updated).await["limit_value"], 7);
    let bad_update = request(
        &app,
        Method::PUT,
        &format!("/platform/ai/budgets/{id}"),
        Some(&admin),
        Some(json!({"limit_value": -1})),
    )
    .await;
    assert_eq!(bad_update.status(), StatusCode::BAD_REQUEST);
    let status = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/budgets/status?scope=group&target=ALL",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(status["budgets"].as_array().unwrap().len(), 1);
    assert_eq!(status["budgets"][0]["limit_value"], 7);
    assert!(
        status["budgets"][0]["period_key"]
            .as_str()
            .unwrap()
            .starts_with('m')
    );
    let me = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/usage/me",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(me["budgets"].as_array().unwrap().len(), 1, "{me}");
    // Non-admins can read their own status but not others' or manage budgets.
    let bob = create_platform_user(&app, &admin, "bob").await;
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/budgets/status?scope=group&target=ALL",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/budgets/status?scope=user&target=bob",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // A user's status includes the group (ALL) budget that applies to them.
    let statuses = json_body(response).await;
    assert!(
        statuses["budgets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["scope"] == "group"),
        "{statuses}"
    );
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/budgets/status?scope=user&target=admin",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = request(&app, Method::GET, "/platform/ai/budgets", Some(&bob), None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let deleted = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/budgets/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        json_body(deleted).await,
        json!({"message": "AI budget deleted", "budget_id": id})
    );
    let response = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/budgets/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tier_accepts_ai_monthly_token_allowance() {
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let tier = json!({"tier_id": "pro-ai", "name": "pro", "display_name": "Pro",
        "limits": {"requests_per_minute": 100, "ai_monthly_token_allowance": 2_000_000}});
    let response = request(
        &app,
        Method::POST,
        "/platform/tiers/",
        Some(&admin),
        Some(tier),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let saved = json_body(
        request(
            &app,
            Method::GET,
            "/platform/tiers/pro-ai",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        saved["limits"]["ai_monthly_token_allowance"], 2_000_000,
        "{saved}"
    );
    let response = request(
        &app,
        Method::PUT,
        "/platform/tiers/pro-ai",
        Some(&admin),
        Some(json!({"limits": {"ai_monthly_token_allowance": 5}})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["limits"]["ai_monthly_token_allowance"],
        5
    );
    for bad in [json!(-5), json!("lots"), json!(0)] {
        let response = request(
            &app,
            Method::PUT,
            "/platform/tiers/pro-ai",
            Some(&admin),
            Some(json!({"limits": {"ai_monthly_token_allowance": bad}})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
}

#[tokio::test]
async fn ai_analytics_breaks_down_by_role_tier_and_provider() {
    let (app, storage) = platform_app().await;
    let mut eng = usage_row(
        "2026-10-02",
        "a/v1",
        "gpt-x",
        "erin",
        &["eng"],
        2,
        10,
        10,
        4_000,
    );
    eng["role"] = json!("developer");
    eng["tier"] = json!("pro");
    let mut sales = usage_row(
        "2026-10-03",
        "c/v1",
        "claude-x",
        "sam",
        &["sales"],
        3,
        10,
        10,
        1_000,
    );
    sales["provider"] = json!("anthropic");
    sales["role"] = json!("seller");
    // Recorded before role/tier snapshots: falls back to the current user (admin).
    let legacy = usage_row(
        "2026-10-04",
        "a/v1",
        "gpt-x",
        "admin",
        &["ALL"],
        1,
        1,
        1,
        500,
    );
    for row in [eng, sales, legacy] {
        storage.insert_one("ai_usage_daily", row).await.unwrap();
    }
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let get = |path: String| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { json_body(request(&app, Method::GET, &path, Some(&admin), None).await).await }
    };
    let range = "start=2026-10-01&end=2026-10-31";
    let keys = |body: &Value| -> Vec<(String, u64)> {
        body["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["key"].as_str().unwrap().to_owned(),
                    row["requests"].as_u64().unwrap(),
                )
            })
            .collect()
    };
    let roles = get(format!(
        "/platform/analytics/ai/breakdown?dimension=role&{range}"
    ))
    .await;
    assert_eq!(
        keys(&roles),
        vec![
            ("developer".into(), 2),
            ("seller".into(), 3),
            ("admin".into(), 1)
        ]
    );
    let tiers = get(format!(
        "/platform/analytics/ai/breakdown?dimension=tier&{range}"
    ))
    .await;
    assert_eq!(keys(&tiers), vec![("pro".into(), 2), ("(none)".into(), 4)]);
    let providers = get(format!(
        "/platform/analytics/ai/breakdown?dimension=provider&{range}"
    ))
    .await;
    assert_eq!(
        keys(&providers),
        vec![("openai".into(), 3), ("anthropic".into(), 3)]
    );
    // Filters combine with every report.
    let overview = get(format!(
        "/platform/analytics/ai/overview?{range}&provider=anthropic"
    ))
    .await;
    assert_eq!(overview["requests"], 3);
    let overview = get(format!(
        "/platform/analytics/ai/overview?{range}&role=developer&tier=pro"
    ))
    .await;
    assert_eq!(overview["requests"], 2);
    // Employee rows carry their role and tier next to their groups.
    let users = get(format!(
        "/platform/analytics/ai/breakdown?dimension=user&{range}"
    ))
    .await;
    let erin = users["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == "erin")
        .unwrap();
    assert_eq!(
        (erin["role"].clone(), erin["tier"].clone()),
        (json!("developer"), json!("pro"))
    );
    let bad = request(
        &app,
        Method::GET,
        &format!("/platform/analytics/ai/breakdown?dimension=planet&{range}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ai_analytics_filters_by_model_group_and_username() {
    let (app, storage) = platform_app().await;
    seed_usage(&storage).await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let get = |query: &'static str| {
        let app = app.clone();
        let admin = admin.clone();
        async move {
            json_body(
                request(
                    &app,
                    Method::GET,
                    &format!(
                        "/platform/analytics/ai/overview?start=2026-10-01&end=2026-10-31&{query}"
                    ),
                    Some(&admin),
                    None,
                )
                .await,
            )
            .await
        }
    };
    assert_eq!(get("model=gpt-x").await["requests"], 3);
    assert_eq!(get("username=bob").await["requests"], 5);
    assert_eq!(get("group=admin").await["requests"], 2);
    assert_eq!(get("group=eng&model=gpt-x-mini").await["requests"], 4);
    assert_eq!(get("username=bob&group=admin").await["requests"], 0);
    let breakdown = json_body(request(&app, Method::GET, "/platform/analytics/ai/breakdown?dimension=model&start=2026-10-01&end=2026-10-31&username=bob", Some(&admin), None).await).await;
    assert_eq!(breakdown["rows"].as_array().unwrap().len(), 2);
    let series = json_body(
        request(
            &app,
            Method::GET,
            "/platform/analytics/ai/timeseries?start=2026-10-01&end=2026-10-31&group=admin",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(series["points"].as_array().unwrap().len(), 1);
}

fn guardrail(id: &str, direction: &str, detectors: Value, action: &str) -> Value {
    json!({"guardrail_id": id, "name": format!("rail-{id}"), "enabled": true,
        "applies_to": {"apis": ["*"], "groups": ["*"]}, "direction": direction,
        "detectors": detectors, "action": action, "mode": "enforce"})
}

/// Re-runs `test` in a child process with extra environment, so process-wide
/// settings (encryption key, egress IPs) never leak into parallel tests.
fn run_in_child(test: &str, env: &[(&str, &str)]) -> bool {
    if std::env::var_os("DOORMAN_AI_TEST_CHILD").is_some() {
        return false;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env("DOORMAN_AI_TEST_CHILD", "1");
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

#[tokio::test]
async fn block_returns_ai005_without_echoing_match() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_guardrails",
            guardrail(
                "block",
                "input",
                json!([{"type": "keywords", "values": ["ACME-CONFIDENTIAL"]}]),
                "block",
            ),
        )
        .await
        .unwrap();
    h.storage
        .insert_one(
            "ai_guardrails",
            guardrail(
                "pii",
                "input",
                json!([{"type": "builtin", "id": "email"}]),
                "redact",
            ),
        )
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let body = json!({"model": "gpt-x", "messages": [{"role": "user", "content": "leak ACME-CONFIDENTIAL now"}]});
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let text = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert!(!text.contains("ACME-CONFIDENTIAL"), "{text}");
    let error: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(error["error_code"], "AI005");
    assert!(error["guardrail"].as_str().is_some());
    assert!(fake.calls().is_empty());
    // Redaction rewrites only the matched span and reports the count.
    let body = json!({"model": "gpt-x", "messages": [{"role": "user", "content": "mail me at jane@example.com please"}]});
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-doorman-ai-redactions"], "1");
    let sent = fake.last().json();
    assert_eq!(
        sent["messages"][0]["content"],
        "mail me at [REDACTED:email] please"
    );
}

#[tokio::test]
async fn default_log_level_is_metadata() {
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness(
        "corp-openai",
        "openai",
        &fake.url,
        // A per-API `full` cannot raise the global level (USER-approved semantics).
        json!({"api_ai_config": {"credential_group": "prov-cred", "allowed_models": ["gpt-x"], "log_level": "full"}}),
    )
    .await;
    insert_admin_user(&h.storage).await;
    h.storage.initialize_core().await.unwrap();
    let admin = login(&h.app, "admin@doorman.dev", fixture_password()).await;
    let settings = json_body(
        request(
            &h.app,
            Method::GET,
            "/platform/ai/settings",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(settings["log_level"], "metadata");
    assert_eq!(settings["retention_days"], 30);
    assert_eq!(settings["notice_text"], Value::Null);
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    wait_for_usage(&h.storage, 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        h.storage
            .find_many("ai_prompt_logs", &json!({}))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn full_logging_encrypts_and_expires() {
    if run_in_child(
        "full_logging_encrypts_and_expires",
        &[(
            "TOKEN_ENCRYPTION_KEY",
            "ai-gateway-test-encryption-key-0123456789",
        )],
    ) {
        return;
    }
    let fake = FakeProvider::start(vec![
        Reply::ok(chat_reply()),
        Reply::Sse(
            OPENAI_SSE
                .iter()
                .map(|chunk| (Duration::ZERO, *chunk))
                .collect(),
        ),
    ])
    .await;
    let h = harness("corp-openai", "openai", &fake.url, json!({})).await;
    h.storage
        .insert_one(
            "ai_guardrails",
            guardrail(
                "pii",
                "input",
                json!([{"type": "builtin", "id": "email"}]),
                "redact",
            ),
        )
        .await
        .unwrap();
    h.storage
        .insert_one("settings", json!({"type": "ai_settings", "log_level": "full", "retention_days": 7, "notice_text": "Prompts are logged"}))
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let body = json!({"model": "gpt-x", "messages": [{"role": "user", "content": "secret plan for jane@example.com"}]});
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(body.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut streamed = body;
    streamed["stream"] = json!(true);
    let response = send(
        &h.app,
        Method::POST,
        CHAT,
        &[("authorization", &auth)],
        Some(streamed),
    )
    .await;
    body_bytes(response).await;
    let mut logs = Vec::new();
    for _ in 0..100 {
        logs = h
            .storage
            .find_many("ai_prompt_logs", &json!({}))
            .await
            .unwrap();
        if logs.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(logs.len(), 2, "{logs:?}");
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    for log in &logs {
        let raw = log.to_string();
        assert!(
            !raw.contains("secret plan") && !raw.contains("jane@example.com"),
            "{raw}"
        );
        assert!(log["prompt_enc"].as_str().unwrap().starts_with("enc:"));
        let prompt =
            doorman_gateway::storage::field_encryption::decrypt_value(log["prompt_enc"].as_str())
                .unwrap();
        assert!(
            prompt.contains("secret plan for [REDACTED:email]"),
            "{prompt}"
        );
        let completion = doorman_gateway::storage::field_encryption::decrypt_value(
            log["completion_enc"].as_str(),
        )
        .unwrap();
        assert!(completion.contains("hel"), "{completion}");
        assert_eq!(
            log["redactions"],
            json!([{"detector": "email", "count": 1}])
        );
        let expires = log["expires_at"].as_u64().unwrap();
        assert!(expires > now + 6 * 86_400 && expires <= now + 7 * 86_400 + 5);
    }
    assert_eq!(
        h.storage
            .purge_expired_prompt_logs(now + 86_400)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        h.storage
            .purge_expired_prompt_logs(now + 8 * 86_400)
            .await
            .unwrap(),
        2
    );
    assert!(
        h.storage
            .find_many("ai_prompt_logs", &json!({}))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn prompt_logs_require_view_logs() {
    let (app, storage) = platform_app().await;
    storage
        .insert_one(
            "ai_prompt_logs",
            json!({"log_id": "log-1", "request_id": "req-1", "at": "2026-10-18T10:00:00Z", "username": "alice",
                "api": "corp-openai/v1", "model": "gpt-x", "prompt_enc": "hello", "completion_enc": "hi",
                "redactions": [], "expires_at": 4_000_000_000u64}),
        )
        .await
        .unwrap();
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let bob = create_platform_user(&app, &admin, "bob").await;
    for (method, path) in [
        (Method::GET, "/platform/ai/prompt-logs"),
        (Method::GET, "/platform/ai/prompt-logs/log-1"),
        (Method::DELETE, "/platform/ai/prompt-logs/log-1"),
    ] {
        let response = request(&app, method.clone(), path, Some(&bob), None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }
    let list = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/prompt-logs",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        list["logs"],
        json!([{"log_id": "log-1", "request_id": "req-1", "at": "2026-10-18T10:00:00Z",
        "username": "alice", "api": "corp-openai/v1", "model": "gpt-x", "redactions": []}])
    );
    let one = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/prompt-logs/log-1",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(one["prompt"], "hello");
    assert_eq!(one["completion"], "hi");
    let deleted = request(
        &app,
        Method::DELETE,
        "/platform/ai/prompt-logs/log-1",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        json_body(deleted).await,
        json!({"message": "AI prompt log deleted", "log_id": "log-1"})
    );
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/prompt-logs/log-1",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn guardrail_test_endpoint_returns_redacted_preview() {
    let (app, storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let rail = guardrail(
        "x",
        "both",
        json!([{"type": "builtin", "id": "email"}, {"type": "keywords", "values": ["bluebird"]}]),
        "redact",
    );
    let response = request(
        &app,
        Method::POST,
        "/platform/ai/guardrails/test",
        Some(&admin),
        Some(json!({"guardrail": rail, "text": "write to a@b.co about bluebird"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result = json_body(response).await;
    assert_eq!(result["matches"].as_array().unwrap().len(), 2, "{result}");
    assert_eq!(result["matches"][0]["detector"], "email");
    assert!(
        result["redacted"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:email]")
    );
    assert!(!result["redacted"].as_str().unwrap().contains("bluebird"));
    let response = request(
        &app,
        Method::POST,
        "/platform/ai/guardrails/test",
        Some(&admin),
        Some(json!({"guardrail": {"name": "bad"}, "text": "x"})),
    )
    .await;
    assert_eq!(json_body(response).await["error_code"], "AI009");
    // Sampling over stored prompts returns counts only.
    storage
        .insert_one("ai_prompt_logs", json!({"log_id": "l1", "at": "2026-10-18T10:00:00Z", "prompt_enc": "ping c@d.io", "expires_at": 4_000_000_000u64}))
        .await
        .unwrap();
    let sampled = json_body(
        request(
            &app,
            Method::POST,
            "/platform/ai/guardrails/test",
            Some(&admin),
            Some(json!({"guardrail": rail, "sample_last_n": 10})),
        )
        .await,
    )
    .await;
    assert_eq!(sampled, json!({"sampled": 1, "counts": {"email": 1}}));
    // CRUD with manage_security.
    let mut body = rail.clone();
    body.as_object_mut().unwrap().remove("guardrail_id");
    let created = request(
        &app,
        Method::POST,
        "/platform/ai/guardrails",
        Some(&admin),
        Some(body),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created).await;
    let id = created["guardrail_id"].as_str().unwrap().to_owned();
    let invalid = request(
        &app,
        Method::POST,
        "/platform/ai/guardrails",
        Some(&admin),
        Some(json!({"name": "x", "direction": "sideways"})),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let updated = request(
        &app,
        Method::PUT,
        &format!("/platform/ai/guardrails/{id}"),
        Some(&admin),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(json_body(updated).await["enabled"], false);
    let listed = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/guardrails",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(listed["guardrails"].as_array().unwrap().len(), 1);
    let bob = create_platform_user(&app, &admin, "bob").await;
    let response = request(
        &app,
        Method::GET,
        "/platform/ai/guardrails",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let deleted = request(
        &app,
        Method::DELETE,
        &format!("/platform/ai/guardrails/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        json_body(deleted).await,
        json!({"message": "AI guardrail deleted", "guardrail_id": id})
    );
}

#[tokio::test]
async fn ai_settings_exposes_egress_ips_read_only() {
    if run_in_child(
        "ai_settings_exposes_egress_ips_read_only",
        &[("DOORMAN_EGRESS_IPS", "203.0.113.7, 198.51.100.0/28")],
    ) {
        return;
    }
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let settings = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/settings",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        settings["egress_ips"],
        json!(["203.0.113.7", "198.51.100.0/28"])
    );
    let response = request(
        &app,
        Method::PUT,
        "/platform/ai/settings",
        Some(&admin),
        Some(json!({"egress_ips": ["1.2.3.4"]})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = request(
        &app,
        Method::PUT,
        "/platform/ai/settings",
        Some(&admin),
        Some(json!({"log_level": "full"})),
    )
    .await;
    let error = json_body(response).await;
    assert_eq!(error["error_code"], "AI009");
    assert!(
        error["error_message"]
            .as_str()
            .unwrap()
            .contains("notice_text")
    );
    let saved = json_body(request(&app, Method::PUT, "/platform/ai/settings", Some(&admin), Some(json!({"log_level": "full", "notice_text": "AI prompts are logged", "retention_days": 14}))).await).await;
    assert_eq!(saved["log_level"], "full");
    assert_eq!(saved["retention_days"], 14);
    assert_eq!(
        saved["egress_ips"],
        json!(["203.0.113.7", "198.51.100.0/28"])
    );
    // Everyone signed in can read (for the notice banner); only manage_ai writes.
    let bob = create_platform_user(&app, &admin, "bob").await;
    let read =
        json_body(request(&app, Method::GET, "/platform/ai/settings", Some(&bob), None).await)
            .await;
    assert_eq!(read["notice_text"], "AI prompts are logged");
    let response = request(
        &app,
        Method::PUT,
        "/platform/ai/settings",
        Some(&bob),
        Some(json!({"log_level": "none"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn demo_seed_creates_keyless_ai_apis_and_usage() {
    let storage = memory_storage().await;
    insert_admin_user(&storage).await;
    storage.initialize_core().await.unwrap();
    let options = doorman_gateway::demo_seed::SeedOptions {
        users: 3,
        apis: 1,
        endpoints: 1,
        groups: 1,
        protos: 0,
        logs: 0,
        seed: Some(11),
    };
    doorman_gateway::demo_seed::run_seed(&storage, &options)
        .await
        .unwrap();
    let apis: Vec<Value> = storage
        .find_many("apis", &json!({"api_type": "AI"}))
        .await
        .unwrap();
    let mut providers: Vec<&str> = apis
        .iter()
        .map(|api| api["api_ai_provider"].as_str().unwrap())
        .collect();
    providers.sort_unstable();
    assert_eq!(
        providers,
        vec![
            "anthropic",
            "azure_openai",
            "gemini",
            "openai",
            "openai_compatible"
        ]
    );
    for api in &apis {
        doorman_gateway::platform_contract::validate_ai_api(api)
            .unwrap_or_else(|e| panic!("{api}: {e:?}"));
        let group = api["api_ai_config"]["credential_group"].as_str().unwrap();
        let def = storage
            .find_one("credit_defs", &json!({"api_credit_group": group}))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(def["api_key"], "", "demo credentials never hold a key");
    }
    let pricing = storage.find_many("ai_pricing", &json!({})).await.unwrap();
    assert_eq!(pricing.len(), 4);
    assert!(
        pricing
            .iter()
            .all(|row| doorman_gateway::ai::pricing::validate_pricing_doc(row).is_ok())
    );
    assert_eq!(
        storage
            .find_many("ai_budgets", &json!({}))
            .await
            .unwrap()
            .len(),
        1
    );
    let rails = storage
        .find_many("ai_guardrails", &json!({}))
        .await
        .unwrap();
    assert_eq!(rails.len(), 1);
    doorman_gateway::ai::guardrails::validate_guardrail_doc(&rails[0]).unwrap();
    let usage = storage
        .find_many("ai_usage_daily", &json!({}))
        .await
        .unwrap();
    let days: std::collections::BTreeSet<&str> = usage
        .iter()
        .map(|row| row["day"].as_str().unwrap())
        .collect();
    assert!(days.len() >= 25, "{} days", days.len());
    assert!(
        usage
            .iter()
            .any(|row| row["cost_nanos"].as_u64().unwrap_or(0) > 0)
    );
    // Seeding twice does not duplicate the AI definitions.
    doorman_gateway::demo_seed::run_seed(&storage, &options)
        .await
        .unwrap();
    assert_eq!(
        storage
            .find_many("apis", &json!({"api_type": "AI"}))
            .await
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        storage
            .find_many("ai_pricing", &json!({}))
            .await
            .unwrap()
            .len(),
        4
    );

    // A call to a demo API is rejected with AI006 (no key is ever seeded).
    let key = doorman_gateway::ai::keys::generate_key();
    storage.insert_one("ai_access_keys", json!({"key_id": "k", "username": "admin", "key_hash": doorman_gateway::ai::keys::hash_key(&key), "revoked": false})).await.unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "admin", "apis": ["demo-claude/v1"]}),
        )
        .await
        .ok();
    storage
        .update_one(
            "subscriptions",
            &json!({"username": "admin"}),
            &json!({"apis": ["demo-claude/v1"]}),
        )
        .await
        .unwrap();
    let mut state = AppState::new(Config::for_test("removed-internal-backend".to_owned())).unwrap();
    state.storage = Some(Arc::new(storage));
    let app = build_router(state);
    let response = send(&app, Method::POST, "/api/ai/demo-claude/v1/v1/messages", &[("x-api-key", &key)],
        Some(json!({"model": "claude-haiku-5-5", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}))).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_json(response).await["error_code"], "AI006");
}

#[tokio::test]
async fn failover_moves_to_backup_on_503_and_benches_primary() {
    let primary = FakeProvider::start(vec![Reply::status(
        503,
        json!({"error": {"message": "overloaded"}}),
    )])
    .await;
    let backup = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness(
        "failover-openai",
        "openai",
        &primary.url,
        json!({"api_ai_config": {
            "credential_group": "prov-cred",
            "allowed_models": ["gpt-x"],
            "fallback_targets": [{"credential_group": "backup-cred", "server": backup.url}],
        }}),
    )
    .await;
    h.storage
        .insert_one(
            "credit_defs",
            json!({"api_credit_group": "backup-cred", "api_key": "BACKUP_KEY",
                "api_key_header": "authorization", "credit_tiers": []}),
        )
        .await
        .unwrap();
    let auth = bearer(&h.key);
    let uri = "/api/ai/failover-openai/v1/v1/chat/completions";
    let first = send(
        &h.app,
        Method::POST,
        uri,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["x-doorman-ai-fallbacks"], "1");
    assert_eq!(body_json(first).await, chat_reply());
    assert_eq!(primary.calls().len(), 1);
    assert_eq!(backup.last().headers["authorization"], "Bearer BACKUP_KEY");

    // The failed primary is benched, so the next request goes straight to the backup.
    let second = send(
        &h.app,
        Method::POST,
        uri,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    assert!(second.headers().get("x-doorman-ai-fallbacks").is_none());
    assert_eq!(primary.calls().len(), 1);
    assert_eq!(backup.calls().len(), 2);
}

#[tokio::test]
async fn failover_never_moves_a_429_to_a_backup() {
    // C3: a provider rate limit is passed through even when backups exist.
    let primary = FakeProvider::start(vec![Reply::status(
        429,
        json!({"error": {"message": "rate limited"}}),
    )])
    .await;
    let backup = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness(
        "no-429-failover",
        "openai",
        &primary.url,
        json!({"api_ai_config": {
            "credential_group": "prov-cred",
            "allowed_models": ["gpt-x"],
            "fallback_targets": [{"server": backup.url}],
        }}),
    )
    .await;
    let auth = bearer(&h.key);
    let response = send(
        &h.app,
        Method::POST,
        "/api/ai/no-429-failover/v1/v1/chat/completions",
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(primary.calls().len(), 1);
    assert!(backup.calls().is_empty());
}

#[tokio::test]
async fn builtin_prices_are_listed_and_recalculate_reprices_unpriced_days() {
    let (app, storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let builtin = json_body(
        request(
            &app,
            Method::GET,
            "/platform/ai/pricing/builtin",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(builtin["enabled"], true);
    assert!(builtin["prices"].as_array().unwrap().len() > 100);
    assert!(builtin["license"].as_str().unwrap().contains("MIT"));

    let today = time::OffsetDateTime::now_utc().date().to_string();
    for (id, model, unpriced) in [
        ("a", "gpt-x", 2),
        ("b", "gpt-partly", 1),
        ("c", "mystery", 3),
    ] {
        storage
            .insert_one(
                "ai_usage_daily",
                json!({"_id": id, "day": today, "api": "corp/v1", "provider": "openai", "model": model,
                    "username": "alice", "requests": 3, "errors": if id == "c" { 0 } else { 1 },
                    "input_tokens": 1_000_000, "output_tokens": 0, "cache_read_tokens": 0,
                    "cache_write_tokens": 0, "cost_nanos": 0, "unpriced_requests": unpriced}),
            )
            .await
            .unwrap();
    }
    let put = request(
        &app,
        Method::PUT,
        "/platform/ai/pricing",
        Some(&admin),
        Some(json!({"pricing": [
            {"provider": "openai", "model_pattern": "gpt-x", "input_usd_per_mtok": 2, "output_usd_per_mtok": 8, "effective_from": "2020-01-01"},
            {"provider": "openai", "model_pattern": "gpt-partly", "input_usd_per_mtok": 2, "output_usd_per_mtok": 8, "effective_from": "2020-01-01"},
        ]})),
    )
    .await;
    assert_eq!(put.status(), StatusCode::OK);
    let result = json_body(
        request(
            &app,
            Method::POST,
            "/platform/ai/pricing/recalculate",
            Some(&admin),
            Some(json!({"days": 30})),
        )
        .await,
    )
    .await;
    assert_eq!(result["repriced_rows"], 1);
    assert_eq!(result["repriced_requests"], 2);
    assert_eq!(result["added_cost_usd"], "2.000000");
    assert_eq!(result["skipped_partly_priced_rows"], 1);
    assert_eq!(result["still_unpriced_rows"], 1);
    let row = storage
        .find_one("ai_usage_daily", &json!({"_id": "a"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row["cost_nanos"], 2_000_000_000_i64);
    assert_eq!(row["unpriced_requests"], 0);
}

#[tokio::test]
async fn requests_per_minute_limit_blocks_and_names_the_allowance() {
    // Start well inside a minute so both requests share one window.
    let second = time::OffsetDateTime::now_utc().second();
    if second > 50 {
        tokio::time::sleep(Duration::from_secs(u64::from(61 - second))).await;
    }
    let fake = FakeProvider::start(vec![Reply::ok(chat_reply())]).await;
    let h = harness("rpm-openai", "openai", &fake.url, json!({})).await;
    let mut rpm = budget("rpm", "global", "", "requests", 1, "block");
    rpm["period"] = json!("minute");
    h.storage.insert_one("ai_budgets", rpm).await.unwrap();
    let auth = bearer(&h.key);
    let uri = "/api/ai/rpm-openai/v1/v1/chat/completions";
    let first = send(
        &h.app,
        Method::POST,
        uri,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    body_bytes(first).await;
    for _ in 0..50 {
        if minute_used(&h.storage, "rpm").await > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        minute_used(&h.storage, "rpm").await,
        1,
        "one request counted"
    );
    let blocked = send(
        &h.app,
        Method::POST,
        uri,
        &[("authorization", &auth)],
        Some(chat_body("gpt-x")),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = blocked.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry_after), "retry-after {retry_after}");
    assert_eq!(body_json(blocked).await["budget"], "budget-rpm");
    assert_eq!(fake.calls().len(), 1);
}

async fn minute_used(storage: &SharedStorage, id: &str) -> u64 {
    let key = format!(
        "ai_budget:{id}:{}",
        doorman_gateway::ai::budgets::period_key(time::OffsetDateTime::now_utc(), "minute")
    );
    storage.current_counter(&key).await.unwrap()
}

#[tokio::test]
async fn short_window_allowances_must_block() {
    let (app, _storage) = platform_app().await;
    let admin = login(&app, "admin@doorman.dev", fixture_password()).await;
    let body = |action: &str| {
        json!({"name": "rpm", "scope": "global", "period": "minute", "limit_type": "requests",
            "limit_value": 60, "action": action})
    };
    let warn = request(
        &app,
        Method::POST,
        "/platform/ai/budgets",
        Some(&admin),
        Some(body("warn")),
    )
    .await;
    assert_eq!(warn.status(), StatusCode::BAD_REQUEST);
    assert!(
        json_body(warn).await["error_message"]
            .as_str()
            .unwrap()
            .contains("always block")
    );
    let block = request(
        &app,
        Method::POST,
        "/platform/ai/budgets",
        Some(&admin),
        Some(body("block")),
    )
    .await;
    assert_eq!(block.status(), StatusCode::CREATED);
}
