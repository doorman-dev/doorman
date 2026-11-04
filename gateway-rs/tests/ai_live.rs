//! Opt-in live provider smoke test (plan P1.4). Runs only with
//! `DOORMAN_AI_LIVE_TEST=1` plus a user-supplied provider key:
//! `DOORMAN_AI_LIVE_OPENAI_KEY`, `DOORMAN_AI_LIVE_ANTHROPIC_KEY` and/or
//! `DOORMAN_AI_LIVE_GEMINI_KEY`. Otherwise it prints "skip" and passes.

#[path = "common/ai.rs"]
mod ai_common;

use ai_common::{harness, send};
use http::{Method, StatusCode};
use serde_json::json;

#[tokio::test]
async fn ai_live_providers_roundtrip() {
    if std::env::var("DOORMAN_AI_LIVE_TEST").ok().as_deref() != Some("1") {
        println!("skip: DOORMAN_AI_LIVE_TEST is not 1");
        return;
    }
    let cases = [
        (
            "DOORMAN_AI_LIVE_OPENAI_KEY",
            "openai",
            "https://api.openai.com",
            "/api/ai/live-openai/v1/v1/chat/completions",
            json!({"model": "gpt-4o-mini", "max_completion_tokens": 16,
                "messages": [{"role": "user", "content": "Say ok"}]}),
            "gpt-4o-mini",
        ),
        (
            "DOORMAN_AI_LIVE_ANTHROPIC_KEY",
            "anthropic",
            "https://api.anthropic.com",
            "/api/ai/live-anthropic/v1/v1/messages",
            json!({"model": "claude-haiku-5-5", "max_tokens": 16,
                "messages": [{"role": "user", "content": "Say ok"}]}),
            "claude-haiku-5-5",
        ),
        (
            "DOORMAN_AI_LIVE_GEMINI_KEY",
            "gemini",
            "https://generativelanguage.googleapis.com",
            "/api/ai/live-gemini/v1/v1beta/models/gemini-2.5-flash:generateContent",
            json!({"contents": [{"role": "user", "parts": [{"text": "Say ok"}]}],
                "generationConfig": {"maxOutputTokens": 16}}),
            "gemini-2.5-flash",
        ),
    ];
    let mut exercised = Vec::new();
    for (env, provider, server, path, body, model) in cases {
        let Some(key) = std::env::var(env).ok().filter(|key| !key.is_empty()) else {
            println!("skip {provider}: {env} not set");
            continue;
        };
        let name = path.split('/').nth(3).unwrap();
        let h = harness(
            name,
            provider,
            server,
            json!({"api_ai_config": {"credential_group": "live-cred", "allowed_models": [model]}}),
        )
        .await;
        let header = match provider {
            "anthropic" => "x-api-key",
            "gemini" => "x-goog-api-key",
            _ => "authorization",
        };
        h.storage
            .insert_one(
                "credit_defs",
                json!({"api_credit_group": "live-cred", "api_key": key,
                    "api_key_header": header, "credit_tiers": []}),
            )
            .await
            .unwrap();
        let auth = format!("Bearer {}", h.key);
        let response = send(
            &h.app,
            Method::POST,
            path,
            &[("authorization", &auth)],
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{provider}");
        exercised.push(provider);
    }
    println!("live providers exercised: {exercised:?}");
}
