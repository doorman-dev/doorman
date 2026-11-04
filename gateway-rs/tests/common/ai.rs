#![allow(dead_code)]
//! Fake AI provider upstream and gateway harness for `tests/ai_gateway.rs`.

use std::{
    collections::VecDeque,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::Request,
    response::Response,
};
use doorman_gateway::{AppState, Config, ai::keys, build_router, storage::runtime::SharedStorage};
use http::{HeaderMap, Method, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Clone, Debug)]
pub struct Captured {
    pub method: Method,
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Captured {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

#[derive(Clone, Debug)]
pub enum Reply {
    Json {
        status: u16,
        body: Value,
        headers: Vec<(&'static str, &'static str)>,
    },
    /// SSE chunks, each sent after its delay.
    Sse(Vec<(Duration, &'static str)>),
    /// Waits before answering.
    Delayed(Duration, Box<Reply>),
}

impl Reply {
    pub fn ok(body: Value) -> Self {
        Reply::Json {
            status: 200,
            body,
            headers: vec![],
        }
    }

    pub fn status(status: u16, body: Value) -> Self {
        Reply::Json {
            status,
            body,
            headers: vec![],
        }
    }
}

#[derive(Clone)]
pub struct FakeProvider {
    pub url: String,
    pub captured: Arc<Mutex<Vec<Captured>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
}

impl FakeProvider {
    /// Replies are used in order; the last one repeats.
    pub async fn start(replies: Vec<Reply>) -> Self {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let state = (captured.clone(), replies.clone());
        let app = Router::new().fallback(move |request: Request| {
            let (captured, replies) = state.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, 64 * 1024 * 1024).await.unwrap();
                captured.lock().unwrap().push(Captured {
                    method: parts.method,
                    path_and_query: parts
                        .uri
                        .path_and_query()
                        .map(|value| value.as_str().to_owned())
                        .unwrap_or_default(),
                    headers: parts.headers,
                    body,
                });
                let reply = {
                    let mut replies = replies.lock().unwrap();
                    if replies.len() > 1 {
                        replies.pop_front().unwrap()
                    } else {
                        replies.front().cloned().unwrap()
                    }
                };
                render(reply).await
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://{addr}"),
            captured,
            replies,
        }
    }

    pub fn calls(&self) -> Vec<Captured> {
        self.captured.lock().unwrap().clone()
    }

    pub fn last(&self) -> Captured {
        self.calls().pop().expect("upstream was not called")
    }

    pub fn set_replies(&self, replies: Vec<Reply>) {
        *self.replies.lock().unwrap() = VecDeque::from(replies);
    }
}

fn render(reply: Reply) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    Box::pin(async move {
        match reply {
            Reply::Json {
                status,
                body,
                headers,
            } => {
                let mut response = Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json");
                for (name, value) in headers {
                    response = response.header(name, value);
                }
                response.body(Body::from(body.to_string())).unwrap()
            }
            Reply::Sse(chunks) => {
                let stream =
                    futures_util::stream::unfold(VecDeque::from(chunks), |mut chunks| async move {
                        let (delay, chunk) = chunks.pop_front()?;
                        tokio::time::sleep(delay).await;
                        Some((
                            Ok::<_, Infallible>(Bytes::from_static(chunk.as_bytes())),
                            chunks,
                        ))
                    });
                Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
            Reply::Delayed(delay, reply) => {
                tokio::time::sleep(delay).await;
                render(*reply).await
            }
        }
    })
}

pub const UPSTREAM_KEY: &str = "sk-upstream-fixture";

pub struct Harness {
    pub app: Router,
    pub storage: Arc<SharedStorage>,
    /// A valid `dk_` key for alice.
    pub key: String,
}

/// Gateway with alice (subscribed), one AI API named `{name}/v1` pointing at
/// `upstream`, a credential group `prov-cred` holding `UPSTREAM_KEY`, and a key.
pub async fn harness(name: &str, provider: &str, upstream: &str, api_overrides: Value) -> Harness {
    harness_with(name, provider, upstream, api_overrides, |_| {}).await
}

pub async fn harness_with(
    name: &str,
    provider: &str,
    upstream: &str,
    api_overrides: Value,
    configure: impl FnOnce(&mut Config),
) -> Harness {
    let mut config = Config::for_test("removed-internal-backend".to_owned());
    configure(&mut config);
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one(
            "users",
            json!({"username": "alice", "email": "alice@example.com", "password": "unused",
                "role": "developer", "groups": ["ALL", "eng"], "active": true}),
        )
        .await
        .unwrap();
    storage
        .insert_one(
            "subscriptions",
            json!({"username": "alice", "apis": [format!("{name}/v1")]}),
        )
        .await
        .unwrap();
    let mut api = json!({
        "api_id": uuid::Uuid::new_v4().to_string(),
        "api_name": name,
        "api_version": "v1",
        "api_type": "AI",
        "api_ai_provider": provider,
        "api_servers": [upstream],
        "api_public": false,
        "api_auth_required": true,
        "api_allowed_groups": ["ALL"],
        "api_allowed_roles": [],
        "api_allowed_retry_count": 0,
        "active": true,
        "api_ai_config": {
            "credential_group": "prov-cred",
            "allowed_models": ["gpt-x", "gpt-x-mini*", "claude-opus-5-5", "gemini-x"],
            "model_aliases": {"fast": "gpt-x-mini"},
        }
    });
    for (key, value) in api_overrides.as_object().unwrap() {
        api[key] = value.clone();
    }
    storage.insert_one("apis", api).await.unwrap();
    let header = match provider {
        "anthropic" => "x-api-key",
        "gemini" => "x-goog-api-key",
        "azure_openai" => "api-key",
        _ => "authorization",
    };
    storage
        .insert_one(
            "credit_defs",
            json!({"api_credit_group": "prov-cred", "api_key": UPSTREAM_KEY,
                "api_key_header": header, "credit_tiers": []}),
        )
        .await
        .unwrap();
    let key = keys::generate_key();
    storage
        .insert_one(
            "ai_access_keys",
            json!({"key_id": "key-alice", "username": "alice", "name": "test",
                "key_prefix": keys::key_prefix(&key), "key_hash": keys::hash_key(&key),
                "revoked": false}),
        )
        .await
        .unwrap();
    let storage = Arc::new(storage);
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(storage.clone());
    Harness {
        app: build_router(state),
        storage,
        key,
    }
}

pub async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Response {
    let mut builder =
        http::Request::builder()
            .method(method)
            .uri(uri)
            .extension(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                40000,
            ))));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match body {
        Some(body) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

pub async fn body_bytes(response: Response) -> Bytes {
    to_bytes(response.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap()
}

pub async fn body_json(response: Response) -> Value {
    serde_json::from_slice(&body_bytes(response).await).unwrap()
}

pub fn status_of(response: &Response) -> StatusCode {
    response.status()
}
