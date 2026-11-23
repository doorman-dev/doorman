//! Unified AI endpoint (step 5): `/api/ai/v1/chat/completions` and `/api/ai/v1/models`.
//!
//! The caller's `model` picks an AI API (`ai::access::resolve`). The OpenAI chat
//! request is translated to that provider's native request and sent through the
//! normal AI pipeline (`rest_policy_then_proxy` → `execute_ai`) unchanged, so
//! subscriptions, budgets, guardrails, prompt logging, failover, signing and
//! pricing all run on the native request and reply. The reply is translated back
//! here, around the pipeline, so policy errors are translated too.

use std::convert::Infallible;

use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use futures_util::{StreamExt, stream::BoxStream};
use http::{HeaderValue, Method, StatusCode, Uri, header};
use serde_json::{Value, json};

use crate::{
    ai::{
        access::{self, Candidate},
        eventstream::Decoder,
        keys::peek_key,
        sse::{SseEvent, SseParser},
        translate::{self, ChunkTranslator, Target},
    },
    error::GatewayError,
    error_codes::ErrorCode,
    middleware::body_limit::BodyLimits,
    routes::{
        ai::{AiRoute, UnifiedCtx},
        rest::{DataPlaneProtocol, PolicyPath, rest_policy_then_proxy},
    },
    state::AppState,
    storage::models::PolicyDocuments,
};

const MAX_STREAM_EVENT_BYTES: usize = 1024 * 1024;
/// Upper bound for a buffered non-stream provider reply.
const MAX_REPLY_BYTES: usize = 64 * 1024 * 1024;

/// OpenAI-shaped error with Doorman's code.
fn openai_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = translate::error_to_openai(
        status,
        &serde_json::to_vec(&json!({"error_code": code, "error_message": message}))
            .unwrap_or_default(),
    );
    (status, Json(body)).into_response()
}

async fn load_documents(state: &AppState) -> Option<PolicyDocuments> {
    if let Some(injected) = &state.policy_documents {
        return injected.lock().ok().map(|documents| documents.clone());
    }
    state.storage.as_ref()?.load_policy_documents().await.ok()
}

/// Entry from `ai_policy_then_proxy` when the API name is `v1`; `rest` is the
/// path after `/api/ai/v1/`.
pub(crate) async fn handle(
    state: AppState,
    request: Request,
    rest: &str,
) -> Result<Response, GatewayError> {
    let rest = rest.trim_end_matches('/');
    let method = request.method().clone();
    if !matches!(
        (&method, rest),
        (&Method::GET, "models") | (&Method::POST, "chat/completions")
    ) {
        return Ok(openai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "The one-endpoint address supports GET /models and POST /chat/completions",
        ));
    }
    let Some(documents) = load_documents(&state).await else {
        return Ok(openai_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "GTW006",
            "Gateway state store unavailable",
        ));
    };
    let settings = crate::storage::ai_settings::from_documents(&documents.settings);
    if !access::unified_enabled(&settings) {
        return Ok(openai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_OPERATION_NOT_ALLOWED,
            "The one-endpoint AI address is turned off; use your provider's own address from My AI",
        ));
    }
    let query: Vec<(String, String)> = request
        .uri()
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    let owner = match peek_key(request.headers(), &query, &documents) {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return Ok(openai_error(
                StatusCode::UNAUTHORIZED,
                ErrorCode::AI_ACCESS_KEY_INVALID,
                "Use your Doorman AI key (dk_…) from My AI as the API key",
            ));
        }
        Err(failure) => {
            return Ok(openai_error(
                failure.status,
                &failure.error_code,
                &failure.error_message,
            ));
        }
    };
    let usable = access::find_user(&documents, &owner.username)
        .map(|user| access::usable_ai_apis(&documents, user))
        .map(|apis| access::within_scope(apis, &owner.api_scope))
        .unwrap_or_default();

    if method == Method::GET {
        let data: Vec<Value> = access::unified_models(&settings, &usable)
            .into_iter()
            .map(|id| json!({"id": id, "object": "model", "created": 0, "owned_by": "doorman"}))
            .collect();
        return Ok(Json(json!({"object": "list", "data": data})).into_response());
    }

    let (parts, body) = request.into_parts();
    let limit = BodyLimits::from_env().ai;
    let Ok(raw) = to_bytes(body, limit).await else {
        return Ok(openai_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "REQ001",
            &format!("Request entity too large (max: {limit} bytes)"),
        ));
    };
    let chat = match serde_json::from_slice::<Value>(&raw) {
        Ok(chat) if chat.is_object() => chat,
        _ => {
            return Ok(openai_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::AI_INVALID_REQUEST,
                "Request body must be a JSON object",
            ));
        }
    };
    let Some(requested) = chat["model"]
        .as_str()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_owned)
    else {
        return Ok(openai_error(
            StatusCode::BAD_REQUEST,
            ErrorCode::AI_INVALID_REQUEST,
            "Request has no model",
        ));
    };
    let candidates = access::resolve(&settings, &usable, &requested);
    if candidates.is_empty() {
        return Ok(openai_error(
            StatusCode::NOT_FOUND,
            ErrorCode::AI_NO_PROVIDER_FOR_MODEL,
            &format!("No AI provider you can use serves the model {requested}"),
        ));
    }
    let include_usage = chat["stream_options"]["include_usage"] == true;
    let id = format!("chatcmpl-{}", uuid::Uuid::new_v4().simple());
    let created = time::OffsetDateTime::now_utc().unix_timestamp();

    let last = candidates.len() - 1;
    for (index, candidate) in candidates.iter().enumerate() {
        let native = match translate::to_native(candidate.provider, &candidate.model, &chat) {
            Ok(native) => native,
            Err(error) => {
                return Ok(openai_error(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::AI_TRANSLATION_FAILED,
                    &error.0,
                ));
            }
        };
        let target = translate::target_for(candidate.provider, &candidate.model);
        let unified = UnifiedCtx {
            requested_model: requested.clone(),
        };
        let Some(sub) = sub_request(&parts, candidate, native, unified) else {
            return Ok(openai_error(
                StatusCode::BAD_REQUEST,
                ErrorCode::AI_TRANSLATION_FAILED,
                "The translated request could not be built",
            ));
        };
        let response = rest_policy_then_proxy(State(state.clone()), sub).await?;
        let status = response.status().as_u16();
        // Decision 6: only provider outages move on; budget, guardrail and
        // other 4xx answers are final.
        if (502..=504).contains(&status) && index < last {
            tracing::warn!(
                api = %format!("{}/{}", candidate.api_name, candidate.api_version),
                status,
                "Unified AI target failed; trying the next route target"
            );
            continue;
        }
        return Ok(
            translate_reply(response, target, &requested, &id, created, include_usage).await,
        );
    }
    unreachable!("candidates is non-empty and the last one always returns")
}

/// The native request the normal AI pipeline sees, as if the client had called
/// `/api/ai/{name}/{ver}/{rest_path}` with the same headers and extensions.
fn sub_request(
    parts: &http::request::Parts,
    candidate: &Candidate,
    native: translate::NativeRequest,
    unified: UnifiedCtx,
) -> Option<Request> {
    let mut path = format!(
        "/api/ai/{}/{}/{}",
        candidate.api_name, candidate.api_version, native.rest_path
    );
    if !native.query.is_empty() {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(native.query.iter())
            .finish();
        path = format!("{path}?{query}");
    }
    let uri: Uri = path.parse().ok()?;
    let body = serde_json::to_vec(&native.body).ok()?;
    let mut request = Request::new(Body::from(body.clone()));
    *request.method_mut() = Method::POST;
    *request.uri_mut() = uri;
    *request.headers_mut() = parts.headers.clone();
    *request.extensions_mut() = parts.extensions.clone();
    let headers = request.headers_mut();
    headers.remove(header::CONTENT_ENCODING);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    let extensions = request.extensions_mut();
    extensions.insert(PolicyPath(format!(
        "/api/rest/{}/{}/{}",
        candidate.api_name, candidate.api_version, native.rest_path
    )));
    extensions.insert(DataPlaneProtocol::Ai);
    extensions.insert(AiRoute {
        name: candidate.api_name.clone(),
        version: candidate.api_version.clone(),
        rest_path: native.rest_path,
    });
    extensions.insert(unified);
    Some(request)
}

/// Pipeline reply → OpenAI reply. Status, response extensions (activity log)
/// and pass-through headers are kept.
async fn translate_reply(
    response: Response,
    target: Target,
    requested: &str,
    id: &str,
    created: i64,
    include_usage: bool,
) -> Response {
    let (mut parts, body) = response.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_ENCODING);

    let aws = content_type.starts_with("application/vnd.amazon.eventstream");
    if parts.status.is_success() && (aws || content_type.starts_with("text/event-stream")) {
        let translator =
            translate::stream_translator(target, requested, id, created, include_usage);
        let framer = if aws {
            Framer::Aws(Decoder::new(MAX_STREAM_EVENT_BYTES))
        } else {
            Framer::Sse(SseParser::new(MAX_STREAM_EVENT_BYTES))
        };
        let state = StreamState {
            inner: body.into_data_stream().boxed(),
            framer,
            translator,
            done: false,
        };
        let stream = futures_util::stream::unfold(state, StreamState::next_bytes);
        parts.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        parts
            .headers
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        return Response::from_parts(parts, Body::from_stream(stream));
    }

    let bytes = to_bytes(body, MAX_REPLY_BYTES).await.unwrap_or_default();
    let payload = if parts.status.is_success() {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(native) => translate::from_native(target, requested, &native),
            Err(_) => {
                parts.status = StatusCode::BAD_GATEWAY;
                translate::error_to_openai(StatusCode::BAD_GATEWAY, b"")
            }
        }
    } else {
        translate::error_to_openai(parts.status, &bytes)
    };
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    Response::from_parts(parts, Body::from(body))
}

enum Framer {
    Sse(SseParser),
    Aws(Decoder),
}

struct StreamState {
    inner: BoxStream<'static, Result<Bytes, axum::Error>>,
    framer: Framer,
    translator: Box<dyn ChunkTranslator>,
    done: bool,
}

fn data_line(value: &Value) -> String {
    format!("data: {value}\n\n")
}

fn error_line(message: &str) -> String {
    data_line(
        &json!({"error": {"message": message, "type": "api_error", "code": null, "param": null}}),
    )
}

/// Anthropic `event: error`, AWS exception / error frames (named by
/// `Frame::to_sse_event` after `:exception-type` / `:error-code`).
fn stream_error(event: &SseEvent) -> Option<String> {
    let name = event.event.as_deref()?;
    let is_error = name == "error"
        || name.ends_with("Exception")
        || name.ends_with("Error")
        || name.ends_with("Fault");
    if !is_error {
        return None;
    }
    let data: Value = serde_json::from_str(&event.data).unwrap_or(Value::Null);
    let message = data["error"]["message"]
        .as_str()
        .or_else(|| data["message"].as_str())
        .or_else(|| data["Message"].as_str())
        .unwrap_or(name);
    Some(message.to_owned())
}

impl StreamState {
    fn events(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, ()> {
        match &mut self.framer {
            Framer::Sse(parser) => Ok(parser.push(bytes)),
            Framer::Aws(decoder) => decoder
                .push(bytes)
                .into_iter()
                .map(|frame| frame.map(|frame| frame.to_sse_event()).map_err(|_| ()))
                .collect(),
        }
    }

    fn translate(&mut self, bytes: &[u8]) -> String {
        let mut out = String::new();
        let Ok(events) = self.events(bytes) else {
            out.push_str(&error_line("The provider's stream could not be read"));
            self.done = true;
            return out;
        };
        for event in &events {
            if let Some(message) = stream_error(event) {
                out.push_str(&error_line(&message));
                continue;
            }
            for chunk in self.translator.on_event(event) {
                out.push_str(&data_line(&chunk));
            }
        }
        out
    }

    fn finish(&mut self) -> String {
        let mut out: String = self.translator.finish().iter().map(data_line).collect();
        out.push_str("data: [DONE]\n\n");
        out
    }

    async fn next_bytes(mut self) -> Option<(Result<Bytes, Infallible>, Self)> {
        if self.done {
            return None;
        }
        loop {
            match self.inner.next().await {
                Some(Ok(bytes)) => {
                    let mut out = self.translate(&bytes);
                    if self.done {
                        out.push_str(&self.finish());
                    }
                    if !out.is_empty() {
                        return Some((Ok(Bytes::from(out)), self));
                    }
                }
                Some(Err(_)) => {
                    self.done = true;
                    let mut out = error_line("The provider's stream ended early");
                    out.push_str(&self.finish());
                    return Some((Ok(Bytes::from(out)), self));
                }
                None => {
                    self.done = true;
                    let out = self.finish();
                    return Some((Ok(Bytes::from(out)), self));
                }
            }
        }
    }
}
