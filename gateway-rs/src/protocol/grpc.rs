use std::{convert::Infallible, time::Duration};

use axum::{
    Json,
    body::Body,
    response::{IntoResponse, Response},
};
use base64::Engine;
use bytes::Bytes;
use futures_util::stream;
use http::{HeaderMap, StatusCode, uri::PathAndQuery};
use prost::Message;
use prost_reflect::{
    DescriptorPool, DynamicMessage, MessageDescriptor, MethodDescriptor, ReflectMessage,
};
use serde::Deserialize;
use serde_json::Value;
use tonic::{
    Request, Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    metadata::{Ascii, MetadataKey, MetadataValue},
    transport::Channel,
};

use crate::{
    policy::{PolicyDecision, PolicyErrorBody},
    state::AppState,
};

#[derive(Clone, Debug, Deserialize)]
struct JsonGrpcRequest {
    method: String,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    message: Value,
    #[serde(default)]
    messages: Vec<Value>,
    #[serde(default, rename = "stream")]
    stream_kind: Option<String>,
    #[serde(default = "default_max_items")]
    max_items: usize,
}

pub async fn execute_json_gateway(
    state: &AppState,
    decision: &PolicyDecision,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    match execute(state, decision, headers, body).await {
        Ok(value) => Json(value).into_response(),
        Err(GrpcGatewayError::Request(message)) => {
            policy_error(StatusCode::BAD_REQUEST, "GTW011", &message)
        }
        Err(GrpcGatewayError::MissingMethod(message)) => {
            policy_error(StatusCode::INTERNAL_SERVER_ERROR, "GTW006", &message)
        }
        Err(GrpcGatewayError::Forbidden(message)) => {
            policy_error(StatusCode::FORBIDDEN, "GTW013", &message)
        }
        Err(GrpcGatewayError::MissingDescriptor) => policy_error(
            StatusCode::NOT_FOUND,
            "GTW012",
            "Proto descriptor set not found for API",
        ),
        Err(GrpcGatewayError::Status(status)) => grpc_status_response(status),
        Err(GrpcGatewayError::Transport(message)) => {
            tracing::error!(error = %message, "native gRPC transport failed");
            policy_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "GTW006",
                "Upstream gRPC service unavailable",
            )
        }
    }
}

pub async fn execute_web_gateway(
    state: &AppState,
    decision: &PolicyDecision,
    headers: &HeaderMap,
    body: &[u8],
    service_path: &str,
    method_name: &str,
) -> Response {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/grpc-web") {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Invalid Content-Type").into_response();
    }
    let text_mode = content_type.starts_with("application/grpc-web-text");
    if !decision.grpc_web_enabled {
        return web_trailer_response(
            text_mode,
            tonic::Code::PermissionDenied,
            "gRPC-Web disabled",
        );
    }
    let descriptor = match decision.grpc_descriptor_set.as_deref() {
        Some(descriptor) => descriptor,
        None => {
            return web_trailer_response(
                text_mode,
                tonic::Code::Unimplemented,
                "Proto descriptor set not found",
            );
        }
    };
    let descriptor = match base64::engine::general_purpose::STANDARD.decode(descriptor) {
        Ok(descriptor) => descriptor,
        Err(_) => {
            return web_trailer_response(
                text_mode,
                tonic::Code::Internal,
                "Invalid stored proto descriptor",
            );
        }
    };
    let pool = match DescriptorPool::decode(descriptor.as_slice()) {
        Ok(pool) => pool,
        Err(_) => {
            return web_trailer_response(
                text_mode,
                tonic::Code::Internal,
                "Invalid stored proto descriptor",
            );
        }
    };
    let (package, service_name) = service_path
        .rsplit_once('.')
        .map_or((None, service_path), |(package, service)| {
            (Some(package), service)
        });
    if let Err(error) = enforce_allowlists(decision, package, service_name, method_name) {
        let message = match error {
            GrpcGatewayError::Forbidden(message) => message,
            _ => "gRPC target not allowed".to_owned(),
        };
        return web_trailer_response(text_mode, tonic::Code::PermissionDenied, &message);
    }
    let Some(method) = find_method(&pool, package, service_name, method_name) else {
        return web_trailer_response(text_mode, tonic::Code::Unimplemented, "Method not found");
    };
    if method.is_client_streaming() {
        return web_trailer_response(
            text_mode,
            tonic::Code::Unimplemented,
            "gRPC-Web does not support client or bidirectional streaming",
        );
    }
    if method.is_server_streaming() && !text_mode {
        return web_trailer_response(
            false,
            tonic::Code::Unimplemented,
            "Binary gRPC-Web server streaming is not supported",
        );
    }
    let raw = if text_mode {
        let compact = body
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        match base64::engine::general_purpose::STANDARD.decode(compact) {
            Ok(raw) => raw,
            Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64 body").into_response(),
        }
    } else {
        body.to_vec()
    };
    let payload = match decode_web_data_frame(&raw) {
        Ok(payload) => payload,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    let input = match DynamicMessage::decode(method.input(), payload.as_slice()) {
        Ok(input) => input,
        Err(_) => {
            return web_trailer_response(
                text_mode,
                tonic::Code::InvalidArgument,
                "Invalid protobuf request",
            );
        }
    };
    let Some(upstream) = decision.upstream.as_deref() else {
        return web_trailer_response(text_mode, tonic::Code::Unavailable, "No upstream");
    };
    let endpoint = match normalize_endpoint(upstream) {
        Ok(endpoint) => endpoint,
        Err(_) => {
            return web_trailer_response(text_mode, tonic::Code::Unavailable, "Invalid upstream");
        }
    };
    let channel = match state
        .grpc_channel(
            &endpoint,
            decision.upstream_tls_profile_id.as_deref(),
            decision.request_timeout_ms,
        )
        .await
    {
        Ok(channel) => channel,
        Err(_) => {
            return web_trailer_response(
                text_mode,
                tonic::Code::Unavailable,
                "Upstream unavailable",
            );
        }
    };
    let path = match PathAndQuery::try_from(format!(
        "/{}/{}",
        method.parent_service().full_name(),
        method.name()
    )) {
        Ok(path) => path,
        Err(_) => {
            return web_trailer_response(text_mode, tonic::Code::Internal, "Invalid method path");
        }
    };
    let codec = DynamicCodec::new(method.input(), method.output());
    let mut client = tonic::client::Grpc::new(channel);
    if client.ready().await.is_err() {
        return web_trailer_response(text_mode, tonic::Code::Unavailable, "Upstream unavailable");
    }
    let timeout = Duration::from_millis(decision.request_timeout_ms.max(1));
    let mut request = Request::new(input);
    configure_request(&mut request, decision, headers, timeout);
    if method.is_server_streaming() {
        return match client.server_streaming(request, path, codec).await {
            Ok(response) => text_streaming_response(response.into_inner()),
            Err(status) => web_trailer_response(true, status.code(), status.message()),
        };
    }
    match client.unary(request, path, codec).await {
        Ok(response) => {
            let mut framed = web_data_frame(&response.into_inner().encode_to_vec());
            framed.extend(web_trailer_frame(tonic::Code::Ok, ""));
            web_body_response(text_mode, framed)
        }
        Err(status) => web_trailer_response(text_mode, status.code(), status.message()),
    }
}

fn text_streaming_response(stream: tonic::Streaming<DynamicMessage>) -> Response {
    struct StreamState {
        stream: tonic::Streaming<DynamicMessage>,
        pending: Vec<u8>,
        finished: bool,
    }
    let output = stream::unfold(
        StreamState {
            stream,
            pending: Vec::new(),
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }
            loop {
                match state.stream.message().await {
                    Ok(Some(message)) => state
                        .pending
                        .extend(web_data_frame(&message.encode_to_vec())),
                    Ok(None) => {
                        state.pending.extend(web_trailer_frame(tonic::Code::Ok, ""));
                        state.finished = true;
                    }
                    Err(status) => {
                        state
                            .pending
                            .extend(web_trailer_frame(status.code(), status.message()));
                        state.finished = true;
                    }
                }
                let emit = if state.finished {
                    state.pending.len()
                } else {
                    (state.pending.len() / 3) * 3
                };
                if emit > 0 {
                    let chunk = state.pending.drain(..emit).collect::<Vec<_>>();
                    let encoded = base64::engine::general_purpose::STANDARD.encode(chunk);
                    return Some((Ok::<Bytes, Infallible>(Bytes::from(encoded)), state));
                }
            }
        },
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(
            http::header::CONTENT_TYPE,
            "application/grpc-web-text+proto",
        )
        .header("x-grpc-web", "1")
        .header(
            http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            "grpc-status, grpc-message, grpc-status-details-bin",
        )
        .body(Body::from_stream(output))
        .expect("static gRPC-Web streaming response")
}

pub(crate) fn decode_web_data_frame(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() < 5 || raw[0] & 0x80 != 0 || raw[0] & 0x01 != 0 {
        return Err("Invalid gRPC-Web frame");
    }
    let length = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
    if raw.len() != length.saturating_add(5) {
        return Err("Invalid gRPC-Web frame length");
    }
    Ok(raw[5..].to_vec())
}

pub(crate) fn web_data_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(0);
    frame.extend((payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    frame
}

fn web_trailer_frame(code: tonic::Code, message: &str) -> Vec<u8> {
    let message = message.replace(['\r', '\n'], " ");
    let trailers = format!(
        "grpc-status: {}\r\ngrpc-message: {message}\r\n",
        code as i32
    );
    let mut frame = Vec::with_capacity(trailers.len() + 5);
    frame.push(0x80);
    frame.extend((trailers.len() as u32).to_be_bytes());
    frame.extend(trailers.as_bytes());
    frame
}

pub(crate) fn web_trailer_response(text_mode: bool, code: tonic::Code, message: &str) -> Response {
    web_body_response(text_mode, web_trailer_frame(code, message))
}

pub(crate) fn web_body_response(text_mode: bool, body: Vec<u8>) -> Response {
    let (content_type, body) = if text_mode {
        (
            "application/grpc-web-text+proto",
            base64::engine::general_purpose::STANDARD
                .encode(body)
                .into_bytes(),
        )
    } else {
        ("application/grpc-web+proto", body)
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, content_type)
        .header("x-grpc-web", "1")
        .header(
            http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            "grpc-status, grpc-message, grpc-status-details-bin",
        )
        .body(Body::from(body))
        .expect("static gRPC-Web response")
}

async fn execute(
    state: &AppState,
    decision: &PolicyDecision,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value, GrpcGatewayError> {
    let request: JsonGrpcRequest = serde_json::from_slice(body)
        .map_err(|_| GrpcGatewayError::Request("Invalid JSON in request body".to_owned()))?;
    let descriptor = decision
        .grpc_descriptor_set
        .as_deref()
        .ok_or(GrpcGatewayError::MissingDescriptor)?;
    let descriptor = base64::engine::general_purpose::STANDARD
        .decode(descriptor)
        .map_err(|_| GrpcGatewayError::Request("Invalid stored proto descriptor".to_owned()))?;
    let pool = DescriptorPool::decode(descriptor.as_slice())
        .map_err(|_| GrpcGatewayError::Request("Invalid stored proto descriptor".to_owned()))?;
    let (service_name, method_name) = request.method.split_once('.').ok_or_else(|| {
        GrpcGatewayError::Request(
            "Invalid gRPC method. Use Service.Method with alphanumerics/underscore.".to_owned(),
        )
    })?;
    if !valid_identifier(service_name) || !valid_identifier(method_name) {
        return Err(GrpcGatewayError::Request(
            "Invalid gRPC method. Use Service.Method with alphanumerics/underscore.".to_owned(),
        ));
    }
    let package = decision
        .grpc_package
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            request
                .package
                .as_deref()
                .filter(|value| !value.trim().is_empty())
        });
    if package.is_some_and(|package| !valid_package(package)) {
        return Err(GrpcGatewayError::Request(
            "Invalid gRPC package. Use letters, digits, underscore and dots only.".to_owned(),
        ));
    }
    enforce_allowlists(decision, package, service_name, method_name)?;
    let method = find_method(&pool, package, service_name, method_name).ok_or_else(|| {
        GrpcGatewayError::MissingMethod(format!(
            "Message types {method_name}Request/{method_name}Reply not found in protobuf module"
        ))
    })?;
    if let Some(stream_kind) = request.stream_kind.as_deref() {
        validate_stream_hint(stream_kind, &method)?;
    }

    let Some(upstream) = decision.upstream.as_deref() else {
        return Err(GrpcGatewayError::Transport(
            "No upstream servers configured".to_owned(),
        ));
    };
    let endpoint = normalize_endpoint(upstream)?;
    let attempts = decision
        .retry_count
        .max(env_u32("GRPC_MAX_RETRIES", 0))
        .saturating_add(1);
    for attempt in 0..attempts {
        let result = match state
            .grpc_channel(
                &endpoint,
                decision.upstream_tls_profile_id.as_deref(),
                decision.request_timeout_ms,
            )
            .await
        {
            Ok(channel) => {
                invoke(
                    channel,
                    decision,
                    headers,
                    request.clone(),
                    method.clone(),
                    false,
                )
                .await
            }
            Err(error) => Err(GrpcGatewayError::Transport(error.to_string())),
        };
        match result {
            Ok(value) => return Ok(value),
            Err(error) if attempt + 1 < attempts && retryable_grpc_error(&error) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_attempts = attempts,
                    "retrying transient native gRPC failure"
                );
                grpc_retry_backoff(attempt).await;
            }
            Err(primary_error) => {
                // The Python gateway makes one final compatibility attempt without the
                // protobuf package. Some legacy gRPC services register that path.
                let fallback = match state
                    .grpc_channel(
                        &endpoint,
                        decision.upstream_tls_profile_id.as_deref(),
                        decision.request_timeout_ms,
                    )
                    .await
                {
                    Ok(channel) => {
                        invoke(
                            channel,
                            decision,
                            headers,
                            request.clone(),
                            method.clone(),
                            true,
                        )
                        .await
                    }
                    Err(error) => Err(GrpcGatewayError::Transport(error.to_string())),
                };
                return fallback.or(Err(primary_error));
            }
        }
    }
    unreachable!("gRPC attempts is always at least one")
}

fn retryable_grpc_error(error: &GrpcGatewayError) -> bool {
    match error {
        GrpcGatewayError::Transport(_) => true,
        GrpcGatewayError::Status(status) => matches!(
            status.code(),
            tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::ResourceExhausted
                | tonic::Code::Aborted
        ),
        _ => false,
    }
}

async fn grpc_retry_backoff(attempt: u32) {
    let base = env_u64("GRPC_RETRY_BASE_MS", 100);
    let maximum = env_u64("GRPC_RETRY_MAX_MS", 1_000);
    let delay = base.saturating_mul(1_u64 << attempt.min(20)).min(maximum);
    tokio::time::sleep(Duration::from_millis(delay.max(10))).await;
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

async fn invoke(
    channel: Channel,
    decision: &PolicyDecision,
    headers: &HeaderMap,
    request: JsonGrpcRequest,
    method: MethodDescriptor,
    unqualified_path: bool,
) -> Result<Value, GrpcGatewayError> {
    let service = method.parent_service();
    let path = if unqualified_path {
        format!("/{}/{}", service.name(), method.name())
    } else {
        format!("/{}/{}", service.full_name(), method.name())
    };
    let path = PathAndQuery::try_from(path)
        .map_err(|_| GrpcGatewayError::Request("Invalid gRPC method path".to_owned()))?;
    let codec = DynamicCodec::new(method.input(), method.output());
    let mut client = tonic::client::Grpc::new(channel);
    client
        .ready()
        .await
        .map_err(|error| GrpcGatewayError::Transport(error.to_string()))?;
    let timeout = Duration::from_millis(decision.request_timeout_ms.max(1));
    let client_streaming = method.is_client_streaming();
    let server_streaming = method.is_server_streaming();
    match (client_streaming, server_streaming) {
        (false, false) => {
            let message = dynamic_message(method.input(), &request.message)?;
            let mut request = Request::new(message);
            configure_request(&mut request, decision, headers, timeout);
            let response = client
                .unary(request, path, codec)
                .await
                .map_err(GrpcGatewayError::Status)?;
            dynamic_json(response.into_inner())
        }
        (false, true) => {
            let message = dynamic_message(method.input(), &request.message)?;
            let mut tonic_request = Request::new(message);
            configure_request(&mut tonic_request, decision, headers, timeout);
            let response = client
                .server_streaming(tonic_request, path, codec)
                .await
                .map_err(GrpcGatewayError::Status)?;
            collect_stream(response.into_inner(), request.max_items).await
        }
        (true, false) => {
            let messages = dynamic_messages(method.input(), &request)?;
            let mut tonic_request = Request::new(stream::iter(messages));
            configure_request(&mut tonic_request, decision, headers, timeout);
            let response = client
                .client_streaming(tonic_request, path, codec)
                .await
                .map_err(GrpcGatewayError::Status)?;
            dynamic_json(response.into_inner())
        }
        (true, true) => {
            let messages = dynamic_messages(method.input(), &request)?;
            let mut tonic_request = Request::new(stream::iter(messages));
            configure_request(&mut tonic_request, decision, headers, timeout);
            let response = client
                .streaming(tonic_request, path, codec)
                .await
                .map_err(GrpcGatewayError::Status)?;
            collect_stream(response.into_inner(), request.max_items).await
        }
    }
}

async fn collect_stream(
    mut stream: tonic::Streaming<DynamicMessage>,
    max_items: usize,
) -> Result<Value, GrpcGatewayError> {
    let mut items = Vec::new();
    let limit = max_items.clamp(1, 10_000);
    while items.len() < limit {
        let Some(message) = stream.message().await.map_err(GrpcGatewayError::Status)? else {
            break;
        };
        items.push(dynamic_json(message)?);
    }
    Ok(serde_json::json!({ "items": items }))
}

fn dynamic_messages(
    descriptor: MessageDescriptor,
    request: &JsonGrpcRequest,
) -> Result<Vec<DynamicMessage>, GrpcGatewayError> {
    let values = if request.messages.is_empty() {
        vec![request.message.clone()]
    } else {
        request.messages.clone()
    };
    values
        .iter()
        .map(|value| dynamic_message(descriptor.clone(), value))
        .collect()
}

fn dynamic_message(
    descriptor: MessageDescriptor,
    value: &Value,
) -> Result<DynamicMessage, GrpcGatewayError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| GrpcGatewayError::Request(error.to_string()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let message = DynamicMessage::deserialize(descriptor, &mut deserializer)
        .map_err(|error| GrpcGatewayError::Request(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| GrpcGatewayError::Request(error.to_string()))?;
    Ok(message)
}

fn dynamic_json(message: DynamicMessage) -> Result<Value, GrpcGatewayError> {
    serde_json::to_value(message).map_err(|error| GrpcGatewayError::Transport(error.to_string()))
}

fn find_method(
    pool: &DescriptorPool,
    package: Option<&str>,
    service_name: &str,
    method_name: &str,
) -> Option<MethodDescriptor> {
    pool.services()
        .filter(|service| service.name() == service_name)
        .filter(|service| {
            package.is_none_or(|package| {
                service
                    .full_name()
                    .strip_suffix(&format!(".{service_name}"))
                    == Some(package)
            })
        })
        .find_map(|service| {
            service
                .methods()
                .find(|method| method.name() == method_name)
        })
}

fn enforce_allowlists(
    decision: &PolicyDecision,
    package: Option<&str>,
    service: &str,
    method: &str,
) -> Result<(), GrpcGatewayError> {
    if !decision.grpc_allowed_packages.is_empty()
        && !package.is_some_and(|package| {
            decision
                .grpc_allowed_packages
                .iter()
                .any(|item| item == package)
        })
    {
        return Err(GrpcGatewayError::Forbidden(
            "gRPC package not allowed".to_owned(),
        ));
    }
    if !decision.grpc_allowed_services.is_empty()
        && !decision
            .grpc_allowed_services
            .iter()
            .any(|item| item == service)
    {
        return Err(GrpcGatewayError::Forbidden(
            "gRPC service not allowed".to_owned(),
        ));
    }
    let full_method = format!("{service}.{method}");
    if !decision.grpc_allowed_methods.is_empty()
        && !decision
            .grpc_allowed_methods
            .iter()
            .any(|item| item == &full_method)
    {
        return Err(GrpcGatewayError::Forbidden(
            "gRPC method not allowed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_stream_hint(hint: &str, method: &MethodDescriptor) -> Result<(), GrpcGatewayError> {
    let expected = match (method.is_client_streaming(), method.is_server_streaming()) {
        (false, false) => "unary",
        (false, true) => "server",
        (true, false) => "client",
        (true, true) => "bidi",
    };
    if hint.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(GrpcGatewayError::Request(format!(
            "gRPC stream mode mismatch: descriptor requires {expected}"
        )))
    }
}

fn configure_request<T>(
    request: &mut Request<T>,
    decision: &PolicyDecision,
    headers: &HeaderMap,
    timeout: Duration,
) {
    request.set_timeout(timeout);
    for name in decision
        .allowed_headers
        .iter()
        .chain(std::iter::once(&"x-request-id".to_owned()))
    {
        let Some(value) = headers.get(name) else {
            continue;
        };
        let (Ok(key), Ok(value)) = (
            MetadataKey::<Ascii>::from_bytes(name.to_ascii_lowercase().as_bytes()),
            MetadataValue::<Ascii>::try_from(value.as_bytes()),
        ) else {
            continue;
        };
        request.metadata_mut().insert(key, value);
    }
}

fn normalize_endpoint(upstream: &str) -> Result<String, GrpcGatewayError> {
    let upstream = upstream.trim_end_matches('/');
    if let Some(target) = upstream.strip_prefix("grpc://") {
        Ok(format!("http://{target}"))
    } else if let Some(target) = upstream.strip_prefix("grpcs://") {
        Ok(format!("https://{target}"))
    } else if upstream.starts_with("http://") || upstream.starts_with("https://") {
        Ok(upstream.to_owned())
    } else {
        Err(GrpcGatewayError::Transport(
            "Invalid gRPC upstream URL".to_owned(),
        ))
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn valid_package(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(valid_identifier)
}

fn default_max_items() -> usize {
    100
}

fn policy_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(PolicyErrorBody {
            error_code: code.to_owned(),
            error_message: message.to_owned(),
        }),
    )
        .into_response()
}

fn grpc_status_response(status: Status) -> Response {
    let http = match status.code() {
        tonic::Code::InvalidArgument
        | tonic::Code::FailedPrecondition
        | tonic::Code::OutOfRange => StatusCode::BAD_REQUEST,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        tonic::Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_GATEWAY,
    };
    policy_error(http, "GTW006", status.message())
}

#[derive(Debug)]
enum GrpcGatewayError {
    Request(String),
    MissingMethod(String),
    Forbidden(String),
    MissingDescriptor,
    Status(Status),
    Transport(String),
}

#[derive(Clone)]
struct DynamicCodec {
    input: MessageDescriptor,
    output: MessageDescriptor,
}

impl DynamicCodec {
    fn new(input: MessageDescriptor, output: MessageDescriptor) -> Self {
        Self { input, output }
    }
}

impl Codec for DynamicCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynamicEncoder;
    type Decoder = DynamicDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        DynamicEncoder {
            descriptor: self.input.clone(),
        }
    }
    fn decoder(&mut self) -> Self::Decoder {
        DynamicDecoder {
            descriptor: self.output.clone(),
        }
    }
}

struct DynamicEncoder {
    descriptor: MessageDescriptor,
}

impl Encoder for DynamicEncoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn encode(
        &mut self,
        item: Self::Item,
        destination: &mut EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        if item.descriptor() != self.descriptor {
            return Err(Status::internal("dynamic protobuf descriptor mismatch"));
        }
        item.encode(destination)
            .map_err(|error| Status::internal(error.to_string()))
    }
}

struct DynamicDecoder {
    descriptor: MessageDescriptor,
}

impl Decoder for DynamicDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        DynamicMessage::decode(self.descriptor.clone(), source)
            .map(Some)
            .map_err(|error| Status::internal(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unary_echo_descriptor(package: &str) -> Vec<u8> {
        use prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
            MethodDescriptorProto, ServiceDescriptorProto,
            field_descriptor_proto::{Label, Type},
        };
        let request_message = DescriptorProto {
            name: Some("EchoRequest".to_owned()),
            field: vec![FieldDescriptorProto {
                name: Some("message".to_owned()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };
        let response_message = DescriptorProto {
            name: Some("EchoReply".to_owned()),
            field: request_message.field.clone(),
            ..Default::default()
        };
        FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("echo.proto".to_owned()),
                package: Some(package.to_owned()),
                syntax: Some("proto3".to_owned()),
                message_type: vec![request_message, response_message],
                service: vec![ServiceDescriptorProto {
                    name: Some("Echo".to_owned()),
                    method: vec![MethodDescriptorProto {
                        name: Some("Echo".to_owned()),
                        input_type: Some(format!(".{package}.EchoRequest")),
                        output_type: Some(format!(".{package}.EchoReply")),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    #[test]
    fn normalizes_grpc_schemes_and_validates_names() {
        assert_eq!(
            normalize_endpoint("grpc://localhost:50051").unwrap(),
            "http://localhost:50051"
        );
        assert_eq!(
            normalize_endpoint("grpcs://example.com").unwrap(),
            "https://example.com"
        );
        assert!(valid_package("acme.customer_v1"));
        assert!(!valid_package("acme/customer"));
    }

    #[tokio::test]
    async fn unreachable_secure_grpc_transport_maps_to_python_503() {
        use axum::body::to_bytes;

        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let decision = PolicyDecision {
            upstream: Some("grpcs://127.0.0.1:9".to_owned()),
            grpc_descriptor_set: Some(
                base64::engine::general_purpose::STANDARD.encode(unary_echo_descriptor("acme")),
            ),
            grpc_package: Some("acme".to_owned()),
            request_timeout_ms: 100,
            ..Default::default()
        };
        let response = execute_json_gateway(
            &state,
            &decision,
            &HeaderMap::new(),
            br#"{"method":"Echo.Echo","message":{"message":"hello"}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error_code"],
            "GTW006"
        );
    }

    #[tokio::test]
    async fn grpc_allowlist_and_traversal_match_python_gateway_errors() {
        use axum::body::to_bytes;
        use prost_types::{FileDescriptorProto, FileDescriptorSet};

        let descriptor = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("allowlist.proto".to_owned()),
                package: Some("acme".to_owned()),
                syntax: Some("proto3".to_owned()),
                ..Default::default()
            }],
        }
        .encode_to_vec();
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();

        let cases = [
            (
                PolicyDecision {
                    grpc_descriptor_set: Some(
                        base64::engine::general_purpose::STANDARD.encode(&descriptor),
                    ),
                    grpc_allowed_services: vec!["Greeter".to_owned()],
                    ..Default::default()
                },
                br#"{"method":"Admin.DeleteAll","message":{}}"#.as_slice(),
                StatusCode::FORBIDDEN,
                "GTW013",
            ),
            (
                PolicyDecision {
                    grpc_descriptor_set: Some(
                        base64::engine::general_purpose::STANDARD.encode(&descriptor),
                    ),
                    grpc_allowed_methods: vec!["Greeter.SayHello".to_owned()],
                    ..Default::default()
                },
                br#"{"method":"Greeter.DeleteAll","message":{}}"#.as_slice(),
                StatusCode::FORBIDDEN,
                "GTW013",
            ),
            (
                PolicyDecision {
                    grpc_descriptor_set: Some(
                        base64::engine::general_purpose::STANDARD.encode(&descriptor),
                    ),
                    grpc_allowed_packages: vec!["goodpkg".to_owned()],
                    ..Default::default()
                },
                br#"{"method":"Greeter.SayHello","package":"badpkg","message":{}}"#.as_slice(),
                StatusCode::FORBIDDEN,
                "GTW013",
            ),
            (
                PolicyDecision {
                    grpc_descriptor_set: Some(
                        base64::engine::general_purpose::STANDARD.encode(&descriptor),
                    ),
                    ..Default::default()
                },
                br#"{"method":"../Evil","message":{}}"#.as_slice(),
                StatusCode::BAD_REQUEST,
                "GTW011",
            ),
            (
                PolicyDecision {
                    grpc_descriptor_set: Some(
                        base64::engine::general_purpose::STANDARD.encode(&descriptor),
                    ),
                    ..Default::default()
                },
                br#"{"method":"Svc.M","package":"../evil","message":{}}"#.as_slice(),
                StatusCode::BAD_REQUEST,
                "GTW011",
            ),
            (
                PolicyDecision::default(),
                br#"{"method":"Svc.M","message":{}}"#.as_slice(),
                StatusCode::NOT_FOUND,
                "GTW012",
            ),
        ];

        for (decision, request, expected_status, expected_code) in cases {
            let response =
                execute_json_gateway(&state, &decision, &HeaderMap::new(), request).await;
            assert_eq!(response.status(), expected_status);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["error_code"],
                expected_code
            );
        }
    }

    #[tokio::test]
    async fn dynamically_invokes_unary_grpc_from_json() {
        use axum::{Router, body::to_bytes, routing::post};

        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

        async fn echo(request: axum::extract::Request) -> Response {
            if CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/grpc")
                    .header("grpc-status", "14")
                    .header("grpc-message", "retry me")
                    .body(Body::empty())
                    .unwrap();
            }
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            let payload = decode_web_data_frame(&body).unwrap();
            let framed = web_data_frame(&payload);
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", "0")
                .body(Body::from(framed))
                .unwrap()
        }

        CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/acme.Echo/Echo", post(echo)))
                .await
                .unwrap();
        });

        let descriptor = unary_echo_descriptor("acme");
        let decision = PolicyDecision {
            upstream: Some(format!("grpc://{address}")),
            grpc_descriptor_set: Some(base64::engine::general_purpose::STANDARD.encode(descriptor)),
            grpc_package: Some("acme".to_owned()),
            retry_count: 1,
            request_timeout_ms: 2_000,
            ..Default::default()
        };
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let body = br#"{"method":"Echo.Echo","package":"request.must.not.win","message":{"message":"hello"}}"#;
        let response = execute_json_gateway(&state, &decision, &HeaderMap::new(), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            serde_json::json!({"message":"hello"})
        );
        assert_eq!(CALLS.load(std::sync::atomic::Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn request_and_descriptor_packages_resolve_dynamic_grpc_without_api_override() {
        use axum::{Router, body::to_bytes, routing::post};

        async fn echo(request: axum::extract::Request) -> Response {
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            let payload = decode_web_data_frame(&body).unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", "0")
                .body(Body::from(web_data_frame(&payload)))
                .unwrap()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/acme.Echo/Echo", post(echo)))
                .await
                .unwrap();
        });
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let decision = PolicyDecision {
            upstream: Some(format!("grpc://{address}")),
            grpc_descriptor_set: Some(
                base64::engine::general_purpose::STANDARD.encode(unary_echo_descriptor("acme")),
            ),
            request_timeout_ms: 2_000,
            ..Default::default()
        };
        for body in [
            br#"{"method":"Echo.Echo","package":"acme","message":{"message":"request-package"}}"#
                .as_slice(),
            br#"{"method":"Echo.Echo","message":{"message":"descriptor-package"}}"#.as_slice(),
        ] {
            let response = execute_json_gateway(&state, &decision, &HeaderMap::new(), body).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(
                serde_json::from_slice::<Value>(&body).unwrap()["message"]
                    .as_str()
                    .is_some_and(|message| message.ends_with("package"))
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_grpc_retries_exhaustion_maps_to_python_503() {
        use axum::{Router, body::to_bytes, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CALLS: AtomicUsize = AtomicUsize::new(0);

        async fn unavailable() -> Response {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", "14")
                .header("grpc-message", "still unavailable")
                .body(Body::empty())
                .unwrap()
        }

        CALLS.store(0, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/acme.Echo/Echo", post(unavailable))
                    .route("/Echo/Echo", post(unavailable)),
            )
            .await
            .unwrap();
        });
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let decision = PolicyDecision {
            upstream: Some(format!("grpc://{address}")),
            grpc_descriptor_set: Some(
                base64::engine::general_purpose::STANDARD.encode(unary_echo_descriptor("acme")),
            ),
            grpc_package: Some("acme".to_owned()),
            retry_count: 2,
            request_timeout_ms: 2_000,
            ..Default::default()
        };
        let response = execute_json_gateway(
            &state,
            &decision,
            &HeaderMap::new(),
            br#"{"method":"Echo.Echo","message":{"message":"hello"}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error_code"],
            "GTW006"
        );
        // Three configured attempts plus the compatibility-path attempt.
        assert_eq!(CALLS.load(Ordering::SeqCst), 4);
        server.abort();
    }

    #[tokio::test]
    async fn falls_back_to_unqualified_grpc_method_path_like_python() {
        use axum::{Router, body::to_bytes, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static PRIMARY_CALLS: AtomicUsize = AtomicUsize::new(0);
        static FALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);

        async fn qualified() -> Response {
            PRIMARY_CALLS.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", "10")
                .header("grpc-message", "qualified path unavailable")
                .body(Body::empty())
                .unwrap()
        }

        async fn unqualified(request: axum::extract::Request) -> Response {
            FALLBACK_CALLS.fetch_add(1, Ordering::SeqCst);
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            let payload = decode_web_data_frame(&body).unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", "0")
                .body(Body::from(web_data_frame(&payload)))
                .unwrap()
        }

        PRIMARY_CALLS.store(0, Ordering::SeqCst);
        FALLBACK_CALLS.store(0, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/acme.Echo/Echo", post(qualified))
                    .route("/Echo/Echo", post(unqualified)),
            )
            .await
            .unwrap();
        });
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let decision = PolicyDecision {
            upstream: Some(format!("grpc://{address}")),
            grpc_descriptor_set: Some(
                base64::engine::general_purpose::STANDARD.encode(unary_echo_descriptor("acme")),
            ),
            grpc_package: Some("acme".to_owned()),
            request_timeout_ms: 2_000,
            ..Default::default()
        };
        let response = execute_json_gateway(
            &state,
            &decision,
            &HeaderMap::new(),
            br#"{"method":"Echo.Echo","message":{"message":"hello"}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            serde_json::json!({"message":"hello"})
        );
        assert_eq!(PRIMARY_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FALLBACK_CALLS.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_then_unimplemented_succeeds_via_unqualified_fallback() {
        use axum::{Router, body::to_bytes, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static PRIMARY_CALLS: AtomicUsize = AtomicUsize::new(0);
        static FALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);

        async fn qualified() -> Response {
            let status = if PRIMARY_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                "14"
            } else {
                "12"
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", status)
                .body(Body::empty())
                .unwrap()
        }

        async fn unqualified(request: axum::extract::Request) -> Response {
            FALLBACK_CALLS.fetch_add(1, Ordering::SeqCst);
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header("grpc-status", "0")
                .body(Body::from(web_data_frame(
                    &decode_web_data_frame(&body).unwrap(),
                )))
                .unwrap()
        }

        PRIMARY_CALLS.store(0, Ordering::SeqCst);
        FALLBACK_CALLS.store(0, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/acme.Echo/Echo", post(qualified))
                    .route("/Echo/Echo", post(unqualified)),
            )
            .await
            .unwrap();
        });
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let decision = PolicyDecision {
            upstream: Some(format!("grpc://{address}")),
            grpc_descriptor_set: Some(
                base64::engine::general_purpose::STANDARD.encode(unary_echo_descriptor("acme")),
            ),
            grpc_package: Some("acme".to_owned()),
            retry_count: 1,
            request_timeout_ms: 2_000,
            ..Default::default()
        };
        let response = execute_json_gateway(
            &state,
            &decision,
            &HeaderMap::new(),
            br#"{"method":"Echo.Echo","message":{"message":"hello"}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(PRIMARY_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(FALLBACK_CALLS.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn missing_method_matches_python_message_resolution_error() {
        use axum::body::to_bytes;
        use prost_types::{FileDescriptorProto, FileDescriptorSet, ServiceDescriptorProto};

        let descriptor = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("empty.proto".to_owned()),
                package: Some("acme".to_owned()),
                syntax: Some("proto3".to_owned()),
                service: vec![ServiceDescriptorProto {
                    name: Some("Greeter".to_owned()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();
        let decision = PolicyDecision {
            upstream: Some("grpc://127.0.0.1:9".to_owned()),
            grpc_descriptor_set: Some(base64::engine::general_purpose::STANDARD.encode(descriptor)),
            grpc_package: Some("acme".to_owned()),
            ..Default::default()
        };
        let state = AppState::new(crate::config::Config::for_test(
            "http://127.0.0.1:9".to_owned(),
        ))
        .unwrap();
        let response = execute_json_gateway(
            &state,
            &decision,
            &HeaderMap::new(),
            br#"{"method":"Nope.Do","message":{}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            serde_json::json!({
                "error_code": "GTW006",
                "error_message": "Message types DoRequest/DoReply not found in protobuf module"
            })
        );
    }

    #[test]
    fn grpc_web_frames_round_trip_and_emit_trailers() {
        let payload = b"protobuf-payload";
        let frame = web_data_frame(payload);
        assert_eq!(decode_web_data_frame(&frame).unwrap(), payload);

        let trailers = web_trailer_frame(tonic::Code::PermissionDenied, "line\r\nbreak");
        assert_eq!(trailers[0], 0x80);
        let length = u32::from_be_bytes(trailers[1..5].try_into().unwrap()) as usize;
        assert_eq!(trailers.len(), length + 5);
        let text = std::str::from_utf8(&trailers[5..]).unwrap();
        assert!(text.contains("grpc-status: 7\r\n"));
        assert!(text.contains("grpc-message: line  break\r\n"));
    }

    #[test]
    fn rejects_malformed_grpc_web_frames() {
        assert!(decode_web_data_frame(&[]).is_err());
        assert!(decode_web_data_frame(&[0x80, 0, 0, 0, 0]).is_err());
        assert!(decode_web_data_frame(&[0, 0, 0, 0, 1]).is_err());
    }
}
