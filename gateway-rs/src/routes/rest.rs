use std::{
    net::SocketAddr,
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{ConnectInfo, OriginalUri, Request, State},
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use serde_json::Value;

use crate::{
    error::GatewayError,
    gateway::{
        circuit_breaker::{check as circuit_allows, record_failure, record_success},
        transforms::{transform_request, transform_response},
    },
    middleware::{
        body_limit::BodyLimits,
        cors::{apply_actual_response, preflight_response},
    },
    policy::{
        PolicyErrorBody,
        evaluator::{PolicyRequest, PolicyRuntime, evaluate_rest_policy, evaluate_shared_effects},
    },
    state::AppState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataPlaneProtocol {
    Rest,
    Graphql,
    Soap,
    Grpc,
    GrpcWeb,
}

#[derive(Clone, Debug)]
pub struct PolicyPath(pub String);

pub async fn rest_policy_then_proxy(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, GatewayError> {
    if !matches!(
        *request.method(),
        http::Method::GET
            | http::Method::POST
            | http::Method::PUT
            | http::Method::DELETE
            | http::Method::HEAD
            | http::Method::PATCH
            | http::Method::OPTIONS
    ) {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let protocol = request
        .extensions()
        .get::<DataPlaneProtocol>()
        .copied()
        .unwrap_or(DataPlaneProtocol::Rest);
    let path = request
        .extensions()
        .get::<PolicyPath>()
        .map(|value| value.0.clone())
        .or_else(|| {
            request
                .extensions()
                .get::<OriginalUri>()
                .map(|value| value.0.path().to_owned())
        })
        .unwrap_or_else(|| request.uri().path().to_owned());
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip());
    let headers = request.headers().clone();
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let policy_method = if request.method() == http::Method::OPTIONS {
        headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| http::Method::from_bytes(value.as_bytes()).ok())
            .unwrap_or(http::Method::OPTIONS)
    } else {
        request.method().clone()
    };
    let policy_request = PolicyRequest {
        method: policy_method,
        path,
        headers,
        direct_ip: peer,
        now_millis: now_millis(),
        content_length,
    };

    let documents = if let Some(injected) = &state.policy_documents {
        injected
            .lock()
            .map(|documents| documents.clone())
            .map_err(|error| error.to_string())
    } else if let Some(storage) = &state.storage {
        storage
            .load_policy_documents()
            .await
            .map_err(|error| error.to_string())
    } else {
        Err("shared policy storage is unavailable".to_owned())
    };
    let result = match documents {
        Ok(mut documents) => match evaluate_rest_policy(
            &mut documents,
            &policy_request,
            &state.config.shared_storage,
            &PolicyRuntime::default(),
        ) {
            Ok(Some(mut decision)) => {
                if let Some(storage) = &state.storage {
                    evaluate_shared_effects(
                        &documents,
                        &policy_request,
                        &mut decision,
                        storage,
                        true,
                    )
                    .await
                    .map(|()| Some(decision))
                } else if state.policy_documents.is_some() {
                    Ok(Some(decision))
                } else {
                    Err(crate::policy::PolicyFailure::new(
                        crate::policy::PolicyStage::Resolution,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "GTW006",
                        "Gateway state store unavailable",
                    ))
                }
            }
            other => other,
        },
        Err(error) => {
            tracing::error!(error = %error, "rust policy storage unavailable");
            Err(crate::policy::PolicyFailure::new(
                crate::policy::PolicyStage::Resolution,
                StatusCode::SERVICE_UNAVAILABLE,
                "GTW006",
                "Gateway state store unavailable",
            ))
        }
    };
    match result {
        Ok(Some(decision)) => {
            if request.method() == http::Method::OPTIONS {
                let mut response = preflight_response(&decision, request.headers());
                if protocol != DataPlaneProtocol::Rest
                    && !cors_requested_headers_are_allowed(&decision, request.headers())
                {
                    response
                        .headers_mut()
                        .remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
                }
                return Ok(response);
            }
            let origin = request
                .headers()
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut response = execute_rest(&state, request, decision.clone(), protocol).await?;
            apply_tier_headers(&mut response, decision.tier_limit_status.as_ref());
            apply_actual_response(&mut response, &decision, origin.as_deref());
            response
                .extensions_mut()
                .insert(crate::middleware::activity::ActivityContext {
                    username: decision
                        .username
                        .clone()
                        .or_else(|| decision.tier_username.clone()),
                    api: decision
                        .api_name
                        .as_ref()
                        .map(|name| format!("{}:{name}", protocol_name(protocol))),
                    endpoint: decision.upstream_path.clone(),
                    upstream: decision.upstream.clone(),
                });
            Ok(response)
        }
        Ok(None) => Ok((
            StatusCode::NOT_FOUND,
            Json(PolicyErrorBody {
                error_code: "GTW001".to_owned(),
                error_message: "API does not exist for the requested name and version".to_owned(),
            }),
        )
            .into_response()),
        Err(failure) => {
            if request.method() == http::Method::OPTIONS
                && std::env::var("STRICT_OPTIONS_405")
                    .ok()
                    .is_some_and(|value| {
                        matches!(
                            value.to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                    })
                && failure.error_code == "GTW003"
            {
                return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
            }
            if let Some(tier_limit) = failure.tier_limit {
                let (body, status) = *tier_limit;
                let mut response = (failure.status, Json(body)).into_response();
                apply_tier_headers(&mut response, Some(&status));
                return Ok(response);
            }
            Ok((
                failure.status,
                Json(PolicyErrorBody {
                    error_code: failure.error_code,
                    error_message: failure.error_message,
                }),
            )
                .into_response())
        }
    }
}

fn protocol_name(protocol: DataPlaneProtocol) -> &'static str {
    match protocol {
        DataPlaneProtocol::Rest => "rest",
        DataPlaneProtocol::Graphql => "graphql",
        DataPlaneProtocol::Soap => "soap",
        DataPlaneProtocol::Grpc | DataPlaneProtocol::GrpcWeb => "grpc",
    }
}

fn cors_requested_headers_are_allowed(
    decision: &crate::policy::PolicyDecision,
    request_headers: &HeaderMap,
) -> bool {
    let Some(requested) = request_headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Some(allowed) = decision.cors_allow_headers.as_deref() else {
        return true;
    };
    allowed.iter().any(|value| value.trim() == "*")
        || requested.split(',').map(str::trim).all(|header| {
            allowed
                .iter()
                .any(|allowed| allowed.trim().eq_ignore_ascii_case(header))
        })
}

fn apply_tier_headers(
    response: &mut Response,
    status: Option<&crate::policy::tier::TierLimitStatus>,
) {
    let Some(status) = status else {
        return;
    };
    for (name, value) in status.headers() {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::try_from(name),
            http::HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
}

async fn execute_rest(
    state: &AppState,
    request: Request,
    mut decision: crate::policy::PolicyDecision,
    protocol: DataPlaneProtocol,
) -> Result<Response, GatewayError> {
    if matches!(
        protocol,
        DataPlaneProtocol::Rest | DataPlaneProtocol::Graphql | DataPlaneProtocol::Soap
    ) {
        let settings = state.hot_reload.http_settings();
        if let Some(timeout_seconds) = settings.timeout_seconds {
            decision.request_timeout_ms = timeout_seconds.saturating_mul(1_000);
        }
        if let Some(retry_count) = settings.retry_count {
            decision.retry_count = retry_count;
        }
    }
    if let Some(delay_ms) = decision.throttle_delay_ms.filter(|delay| *delay > 0) {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }
    if decision.is_crud {
        if protocol == DataPlaneProtocol::Rest {
            return execute_crud(state, request, &decision).await;
        }
        return crate::protocol::crud::execute(state, request, &decision, protocol).await;
    }
    let circuit_key = decision
        .api_id
        .clone()
        .unwrap_or_else(|| "unknown".to_owned());

    let Some(base_url) = decision.upstream.clone() else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(PolicyErrorBody {
                error_code: "GTW001".to_owned(),
                error_message: "No upstream servers configured".to_owned(),
            }),
        )
            .into_response());
    };
    if !circuit_allows(&state.runtime.circuits, &circuit_key) {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(PolicyErrorBody {
                error_code: "GTW999".to_owned(),
                error_message: "Upstream circuit open".to_owned(),
            }),
        )
            .into_response());
    }
    let upstream_path = decision
        .upstream_path
        .clone()
        .unwrap_or_else(|| "/".to_owned());
    let original_query = request.uri().query().map(str::to_owned);
    let request_path = request.uri().path().to_owned();
    let (parts, body) = request.into_parts();
    let limits = BodyLimits::from_env();
    let body_limit = match protocol {
        DataPlaneProtocol::Rest => limits.rest,
        DataPlaneProtocol::Graphql => limits.graphql,
        DataPlaneProtocol::Soap => limits.soap,
        DataPlaneProtocol::Grpc | DataPlaneProtocol::GrpcWeb => limits.grpc,
    };
    let body = match to_bytes(body, BodyLimits::for_path(&request_path, body_limit)).await {
        Ok(body) => body,
        Err(_) => {
            return Ok(policy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "REQ001",
                &format!("Request entity too large (max: {body_limit} bytes)"),
            ));
        }
    };
    if let Err(failure) = validate_protocol_request_with_registry(
        protocol,
        &parts.method,
        &body,
        decision.graphql_max_depth,
        decision.endpoint_validation.as_ref(),
        state.validators.as_ref(),
    ) {
        return Ok((
            failure.status,
            Json(PolicyErrorBody {
                error_code: failure.error_code,
                error_message: failure.error_message,
            }),
        )
            .into_response());
    }
    if protocol == DataPlaneProtocol::Grpc {
        let (headers, body, _) = transform_request(
            parts.headers.clone(),
            body.to_vec(),
            None,
            decision.request_transform.as_ref(),
        );
        return Ok(
            crate::protocol::grpc::execute_json_gateway(state, &decision, &headers, &body).await,
        );
    }
    if protocol == DataPlaneProtocol::GrpcWeb {
        let Some(target) = parts
            .extensions
            .get::<crate::routes::grpc_web::GrpcWebTarget>()
            .cloned()
        else {
            return Ok(policy_error_response(
                StatusCode::BAD_REQUEST,
                "GTW011",
                "Invalid gRPC-Web target",
            ));
        };
        return Ok(crate::protocol::grpc::execute_web_gateway(
            state,
            &decision,
            &parts.headers,
            &body,
            &target.service,
            &target.method,
        )
        .await);
    }
    let request_header_bytes = parts
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>();
    let request_body_bytes = body.len();
    let allowed = decision
        .allowed_headers
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        let lower = name.as_str().to_ascii_lowercase();
        let always_forward = matches!(
            lower.as_str(),
            "content-type" | "accept" | "user-agent" | "x-request-id"
        );
        let protocol_default = protocol == DataPlaneProtocol::Soap
            && matches!(
                lower.as_str(),
                "soapaction" | "user-agent" | "accept-encoding"
            );
        if (always_forward || protocol_default || allowed.iter().any(|item| item == &lower))
            && !is_hop_by_hop(name)
            && !is_sensitive_forward_header(name)
            && name != header::HOST
        {
            if let Some(value) = sanitize_forwarded_header_value(value) {
                headers.append(name.clone(), value);
            }
        }
    }
    if let Some(source_name) = decision
        .authorization_field_swap
        .as_deref()
        .and_then(|name| HeaderName::try_from(name).ok())
    {
        let swapped = headers
            .get(&source_name)
            .filter(|value| !value.as_bytes().iter().all(u8::is_ascii_whitespace))
            .cloned()
            .or_else(|| parts.headers.get(header::AUTHORIZATION).cloned());
        if let Some(value) = swapped {
            headers.insert(header::AUTHORIZATION, value);
        }
    }
    if protocol == DataPlaneProtocol::Graphql {
        headers.insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
    }
    if let Some(username) = decision.username.as_deref() {
        if let Ok(value) = http::HeaderValue::from_str(username) {
            headers.insert("x-user-email", value.clone());
            headers.insert("x-doorman-user", value);
        }
    }
    if let Some(name) = decision
        .credit_header_name
        .as_deref()
        .and_then(|name| HeaderName::try_from(name).ok())
    {
        let value = decision
            .user_credit_header_value
            .as_deref()
            .or(decision.credit_header_value.as_deref());
        if let Some(value) = value.and_then(|value| http::HeaderValue::from_str(value).ok()) {
            headers.insert(name, value);
        }
    }
    let mut headers = headers;
    let mut outbound_body = body.to_vec();
    if protocol == DataPlaneProtocol::Soap {
        outbound_body = crate::protocol::soap::prepare_request(
            &mut headers,
            outbound_body,
            decision.soap_version.as_deref(),
            decision.ws_security.as_ref(),
        );
    }
    let (headers, body, query) = transform_request(
        headers,
        outbound_body,
        original_query.as_deref(),
        decision.request_transform.as_ref(),
    );
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let target = format!(
        "{}/{}{}",
        base_url.trim_end_matches('/'),
        upstream_path.trim_start_matches('/'),
        query
    );
    let attempts = decision.retry_count.saturating_add(1);
    let mut attempt = 0_u32;
    let upstream = loop {
        attempt += 1;
        let result = state
            .proxy_client
            .request(parts.method.clone(), target.clone())
            .headers(headers.clone())
            .timeout(std::time::Duration::from_millis(
                decision.request_timeout_ms.max(1),
            ))
            .body(body.clone())
            .send()
            .await;
        match result {
            Ok(response)
                if matches!(response.status().as_u16(), 500 | 502 | 503 | 504)
                    && attempt < attempts =>
            {
                record_failure(&state.runtime.circuits, &circuit_key);
                state.runtime.retries_total.fetch_add(1, Ordering::Relaxed);
                retry_backoff(attempt).await;
            }
            Ok(response) => break response,
            Err(error) if error.is_timeout() && attempt < attempts => {
                record_failure(&state.runtime.circuits, &circuit_key);
                state.runtime.retries_total.fetch_add(1, Ordering::Relaxed);
                state
                    .runtime
                    .upstream_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                retry_backoff(attempt).await;
            }
            Err(_) if attempt < attempts => {
                record_failure(&state.runtime.circuits, &circuit_key);
                state.runtime.retries_total.fetch_add(1, Ordering::Relaxed);
                retry_backoff(attempt).await;
            }
            Err(error) if error.is_timeout() => {
                record_failure(&state.runtime.circuits, &circuit_key);
                state
                    .runtime
                    .upstream_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok((
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(PolicyErrorBody {
                        error_code: "GTW010".to_owned(),
                        error_message: "Gateway timeout".to_owned(),
                    }),
                )
                    .into_response());
            }
            Err(error) => {
                record_failure(&state.runtime.circuits, &circuit_key);
                return Err(error.into());
            }
        }
    };
    let status = upstream.status();
    if matches!(status.as_u16(), 500 | 502 | 503 | 504) {
        record_failure(&state.runtime.circuits, &circuit_key);
    } else {
        record_success(&state.runtime.circuits, &circuit_key);
    }
    if status == StatusCode::NOT_FOUND {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(PolicyErrorBody {
                error_code: "GTW005".to_owned(),
                error_message: "Endpoint does not exist in backend service".to_owned(),
            }),
        )
            .into_response());
    }
    let upstream_headers = upstream.headers().clone();
    let bytes = upstream.bytes().await?;
    if let (Some(storage), Some(key), Some(ttl)) = (
        state.storage.as_ref(),
        decision.bandwidth_key.as_deref(),
        decision.bandwidth_ttl_seconds,
    ) {
        let response_header_bytes = upstream_headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>();
        let accounted = request_header_bytes
            .saturating_add(request_body_bytes)
            .saturating_add(response_header_bytes)
            .saturating_add(bytes.len()) as u64;
        if let Err(error) = storage.add_bandwidth(key, accounted, ttl).await {
            tracing::error!(error = %error, "bandwidth accounting failed");
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(PolicyErrorBody {
                    error_code: "GTW006".to_owned(),
                    error_message: "Gateway state store unavailable".to_owned(),
                }),
            )
                .into_response());
        }
    }
    let (upstream_headers, bytes, status) = transform_response(
        upstream_headers,
        bytes.to_vec(),
        status,
        decision.response_transform.as_ref(),
    );
    // GraphQL clients expect execution failures in a valid `errors` envelope,
    // even when an upstream incorrectly reports that envelope with a 5xx status.
    // Preserve transport failures and malformed/non-GraphQL responses as errors.
    let status = if protocol == DataPlaneProtocol::Graphql
        && status.is_server_error()
        && serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|body| body.get("errors").and_then(Value::as_array).cloned())
            .is_some_and(|errors| !errors.is_empty())
    {
        StatusCode::OK
    } else {
        status
    };
    let is_json = upstream_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("application/json"));
    if protocol == DataPlaneProtocol::Rest
        && is_json
        && serde_json::from_slice::<Value>(&bytes).is_err()
    {
        return Ok(policy_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "GTW006",
            "Malformed JSON from upstream",
        ));
    }
    let upstream_content_type = upstream_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(match protocol {
            DataPlaneProtocol::Soap => "application/xml",
            DataPlaneProtocol::Grpc | DataPlaneProtocol::GrpcWeb => "application/grpc",
            DataPlaneProtocol::Rest | DataPlaneProtocol::Graphql => "application/json",
        })
        .to_owned();
    let (body, content_type) = match protocol {
        DataPlaneProtocol::Soap
        | DataPlaneProtocol::Graphql
        | DataPlaneProtocol::Grpc
        | DataPlaneProtocol::GrpcWeb => (bytes.to_vec(), upstream_content_type),
        DataPlaneProtocol::Rest if !is_json => (
            serde_json::to_vec(&String::from_utf8_lossy(&bytes))
                .unwrap_or_else(|_| b"null".to_vec()),
            "application/json".to_owned(),
        ),
        DataPlaneProtocol::Rest => (bytes.to_vec(), upstream_content_type),
    };
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type);
    for name in [
        "grpc-status",
        "grpc-message",
        "grpc-encoding",
        "grpc-accept-encoding",
    ] {
        if protocol == DataPlaneProtocol::Grpc {
            if let Some(value) = upstream_headers.get(name) {
                response = response.header(name, value);
            }
        }
    }
    for name in &decision.allowed_headers {
        if let Ok(header_name) = HeaderName::try_from(name) {
            if let Some(value) = upstream_headers.get(&header_name) {
                response = response.header(header_name, value);
            }
        }
    }
    Ok(response.body(Body::from(body))?)
}

async fn execute_crud(
    state: &AppState,
    request: Request,
    decision: &crate::policy::PolicyDecision,
) -> Result<Response, GatewayError> {
    let Some(storage) = state.storage.as_ref() else {
        return Ok(policy_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "GTW006",
            "Gateway state store unavailable",
        ));
    };
    let Some(collection) = decision
        .crud_collection
        .as_deref()
        .filter(|name| valid_collection_name(name))
    else {
        return Ok(policy_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CRUD500",
            "CRUD collection is not configured",
        ));
    };

    let method = request.method().clone();
    let request_path = request.uri().path().to_owned();
    let resource_id = crud_resource_id(&request_path).map(str::to_owned);
    let (_, body) = request.into_parts();
    let body_limit = BodyLimits::from_env().rest;
    let body = match to_bytes(body, BodyLimits::for_path(&request_path, body_limit)).await {
        Ok(body) => body,
        Err(_) => {
            return Ok(policy_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "REQ001",
                &format!("Request entity too large (max: {body_limit} bytes)"),
            ));
        }
    };
    let operation = async {
        match method {
            http::Method::GET => {
                if let Some(resource_id) = resource_id.as_deref() {
                    storage
                        .crud_find_one(collection, resource_id)
                        .await
                        .map(|value| match value {
                            Some(value) => crud_success(StatusCode::OK, value),
                            None => policy_error_response(
                                StatusCode::NOT_FOUND,
                                "CRUD404",
                                "Resource not found",
                            ),
                        })
                } else {
                    storage.crud_list(collection).await.map(|items| {
                        crud_success(StatusCode::OK, serde_json::json!({ "items": items }))
                    })
                }
            }
            http::Method::POST => {
                let mut value = parse_crud_body(&body)?;
                if value.get("_id").is_none() {
                    value["_id"] = Value::String(uuid::Uuid::new_v4().to_string());
                }
                validate_crud_schema(decision.crud_schema.as_ref(), &value, false)?;
                storage
                    .crud_insert(collection, &value)
                    .await
                    .map(|()| crud_success(StatusCode::CREATED, value))
            }
            http::Method::PUT | http::Method::PATCH => {
                let Some(resource_id) = resource_id.as_deref() else {
                    return Ok(policy_error_response(
                        StatusCode::BAD_REQUEST,
                        "CRUD400",
                        "Resource ID required for update",
                    ));
                };
                let value = parse_crud_body(&body)?;
                validate_crud_schema(decision.crud_schema.as_ref(), &value, true)?;
                storage
                    .crud_update(collection, resource_id, &value)
                    .await
                    .map(|value| match value {
                        Some(value) => crud_success(StatusCode::OK, value),
                        None => policy_error_response(
                            StatusCode::NOT_FOUND,
                            "CRUD404",
                            "Resource not found",
                        ),
                    })
            }
            http::Method::DELETE => {
                let Some(resource_id) = resource_id.as_deref() else {
                    return Ok(policy_error_response(
                        StatusCode::BAD_REQUEST,
                        "CRUD400",
                        "Resource ID required for deletion",
                    ));
                };
                storage
                    .crud_delete(collection, resource_id)
                    .await
                    .map(|deleted| {
                        if deleted {
                            crud_success(
                                StatusCode::OK,
                                serde_json::json!({ "message": "Resource deleted successfully" }),
                            )
                        } else {
                            policy_error_response(
                                StatusCode::NOT_FOUND,
                                "CRUD404",
                                "Resource not found",
                            )
                        }
                    })
            }
            _ => Ok(policy_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "CRUD405",
                "Method not allowed",
            )),
        }
    }
    .await;

    match operation {
        Ok(response) => Ok(response),
        Err(crate::storage::runtime::StorageError::InvalidDocument(error)) => {
            tracing::debug!(error = %error, "CRUD validation failed");
            Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error_code": "CRUD400",
                    "error_message": "Validation failed",
                    "response": {"errors": error.split("; ").collect::<Vec<_>>()}
                })),
            )
                .into_response())
        }
        Err(error) => {
            tracing::error!(error = %error, "CRUD storage operation failed");
            Ok(policy_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "GTW006",
                "Gateway state store unavailable",
            ))
        }
    }
}

pub(crate) fn valid_collection_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && !name.starts_with("system.")
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn crud_resource_id(path: &str) -> Option<&str> {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let rest = segments.iter().position(|segment| *segment == "rest")?;
    let endpoint = segments.get(rest + 3..)?;
    (endpoint.len() > 1).then(|| *endpoint.last().expect("endpoint is non-empty"))
}

fn parse_crud_body(body: &[u8]) -> Result<Value, crate::storage::runtime::StorageError> {
    // Python treats request.json() failures as an empty object for CRUD REST.
    let value: Value = serde_json::from_slice(body).unwrap_or_else(|_| serde_json::json!({}));
    if !value.is_object() {
        return Err(crate::storage::runtime::StorageError::InvalidDocument(
            "CRUD request body must be a JSON object".to_owned(),
        ));
    }
    Ok(value)
}

pub(crate) fn validate_crud_schema(
    schema: Option<&Value>,
    value: &Value,
    partial: bool,
) -> Result<(), crate::storage::runtime::StorageError> {
    let Some(schema) = schema.and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(value) = value.as_object() else {
        return Err(crate::storage::runtime::StorageError::InvalidDocument(
            "CRUD request body must be a JSON object".to_owned(),
        ));
    };
    let mut errors = Vec::new();
    validate_crud_fields(schema, value, partial, "", &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(crate::storage::runtime::StorageError::InvalidDocument(
            errors.join("; "),
        ))
    }
}

fn validate_crud_fields(
    schema: &serde_json::Map<String, Value>,
    value: &serde_json::Map<String, Value>,
    partial: bool,
    prefix: &str,
    errors: &mut Vec<String>,
) {
    for (field, rules) in schema {
        let Some(rules) = rules.as_object() else {
            continue;
        };
        let path = if prefix.is_empty() {
            field.clone()
        } else {
            format!("{prefix}.{field}")
        };
        let field_value = value.get(field).filter(|value| !value.is_null());
        if field_value.is_none() {
            if !partial && rules.get("required").and_then(Value::as_bool) == Some(true) {
                errors.push(format!("Field '{path}' is required"));
            }
            continue;
        }
        let field_value = field_value.expect("checked above");
        let expected = rules.get("type").and_then(Value::as_str);
        let valid_type = match expected {
            Some("string") => field_value.is_string(),
            Some("number") => field_value.is_number() || field_value.is_boolean(),
            Some("integer") => {
                field_value.as_i64().is_some()
                    || field_value.as_u64().is_some()
                    || field_value.is_boolean()
            }
            Some("boolean") => field_value.is_boolean(),
            Some("array") => field_value.is_array(),
            Some("object") => field_value.is_object(),
            _ => true,
        };
        if !valid_type {
            errors.push(format!(
                "Field '{path}' must be of type {}",
                expected.unwrap_or_default()
            ));
            continue;
        }
        if let Some(text) = field_value.as_str() {
            if rules
                .get("min_length")
                .and_then(Value::as_u64)
                .is_some_and(|min| text.chars().count() < min as usize)
            {
                errors.push(format!(
                    "Field '{path}' must be at least {} characters",
                    rules["min_length"]
                ));
            }
            if rules
                .get("max_length")
                .and_then(Value::as_u64)
                .is_some_and(|max| text.chars().count() > max as usize)
            {
                errors.push(format!(
                    "Field '{path}' must be at most {} characters",
                    rules["max_length"]
                ));
            }
            if let Some(pattern) = rules.get("pattern").and_then(Value::as_str)
                && let Ok(pattern) = regex::Regex::new(&format!("^(?:{pattern})"))
                && !pattern.is_match(text)
            {
                errors.push(format!(
                    "Field '{path}' does not match pattern {}",
                    rules["pattern"].as_str().unwrap_or_default()
                ));
            }
            if let Some(allowed) = rules.get("enum").and_then(Value::as_array)
                && !allowed.contains(field_value)
            {
                errors.push(format!(
                    "Field '{path}' must be one of: {}",
                    allowed
                        .iter()
                        .map(|value| value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        let numeric_value = field_value.as_f64().or_else(|| {
            field_value
                .as_bool()
                .map(|value| if value { 1.0 } else { 0.0 })
        });
        if let Some(numeric_value) = numeric_value {
            if let Some(minimum) = rules.get("min_value").and_then(Value::as_f64)
                && numeric_value < minimum
            {
                errors.push(format!("Field '{path}' must be >= {}", rules["min_value"]));
            }
            if let Some(maximum) = rules.get("max_value").and_then(Value::as_f64)
                && numeric_value > maximum
            {
                errors.push(format!("Field '{path}' must be <= {}", rules["max_value"]));
            }
        }
        if let (Some(properties), Some(object)) = (
            rules.get("properties").and_then(Value::as_object),
            field_value.as_object(),
        ) {
            validate_crud_fields(properties, object, false, &path, errors);
        }
    }
}

fn crud_success(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn policy_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(PolicyErrorBody {
            error_code: code.to_owned(),
            error_message: message.to_owned(),
        }),
    )
        .into_response()
}

#[cfg(test)]
fn validate_protocol_request(
    protocol: DataPlaneProtocol,
    method: &http::Method,
    body: &[u8],
    graphql_max_depth: u64,
    endpoint_validation: Option<&Value>,
) -> Result<(), crate::policy::PolicyFailure> {
    validate_protocol_request_with_registry(
        protocol,
        method,
        body,
        graphql_max_depth,
        endpoint_validation,
        &crate::validation::json::ValidatorRegistry::default(),
    )
}

fn validate_protocol_request_with_registry(
    protocol: DataPlaneProtocol,
    method: &http::Method,
    body: &[u8],
    graphql_max_depth: u64,
    endpoint_validation: Option<&Value>,
    validators: &crate::validation::json::ValidatorRegistry,
) -> Result<(), crate::policy::PolicyFailure> {
    match protocol {
        DataPlaneProtocol::Rest => {
            if let Some(schema) = endpoint_validation {
                let document: Value = serde_json::from_slice(body)
                    .map_err(|_| protocol_failure("GTW011", "Invalid JSON in request body"))?;
                crate::validation::json::validate_json_with_registry(&document, schema, validators)
                    .map_err(|error| protocol_failure("GTW011", error))?;
            }
            Ok(())
        }
        DataPlaneProtocol::Graphql => {
            let document: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| protocol_failure("GTW011", "Invalid GraphQL request body"))?;
            let query = document
                .get("query")
                .and_then(serde_json::Value::as_str)
                .filter(|query| !query.trim().is_empty())
                .ok_or_else(|| protocol_failure("GTW011", "GraphQL query is required"))?;
            let depth = graphql_depth(query)
                .ok_or_else(|| protocol_failure("GTW011", "Invalid GraphQL query"))?;
            if graphql_max_depth > 0 && depth > graphql_max_depth {
                return Err(protocol_failure(
                    "GTW013",
                    format!(
                        "Query depth {depth} exceeds maximum allowed depth of {graphql_max_depth}"
                    ),
                ));
            }
            if let Some(schema) = endpoint_validation {
                let variables = document.get("variables").unwrap_or(&Value::Null);
                let scoped_schema = graphql_validation_schema(schema, query);
                crate::validation::json::validate_json_with_registry(
                    variables,
                    &scoped_schema,
                    validators,
                )
                .map_err(|error| protocol_failure("GTW011", error))?;
            }
            Ok(())
        }
        DataPlaneProtocol::Soap if *method == http::Method::GET && body.is_empty() => Ok(()),
        DataPlaneProtocol::Soap => {
            let xml = std::str::from_utf8(body)
                .map_err(|_| protocol_failure("GTW011", "Invalid SOAP envelope"))?;
            let lower = xml.to_ascii_lowercase();
            if lower.contains("<!doctype") || lower.contains("<!entity") {
                return Err(protocol_failure(
                    "GTW011",
                    "XML DTD/entities are not allowed",
                ));
            }
            if let Some(schema) = endpoint_validation {
                let document = crate::validation::xml::soap_body_object(xml)
                    .map_err(|error| protocol_failure("GTW011", error))?;
                crate::validation::json::validate_json_with_registry(&document, schema, validators)
                    .map_err(|error| protocol_failure("GTW011", error))?;
            }
            Ok(())
        }
        DataPlaneProtocol::Grpc => {
            let document: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| protocol_failure("GTW011", "Invalid JSON in request body"))?;
            let grpc_method = document
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let mut parts = grpc_method.split('.');
            let valid_part = |part: &str| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
            };
            if !parts.next().is_some_and(valid_part)
                || !parts.next().is_some_and(valid_part)
                || parts.next().is_some()
            {
                return Err(protocol_failure(
                    "GTW011",
                    "Invalid gRPC method. Use Service.Method with alphanumerics/underscore.",
                ));
            }
            if let Some(schema) = endpoint_validation {
                let message = document.get("message").unwrap_or(&Value::Null);
                crate::validation::json::validate_json_with_registry(message, schema, validators)
                    .map_err(|error| protocol_failure("GTW011", error))?;
            }
            Ok(())
        }
        DataPlaneProtocol::GrpcWeb => Ok(()),
    }
}

fn graphql_validation_schema(schema: &Value, query: &str) -> Value {
    let Some(operation) = regex::Regex::new(r"(?:query|mutation)\s+(\w+)")
        .ok()
        .and_then(|regex| regex.captures(query))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str())
    else {
        return serde_json::json!({});
    };
    let mapping = schema
        .get("validation_schema")
        .unwrap_or(schema)
        .as_object();
    let Some(mapping) = mapping else {
        return serde_json::json!({});
    };
    let prefix = format!("{operation}.");
    Value::Object(
        mapping
            .iter()
            .filter_map(|(path, rules)| {
                path.strip_prefix(&prefix)
                    .map(|path| (path.to_owned(), rules.clone()))
            })
            .collect(),
    )
}

pub(crate) fn graphql_depth(query: &str) -> Option<u64> {
    let mut depth = 0_u64;
    let mut maximum = 0_u64;
    let mut quote = None;
    let mut comment = false;
    let mut escaped = false;
    for character in query.chars() {
        if comment {
            if character == '\n' {
                comment = false;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '#' => comment = true,
            '\'' | '"' => quote = Some(character),
            '{' => {
                depth += 1;
                maximum = maximum.max(depth);
            }
            '}' if depth == 0 => return None,
            '}' => depth -= 1,
            _ => {}
        }
    }
    (quote.is_none() && depth == 0).then_some(maximum)
}

fn protocol_failure(
    code: impl Into<String>,
    message: impl Into<String>,
) -> crate::policy::PolicyFailure {
    crate::policy::PolicyFailure::new(
        crate::policy::PolicyStage::Resolution,
        StatusCode::BAD_REQUEST,
        code,
        message,
    )
}

async fn retry_backoff(attempt: u32) {
    let base_ms = std::env::var("HTTP_RETRY_BASE_DELAY")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|seconds| (seconds * 1000.0) as u64)
        .unwrap_or(250);
    let maximum_ms = std::env::var("HTTP_RETRY_MAX_DELAY")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|seconds| (seconds * 1000.0) as u64)
        .unwrap_or(2_000);
    let delay_ms = base_ms
        .saturating_mul(1_u64 << attempt.min(20))
        .min(maximum_ms);
    let jitter_ms = if delay_ms == 0 {
        0
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64
            % (delay_ms + 1)
    };
    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_sensitive_forward_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "www-authenticate"
            | "x-api-key"
            | "api-key"
            | "cookie"
            | "set-cookie"
            | "x-csrf-token"
            | "csrf-token"
    )
}

/// Matches Python's gateway header sanitizer for values that are safe to
/// forward: remove line/control separators and complete HTML-like tags.
fn sanitize_forwarded_header_value(value: &HeaderValue) -> Option<HeaderValue> {
    let mut sanitized = value.to_str().ok()?.replace(['\n', '\r', '\0'], "");
    while let Some(start) = sanitized.find('<') {
        let Some(relative_end) = sanitized[start + 1..].find('>') else {
            break;
        };
        let end = start + relative_end + 2;
        sanitized.replace_range(start..end, "");
    }
    if sanitized.chars().count() > 8_192 {
        sanitized = sanitized.chars().take(8_192).collect::<String>();
        sanitized.push_str("...[TRUNCATED]");
    }
    HeaderValue::from_str(&sanitized).ok()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::to_bytes, routing::any};
    use http::{Method, Request};
    use serde_json::{Value, json};

    #[test]
    fn sanitizes_and_bounds_forwarded_header_values_like_python() {
        let value = HeaderValue::from_static("abc<script>alert(1)</script>");
        assert_eq!(
            sanitize_forwarded_header_value(&value)
                .unwrap()
                .to_str()
                .unwrap(),
            "abcalert(1)"
        );
        let long = HeaderValue::from_str(&"a".repeat(8_193)).unwrap();
        let sanitized = sanitize_forwarded_header_value(&long).unwrap();
        assert_eq!(sanitized.as_bytes().len(), 8_206);
        assert!(sanitized.to_str().unwrap().ends_with("...[TRUNCATED]"));
    }

    #[test]
    fn sensitive_allowed_request_headers_are_never_forwarded() {
        assert!(is_sensitive_forward_header(&HeaderName::from_static(
            "authorization"
        )));
        assert!(is_sensitive_forward_header(&HeaderName::from_static(
            "x-api-key"
        )));
        assert!(!is_sensitive_forward_header(&HeaderName::from_static(
            "x-allowed"
        )));
    }

    #[tokio::test]
    async fn executes_selected_upstream_with_filtered_and_credit_headers() {
        async fn upstream(
            method: Method,
            headers: HeaderMap,
            uri: http::Uri,
            body: axum::body::Bytes,
        ) -> (StatusCode, [(String, String); 1], Json<Value>) {
            (
                StatusCode::CREATED,
                [("x-upstream".to_owned(), "kept".to_owned())],
                Json(json!({
                    "method": method.as_str(),
                    "body": String::from_utf8_lossy(&body),
                    "x-test": headers.get("x-test").and_then(|value| value.to_str().ok()),
                    "x-secret": headers.get("x-secret").and_then(|value| value.to_str().ok()),
                    "x-api-key": headers.get("x-api-key").and_then(|value| value.to_str().ok()),
                    "x-user-email": headers.get("x-user-email").and_then(|value| value.to_str().ok()),
                    "query": uri.query(),
                })),
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/items", any(upstream)))
                .await
                .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let decision = crate::policy::PolicyDecision {
            upstream: Some(format!("http://{address}")),
            upstream_path: Some("/items".to_owned()),
            allowed_headers: vec!["X-Test".to_owned(), "x-upstream".to_owned()],
            username: Some("alice".to_owned()),
            credit_header_name: Some("x-api-key".to_owned()),
            credit_header_value: Some("system-key".to_owned()),
            user_credit_header_value: Some("user-key".to_owned()),
            request_timeout_ms: 1_000,
            ..Default::default()
        };
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/rest/demo/v1/items?foo=1&bar=2")
            .header("content-type", "application/json")
            .header("x-test", "abc<script>alert(1)</script>")
            .header("x-secret", "dropped")
            .body(Body::from(r#"{"hello":"world"}"#))
            .unwrap();

        let response = execute_rest(&state, request, decision.clone(), DataPlaneProtocol::Rest)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get("x-upstream").unwrap(), "kept");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["method"], "POST");
        assert_eq!(body["x-test"], "abcalert(1)");
        assert!(body["x-secret"].is_null());
        assert_eq!(body["x-api-key"], "user-key");
        assert_eq!(body["x-user-email"], "alice");
        assert_eq!(body["query"], "foo=1&bar=2");
        assert_eq!(body["body"], r#"{"hello":"world"}"#);

        let text_response = execute_rest(
            &state,
            Request::builder()
                .method(Method::POST)
                .uri("/api/rest/demo/v1/items")
                .header("content-type", "text/plain")
                .body(Body::from("hello-world"))
                .unwrap(),
            decision,
            DataPlaneProtocol::Rest,
        )
        .await
        .unwrap();
        assert_eq!(text_response.status(), StatusCode::CREATED);
        let text_body: Value =
            serde_json::from_slice(&to_bytes(text_response.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(text_body["body"], "hello-world");
        server.abort();
    }

    #[tokio::test]
    async fn maps_upstream_not_found_to_python_gateway_error() {
        async fn upstream_not_found() -> StatusCode {
            StatusCode::NOT_FOUND
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/missing", any(upstream_not_found)),
            )
            .await
            .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let decision = crate::policy::PolicyDecision {
            upstream: Some(format!("http://{address}")),
            upstream_path: Some("/missing".to_owned()),
            request_timeout_ms: 1_000,
            ..Default::default()
        };
        let request = Request::builder()
            .uri("/api/rest/demo/v1/missing")
            .body(Body::empty())
            .unwrap();

        let response = execute_rest(&state, request, decision, DataPlaneProtocol::Rest)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["error_code"], "GTW005");
        assert_eq!(
            body["error_message"],
            "Endpoint does not exist in backend service"
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_malformed_json_from_rest_upstream_like_python() {
        async fn malformed_json() -> ([(http::HeaderName, &'static str); 1], &'static str) {
            ([(header::CONTENT_TYPE, "application/json")], r#"{"x": 1"#)
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/invalid-json", any(malformed_json)),
            )
            .await
            .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let response = execute_rest(
            &state,
            Request::builder()
                .uri("/api/rest/demo/v1/invalid-json")
                .body(Body::empty())
                .unwrap(),
            crate::policy::PolicyDecision {
                upstream: Some(format!("http://{address}")),
                upstream_path: Some("/invalid-json".to_owned()),
                request_timeout_ms: 1_000,
                ..Default::default()
            },
            DataPlaneProtocol::Rest,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["error_code"], "GTW006");
        assert_eq!(body["error_message"], "Malformed JSON from upstream");
        server.abort();
    }

    #[tokio::test]
    async fn authorization_field_swap_matches_python_empty_and_missing_cases() {
        async fn upstream(headers: HeaderMap) -> Json<Value> {
            Json(json!({
                "authorization": headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/auth", any(upstream)))
                .await
                .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let send = |headers: Vec<(String, String)>| {
            let state = state.clone();
            async move {
                let mut request = Request::builder()
                    .uri("/api/rest/demo/v1/auth")
                    .body(Body::empty())
                    .unwrap();
                for (name, value) in headers {
                    request.headers_mut().insert(
                        HeaderName::try_from(name).unwrap(),
                        HeaderValue::try_from(value).unwrap(),
                    );
                }
                let response = execute_rest(
                    &state,
                    request,
                    crate::policy::PolicyDecision {
                        upstream: Some(format!("http://{address}")),
                        upstream_path: Some("/auth".to_owned()),
                        allowed_headers: vec!["x-backend-auth".to_owned()],
                        authorization_field_swap: Some("x-backend-auth".to_owned()),
                        request_timeout_ms: 1_000,
                        ..Default::default()
                    },
                    DataPlaneProtocol::Rest,
                )
                .await
                .unwrap();
                serde_json::from_slice::<Value>(
                    &to_bytes(response.into_body(), 4096).await.unwrap(),
                )
                .unwrap()
            }
        };

        assert_eq!(
            send(vec![(
                "x-backend-auth".to_owned(),
                "Bearer backend-token".to_owned(),
            )])
            .await["authorization"],
            "Bearer backend-token"
        );
        assert!(send(vec![]).await["authorization"].is_null());
        assert_eq!(
            send(vec![
                ("x-backend-auth".to_owned(), String::new()),
                ("authorization".to_owned(), "Bearer existing".to_owned()),
            ])
            .await["authorization"],
            "Bearer existing"
        );
        server.abort();
    }

    #[tokio::test]
    async fn retries_transient_upstream_statuses() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        type ForwardedRequest = (Option<String>, Option<String>);

        #[derive(Clone)]
        struct RetryCapture {
            attempts: Arc<AtomicUsize>,
            requests: Arc<Mutex<Vec<ForwardedRequest>>>,
        }

        async fn flaky(
            State(capture): State<RetryCapture>,
            headers: HeaderMap,
            uri: http::Uri,
        ) -> (StatusCode, Json<Value>) {
            capture.requests.lock().unwrap().push((
                uri.query().map(str::to_owned),
                headers
                    .get("x-custom")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            ));
            let attempt = capture.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "attempt": 1 })),
                )
            } else {
                (StatusCode::OK, Json(json!({ "attempt": 2 })))
            }
        }

        let capture = RetryCapture {
            attempts: Arc::new(AtomicUsize::new(0)),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_capture = capture.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/retry", any(flaky))
                    .with_state(server_capture),
            )
            .await
            .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let decision = crate::policy::PolicyDecision {
            upstream: Some(format!("http://{address}")),
            upstream_path: Some("/retry".to_owned()),
            allowed_headers: vec!["x-custom".to_owned()],
            retry_count: 1,
            request_timeout_ms: 1_000,
            ..Default::default()
        };
        let request = Request::builder()
            .uri("/api/rest/demo/v1/retry?foo=bar")
            .header("x-custom", "abc")
            .body(Body::empty())
            .unwrap();

        let response = execute_rest(&state, request, decision, DataPlaneProtocol::Rest)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(capture.attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            capture.requests.lock().unwrap().as_slice(),
            &[
                (Some("foo=bar".to_owned()), Some("abc".to_owned())),
                (Some("foo=bar".to_owned()), Some("abc".to_owned())),
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn soap_retries_transient_upstream_statuses_like_python() {
        use axum::extract::{Path, State};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        async fn flaky_soap(
            State(attempts): State<Arc<AtomicUsize>>,
            Path(status): Path<u16>,
        ) -> Response {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Response::builder()
                    .status(StatusCode::from_u16(status).unwrap())
                    .body(Body::from("<retry/>"))
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/xml")
                .body(Body::from("<ok/>"))
                .unwrap()
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/{status}", any(flaky_soap))
                    .with_state(server_attempts),
            )
            .await
            .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();

        for status in [500, 502, 503, 504] {
            attempts.store(0, Ordering::SeqCst);
            let decision = crate::policy::PolicyDecision {
                upstream: Some(format!("http://{address}")),
                upstream_path: Some(format!("/{status}")),
                retry_count: 1,
                request_timeout_ms: 1_000,
                ..Default::default()
            };
            let request = Request::builder()
                .uri("/api/soap/demo/v1/call")
                .method(Method::POST)
                .header(http::header::CONTENT_TYPE, "application/xml")
                .body(Body::from("<Envelope/>"))
                .unwrap();
            let response = execute_rest(&state, request, decision, DataPlaneProtocol::Soap)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(), "<ok/>");
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
        }

        attempts.store(0, Ordering::SeqCst);
        let decision = crate::policy::PolicyDecision {
            upstream: Some(format!("http://{address}")),
            upstream_path: Some("/500".to_owned()),
            retry_count: 0,
            request_timeout_ms: 1_000,
            ..Default::default()
        };
        let request = Request::builder()
            .uri("/api/soap/demo/v1/call")
            .method(Method::POST)
            .body(Body::from("<Envelope/>"))
            .unwrap();
        let response = execute_rest(&state, request, decision, DataPlaneProtocol::Soap)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn soap_forwards_common_headers_without_an_allowlist_like_python() {
        use axum::extract::State;
        use std::sync::{Arc, Mutex};

        async fn capture_soap_headers(
            State(captured): State<Arc<Mutex<HeaderMap>>>,
            headers: HeaderMap,
        ) -> Response {
            *captured.lock().unwrap() = headers;
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/xml")
                .body(Body::from("<ok/>"))
                .unwrap()
        }

        let captured = Arc::new(Mutex::new(HeaderMap::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_captured = captured.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/soap", any(capture_soap_headers))
                    .with_state(server_captured),
            )
            .await
            .unwrap();
        });
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let decision = crate::policy::PolicyDecision {
            upstream: Some(format!("http://{address}")),
            upstream_path: Some("/soap".to_owned()),
            request_timeout_ms: 1_000,
            ..Default::default()
        };
        let request = Request::builder()
            .uri("/api/soap/demo/v1/call")
            .method(Method::POST)
            .header(http::header::CONTENT_TYPE, "application/xml")
            .header(http::header::ACCEPT, "text/xml")
            .header(http::header::USER_AGENT, "doorman-tests/1.0")
            .body(Body::from("<Envelope/>"))
            .unwrap();
        let response = execute_rest(&state, request, decision, DataPlaneProtocol::Soap)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(), "<ok/>");
        let headers = captured.lock().unwrap();
        assert_eq!(
            headers[http::header::CONTENT_TYPE],
            "text/xml; charset=utf-8"
        );
        assert_eq!(headers[http::header::ACCEPT], "text/xml");
        assert_eq!(headers[http::header::USER_AGENT], "doorman-tests/1.0");
        assert_eq!(headers["soapaction"], "\"\"");
        server.abort();
    }

    #[test]
    fn enforces_graphql_depth_while_ignoring_strings_and_comments() {
        let accepted = br##"{"query":"{ viewer { label(text: \"{ignored}\") # {ignored}\n } }"}"##;
        assert!(
            validate_protocol_request(DataPlaneProtocol::Graphql, &Method::POST, accepted, 2, None)
                .is_ok()
        );

        let rejected = br#"{"query":"{ viewer { team { name } } }"}"#;
        let failure =
            validate_protocol_request(DataPlaneProtocol::Graphql, &Method::POST, rejected, 2, None)
                .unwrap_err();
        assert_eq!(failure.error_code, "GTW013");
    }

    #[test]
    fn scopes_graphql_validation_to_the_named_operation() {
        let schema = json!({"validation_schema": {
            "Create.input.name": {"required": true, "type": "string"},
            "Other.input.id": {"required": true}
        }});
        assert_eq!(
            graphql_validation_schema(
                &schema,
                "mutation Create($input: Input!){ create(input: $input) }"
            ),
            json!({"input.name": {"required": true, "type": "string"}})
        );
        assert_eq!(
            graphql_validation_schema(&schema, "{ viewer { id } }"),
            json!({})
        );
    }

    #[test]
    fn rejects_unsafe_soap_but_preserves_legacy_passthrough_without_a_schema() {
        let legacy = br#"<Envelope/>"#;
        assert!(
            validate_protocol_request(DataPlaneProtocol::Soap, &Method::POST, legacy, 0, None)
                .is_ok()
        );
        let unsafe_xml = br#"<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><Envelope/>"#;
        assert!(
            validate_protocol_request(DataPlaneProtocol::Soap, &Method::POST, unsafe_xml, 0, None)
                .is_err()
        );
    }

    #[test]
    fn validates_http_to_grpc_method_shape() {
        let valid = br#"{"method":"Greeter.SayHello","message":{"name":"Ada"}}"#;
        assert!(
            validate_protocol_request(DataPlaneProtocol::Grpc, &Method::POST, valid, 0, None)
                .is_ok()
        );
        let invalid = br#"{"method":"bad/method"}"#;
        assert!(
            validate_protocol_request(DataPlaneProtocol::Grpc, &Method::POST, invalid, 0, None)
                .is_err()
        );
    }

    #[tokio::test]
    async fn blocks_invalid_payloads_for_every_gateway_protocol_like_python() {
        use axum::body::to_bytes;

        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let cases = [
            (
                DataPlaneProtocol::Rest,
                br#"{"user":{"name":"A"}}"#.as_slice(),
                json!({"user.name": {"required": true, "type": "string", "min": 2}}),
            ),
            (
                DataPlaneProtocol::Graphql,
                br#"{"query":"mutation CreateUser($input: UserInput!){ createUser(input: $input){ id } }","variables":{"input":{"name":"A"}}}"#.as_slice(),
                json!({"CreateUser.input.name": {"required": true, "type": "string", "min": 2}}),
            ),
            (
                DataPlaneProtocol::Soap,
                br#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Request><name>A</name></Request></soap:Body></soap:Envelope>"#.as_slice(),
                json!({"name": {"required": true, "type": "string", "min": 2}}),
            ),
            (
                DataPlaneProtocol::Grpc,
                br#"{"method":"Service.Method","message":{"user":{"name":"A"}}}"#.as_slice(),
                json!({"user.name": {"required": true, "type": "string", "min": 2}}),
            ),
        ];

        for (protocol, body, schema) in cases {
            let request = Request::builder()
                .method(Method::POST)
                .uri("/api/test")
                .body(Body::from(body.to_vec()))
                .unwrap();
            let decision = crate::policy::PolicyDecision {
                upstream: Some("http://127.0.0.1:9".to_owned()),
                endpoint_validation: Some(schema),
                graphql_max_depth: 10,
                ..Default::default()
            };
            let response = execute_rest(&state, request, decision, protocol)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["error_code"],
                "GTW011"
            );
        }
    }

    #[test]
    fn validates_crud_schema_and_extracts_resource_ids() {
        let schema = json!({
            "name": { "type": "string", "required": true, "min_length": 2 },
            "count": { "type": "integer" },
            "profile": {
                "type": "object",
                "properties": { "enabled": { "type": "boolean", "required": true } }
            }
        });
        let valid = json!({ "name": "Ada", "count": 2, "profile": { "enabled": true } });
        assert!(validate_crud_schema(Some(&schema), &valid, false).is_ok());

        let missing = json!({ "count": 2 });
        assert!(validate_crud_schema(Some(&schema), &missing, false).is_err());
        assert!(validate_crud_schema(Some(&schema), &missing, true).is_ok());

        let wrong_type = json!({ "name": "Ada", "count": "two" });
        assert!(validate_crud_schema(Some(&schema), &wrong_type, false).is_err());

        let constraints = json!({
            "code": {"type": "string", "pattern": "[A-Z]{2}", "enum": ["AB", "CD"]},
            "score": {"type": "number", "min_value": 1, "max_value": 5},
            "integer": {"type": "integer"}
        });
        assert!(
            validate_crud_schema(
                Some(&constraints),
                &json!({"code": "AB", "score": 3, "integer": true}),
                false
            )
            .is_ok()
        );
        let error = validate_crud_schema(
            Some(&constraints),
            &json!({"code": "zz", "score": 8, "integer": false}),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not match pattern"));
        assert!(error.contains("must be one of: AB, CD"));
        assert!(error.contains("must be <= 5"));
        assert_eq!(
            crud_resource_id("/api/rest/demo/v1/items/resource-1"),
            Some("resource-1")
        );
        assert_eq!(crud_resource_id("/api/rest/demo/v1/items"), None);
    }

    #[test]
    fn rejects_unsafe_crud_collection_names() {
        assert!(valid_collection_name("crud_data_accounts"));
        assert!(!valid_collection_name("system.users"));
        assert!(!valid_collection_name("../../users"));
    }
}
