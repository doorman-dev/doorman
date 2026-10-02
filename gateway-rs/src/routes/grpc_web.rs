use axum::{
    extract::{Path, Request, State},
    response::Response,
};

use crate::{
    error::GatewayError,
    routes::rest::{DataPlaneProtocol, PolicyPath, rest_policy_then_proxy},
    state::AppState,
};

#[derive(Clone, Debug)]
pub struct GrpcWebTarget {
    pub service: String,
    pub method: String,
}

pub async fn grpc_web_policy_then_execute(
    State(state): State<AppState>,
    Path((api_name, service, method)): Path<(String, String, String)>,
    mut request: Request,
) -> Result<Response, GatewayError> {
    if !matches!(
        request.method(),
        &http::Method::POST | &http::Method::OPTIONS
    ) {
        return Ok(http::StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    // The pinned proxy rejects a non-gRPC-Web body before resolving the API.
    if request.method() == http::Method::POST
        && !request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/grpc-web"))
    {
        // Starlette's bare Response sets no media type.
        return Ok(Response::builder()
            .status(http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .body(axum::body::Body::from("Invalid Content-Type"))
            .expect("static 415 response"));
    }
    if let Some(response) = crate::routes::rest::early_body_limit(
        &state,
        request.uri().path(),
        request.headers(),
        request.method() == http::Method::OPTIONS,
        DataPlaneProtocol::GrpcWeb,
    )
    .await
    {
        return Ok(response);
    }
    let version = request
        .headers()
        .get("x-api-version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("v1")
        .to_owned();
    request
        .extensions_mut()
        .insert(PolicyPath(format!("/api/rest/{api_name}/{version}/grpc")));
    request.extensions_mut().insert(DataPlaneProtocol::GrpcWeb);
    request
        .extensions_mut()
        .insert(GrpcWebTarget { service, method });
    let response = rest_policy_then_proxy(State(state), request).await?;
    if response.status() != http::StatusCode::NOT_FOUND {
        return Ok(response);
    }
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 64 * 1024)
        .await
        .unwrap_or_default();
    let missing_api = serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|value| {
        value.get("error_code").and_then(serde_json::Value::as_str) == Some("GTW001")
    });
    if !missing_api {
        return Ok(Response::from_parts(parts, axum::body::Body::from(body)));
    }
    // Python answers an unknown API in-band: HTTP 200 carrying grpc-status 12.
    let mut response = crate::protocol::grpc::web_trailer_response(
        false,
        tonic::Code::Unimplemented,
        "API not found",
    );
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc-web"),
    );
    Ok(response)
}

use axum::response::IntoResponse;
