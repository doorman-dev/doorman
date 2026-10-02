use axum::response::{IntoResponse, Response};
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Request, State},
};
use http::StatusCode;
use serde_json::{Value, json};

use crate::{
    error::GatewayError,
    middleware::body_limit::BodyLimits,
    routes::rest::{DataPlaneProtocol, PolicyPath, rest_policy_then_proxy},
    state::AppState,
};

pub async fn grpc_policy_then_execute(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, GatewayError> {
    // Python's gRPC gateway route accepts both POST and GET (the latter used
    // for proto discovery as well as plain GET calls), plus OPTIONS for CORS.
    if !matches!(
        request.method(),
        &http::Method::POST | &http::Method::GET | &http::Method::OPTIONS
    ) {
        return Ok(http::StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    if let Some(response) = crate::routes::rest::early_body_limit(
        &state,
        request.uri().path(),
        request.headers(),
        request.method() == http::Method::OPTIONS,
        crate::routes::rest::DataPlaneProtocol::Grpc,
    )
    .await
    {
        return Ok(response);
    }
    let path = request.uri().path();
    let subpath = path
        .strip_prefix("/api/grpc/")
        .or_else(|| path.strip_prefix("/grpc/"))
        .unwrap_or(path)
        .trim_matches('/');
    // Python resolves the API from the last path segment (`path_parts[-1]`).
    let api_name = subpath.rsplit('/').next().unwrap_or_default().to_owned();
    // Unlike GraphQL, the pinned gRPC route defaults a missing X-API-Version
    // to v1 (`request.headers.get('X-API-Version', 'v1')`).
    let version = request
        .headers()
        .get("x-api-version")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or("v1")
        .to_owned();
    tracing::info!(path = %path, subpath = %subpath, api_name = %api_name, version = %version, "grpc_policy_then_execute");
    let get = request.method() == http::Method::GET;
    let (parts, body) = request.into_parts();
    let limit = BodyLimits::for_path(parts.uri.path(), BodyLimits::from_env().default);
    let Ok(bytes) = to_bytes(body, limit).await else {
        return Ok(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "REQ001",
            "Request entity too large",
        ));
    };
    let mut request = Request::from_parts(parts, Body::from(bytes.clone()));
    request
        .extensions_mut()
        .insert(PolicyPath(grpc_policy_path(&api_name, &version)));
    request.extensions_mut().insert(DataPlaneProtocol::Grpc);
    let response = rest_policy_then_proxy(State(state), request).await?;
    if response.status() != StatusCode::NOT_FOUND {
        return Ok(response);
    }
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 64 * 1024).await.unwrap_or_default();
    let missing_api = serde_json::from_slice::<Value>(&body)
        .is_ok_and(|value| value.get("error_code").and_then(Value::as_str) == Some("GTW001"));
    if !missing_api {
        return Ok(Response::from_parts(parts, Body::from(body)));
    }
    Ok(missing_api_response(get, &bytes, &api_name, &version))
}

/// For an unknown API the pinned gateway skips the auth pipeline and reaches
/// GatewayService.grpc_gateway, which validates the body and method before
/// failing to locate the generated proto module.
fn missing_api_response(get: bool, body: &[u8], api_name: &str, version: &str) -> Response {
    let parsed = if get {
        Ok(Value::Object(Default::default()))
    } else {
        serde_json::from_slice::<Value>(body)
    };
    let Ok(value) = parsed else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "GTW011",
            "Invalid JSON in request body",
        );
    };
    let Some(object) = value.as_object() else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "GTW011",
            "Invalid request body format",
        );
    };
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let valid_method = method
        .split_once('.')
        .is_some_and(|(service, name)| is_identifier(service.trim()) && is_identifier(name.trim()));
    if !valid_method {
        return json_error(
            StatusCode::BAD_REQUEST,
            "GTW011",
            "Invalid gRPC method. Use Service.Method with alphanumerics/underscore.",
        );
    }
    let package = object
        .get("package")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !package.is_empty()
        && (package.contains('/')
            || package.contains('\\')
            || package.contains("..")
            || !package.split('.').all(is_identifier))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "GTW011",
            "Invalid gRPC package. Use letters, digits, underscore only.",
        );
    }
    json_error(
        StatusCode::NOT_FOUND,
        "GTW012",
        &format!("Proto file not found for API: {api_name}/{version}"),
    )
}

/// Python `_is_valid_identifier`: ASCII letter/underscore start, then
/// letters, digits, or underscores, at most 128 characters.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 128
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"error_code": code, "error_message": message})),
    )
        .into_response()
}

fn grpc_policy_path(api_name: &str, version: &str) -> String {
    format!("/api/rest/{api_name}/{version}/grpc")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_grpc_subscription_lookup_path() {
        assert_eq!(grpc_policy_path("svc4", "v4"), "/api/rest/svc4/v4/grpc");
    }

    #[test]
    fn missing_api_reports_python_proto_error_after_method_validation() {
        let response = missing_api_response(false, br#"{"method":"Resource.Create"}"#, "do", "v1");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            missing_api_response(false, b"{bad", "do", "v1").status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            missing_api_response(true, b"", "do", "v1").status(),
            StatusCode::BAD_REQUEST
        );
    }
}
