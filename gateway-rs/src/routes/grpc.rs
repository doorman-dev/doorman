use axum::response::{IntoResponse, Response};
use axum::{
    Json,
    extract::{Request, State},
};
use http::StatusCode;

use crate::{
    error::GatewayError,
    policy::PolicyErrorBody,
    routes::rest::{DataPlaneProtocol, PolicyPath, rest_policy_then_proxy},
    state::AppState,
};

pub async fn grpc_policy_then_execute(
    State(state): State<AppState>,
    mut request: Request,
) -> Result<Response, GatewayError> {
    // Python's gRPC gateway route accepts both POST and GET (the latter used
    // for proto discovery as well as plain GET calls), plus OPTIONS for CORS.
    if !matches!(
        request.method(),
        &http::Method::POST | &http::Method::GET | &http::Method::OPTIONS
    ) {
        return Ok(http::StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let path = request.uri().path();
    let subpath = path
        .strip_prefix("/api/grpc/")
        .or_else(|| path.strip_prefix("/grpc/"))
        .unwrap_or(path)
        .trim_matches('/');
    let api_name = subpath.split('/').next().unwrap_or_default().to_owned();
    let version = request
        .headers()
        .get("x-api-version")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| (request.method() == http::Method::OPTIONS).then(|| "v1".to_owned()));
    let Some(version) = version else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(PolicyErrorBody {
                error_code: "X-API-Version header is required".to_owned(),
                error_message: "X-API-Version header is required".to_owned(),
            }),
        )
            .into_response());
    };
    tracing::info!(path = %path, subpath = %subpath, api_name = %api_name, version = %version, "grpc_policy_then_execute");
    request
        .extensions_mut()
        .insert(PolicyPath(grpc_policy_path(&api_name, &version)));
    request.extensions_mut().insert(DataPlaneProtocol::Grpc);
    rest_policy_then_proxy(State(state), request).await
}

fn grpc_policy_path(api_name: &str, version: &str) -> String {
    format!("/api/rest/{api_name}/{version}/grpc")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use serde_json::Value;

    #[test]
    fn normalizes_grpc_subscription_lookup_path() {
        assert_eq!(grpc_policy_path("svc4", "v4"), "/api/rest/svc4/v4/grpc");
    }

    #[tokio::test]
    async fn requires_version_header_for_json_grpc_requests_like_python() {
        let state =
            AppState::new(crate::Config::for_test("http://127.0.0.1:9".to_owned())).unwrap();
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/grpc/service/do")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"data":"{}"}"#))
            .unwrap();
        let response = grpc_policy_then_execute(State(state), request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "X-API-Version header is required");
    }
}
