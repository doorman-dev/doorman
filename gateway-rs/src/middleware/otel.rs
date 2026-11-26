//! OpenTelemetry SERVER span for gateway API traffic (`/api/...`).

use axum::{
    body::Body,
    extract::{OriginalUri, Request},
    middleware::Next,
    response::Response,
};
use http::HeaderMap;
use http_body_util::BodyExt;
use opentelemetry::{global, propagation::Extractor};
use tracing::{Span, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::{middleware::request_id::RequestId, observability::otel};

/// The request's SERVER span, for handlers that add AI attributes to it.
#[derive(Clone)]
pub struct ServerSpan(pub Span);

struct Headers<'a>(&'a HeaderMap);

impl Extractor for Headers<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

pub async fn otel_server_span(mut request: Request, next: Next) -> Response {
    if !otel::traces_on() {
        return next.run(request).await;
    }
    let method = request.method().as_str().to_owned();
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.0.path().to_owned())
        .unwrap_or_else(|| format!("/api{}", request.uri().path()));
    let scheme = request.uri().scheme_str().unwrap_or("http").to_owned();
    let span = tracing::info_span!(
        target: otel::TARGET,
        "http.server",
        otel.kind = "server",
        otel.status_code = Empty,
        http.request.method = %method,
        http.route = Empty,
        http.response.status_code = Empty,
        url.scheme = %scheme,
        "error.type" = Empty,
        doorman.request_id = Empty,
        doorman.api = Empty,
        doorman.cache = Empty,
        doorman.unified_model = Empty,
        doorman.fallbacks = Empty,
        doorman.cost_usd = Empty,
        doorman.guardrail.redactions = Empty,
        doorman.ai.blocked = Empty,
        enduser.id = Empty,
    );
    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&Headers(request.headers()))
    });
    let _ = span.set_parent(parent);
    if let Some(RequestId(id)) = request.extensions().get::<RequestId>() {
        span.record("doorman.request_id", id.as_str());
    }
    request.extensions_mut().insert(ServerSpan(span.clone()));
    let response = {
        use tracing::Instrument;
        next.run(request).instrument(span.clone()).await
    };
    let status = response.status();
    let route = route_template(&path, status == http::StatusCode::NOT_FOUND);
    // Renamed through the OpenTelemetry handle: the span has already started.
    {
        use opentelemetry::trace::TraceContextExt;
        span.context()
            .span()
            .update_name(format!("{method} {route}"));
    }
    span.record("http.route", route.as_str());
    span.record("http.response.status_code", status.as_u16() as i64);
    if status.is_server_error() {
        span.record("otel.status_code", "error");
        span.record("error.type", status.as_str());
    }
    // The span ends when the body does, so streamed replies are timed in full.
    let (parts, body) = response.into_parts();
    let end = EndWithBody(span);
    let body = body.map_frame(move |frame| {
        let _keep = &end;
        frame
    });
    Response::from_parts(parts, Body::new(body))
}

/// tracing-opentelemetry takes a span's end time from its last exit, so the
/// span is entered once more when the response body is dropped.
struct EndWithBody(Span);

impl Drop for EndWithBody {
    fn drop(&mut self) {
        let _entered = self.0.enter();
    }
}

/// Low-cardinality route: `/api/{kind}/{name}/{version}` (admin-defined names
/// only), collapsed to `/api/{kind}` when no route matched.
pub fn route_template(path: &str, not_found: bool) -> String {
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let kinds = ["rest", "graphql", "soap", "grpc", "ai"];
    match segments.as_slice() {
        ["api", kind, rest @ ..] if kinds.contains(kind) => {
            let keep = if not_found { 0 } else { rest.len().min(2) };
            let mut route = format!("/api/{kind}");
            for segment in &rest[..keep] {
                route.push('/');
                route.push_str(segment);
            }
            route
        }
        ["api", other, ..] if !not_found => format!("/api/{other}"),
        _ => "/api".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::route_template;

    #[test]
    fn routes_keep_only_the_api_name_and_version() {
        assert_eq!(
            route_template("/api/rest/pets/v1/pets/42", false),
            "/api/rest/pets/v1"
        );
        assert_eq!(
            route_template("/api/ai/v1/chat/completions", false),
            "/api/ai/v1/chat"
        );
        assert_eq!(route_template("/api/rest/unknown/v9/x", true), "/api/rest");
        assert_eq!(route_template("/api/health", false), "/api/health");
        assert_eq!(route_template("/api/random/stuff", true), "/api");
    }
}
