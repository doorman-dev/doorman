use axum::{
    extract::{
        FromRequestParts, Request, State,
        ws::{CloseFrame, Message, WebSocketUpgrade},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::header;

use crate::state::AppState;

pub async fn reject_disabled_websockets(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if state.config.websockets_enabled || !is_websocket_upgrade(&request) {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(upgrade) => upgrade
            .on_upgrade(|mut socket| async move {
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "".into(),
                    })))
                    .await;
            })
            .into_response(),
        Err(_) => next.run(Request::from_parts(parts, body)).await,
    }
}

fn is_websocket_upgrade(request: &Request) -> bool {
    request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

#[cfg(test)]
mod tests {
    use axum::body::Body;

    use super::*;

    #[test]
    fn recognizes_websocket_upgrade_headers_case_insensitively() {
        let request = Request::builder()
            .header(header::CONNECTION, "keep-alive, Upgrade")
            .header(header::UPGRADE, "WebSocket")
            .body(Body::empty())
            .unwrap();
        assert!(is_websocket_upgrade(&request));

        let request = Request::builder().body(Body::empty()).unwrap();
        assert!(!is_websocket_upgrade(&request));
    }
}
