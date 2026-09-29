use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

pub static CHAOS_ENABLED: AtomicBool = AtomicBool::new(false);
pub static CHAOS_LATENCY_MS: AtomicU64 = AtomicU64::new(0);
pub static CHAOS_ERROR_STATUS: AtomicU32 = AtomicU32::new(0);
pub static CHAOS_EVENTS_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CHAOS_ERROR_BUDGET_BURN: AtomicU64 = AtomicU64::new(0);
pub static CHAOS_REDIS_OUTAGE: AtomicBool = AtomicBool::new(false);
pub static CHAOS_MONGO_OUTAGE: AtomicBool = AtomicBool::new(false);

pub async fn chaos_middleware(req: Request, next: Next) -> Response {
    if !CHAOS_ENABLED.load(Ordering::Relaxed) {
        return next.run(req).await;
    }

    CHAOS_EVENTS_COUNT.fetch_add(1, Ordering::Relaxed);

    let latency = CHAOS_LATENCY_MS.load(Ordering::Relaxed);
    if latency > 0 {
        tokio::time::sleep(Duration::from_millis(latency)).await;
    }

    let error_status = CHAOS_ERROR_STATUS.load(Ordering::Relaxed);
    if error_status >= 400 {
        let status =
            StatusCode::from_u16(error_status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (status, "Chaos engineering fault injected").into_response();
    }

    next.run(req).await
}

pub async fn latency_injection(req: Request, next: Next) -> Response {
    let enabled = env::var("ENABLE_LATENCY_INJECTION")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if let Some(delay) = injected_latency_ms(
        enabled,
        req.headers()
            .get("x-doorman-latency")
            // Starlette decodes header bytes as latin-1.
            .map(|value| {
                value
                    .as_bytes()
                    .iter()
                    .map(|b| char::from(*b))
                    .collect::<String>()
            })
            .as_deref(),
    ) {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    next.run(req).await
}

fn injected_latency_ms(enabled: bool, value: Option<&str>) -> Option<u64> {
    if !enabled {
        return None;
    }
    let text = crate::python_scalar::strip(value?);
    let delay = match crate::python_scalar::parse_integer(text) {
        Some(parsed) => parsed.clamp(0, 5_000),
        // Python ints are unbounded; only magnitude beyond i128 needs the sign.
        None if is_oversized_integer(text) => {
            if text.starts_with('-') {
                0
            } else {
                5_000
            }
        }
        None => return None,
    };
    (delay > 0).then_some(delay as u64)
}

fn is_oversized_integer(text: &str) -> bool {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    digits.len() > 38 && digits.chars().all(|c| c.is_ascii_digit()) && digits.len() <= 4_300
}

#[cfg(test)]
mod tests {
    use super::injected_latency_ms;

    #[test]
    fn legacy_header_latency_matches_python_bounds_and_parsing() {
        assert_eq!(injected_latency_ms(false, Some("100")), None);
        assert_eq!(injected_latency_ms(true, None), None);
        assert_eq!(injected_latency_ms(true, Some("bad")), None);
        assert_eq!(injected_latency_ms(true, Some("-1")), None);
        assert_eq!(injected_latency_ms(true, Some("0")), None);
        assert_eq!(injected_latency_ms(true, Some(" 125 ")), Some(125));
        assert_eq!(injected_latency_ms(true, Some("9000")), Some(5_000));
        assert_eq!(injected_latency_ms(true, Some("+1_0")), Some(10));
        assert_eq!(injected_latency_ms(true, Some("１２")), Some(12));
        assert_eq!(injected_latency_ms(true, Some("1__0")), None);
        assert_eq!(
            injected_latency_ms(true, Some(&"9".repeat(60))),
            Some(5_000)
        );
        assert_eq!(
            injected_latency_ms(true, Some(&format!("-{}", "9".repeat(60)))),
            None
        );
    }
}
