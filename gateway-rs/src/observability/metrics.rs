use std::{fmt::Write, sync::atomic::Ordering, time::Duration};

use crate::state::GatewayRuntime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPath {
    Python,
    Rust,
}

pub const DURATION_BUCKETS_SECONDS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub fn observe_request(runtime: &GatewayRuntime, duration: Duration, status: u16) {
    runtime.request_total.fetch_add(1, Ordering::Relaxed);
    runtime.request_duration_micros.fetch_add(
        duration.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    for (index, upper_bound) in DURATION_BUCKETS_SECONDS.iter().enumerate() {
        if duration.as_secs_f64() <= *upper_bound {
            runtime.request_duration_buckets[index].fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Ok(mut responses) = runtime.responses_by_status.lock() {
        *responses.entry(status).or_default() += 1;
    }
}

pub fn render(runtime: &GatewayRuntime) -> String {
    let total = runtime.request_total.load(Ordering::Relaxed);
    let duration_sum = runtime.request_duration_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let mut output = String::new();
    output.push_str(
        "# HELP doorman_http_request_duration_seconds Gateway request duration in seconds\n\
         # TYPE doorman_http_request_duration_seconds histogram\n",
    );
    for (index, upper_bound) in DURATION_BUCKETS_SECONDS.iter().enumerate() {
        let count = runtime.request_duration_buckets[index].load(Ordering::Relaxed);
        let _ = writeln!(
            output,
            "doorman_http_request_duration_seconds_bucket{{le=\"{upper_bound}\"}} {count}"
        );
    }
    let _ = writeln!(
        output,
        "doorman_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {total}"
    );
    let _ = writeln!(
        output,
        "doorman_http_request_duration_seconds_sum {duration_sum}"
    );
    let _ = writeln!(
        output,
        "doorman_http_request_duration_seconds_count {total}"
    );
    output.push_str(
        "# HELP doorman_http_requests_total Gateway request count\n\
         # TYPE doorman_http_requests_total counter\n",
    );
    if let Ok(responses) = runtime.responses_by_status.lock() {
        for (status, count) in responses.iter() {
            let _ = writeln!(
                output,
                "doorman_http_requests_total{{code=\"{status}\"}} {count}"
            );
        }
    }
    output.push_str(
        "# HELP doorman_http_retries_total HTTP retry count\n\
         # TYPE doorman_http_retries_total counter\n",
    );
    let _ = writeln!(
        output,
        "doorman_http_retries_total {}",
        runtime.retries_total.load(Ordering::Relaxed)
    );
    output.push_str(
        "# HELP doorman_upstream_timeouts_total Upstream timeout count\n\
         # TYPE doorman_upstream_timeouts_total counter\n",
    );
    let _ = writeln!(
        output,
        "doorman_upstream_timeouts_total {}",
        runtime.upstream_timeouts_total.load(Ordering::Relaxed)
    );
    output.push_str(
        "# HELP doorman_active_requests Current requests in the Rust gateway\n\
         # TYPE doorman_active_requests gauge\n",
    );
    let _ = writeln!(
        output,
        "doorman_active_requests {}",
        runtime.active_requests.load(Ordering::Relaxed)
    );
    output.push_str("# HELP doorman_tls_reload_total TLS configuration reload outcomes\n# TYPE doorman_tls_reload_total counter\n");
    let _ = writeln!(output, "doorman_tls_reload_total{{result=\"success\"}} {}", runtime.tls_reload_success_total.load(Ordering::Relaxed));
    let _ = writeln!(output, "doorman_tls_reload_total{{result=\"failure\"}} {}", runtime.tls_reload_failure_total.load(Ordering::Relaxed));
    output.push_str("# HELP doorman_tls_certificate_expiry_timestamp_seconds Certificate expiry as Unix time\n# TYPE doorman_tls_certificate_expiry_timestamp_seconds gauge\n");
    if let Ok(expiries) = runtime.tls_certificate_expiries.lock() {
        for (profile, expiry) in expiries.iter() {
            let _ = writeln!(output, "doorman_tls_certificate_expiry_timestamp_seconds{{profile=\"{profile}\"}} {expiry}");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_python_compatible_metric_names() {
        let runtime = GatewayRuntime::default();
        observe_request(&runtime, Duration::from_millis(12), 201);
        let metrics = render(&runtime);
        assert!(metrics.contains("doorman_http_request_duration_seconds_bucket"));
        assert!(metrics.contains("doorman_http_requests_total{code=\"201\"} 1"));
    }
}
