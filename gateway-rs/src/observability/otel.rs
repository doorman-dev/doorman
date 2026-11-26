//! OpenTelemetry export settings, read from the standard `OTEL_*` variables.
//!
//! Export is off unless an OTLP endpoint is set. Prompt and response text,
//! keys and headers are never exported.

use std::sync::{Mutex, OnceLock};

use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::{SdkMeterProvider, periodic_reader_with_async_runtime::PeriodicReader},
    propagation::TraceContextPropagator,
    runtime,
    trace::{SdkTracerProvider, Tracer, span_processor_with_async_runtime::BatchSpanProcessor},
};
use serde_json::{Value, json};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context};

/// `tracing` target of the spans exported over OTLP. Nothing else is exported.
pub const TARGET: &str = "doorman_otel";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    HttpProtobuf,
    Grpc,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::HttpProtobuf => "http/protobuf",
            Protocol::Grpc => "grpc",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OtelConfig {
    pub protocol: Protocol,
    pub traces_endpoint: Option<String>,
    pub metrics_endpoint: Option<String>,
    pub headers: Vec<(String, String)>,
    pub service_name: String,
    pub include_user: bool,
    pub sampler: String,
    pub sampler_arg: Option<String>,
}

impl OtelConfig {
    pub fn enabled(&self) -> bool {
        self.traces_endpoint.is_some() || self.metrics_endpoint.is_some()
    }

    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let value = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let truthy = |name: &str| value(name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let protocol = match value("OTEL_EXPORTER_OTLP_PROTOCOL").as_deref() {
            Some("grpc") => Protocol::Grpc,
            _ => Protocol::HttpProtobuf,
        };
        let disabled = truthy("OTEL_SDK_DISABLED");
        let base = value("OTEL_EXPORTER_OTLP_ENDPOINT");
        // The generic endpoint gets the signal path appended for HTTP; the
        // per-signal endpoints are used exactly as given.
        let signal = |specific: &str, path: &str| {
            if disabled {
                return None;
            }
            value(specific).or_else(|| {
                base.as_ref().map(|base| match protocol {
                    Protocol::HttpProtobuf => format!("{}/{path}", base.trim_end_matches('/')),
                    Protocol::Grpc => base.clone(),
                })
            })
        };
        Self {
            protocol,
            traces_endpoint: signal("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "v1/traces"),
            metrics_endpoint: signal("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "v1/metrics"),
            headers: value("OTEL_EXPORTER_OTLP_HEADERS")
                .map(|raw| parse_headers(&raw))
                .unwrap_or_default(),
            service_name: value("OTEL_SERVICE_NAME").unwrap_or_else(|| "doorman-gateway".into()),
            include_user: truthy("DOORMAN_OTEL_INCLUDE_USER"),
            sampler: value("OTEL_TRACES_SAMPLER").unwrap_or_else(|| "parentbased_always_on".into()),
            sampler_arg: value("OTEL_TRACES_SAMPLER_ARG"),
        }
    }
}

/// `key1=value1,key2=value2`, values percent-decoded (OTLP exporter spec).
fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            let value = percent_decode(value.trim());
            Some((key.to_owned(), value))
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    url::form_urlencoded::parse(format!("v={}", text.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

/// Endpoint without userinfo, query or fragment, safe to show admins.
pub fn redact_endpoint(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => "(invalid endpoint)".into(),
    }
}

static CONFIG: OnceLock<OtelConfig> = OnceLock::new();
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// The configuration read at startup (or now, if telemetry was never started).
pub fn config() -> &'static OtelConfig {
    CONFIG.get_or_init(OtelConfig::from_env)
}

pub fn record_error(error: impl std::fmt::Display) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(error.to_string());
    }
}

/// Body of `GET /platform/ai/telemetry`. Headers are never returned.
pub fn status() -> Value {
    let config = config();
    let last_error = LAST_ERROR.lock().ok().and_then(|slot| slot.clone());
    json!({
        "enabled": config.enabled(),
        "protocol": config.protocol.as_str(),
        "traces_endpoint": config.traces_endpoint.as_deref().map(redact_endpoint),
        "metrics_endpoint": config.metrics_endpoint.as_deref().map(redact_endpoint),
        "service_name": config.service_name,
        "include_user": config.include_user,
        "sampler": match &config.sampler_arg {
            Some(arg) => format!("{} ({arg})", config.sampler),
            None => config.sampler.clone(),
        },
        "last_error": last_error,
    })
}

struct Providers {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
}

static PROVIDERS: Mutex<Option<Providers>> = Mutex::new(None);
static TRACES_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static METRICS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True once metric export has started; instruments are skipped otherwise.
pub fn metrics_on() -> bool {
    METRICS_ON.load(std::sync::atomic::Ordering::Relaxed)
}

/// True once trace export has started; spans are skipped otherwise.
pub fn traces_on() -> bool {
    TRACES_ON.load(std::sync::atomic::Ordering::Relaxed)
}

/// Starts the OTLP exporters when an endpoint is configured and returns the
/// tracer for the `tracing` layer. Needs a running Tokio runtime.
pub fn start() -> Option<Tracer> {
    let config = config();
    if !config.enabled() || tokio::runtime::Handle::try_current().is_err() {
        return None;
    }
    global::set_text_map_propagator(TraceContextPropagator::new());
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();
    let tracer_provider = config.traces_endpoint.as_ref().and_then(|endpoint| {
        let exporter = match config.protocol {
            Protocol::HttpProtobuf => SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build(),
            Protocol::Grpc => SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build(),
        };
        let exporter = exporter.map_err(record_error).ok()?;
        Some(
            SdkTracerProvider::builder()
                .with_span_processor(BatchSpanProcessor::builder(exporter, runtime::Tokio).build())
                .with_resource(resource.clone())
                .build(),
        )
    });
    let meter_provider = config.metrics_endpoint.as_ref().and_then(|endpoint| {
        let exporter = match config.protocol {
            Protocol::HttpProtobuf => MetricExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build(),
            Protocol::Grpc => MetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build(),
        };
        let exporter = exporter.map_err(record_error).ok()?;
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter, runtime::Tokio).build())
            .with_resource(resource.clone())
            .build();
        global::set_meter_provider(provider.clone());
        METRICS_ON.store(true, std::sync::atomic::Ordering::Relaxed);
        Some(provider)
    });
    let tracer = tracer_provider
        .as_ref()
        .map(|provider| provider.tracer("doorman-gateway"));
    TRACES_ON.store(tracer.is_some(), std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut slot) = PROVIDERS.lock() {
        *slot = Some(Providers {
            tracer: tracer_provider,
            meter: meter_provider,
        });
    }
    tracer
}

/// Flushes and stops the exporters (graceful shutdown).
pub fn shutdown() {
    let providers = PROVIDERS.lock().ok().and_then(|mut slot| slot.take());
    TRACES_ON.store(false, std::sync::atomic::Ordering::Relaxed);
    METRICS_ON.store(false, std::sync::atomic::Ordering::Relaxed);
    let Some(providers) = providers else {
        return;
    };
    if let Some(tracer) = providers.tracer
        && let Err(error) = tracer.shutdown()
    {
        record_error(error);
    }
    if let Some(meter) = providers.meter
        && let Err(error) = meter.shutdown()
    {
        record_error(error);
    }
}

/// Keeps the newest OpenTelemetry SDK warning or error for the status route.
pub struct ErrorCapture;

impl<S: Subscriber> Layer<S> for ErrorCapture {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if *metadata.level() > tracing::Level::WARN
            || !metadata.target().starts_with("opentelemetry")
        {
            return;
        }
        let mut text = Message(String::new());
        event.record(&mut text);
        record_error(format!("{}: {}", metadata.target(), text.0.trim()));
    }
}

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> OtelConfig {
        OtelConfig::from_lookup(|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn off_without_an_endpoint() {
        let config = config(&[("OTEL_SERVICE_NAME", "x")]);
        assert!(!config.enabled());
        assert_eq!(config.service_name, "x");
        assert!(!config.include_user);
    }

    #[test]
    fn generic_endpoint_gets_signal_paths_for_http_only() {
        let http = config(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4318/")]);
        assert_eq!(
            http.traces_endpoint.as_deref(),
            Some("http://c:4318/v1/traces")
        );
        assert_eq!(
            http.metrics_endpoint.as_deref(),
            Some("http://c:4318/v1/metrics")
        );
        let grpc = config(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4317"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ]);
        assert_eq!(grpc.traces_endpoint.as_deref(), Some("http://c:4317"));
        assert_eq!(grpc.protocol, Protocol::Grpc);
    }

    #[test]
    fn per_signal_endpoint_and_disable_flag() {
        let only_traces = config(&[("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://t/x")]);
        assert_eq!(only_traces.traces_endpoint.as_deref(), Some("http://t/x"));
        assert!(only_traces.metrics_endpoint.is_none());
        let disabled = config(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4318"),
            ("OTEL_SDK_DISABLED", "TRUE"),
        ]);
        assert!(!disabled.enabled());
    }

    #[test]
    fn headers_are_decoded_and_user_opt_in_is_read() {
        let config = config(&[
            ("OTEL_EXPORTER_OTLP_HEADERS", "api-key=a%20b, x=1=2,bad"),
            ("DOORMAN_OTEL_INCLUDE_USER", "true"),
        ]);
        assert_eq!(
            config.headers,
            [("api-key".into(), "a b".into()), ("x".into(), "1=2".into())]
        );
        assert!(config.include_user);
    }

    #[test]
    fn endpoints_are_redacted() {
        assert_eq!(
            redact_endpoint("https://user:secret@c.example:4318/v1/traces?token=t#f"),
            "https://c.example:4318/v1/traces"
        );
        assert_eq!(redact_endpoint("not a url"), "(invalid endpoint)");
    }
}
