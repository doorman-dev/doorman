use std::{
    collections::VecDeque,
    fmt,
    sync::{LazyLock, Mutex},
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        FmtContext,
        format::{FormatEvent, FormatFields, Writer},
    },
    registry::LookupSpan,
};

use crate::observability::audit::redact_record;

const MEMORY_LOG_CAPACITY: usize = 50_000;
static MEMORY_LOGS: LazyLock<Mutex<VecDeque<String>>> =
    LazyLock::new(|| Mutex::new(VecDeque::with_capacity(MEMORY_LOG_CAPACITY)));

pub fn memory_log_snapshot() -> Vec<String> {
    MEMORY_LOGS
        .lock()
        .map(|logs| logs.iter().cloned().collect())
        .unwrap_or_default()
}

fn remember_log(entry: &str) {
    if let Ok(mut logs) = MEMORY_LOGS.lock() {
        if logs.len() == MEMORY_LOG_CAPACITY {
            logs.pop_front();
        }
        logs.push_back(entry.to_owned());
    }
}

/// Formats complete tracing events as JSON only after recursively removing secrets.
///
/// The formatter is deliberately applied at the sink boundary so a future
/// caller cannot bypass redaction by interpolating a credential into a tracing
/// message instead of using the structured audit helpers.
#[derive(Debug, Default)]
struct RedactingJsonEvent;

impl<S, N> FormatEvent<S, N> for RedactingJsonEvent
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = JsonFieldVisitor::default();
        event.record(&mut fields);
        let mut record = serde_json::json!({
            "timestamp": time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| fmt::Error)?,
            "level": event.metadata().level().to_string(),
            "fields": fields.0,
            "target": event.metadata().target(),
        });
        redact_record(&mut record);
        let encoded = serde_json::to_string(&record).map_err(|_| fmt::Error)?;
        let memory_time = record
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .and_then(|timestamp| timestamp.get(..19))
            .unwrap_or_default();
        let memory_record = serde_json::json!({
            "time": memory_time,
            "name": event.metadata().target(),
            "level": event.metadata().level().to_string(),
            "message": record.pointer("/fields/message").cloned().unwrap_or(serde_json::Value::String(String::new())),
        });
        remember_log(&serde_json::to_string(&memory_record).map_err(|_| fmt::Error)?);
        writer.write_str(&encoded)?;
        writer.write_char('\n')
    }
}

#[derive(Default)]
struct JsonFieldVisitor(serde_json::Map<String, serde_json::Value>);

impl JsonFieldVisitor {
    fn insert(&mut self, field: &Field, value: serde_json::Value) {
        self.0.insert(field.name().to_owned(), value);
    }
}

impl Visit for JsonFieldVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, value.to_string().into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, format!("{value:?}").into());
    }
}

pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("doorman_gateway=info,tower_http=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .event_format(RedactingJsonEvent)
        .try_init();
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use tracing_subscriber::fmt::MakeWriter;

    use super::{RedactingJsonEvent, memory_log_snapshot};

    #[derive(Clone, Default)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLog {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLog {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn json_sink_redacts_free_form_messages_and_sensitive_fields() {
        let capture = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .event_format(RedactingJsonEvent)
            .with_writer(capture.clone())
            .finish();
        let secret = "not-safe-to-emit";

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                authorization = secret,
                x_api_key = secret,
                "Authorization: Bearer {secret}; Cookie: session={secret}; Set-Cookie: session={secret}; X-API-Key: {secret}; X-CSRF-Token: {secret}; access_token={secret}; refresh_token={secret}; Basic {secret}"
            );
        });

        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(!output.contains(secret), "redacted output: {output}");
        let event: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(event["fields"]["authorization"], "[REDACTED]");
        assert_eq!(event["fields"]["x_api_key"], "[REDACTED]");
        assert_eq!(
            event["fields"]["message"],
            "Authorization: [REDACTED]; Cookie: [REDACTED]; Set-Cookie: [REDACTED]; X-API-Key: [REDACTED]; X-CSRF-Token: [REDACTED]; access_token=[REDACTED]; refresh_token=[REDACTED]; Basic [REDACTED]"
        );
        assert!(memory_log_snapshot().iter().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .is_ok_and(|entry| entry["message"] == event["fields"]["message"])
        }));
    }
}
