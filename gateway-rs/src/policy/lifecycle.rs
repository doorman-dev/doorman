//! API version lifecycle: the states a version moves through and the response
//! headers that announce them to consumers.

use serde_json::Value;
use time::{
    Date, OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description,
};

use crate::storage::models::{api_lifecycle_status, string_field};

pub const DEFAULT_STATUS: &str = "active";

/// Response headers a browser client needs exposed to read the lifecycle.
pub const EXPOSED_HEADERS: [&str; 5] = [
    "X-API-Lifecycle-Status",
    "X-API-Resolved-Version",
    "Deprecation",
    "Sunset",
    "Link",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiLifecycle {
    pub status: String,
    pub api_name: String,
    pub resolved_version: String,
    pub deprecated_at: Option<OffsetDateTime>,
    pub retirement_date: Option<OffsetDateTime>,
    pub successor_version: Option<String>,
}

impl ApiLifecycle {
    pub fn from_api(api: &Value) -> Self {
        let date = |field| string_field(api, field).and_then(parse_lifecycle_date);
        Self {
            status: api_lifecycle_status(api).to_owned(),
            api_name: string_field(api, "api_name").unwrap_or_default().to_owned(),
            resolved_version: string_field(api, "api_version")
                .unwrap_or_default()
                .to_owned(),
            deprecated_at: date("api_deprecated_at"),
            retirement_date: date("api_retirement_date"),
            successor_version: string_field(api, "api_successor_version")
                .filter(|version| !version.is_empty())
                .map(str::to_owned),
        }
    }

    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("X-API-Lifecycle-Status", self.status.clone()),
            ("X-API-Resolved-Version", self.resolved_version.clone()),
        ];
        if matches!(self.status.as_str(), "deprecated" | "retired") {
            // RFC 9745 structured-field date.
            if let Some(at) = self.deprecated_at {
                headers.push(("Deprecation", format!("@{}", at.unix_timestamp())));
            }
            // RFC 8594 retirement date.
            if let Some(date) = self.retirement_date.and_then(format_http_date) {
                headers.push(("Sunset", date));
            }
        }
        if let Some(successor) = &self.successor_version {
            headers.push((
                "Link",
                format!(
                    "</api/rest/{}/{successor}>; rel=\"successor-version\"",
                    self.api_name
                ),
            ));
        }
        headers
    }
}

/// Accepts an RFC 3339 timestamp or a `YYYY-MM-DD` date (midnight UTC).
pub fn parse_lifecycle_date(value: &str) -> Option<OffsetDateTime> {
    let value = value.trim();
    OffsetDateTime::parse(value, &Rfc3339).ok().or_else(|| {
        Date::parse(value, format_description!("[year]-[month]-[day]"))
            .ok()
            .map(|date| date.midnight().assume_utc())
    })
}

pub fn format_lifecycle_date(value: OffsetDateTime) -> Option<String> {
    value.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok()
}

fn format_http_date(value: OffsetDateTime) -> Option<String> {
    value
        .to_offset(time::UtcOffset::UTC)
        .format(format_description!(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
        ))
        .ok()
}

/// The transitions an administrator may make; retirement is always manual and
/// can be undone back to deprecated.
pub fn transition_allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("draft", "active")
            | ("active", "deprecated")
            | ("deprecated", "active")
            | ("deprecated", "retired")
            | ("retired", "deprecated")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn active_versions_report_status_only() {
        let lifecycle =
            ApiLifecycle::from_api(&json!({"api_name": "demo", "api_version": "v1.1.0"}));
        assert_eq!(
            lifecycle.headers(),
            vec![
                ("X-API-Lifecycle-Status", "active".to_owned()),
                ("X-API-Resolved-Version", "v1.1.0".to_owned()),
            ]
        );
    }

    #[test]
    fn deprecated_versions_announce_retirement() {
        let lifecycle = ApiLifecycle::from_api(&json!({
            "api_name": "demo",
            "api_version": "v1",
            "api_lifecycle_status": "deprecated",
            "api_deprecated_at": "2026-10-16T00:00:00Z",
            "api_retirement_date": "2027-05-01",
            "api_successor_version": "v2",
        }));
        let headers = lifecycle.headers();
        assert!(headers.contains(&("X-API-Lifecycle-Status", "deprecated".to_owned())));
        assert!(headers.contains(&("Deprecation", "@1792108800".to_owned())));
        assert!(headers.contains(&("Sunset", "Sat, 01 May 2027 00:00:00 GMT".to_owned())));
        assert!(headers.contains(&(
            "Link",
            "</api/rest/demo/v2>; rel=\"successor-version\"".to_owned()
        )));
    }

    #[test]
    fn parses_dates_and_checks_transitions() {
        assert!(parse_lifecycle_date("2027-05-01T12:30:00+02:00").is_some());
        assert!(parse_lifecycle_date("May 1").is_none());
        assert_eq!(
            format_lifecycle_date(parse_lifecycle_date("2027-05-01").unwrap()).as_deref(),
            Some("2027-05-01T00:00:00Z")
        );
        assert!(transition_allowed("active", "deprecated"));
        assert!(!transition_allowed("active", "retired"));
        assert!(!transition_allowed("retired", "active"));
    }
}
