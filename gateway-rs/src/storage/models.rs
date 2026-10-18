use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

use crate::gateway::resolution::ApiVersion;

pub type Document = Map<String, Value>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ApiDocument {
    #[serde(flatten)]
    pub fields: HashMap<String, Value>,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyDocuments {
    pub apis: Vec<Value>,
    pub endpoints: Vec<Value>,
    pub endpoint_validations: Vec<Value>,
    pub users: Vec<Value>,
    pub roles: Vec<Value>,
    pub subscriptions: Vec<Value>,
    pub routings: Vec<Value>,
    pub credit_defs: Vec<Value>,
    pub user_credits: Vec<Value>,
    pub settings: Vec<Value>,
    pub revocations: Vec<Value>,
    pub tiers: Vec<Value>,
    pub tier_assignments: Vec<Value>,
}

pub fn api_name_version(name: &str, version: &str, leading_slash: bool) -> String {
    if leading_slash {
        format!("/{name}/{version}")
    } else {
        format!("{name}/{version}")
    }
}

pub fn strip_mongo_id(value: &mut Value) {
    if let Value::Object(map) = value {
        map.remove("_id");
    }
}

pub fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

pub fn owned_string_field(value: &Value, field: &str) -> Option<String> {
    string_field(value, field).map(str::to_owned)
}

pub fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

pub fn bool_field_default(value: &Value, field: &str, default: bool) -> bool {
    bool_field(value, field).unwrap_or(default)
}

pub fn i64_field(value: &Value, field: &str) -> Option<i64> {
    match value.get(field) {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(raw)) => raw.parse().ok(),
        _ => None,
    }
}

pub fn u64_field(value: &Value, field: &str) -> Option<u64> {
    match value.get(field) {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(raw)) => raw.parse().ok(),
        _ => None,
    }
}

pub fn f64_field(value: &Value, field: &str) -> Option<f64> {
    match value.get(field) {
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(raw)) => raw.parse().ok(),
        _ => None,
    }
}

pub fn string_list_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub fn object_field<'a>(value: &'a Value, field: &str) -> Option<&'a Map<String, Value>> {
    value.get(field).and_then(Value::as_object)
}

pub fn find_by_string<'a>(items: &'a [Value], field: &str, expected: &str) -> Option<&'a Value> {
    items
        .iter()
        .find(|item| string_field(item, field).is_some_and(|actual| actual == expected))
}

pub fn find_api<'a>(items: &'a [Value], name: &str, version: &str) -> Option<&'a Value> {
    items.iter().find(|item| {
        string_field(item, "api_name").is_some_and(|actual| actual == name)
            && string_field(item, "api_version").is_some_and(|actual| actual == version)
    })
}

/// Lifecycle state of an API version; records without one predate lifecycle
/// support and are active.
pub fn api_lifecycle_status(api: &Value) -> &str {
    match string_field(api, "api_lifecycle_status") {
        Some(status @ ("draft" | "active" | "deprecated" | "retired")) => status,
        _ => "active",
    }
}

#[derive(Debug, PartialEq)]
pub enum ApiResolution<'a> {
    Found(&'a Value),
    Retired(&'a Value),
    NotFound,
}

/// Resolves the API record a request version selects. A major-only version
/// (`v1`) picks the highest routable release in that line, counting a legacy
/// `v1` record as 1.0.0; any other version must match exactly. Drafts are never
/// routable, and a line with only retired releases resolves to `Retired`.
pub fn resolve_api<'a>(items: &'a [Value], name: &str, requested: &str) -> ApiResolution<'a> {
    let named = || {
        items
            .iter()
            .filter(move |item| string_field(item, "api_name") == Some(name))
    };
    let requested_version = ApiVersion::parse(requested).filter(|version| version.major_only);
    let Some(line) = requested_version else {
        return match named().find(|item| string_field(item, "api_version") == Some(requested)) {
            Some(api) => match api_lifecycle_status(api) {
                "draft" => ApiResolution::NotFound,
                "retired" => ApiResolution::Retired(api),
                _ => ApiResolution::Found(api),
            },
            None => ApiResolution::NotFound,
        };
    };
    let release_key = |item: &Value| {
        let version = string_field(item, "api_version")?;
        let parsed = ApiVersion::parse(version).filter(|parsed| parsed.major == line.major)?;
        // A legacy exact `v1` record wins a tie with `v1.0.0`.
        Some((parsed.release(), version == requested))
    };
    let best = |status: fn(&str) -> bool| {
        named()
            .filter(|item| status(api_lifecycle_status(item)))
            .filter_map(|item| release_key(item).map(|key| (key, item)))
            .max_by_key(|(key, _)| *key)
            .map(|(_, item)| item)
    };
    if let Some(api) = best(|status| matches!(status, "active" | "deprecated")) {
        return ApiResolution::Found(api);
    }
    match best(|status| status == "retired") {
        Some(api) => ApiResolution::Retired(api),
        None => ApiResolution::NotFound,
    }
}

pub fn find_endpoint<'a>(
    items: &'a [Value],
    api: &Value,
    method: &str,
    routing_uri: &str,
) -> Option<&'a Value> {
    let api_name = string_field(api, "api_name");
    let api_version = string_field(api, "api_version");
    items.iter().find(|item| {
        string_field(item, "api_name") == api_name
            && string_field(item, "api_version") == api_version
            && string_field(item, "endpoint_method")
                .is_some_and(|actual| actual.eq_ignore_ascii_case(method))
            && (string_field(item, "client_uri") == Some(routing_uri)
                || string_field(item, "endpoint_uri") == Some(routing_uri))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn api(version: &str, status: Option<&str>) -> Value {
        let mut api = json!({"api_name": "demo", "api_version": version});
        if let Some(status) = status {
            api["api_lifecycle_status"] = json!(status);
        }
        api
    }

    fn resolved_version(resolution: ApiResolution<'_>) -> Option<(&'static str, String)> {
        match resolution {
            ApiResolution::Found(api) => Some(("found", api["api_version"].as_str()?.to_owned())),
            ApiResolution::Retired(api) => {
                Some(("retired", api["api_version"].as_str()?.to_owned()))
            }
            ApiResolution::NotFound => None,
        }
    }

    #[test]
    fn major_line_resolves_highest_routable_release() {
        let apis = vec![
            api("v1", None),
            api("v1.1.0", None),
            api("v1.10.0", Some("deprecated")),
            api("v1.11.0", Some("draft")),
            api("v1.12.0", Some("retired")),
            api("v2.0.0", None),
        ];
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "v1")),
            Some(("found", "v1.10.0".to_owned()))
        );
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "v2")),
            Some(("found", "v2.0.0".to_owned()))
        );
        assert_eq!(resolve_api(&apis, "demo", "v3"), ApiResolution::NotFound);
        assert_eq!(resolve_api(&apis, "other", "v1"), ApiResolution::NotFound);
    }

    #[test]
    fn legacy_major_record_wins_tie_and_exact_versions_match_exactly() {
        let apis = vec![api("v1.0.0", None), api("v1", None), api("beta", None)];
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "v1")),
            Some(("found", "v1".to_owned()))
        );
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "v1.0.0")),
            Some(("found", "v1.0.0".to_owned()))
        );
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "beta")),
            Some(("found", "beta".to_owned()))
        );
        assert_eq!(resolve_api(&apis, "demo", "v1.0"), ApiResolution::NotFound);
    }

    #[test]
    fn retired_and_draft_releases_are_not_routable() {
        let apis = vec![api("v1.0.0", Some("retired")), api("v1.1.0", Some("draft"))];
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "v1")),
            Some(("retired", "v1.0.0".to_owned()))
        );
        assert_eq!(
            resolved_version(resolve_api(&apis, "demo", "v1.0.0")),
            Some(("retired", "v1.0.0".to_owned()))
        );
        assert_eq!(
            resolve_api(&apis, "demo", "v1.1.0"),
            ApiResolution::NotFound
        );
        assert_eq!(api_lifecycle_status(&api("v1", Some("bogus"))), "active");
    }

    #[test]
    fn builds_api_name_version_keys() {
        assert_eq!(api_name_version("demo", "v1", true), "/demo/v1");
        assert_eq!(api_name_version("demo", "v1", false), "demo/v1");
    }

    #[test]
    fn coerces_string_lists() {
        let value = json!({ "groups": ["admin", 1, "ops"] });
        assert_eq!(string_list_field(&value, "groups"), vec!["admin", "ops"]);
    }
}
