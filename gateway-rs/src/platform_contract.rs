use serde_json::{Map, Number, Value, json};

use crate::ai::{
    adapter::{AiProvider, preset},
    config::{AiApiConfig, model_allowed},
};

const STRING_FIELDS: &[(&str, Option<usize>, Option<usize>)] = &[
    ("api_name", Some(1), Some(64)),
    ("api_version", Some(1), Some(16)),
    ("api_description", None, Some(127)),
    ("api_type", None, None),
    ("api_grpc_package", None, None),
    ("api_authorization_field_swap", None, None),
    ("api_credit_group", None, None),
    ("api_id", None, None),
    ("api_path", None, None),
    ("api_ip_mode", None, None),
    ("api_openapi_url", None, None),
    ("api_wsdl_url", None, None),
    ("api_soap_version", None, None),
    ("api_graphql_schema_url", None, None),
    ("api_grpc_reflection_url", None, None),
    ("api_crud_collection", None, None),
];

const STRING_LIST_FIELDS: &[&str] = &[
    "api_allowed_roles",
    "api_allowed_groups",
    "api_servers",
    "api_grpc_allowed_packages",
    "api_grpc_allowed_services",
    "api_grpc_allowed_methods",
    "api_allowed_headers",
    "api_cors_allow_origins",
    "api_cors_allow_methods",
    "api_cors_allow_headers",
    "api_cors_expose_headers",
    "api_ip_whitelist",
    "api_ip_blacklist",
];

const BOOL_FIELDS: &[&str] = &[
    "api_credits_enabled",
    "active",
    "api_cors_allow_credentials",
    "api_public",
    "api_auth_required",
    "api_trust_x_forwarded_for",
    "api_openapi_auto_discover",
    "api_graphql_subscriptions",
    "api_grpc_web_enabled",
    "api_is_crud",
];

const RUST_EXTENSION_BOOL_FIELDS: &[&str] = &["enforce_admin_subscription"];

const INT_FIELDS: &[&str] = &["api_allowed_retry_count", "api_graphql_max_depth"];

const OBJECT_FIELDS: &[&str] = &[
    "api_request_transform",
    "api_response_transform",
    "api_ws_security",
    "api_crud_schema",
];

const RUST_EXTENSION_FIELDS: &[&str] = &[
    "api_client_tls_policy",
    "api_upstream_tls_profile",
    "api_upstream_tls_profiles",
    "api_wsdl_content",
    "api_openapi_schema",
    "api_graphql_schema",
    "api_grpc_proto_source",
    "api_grpc_descriptor_set",
    "api_grpc_descriptor_sha256",
];

/// AI fields are additive Rust extensions; unlike the Python model's fields they
/// are not defaulted to null on create, so non-AI API documents are unchanged.
const RUST_EXTENSION_STRING_FIELDS: &[&str] = &["api_ai_provider"];
const RUST_EXTENSION_OBJECT_FIELDS: &[&str] = &["api_ai_config"];

pub fn normalize_create_api(payload: &Value) -> Result<Value, Vec<Value>> {
    let mut normalized = normalize_api_fields(payload, false)?;
    // New versions start as a draft or go straight to active; later states are
    // reached only through the lifecycle endpoint.
    match payload.get("api_lifecycle_status") {
        None | Some(Value::Null) => {}
        Some(Value::String(status)) if matches!(status.as_str(), "draft" | "active") => {
            normalized["api_lifecycle_status"] = json!(status);
        }
        Some(_) => {
            return Err(vec![json!({
                "loc": ["body", "api_lifecycle_status"],
                "msg": "new APIs must start as draft or active",
                "type": "value_error.lifecycle"
            })]);
        }
    }
    let object = normalized
        .as_object_mut()
        .expect("normalization returns object");
    for (key, value) in [
        ("api_allowed_roles", json!([])),
        ("api_allowed_groups", json!([])),
        ("api_servers", json!([])),
        ("api_allowed_retry_count", json!(0)),
        ("api_credits_enabled", json!(false)),
        ("active", json!(true)),
        ("api_cors_allow_credentials", json!(false)),
        ("api_public", json!(false)),
        ("api_auth_required", json!(true)),
        ("api_ip_mode", json!("allow_all")),
        ("api_openapi_auto_discover", json!(false)),
        ("api_graphql_subscriptions", json!(false)),
        ("api_grpc_web_enabled", json!(false)),
        ("api_is_crud", json!(false)),
    ] {
        object.entry(key.to_owned()).or_insert(value);
    }
    for key in STRING_FIELDS
        .iter()
        .map(|(key, _, _)| *key)
        .chain(STRING_LIST_FIELDS.iter().copied())
        .chain(BOOL_FIELDS.iter().copied())
        .chain(INT_FIELDS.iter().copied())
        .chain(OBJECT_FIELDS.iter().copied())
    {
        object.entry(key.to_owned()).or_insert(Value::Null);
    }
    Ok(normalized)
}

pub fn normalize_update_api(payload: &Value) -> Result<Value, Vec<Value>> {
    let mut normalized = normalize_api_fields(payload, true)?;
    if let Some(values) = normalized.as_object_mut() {
        values.retain(|field, value| {
            !value.is_null()
                || matches!(
                    field.as_str(),
                    "api_client_tls_policy"
                        | "api_upstream_tls_profile"
                        | "api_upstream_tls_profiles"
                )
        });
    }
    Ok(normalized)
}

fn normalize_api_fields(payload: &Value, update: bool) -> Result<Value, Vec<Value>> {
    let Some(input) = payload.as_object() else {
        return Err(vec![json!({
            "loc": ["body"],
            "msg": "value is not a valid dict",
            "type": "type_error.dict"
        })]);
    };
    let mut output = Map::new();
    let mut errors = Vec::new();

    for (field, min, configured_max) in STRING_FIELDS {
        let update_name_max = Some(25);
        let max = if update && *field == "api_name" {
            &update_name_max
        } else {
            configured_max
        };
        match input.get(*field) {
            None if !update && matches!(*field, "api_name" | "api_version") => {
                errors.push(missing(field));
            }
            None => {}
            Some(Value::Null) => {
                if !update && matches!(*field, "api_name" | "api_version") {
                    errors.push(none_not_allowed(field));
                } else {
                    output.insert((*field).to_owned(), Value::Null);
                }
            }
            Some(value) => match coerce_string(value) {
                Some(value) => {
                    let length = value.chars().count();
                    if min.is_some_and(|limit| length < limit) {
                        errors.push(string_limit(field, "min", min.unwrap()));
                    } else if max.is_some_and(|limit| length > limit) {
                        errors.push(string_limit(field, "max", max.unwrap()));
                    } else {
                        output.insert((*field).to_owned(), Value::String(value));
                    }
                }
                None => errors.push(type_error(field, "str")),
            },
        }
    }

    for field in STRING_LIST_FIELDS {
        normalize_optional(
            input,
            &mut output,
            &mut errors,
            field,
            |value| {
                let array = value.as_array()?;
                array
                    .iter()
                    .map(coerce_string)
                    .collect::<Option<Vec<_>>>()
                    .map(|items| Value::Array(items.into_iter().map(Value::String).collect()))
            },
            "list",
        );
    }
    for field in BOOL_FIELDS {
        normalize_optional(input, &mut output, &mut errors, field, coerce_bool, "bool");
    }
    for field in RUST_EXTENSION_BOOL_FIELDS {
        normalize_optional(input, &mut output, &mut errors, field, coerce_bool, "bool");
    }
    for field in INT_FIELDS {
        normalize_optional(
            input,
            &mut output,
            &mut errors,
            field,
            coerce_int,
            "integer",
        );
    }
    for field in OBJECT_FIELDS {
        normalize_optional(
            input,
            &mut output,
            &mut errors,
            field,
            |value| value.as_object().cloned().map(Value::Object),
            "dict",
        );
    }

    for field in RUST_EXTENSION_STRING_FIELDS {
        normalize_optional(
            input,
            &mut output,
            &mut errors,
            field,
            |value| value.as_str().map(|value| Value::String(value.to_owned())),
            "str",
        );
    }
    for field in RUST_EXTENSION_OBJECT_FIELDS {
        normalize_optional(
            input,
            &mut output,
            &mut errors,
            field,
            |value| value.as_object().cloned().map(Value::Object),
            "dict",
        );
    }

    // These fields are native v2 additions. Preserve them as additive extensions
    // while maintaining the Python model's ignore-extra behavior for all others.
    for field in RUST_EXTENSION_FIELDS {
        if let Some(value) = input.get(*field) {
            output.insert((*field).to_owned(), value.clone());
        }
    }

    if errors.is_empty() {
        validate_credentialed_cors(&output, &mut errors);
    }
    if errors.is_empty() {
        Ok(Value::Object(output))
    } else {
        Err(errors)
    }
}

pub fn is_ai_api(api: &Value) -> bool {
    api.get("api_type")
        .and_then(Value::as_str)
        .is_some_and(|api_type| api_type.eq_ignore_ascii_case("AI"))
}

/// Create-time AI handling: fills the provider's default server when none is
/// given, then validates. No-op for non-AI APIs.
pub fn prepare_ai_api(api: &mut Value) -> Result<(), Vec<Value>> {
    if !is_ai_api(api) {
        return Ok(());
    }
    let servers_empty = api
        .get("api_servers")
        .and_then(Value::as_array)
        .is_none_or(|servers| servers.is_empty());
    let default_server = api
        .get("api_ai_provider")
        .and_then(Value::as_str)
        .and_then(AiProvider::parse)
        .and_then(|provider| preset(provider).default_server);
    if let (true, Some(server), Some(object)) = (servers_empty, default_server, api.as_object_mut())
    {
        object.insert("api_servers".to_owned(), json!([server]));
    }
    validate_ai_api(api)
}

/// Validates an AI API record (create payload or merged update). No-op for
/// non-AI APIs. Errors use the Pydantic-style `{loc,msg,type}` items.
pub fn validate_ai_api(api: &Value) -> Result<(), Vec<Value>> {
    if !is_ai_api(api) {
        return Ok(());
    }
    let mut errors = Vec::new();
    let mut fail = |field: &str, msg: &str| errors.push(ai_error(field, msg));

    let provider = match api.get("api_ai_provider") {
        Some(Value::String(value)) => {
            let provider = AiProvider::parse(value);
            if provider.is_none() {
                fail("api_ai_provider", "unknown AI provider");
            }
            provider
        }
        _ => {
            fail("api_ai_provider", "AI provider is required for AI APIs");
            None
        }
    };
    if api.get("api_public").and_then(Value::as_bool) == Some(true) {
        fail("api_public", "AI APIs cannot be public");
    }
    if api.get("api_auth_required").and_then(Value::as_bool) == Some(false) {
        fail("api_auth_required", "AI APIs always require authentication");
    }
    for field in ["api_request_transform", "api_response_transform"] {
        if api.get(field).is_some_and(|value| {
            !value.is_null() && value.as_object().is_none_or(|v| !v.is_empty())
        }) {
            fail(field, "transforms are not supported on AI APIs");
        }
    }
    let servers: Vec<&str> = api
        .get("api_servers")
        .and_then(Value::as_array)
        .map(|servers| servers.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if servers.iter().all(|server| server.trim().is_empty()) {
        fail("api_servers", "AI APIs need an upstream server");
    }

    let config = match api.get("api_ai_config") {
        Some(value @ Value::Object(_)) => match AiApiConfig::from_value(value) {
            Ok(config) => Some(config),
            Err(error) => {
                fail("api_ai_config", &format!("invalid AI config: {error}"));
                None
            }
        },
        _ => {
            fail("api_ai_config", "AI config is required for AI APIs");
            None
        }
    };
    if let Some(config) = config {
        let credential_group = config.credential_group.trim();
        if credential_group.is_empty() {
            fail(
                "api_ai_config.credential_group",
                "credential group is required",
            );
        } else if credential_group == "none" {
            let private = provider == Some(AiProvider::OpenaiCompatible)
                && !servers.is_empty()
                && servers.iter().all(|server| is_private_upstream(server));
            if !private {
                fail(
                    "api_ai_config.credential_group",
                    "credential_group \"none\" is only allowed for openai_compatible APIs on a private host",
                );
            }
        }
        if config.allowed_models.is_empty()
            || config
                .allowed_models
                .iter()
                .any(|model| model.trim().is_empty())
        {
            fail(
                "api_ai_config.allowed_models",
                "allowed models must be a non-empty list of model IDs",
            );
        }
        for (alias, target) in &config.model_aliases {
            if alias.trim().is_empty() || !model_allowed(target, &config.allowed_models) {
                fail(
                    "api_ai_config.model_aliases",
                    &format!("alias '{alias}' must target an allowed model"),
                );
            }
        }
        if let Some(default_model) = &config.default_model {
            if !model_allowed(default_model, &config.allowed_models) {
                fail(
                    "api_ai_config.default_model",
                    "default model must be allowed",
                );
            }
        }
        if config
            .credential_overrides
            .iter()
            .any(|entry| entry.group.trim().is_empty() || entry.credential_group.trim().is_empty())
        {
            fail(
                "api_ai_config.credential_overrides",
                "credential overrides need a group and a credential group",
            );
        }
        if let (Some(operations), Some(provider)) = (&config.allowed_operations, provider) {
            let supported = preset(provider).operations;
            if operations
                .iter()
                .any(|operation| !supported.contains(&operation.as_str()))
            {
                fail(
                    "api_ai_config.allowed_operations",
                    "operation is not supported by this provider",
                );
            }
        }
        if config.max_output_tokens == Some(0) {
            fail("api_ai_config.max_output_tokens", "must be greater than 0");
        }
        if config
            .log_level
            .as_deref()
            .is_some_and(|level| !matches!(level, "none" | "metadata" | "full"))
        {
            fail(
                "api_ai_config.log_level",
                "log level must be none, metadata or full",
            );
        }
        if config.first_byte_timeout_ms == 0 || config.stream_idle_timeout_ms == 0 {
            fail("api_ai_config", "timeouts must be greater than 0");
        }
        if config.fallback_targets.len() > crate::ai::config::MAX_FALLBACK_TARGETS {
            fail(
                "api_ai_config.fallback_targets",
                "at most 10 backup targets are allowed",
            );
        }
        if config.load_balance
            && !config
                .fallback_targets
                .iter()
                .any(|target| target.server.is_some())
        {
            fail(
                "api_ai_config.load_balance",
                "load balancing needs a backup on a different server; backup keys on the same server are used for failover only",
            );
        }
        for target in &config.fallback_targets {
            if target.credential_group.trim().is_empty() && target.server.is_none() {
                fail(
                    "api_ai_config.fallback_targets",
                    "each backup needs a credential group, a server, or both",
                );
            }
            if target.server.as_deref().is_some_and(|server| {
                !(server.starts_with("https://") || server.starts_with("http://"))
            }) {
                fail(
                    "api_ai_config.fallback_targets",
                    "backup server must be an http(s) URL",
                );
            }
            if !(1..=1000).contains(&target.weight) {
                fail(
                    "api_ai_config.fallback_targets",
                    "weight must be between 1 and 1000",
                );
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// One-line summary of AI validation errors for the `AI009` error message.
pub fn ai_validation_message(errors: &[Value]) -> String {
    errors
        .iter()
        .map(|error| {
            let field = error["loc"]
                .as_array()
                .and_then(|loc| loc.last())
                .and_then(Value::as_str)
                .unwrap_or("body");
            format!("{field}: {}", error["msg"].as_str().unwrap_or("invalid"))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Loopback, RFC 1918 / IPv6 ULA, or a bare single-label (Docker service) name.
fn is_private_upstream(server: &str) -> bool {
    let Ok(url) = url::Url::parse(server.trim()) else {
        return false;
    };
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_private(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Some(url::Host::Domain(domain)) => !domain.is_empty() && !domain.contains('.'),
        None => false,
    }
}

fn ai_error(field: &str, msg: &str) -> Value {
    json!({"loc": ["body", field], "msg": msg, "type": "value_error.ai"})
}

fn validate_credentialed_cors(output: &Map<String, Value>, errors: &mut Vec<Value>) {
    if output
        .get("api_cors_allow_credentials")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return;
    }
    let Some(origins) = output
        .get("api_cors_allow_origins")
        .and_then(Value::as_array)
    else {
        errors.push(json!({
            "loc": ["body", "api_cors_allow_origins"],
            "msg": "credentialed CORS requires a non-empty explicit origin allowlist",
            "type": "value_error.cors_origins"
        }));
        return;
    };
    if origins.is_empty()
        || origins.iter().any(|origin| {
            origin
                .as_str()
                .is_none_or(|origin| origin.trim().is_empty() || origin.trim() == "*")
        })
    {
        errors.push(json!({
            "loc": ["body", "api_cors_allow_origins"],
            "msg": "credentialed CORS must not use wildcard or empty origins",
            "type": "value_error.cors_origins"
        }));
    }
}

fn normalize_optional(
    input: &Map<String, Value>,
    output: &mut Map<String, Value>,
    errors: &mut Vec<Value>,
    field: &str,
    coercer: impl Fn(&Value) -> Option<Value>,
    kind: &str,
) {
    let Some(value) = input.get(field) else {
        return;
    };
    if value.is_null() {
        output.insert(field.to_owned(), Value::Null);
    } else if let Some(value) = coercer(value) {
        output.insert(field.to_owned(), value);
    } else {
        errors.push(type_error(field, kind));
    }
}

fn coerce_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(if *value { "True" } else { "False" }.to_owned()),
        _ => None,
    }
}

fn coerce_bool(value: &Value) -> Option<Value> {
    let value = match value {
        Value::Bool(value) => *value,
        Value::Number(value) if value.as_i64() == Some(0) => false,
        Value::Number(value) if value.as_i64() == Some(1) => true,
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => false,
            "1" | "on" | "t" | "true" | "y" | "yes" => true,
            _ => return None,
        },
        _ => return None,
    };
    Some(Value::Bool(value))
}

fn coerce_int(value: &Value) -> Option<Value> {
    let value = match value {
        Value::Number(value) => value
            .as_i64()
            .or_else(|| value.as_f64().map(|v| v as i64))?,
        Value::String(value) => value
            .parse::<i64>()
            .ok()
            .or_else(|| value.parse::<f64>().ok().map(|v| v as i64))?,
        _ => return None,
    };
    Some(Value::Number(Number::from(value)))
}

fn missing(field: &str) -> Value {
    json!({"loc": ["body", field], "msg": "field required", "type": "value_error.missing"})
}

fn none_not_allowed(field: &str) -> Value {
    json!({
        "loc": ["body", field],
        "msg": "none is not an allowed value",
        "type": "type_error.none.not_allowed"
    })
}

fn type_error(field: &str, kind: &str) -> Value {
    let message = match kind {
        "str" => "str type expected",
        "integer" => "value is not a valid integer",
        _ => {
            return json!({
                "loc": ["body", field],
                "msg": format!("value is not a valid {kind}"),
                "type": format!("type_error.{kind}")
            });
        }
    };
    json!({
        "loc": ["body", field],
        "msg": message,
        "type": format!("type_error.{kind}")
    })
}

fn string_limit(field: &str, direction: &str, limit: usize) -> Value {
    let (message, error_type) = if direction == "min" {
        (
            format!("ensure this value has at least {limit} characters"),
            "value_error.any_str.min_length",
        )
    } else {
        (
            format!("ensure this value has at most {limit} characters"),
            "value_error.any_str.max_length",
        )
    };
    json!({
        "loc": ["body", field],
        "msg": message,
        "type": error_type,
        "ctx": {"limit_value": limit}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_credentialed_wildcard_cors() {
        let error = normalize_create_api(&json!({
            "api_name": "orders",
            "api_version": "v1",
            "api_cors_allow_credentials": true,
            "api_cors_allow_origins": ["*"]
        }))
        .unwrap_err();
        assert_eq!(error[0]["type"], "value_error.cors_origins");
    }

    #[test]
    fn create_materializes_python_defaults_and_ignores_unknown_fields() {
        let value = normalize_create_api(&json!({
            "api_name": "orders",
            "api_version": "v1",
            "unknown": "ignored"
        }))
        .unwrap();
        assert_eq!(value["api_allowed_roles"], json!([]));
        assert_eq!(value["api_auth_required"], true);
        assert_eq!(value["api_description"], Value::Null);
        assert!(value.get("enforce_admin_subscription").is_none());
        assert!(value.get("unknown").is_none());
    }

    #[test]
    fn rust_extension_bool_is_coerced_without_becoming_a_python_default() {
        let value = normalize_create_api(&json!({
            "api_name": "orders",
            "api_version": "v1",
            "enforce_admin_subscription": "yes"
        }))
        .unwrap();
        assert_eq!(value["enforce_admin_subscription"], true);
    }

    #[test]
    fn update_coerces_values_and_removes_nulls() {
        let value = normalize_update_api(&json!({
            "api_name": 123,
            "api_public": "yes",
            "api_description": null,
            "api_client_tls_policy": null,
            "api_upstream_tls_profile": null
        }))
        .unwrap();
        assert_eq!(
            value,
            json!({"api_name": "123", "api_public": true,
            "api_client_tls_policy": null, "api_upstream_tls_profile": null})
        );
    }

    #[test]
    fn validation_uses_fastapi_pydantic_error_shape() {
        let errors = normalize_create_api(&json!({
            "api_name": "",
            "api_version": "version-is-too-long"
        }))
        .unwrap_err();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0]["loc"], json!(["body", "api_name"]));
        assert_eq!(errors[1]["type"], "value_error.any_str.max_length");
    }

    fn ai_api(overrides: Value) -> Value {
        let mut api = json!({
            "api_name": "corp-openai",
            "api_version": "v1",
            "api_type": "AI",
            "api_ai_provider": "openai",
            "api_public": false,
            "api_auth_required": true,
            "api_servers": [],
            "api_ai_config": {
                "credential_group": "openai-prod",
                "allowed_models": ["gpt-x", "gpt-x-mini*"],
            }
        });
        for (key, value) in overrides.as_object().unwrap() {
            api[key] = value.clone();
        }
        api
    }

    fn ai_error_fields(result: Result<(), Vec<Value>>) -> Vec<String> {
        result
            .unwrap_err()
            .iter()
            .map(|error| {
                assert_eq!(error["type"], "value_error.ai");
                error["loc"][1].as_str().unwrap().to_owned()
            })
            .collect()
    }

    #[test]
    fn ai_api_requires_credential_group_and_models() {
        let mut api = ai_api(json!({}));
        prepare_ai_api(&mut api).unwrap();
        assert_eq!(api["api_servers"], json!(["https://api.openai.com"]));

        // validate_ai_api alone does not fill the preset server.
        let api = ai_api(json!({"api_ai_config": {"allowed_models": []}}));
        assert_eq!(
            ai_error_fields(validate_ai_api(&api)),
            vec![
                "api_servers",
                "api_ai_config.credential_group",
                "api_ai_config.allowed_models"
            ]
        );
        let mut api = ai_api(json!({"api_ai_config": null}));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut api)),
            vec!["api_ai_config"]
        );
        let mut api = ai_api(json!({"api_ai_provider": "vertex"}));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut api)),
            vec!["api_ai_provider", "api_servers"]
        );
        // Azure has no default server, so one must be supplied.
        let mut api = ai_api(json!({"api_ai_provider": "azure_openai"}));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut api)),
            vec!["api_servers"]
        );
        let mut api = ai_api(json!({
            "api_ai_config": {
                "credential_group": "openai-prod",
                "allowed_models": ["gpt-x"],
                "credential_overrides": [{"group": "eng", "credential_group": ""}],
            }
        }));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut api)),
            vec!["api_ai_config.credential_overrides"]
        );
    }

    #[test]
    fn ai_api_cannot_be_public() {
        let mut api = ai_api(json!({"api_public": true, "api_auth_required": false}));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut api)),
            vec!["api_public", "api_auth_required"]
        );
        let normalized = normalize_create_api(&ai_api(json!({}))).unwrap();
        assert_eq!(normalized["api_public"], false);
        assert_eq!(normalized["api_auth_required"], true);
        assert_eq!(normalized["api_ai_provider"], "openai");
        assert!(normalized["api_ai_config"].is_object());
    }

    #[test]
    fn ai_alias_must_target_allowed_model() {
        let config = |aliases: Value| {
            ai_api(json!({"api_ai_config": {
                "credential_group": "openai-prod",
                "allowed_models": ["gpt-x", "gpt-x-mini*"],
                "model_aliases": aliases,
            }}))
        };
        let mut ok = config(json!({"fast": "gpt-x-mini-2026", "best": "gpt-x"}));
        prepare_ai_api(&mut ok).unwrap();
        let mut bad = config(json!({"fast": "gpt-y"}));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut bad)),
            vec!["api_ai_config.model_aliases"]
        );
        let message = ai_validation_message(&prepare_ai_api(&mut bad).unwrap_err());
        assert_eq!(
            message,
            "api_ai_config.model_aliases: alias 'fast' must target an allowed model"
        );
    }

    #[test]
    fn non_ai_api_ignores_ai_fields() {
        let payload = json!({
            "api_name": "orders",
            "api_version": "v1",
            "api_type": "REST",
            "api_public": true,
            "api_ai_config": {"allowed_models": []},
            "api_request_transform": {"set": {}},
        });
        let mut normalized = normalize_create_api(&payload).unwrap();
        prepare_ai_api(&mut normalized).unwrap();
        validate_ai_api(&normalized).unwrap();
        assert_eq!(normalized["api_servers"], json!([]));
        // AI extension fields are not defaulted onto non-AI documents.
        let plain =
            normalize_create_api(&json!({"api_name": "orders", "api_version": "v1"})).unwrap();
        assert!(plain.get("api_ai_provider").is_none());
        assert!(plain.get("api_ai_config").is_none());
        assert_eq!(
            normalize_create_api(
                &json!({"api_name": "o", "api_version": "v1", "api_ai_config": 3})
            )
            .unwrap_err()[0]["type"],
            "type_error.dict"
        );
    }

    #[test]
    fn ai_api_rejects_transforms() {
        let mut api = ai_api(json!({
            "api_request_transform": {"set_headers": {"x": "y"}},
            "api_response_transform": {"rename": {}}
        }));
        assert_eq!(
            ai_error_fields(prepare_ai_api(&mut api)),
            vec!["api_request_transform", "api_response_transform"]
        );
        let mut api = ai_api(json!({"api_request_transform": null, "api_response_transform": {}}));
        prepare_ai_api(&mut api).unwrap();
    }

    #[test]
    fn ai_none_credential_requires_private_host() {
        let none = |provider: &str, server: &str| {
            let mut api = ai_api(json!({
                "api_ai_provider": provider,
                "api_servers": [server],
                "api_ai_config": {"credential_group": "none", "allowed_models": ["llama3"]},
            }));
            prepare_ai_api(&mut api)
        };
        for server in [
            "http://ollama:11434",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://10.1.2.3",
            "http://172.20.0.5:80",
            "http://192.168.1.10",
            "http://[::1]:8000",
        ] {
            none("openai_compatible", server).unwrap_or_else(|e| panic!("{server}: {e:?}"));
        }
        for server in [
            "https://llm.example.com",
            "http://8.8.8.8",
            "http://172.32.0.1",
            "not a url",
        ] {
            assert_eq!(
                ai_error_fields(none("openai_compatible", server)),
                vec!["api_ai_config.credential_group"],
                "{server}"
            );
        }
        assert_eq!(
            ai_error_fields(none("openai", "http://ollama:11434")),
            vec!["api_ai_config.credential_group"]
        );
    }
}
