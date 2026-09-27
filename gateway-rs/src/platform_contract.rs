use serde_json::{Map, Number, Value, json};

const STRING_FIELDS: &[(&str, Option<usize>, Option<usize>)] = &[
    ("api_name", Some(1), Some(64)),
    ("api_version", Some(1), Some(8)),
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
    "api_wsdl_content",
    "api_openapi_schema",
    "api_graphql_schema",
    "api_grpc_proto_source",
    "api_grpc_descriptor_set",
    "api_grpc_descriptor_sha256",
];

pub fn normalize_create_api(payload: &Value) -> Result<Value, Vec<Value>> {
    let mut normalized = normalize_api_fields(payload, false)?;
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
        values.retain(|_, value| !value.is_null());
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
            "api_description": null
        }))
        .unwrap();
        assert_eq!(value, json!({"api_name": "123", "api_public": true}));
    }

    #[test]
    fn validation_uses_fastapi_pydantic_error_shape() {
        let errors = normalize_create_api(&json!({
            "api_name": "",
            "api_version": "version-too-long"
        }))
        .unwrap_err();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0]["loc"], json!(["body", "api_name"]));
        assert_eq!(errors[1]["type"], "value_error.any_str.max_length");
    }
}
