use std::{collections::HashMap, fmt, sync::Arc};

use regex::Regex;
use serde_json::Value;

pub type CustomValidator = dyn Fn(&Value, &Value) -> Result<(), String> + Send + Sync + 'static;

#[derive(Clone, Default)]
pub struct ValidatorRegistry {
    validators: HashMap<String, Arc<CustomValidator>>,
}

impl fmt::Debug for ValidatorRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatorRegistry")
            .field("names", &self.validators.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ValidatorRegistry {
    pub fn register(
        &mut self,
        name: impl Into<String>,
        validator: impl Fn(&Value, &Value) -> Result<(), String> + Send + Sync + 'static,
    ) {
        self.validators.insert(name.into(), Arc::new(validator));
    }

    fn validate(&self, name: &str, value: &Value, rules: &Value) -> Result<(), String> {
        match self.validators.get(name) {
            Some(validator) => validator(value, rules),
            None => Ok(()),
        }
    }
}

pub fn validate_json(value: &Value, schema: &Value) -> Result<(), String> {
    validate_json_with_registry(value, schema, &ValidatorRegistry::default())
}

pub fn validate_json_with_registry(
    value: &Value,
    schema: &Value,
    registry: &ValidatorRegistry,
) -> Result<(), String> {
    let mapping = schema
        .get("validation_schema")
        .unwrap_or(schema)
        .as_object()
        .ok_or_else(|| "Invalid endpoint validation schema".to_owned())?;
    validate_schema_paths(mapping, "")?;
    for (path, rules) in mapping {
        let found = nested_value(value, path);
        validate_value(found, rules, path, registry)?;
    }
    Ok(())
}

fn validate_value(
    value: Option<&Value>,
    rules: &Value,
    path: &str,
    registry: &ValidatorRegistry,
) -> Result<(), String> {
    let required = rules
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return if required {
            Err("Field is required".to_owned())
        } else {
            Ok(())
        };
    };
    let expected = rules
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let valid_type = match expected {
        "string" => value.is_string(),
        // bool is a subclass of int in Python, so the pinned number validator
        // accepts JSON booleans and applies numeric bounds to 0/1.
        "number" => value.is_number() || value.is_boolean(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => true,
    };
    if !valid_type {
        return Err(format!(
            "Expected {expected}, got {}",
            python_type_name(value)
        ));
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as f64;
        enforce_range(length, rules, "String length", "", "")?;
        if let Some(pattern) = rules.get("pattern").and_then(Value::as_str) {
            let regex = Regex::new(pattern)
                .map_err(|_| format!("Invalid validation pattern for {path}"))?;
            if regex.find(text).is_none_or(|found| found.start() != 0) {
                return Err(format!("String does not match pattern {pattern}"));
            }
        }
        if let Some(format) = rules.get("format").and_then(Value::as_str) {
            validate_format(text, format, path)?;
        }
    }
    if let Some(number) = value
        .as_f64()
        .or_else(|| value.as_bool().map(|value| if value { 1.0 } else { 0.0 }))
    {
        enforce_range(number, rules, "Value", "", "")?;
    }
    if let Some(items) = value.as_array() {
        enforce_range(items.len() as f64, rules, "Array", " items", " items")?;
        if let Some(item_rules) = rules.get("array_items") {
            for (index, item) in items.iter().enumerate() {
                validate_value(
                    Some(item),
                    item_rules,
                    &format!("{path}[{index}]"),
                    registry,
                )?;
            }
        }
    }
    if let (Some(object), Some(nested)) = (
        value.as_object(),
        rules.get("nested_schema").and_then(Value::as_object),
    ) {
        for (field, nested_rules) in nested {
            if nested_rules
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && object.get(field).is_none_or(Value::is_null)
            {
                return Err(format!("Required field {field} is missing"));
            }
            validate_value(
                object.get(field),
                nested_rules,
                &format!("{path}.{field}"),
                registry,
            )?;
        }
    }
    if let Some(allowed) = rules.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            return Err(format!(
                "Value must be one of {}",
                python_list_repr(allowed)
            ));
        }
    }
    if let Some(name) = rules.get("custom_validator").and_then(Value::as_str) {
        registry
            .validate(name, value, rules)
            .map_err(|message| message.to_owned())?;
    }
    Ok(())
}

fn enforce_range(
    value: f64,
    rules: &Value,
    description: &str,
    minimum_suffix: &str,
    maximum_suffix: &str,
) -> Result<(), String> {
    if let Some(minimum) = rules.get("min").and_then(Value::as_f64)
        && value < minimum
    {
        return Err(format!(
            "{description} must be at least {}{minimum_suffix}",
            python_number(minimum)
        ));
    }
    if let Some(maximum) = rules.get("max").and_then(Value::as_f64)
        && value > maximum
    {
        return Err(format!(
            "{description} must be at most {}{maximum_suffix}",
            python_number(maximum)
        ));
    }
    Ok(())
}

fn validate_format(value: &str, format: &str, path: &str) -> Result<(), String> {
    let valid = match format {
        "email" => Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .is_ok_and(|regex| regex.is_match(value)),
        "url" => Regex::new(
            r"^https?://(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_+.~#?&/=]*$",
        )
        .is_ok_and(|regex| regex.is_match(value)),
        "date" => valid_date(value),
        "datetime" => valid_datetime(value),
        "uuid" => uuid::Uuid::parse_str(value).is_ok(),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        let message = match format {
            "date" => "Invalid date format (YYYY-MM-DD)",
            "datetime" => "Invalid datetime format (ISO 8601)",
            "uuid" => "Invalid UUID format",
            "email" => "Invalid email format",
            "url" => "Invalid URL format",
            _ => return Ok(()),
        };
        let _ = path;
        Err(message.to_owned())
    }
}

fn valid_date(value: &str) -> bool {
    time::Date::parse(
        value,
        &time::format_description::well_known::Iso8601::DEFAULT,
    )
    .is_ok()
}

fn valid_datetime(value: &str) -> bool {
    valid_date(value)
        || time::OffsetDateTime::parse(
            value,
            &time::format_description::well_known::Iso8601::DEFAULT,
        )
        .is_ok()
        || time::PrimitiveDateTime::parse(
            value,
            &time::format_description::well_known::Iso8601::DEFAULT,
        )
        .is_ok()
        || value.find(' ').is_some_and(|index| {
            let mut normalized = value.to_owned();
            normalized.replace_range(index..=index, "T");
            time::PrimitiveDateTime::parse(
                &normalized,
                &time::format_description::well_known::Iso8601::DEFAULT,
            )
            .is_ok()
        })
}

fn python_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_i64() || number.is_u64() => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn python_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        value.to_string()
    }
}

fn python_list_repr(values: &[Value]) -> String {
    let values = values
        .iter()
        .map(|value| match value {
            Value::String(value) => format!("'{value}'"),
            Value::Bool(true) => "True".to_owned(),
            Value::Bool(false) => "False".to_owned(),
            Value::Null => "None".to_owned(),
            value => value.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn validate_schema_paths(
    schema: &serde_json::Map<String, Value>,
    parent: &str,
) -> Result<(), String> {
    for (path, rules) in schema {
        let full_path = if parent.is_empty() {
            path.clone()
        } else {
            format!("{parent}.{path}")
        };
        if full_path.split('.').any(|part| {
            part.is_empty()
                || part.split_once('[').is_some_and(|(field, index)| {
                    field.is_empty()
                        && !index
                            .strip_suffix(']')
                            .unwrap_or(index)
                            .bytes()
                            .all(|byte| byte.is_ascii_digit())
                })
        }) {
            return Err(format!("Invalid field path: {full_path}"));
        }
        if let Some(nested) = rules.get("nested_schema").and_then(Value::as_object) {
            validate_schema_paths(nested, &full_path)?;
        }
    }
    Ok(())
}

fn nested_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        let (field, index) = parse_segment(segment)?;
        if !field.is_empty() {
            current = current.get(field)?;
        }
        if let Some(index) = index {
            current = current.as_array()?.get(index)?;
        }
    }
    Some(current)
}

fn parse_segment(segment: &str) -> Option<(&str, Option<usize>)> {
    if let Some((field, raw_index)) = segment.split_once('[') {
        let index = raw_index.strip_suffix(']')?.parse().ok()?;
        Some((field, Some(index)))
    } else if segment.is_empty() {
        None
    } else {
        Some((segment, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_nested_required_types_ranges_and_formats() {
        let schema = json!({
            "validation_schema": {
                "user.email": {"required": true, "type": "string", "format": "email"},
                "scores[0]": {"required": true, "type": "number", "min": 1}
            }
        });
        assert!(
            validate_json(
                &json!({"user": {"email": "a@b.com"}, "scores": [2]}),
                &schema
            )
            .is_ok()
        );
        assert!(validate_json(&json!({"user": {"email": "bad"}, "scores": [0]}), &schema).is_err());
    }

    #[test]
    fn invokes_registered_custom_validators_and_ignores_unknown_names() {
        let schema = json!({"code": {
            "type": "string",
            "custom_validator": "uppercase"
        }});
        let mut registry = ValidatorRegistry::default();
        registry.register("uppercase", |value, _rules| {
            if value
                .as_str()
                .is_some_and(|text| text == text.to_uppercase())
            {
                Ok(())
            } else {
                Err("Not upper".to_owned())
            }
        });
        assert!(validate_json_with_registry(&json!({"code": "ABC"}), &schema, &registry).is_ok());
        assert_eq!(
            validate_json_with_registry(&json!({"code": "Abc"}), &schema, &registry).unwrap_err(),
            "Not upper"
        );

        let unknown = json!({"code": {"custom_validator": "not_compiled"}});
        assert!(
            validate_json_with_registry(&json!({"code": "anything"}), &unknown, &registry).is_ok()
        );
    }

    #[test]
    fn matches_python_nested_array_enum_and_schema_validation_cases() {
        let nested = json!({
            "validation_schema": {
                "user": {
                    "required": true,
                    "type": "object",
                    "nested_schema": {
                        "name": {"required": true, "type": "string", "min": 2}
                    }
                }
            }
        });
        assert!(validate_json(&json!({"user": {"name": "John"}}), &nested).is_ok());

        let edge_cases = json!({"validation_schema": {
            "user.email": {"required": true, "type": "string", "format": "email"},
            "items": {
                "required": true,
                "type": "array",
                "min": 1,
                "array_items": {
                    "type": "object",
                    "nested_schema": {
                        "id": {"required": true, "type": "string", "format": "uuid"},
                        "quantity": {"required": true, "type": "number", "min": 1}
                    }
                }
            }
        }});
        assert!(validate_json(
            &json!({"user": {"email": "not-an-email"}, "items": [{"id": "123", "quantity": 0}]}),
            &edge_cases
        )
        .is_err());
        assert!(validate_json(
            &json!({"user": {"email": "u@example.com"}, "items": [{"id": "550e8400-e29b-41d4-a716-446655440000", "quantity": 2}]}),
            &edge_cases
        )
        .is_ok());

        let array = json!({"validation_schema": {"tags": {
            "required": true,
            "type": "array",
            "min": 1,
            "array_items": {"required": true, "type": "string", "min": 2}
        }}});
        assert!(validate_json(&json!({"tags": ["ab", "cd"]}), &array).is_ok());
        assert!(validate_json(&json!({"tags": [1, 2]}), &array).is_err());

        let required = json!({"validation_schema": {"profile.age": {
            "required": true,
            "type": "number"
        }}});
        assert!(validate_json(&json!({"profile": {}}), &required).is_err());

        let enum_schema = json!({"validation_schema": {"status": {
            "required": true,
            "type": "string",
            "enum": ["NEW", "OPEN"]
        }}});
        assert!(validate_json(&json!({"status": "OPEN"}), &enum_schema).is_ok());
        assert!(validate_json(&json!({"status": "CLOSED"}), &enum_schema).is_err());

        let custom = json!({"validation_schema": {"code": {
            "required": true,
            "type": "string",
            "custom_validator": "uppercase"
        }}});
        let mut registry = ValidatorRegistry::default();
        registry.register("uppercase", |value, _rules| {
            value
                .as_str()
                .is_some_and(|value| value == value.to_uppercase())
                .then_some(())
                .ok_or_else(|| "Not upper".to_owned())
        });
        assert!(validate_json_with_registry(&json!({"code": "ABC"}), &custom, &registry).is_ok());
        assert!(validate_json_with_registry(&json!({"code": "Abc"}), &custom, &registry).is_err());

        let invalid_path = json!({"validation_schema": {"user..name": {
            "required": true,
            "type": "string"
        }}});
        assert!(validate_json(&json!({"user": {"name": "ok"}}), &invalid_path).is_err());
    }

    #[test]
    fn preserves_python_validation_messages_and_coercion_edges() {
        assert_eq!(
            validate_json(
                &json!({}),
                &json!({"name": {"required": true, "type": "string"}})
            )
            .unwrap_err(),
            "Field is required"
        );
        assert_eq!(
            validate_json(&json!({"name": 1}), &json!({"name": {"type": "string"}})).unwrap_err(),
            "Expected string, got int"
        );
        assert!(
            validate_json(
                &json!({"enabled": true}),
                &json!({"enabled": {"type": "number", "min": 1}})
            )
            .is_ok()
        );
        assert_eq!(
            validate_json(
                &json!({"code": "xxABC"}),
                &json!({"code": {"type": "string", "pattern": "ABC"}})
            )
            .unwrap_err(),
            "String does not match pattern ABC"
        );
        assert_eq!(
            validate_json(
                &json!({"when": "2025-02-30"}),
                &json!({"when": {"type": "string", "format": "date"}})
            )
            .unwrap_err(),
            "Invalid date format (YYYY-MM-DD)"
        );
        assert_eq!(
            validate_json(
                &json!({"status": "CLOSED"}),
                &json!({"status": {"enum": ["NEW", "OPEN"]}})
            )
            .unwrap_err(),
            "Value must be one of ['NEW', 'OPEN']"
        );
    }
}
