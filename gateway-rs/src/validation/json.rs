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
    if let Some(text) = value.as_str().filter(|_| expected == "string") {
        let length = text.chars().count() as f64;
        enforce_range(length, rules, "String length", "", "")?;
        if let Some(pattern) = rules.get("pattern").and_then(Value::as_str) {
            let regex = cached_pattern(pattern)
                .ok_or_else(|| format!("Invalid validation pattern for {path}"))?;
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
        .filter(|_| expected == "number")
    {
        enforce_range(number, rules, "Value", "", "")?;
    }
    if let Some(items) = value.as_array().filter(|_| expected == "array") {
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
        value.as_object().filter(|_| expected == "object"),
        rules.get("nested_schema").and_then(Value::as_object),
    ) {
        for (field, nested_rules) in nested {
            if nested_rules
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && !object.contains_key(field)
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
    if let Some(allowed) = rules
        .get("enum")
        .and_then(Value::as_array)
        .filter(|allowed| !allowed.is_empty())
    {
        if !allowed.iter().any(|candidate| python_eq(candidate, value)) {
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

/// Endpoint validation schemas supply their own patterns; compile each once.
/// The cache is bounded so arbitrary schema churn cannot grow it without limit.
pub(crate) fn cached_pattern(pattern: &str) -> Option<Regex> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Regex>>> =
        std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().ok()?;
    if let Some(regex) = cache.get(pattern) {
        return Some(regex.clone());
    }
    let regex = Regex::new(pattern).ok()?;
    if cache.len() >= 1024 {
        cache.clear();
    }
    cache.insert(pattern.to_owned(), regex.clone());
    Some(regex)
}

fn validate_format(value: &str, format: &str, path: &str) -> Result<(), String> {
    // Python's `$` also matches before one trailing newline.
    let pattern_value = value.strip_suffix('\n').unwrap_or(value);
    let valid = match format {
        "email" => {
            static EMAIL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                    .expect("email expression is valid")
            });
            EMAIL.is_match(pattern_value)
        }
        "url" => {
            static URL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(
                    r"^https?://(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_+.~#?&/=]*$",
                )
                .expect("url expression is valid")
            });
            URL.is_match(pattern_value)
        }
        "date" => valid_date(value),
        "datetime" => valid_datetime(value),
        "uuid" => valid_uuid(value),
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

/// `datetime.strptime(value, '%Y-%m-%d')`: unpadded month/day are accepted.
fn valid_date(value: &str) -> bool {
    static DATE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^([0-9]{4})-(1[0-2]|0[1-9]|[1-9])-(3[0-1]|[1-2][0-9]|0[1-9]|[1-9]| [1-9])$")
            .expect("date expression is valid")
    });
    let Some(parts) = DATE.captures(value) else {
        return false;
    };
    let year: i32 = parts[1].parse().unwrap_or(0);
    let month: u8 = parts[2].parse().unwrap_or(0);
    let day: u8 = parts[3].trim().parse().unwrap_or(0);
    year >= 1
        && time::Month::try_from(month)
            .ok()
            .and_then(|month| time::Date::from_calendar_date(year, month, day).ok())
            .is_some()
}

/// `uuid.UUID(value)`: strips `urn:`/`uuid:`, braces and hyphens, then needs 32 hex digits.
fn valid_uuid(value: &str) -> bool {
    let hex = value
        .replace("urn:", "")
        .replace("uuid:", "")
        .trim_matches(|c| c == '{' || c == '}')
        .replace('-', "");
    hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `datetime.fromisoformat(value.replace('Z', '+00:00'))` (Python 3.11+ grammar):
/// extended or basic dates, ISO week dates, any single-character separator, optional
/// `HH[:MM[:SS[.f]]]` time, and an optional `±HH[:MM[:SS[.f]]]` offset.
fn valid_datetime(value: &str) -> bool {
    static DATE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"^(?:(\d{4})-(\d{2})-(\d{2})|(\d{4})(\d{2})(\d{2})|(\d{4})-W(\d{2})(?:-(\d))?|(\d{4})W(\d{2})(\d)?)",
        )
        .expect("static date pattern")
    });
    static TIME: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"^(\d{2})(?:(?::(\d{2})(?::(\d{2})(?:[.,]\d+)?)?)|(?:(\d{2})(?:(\d{2})(?:[.,]\d+)?)?))?(?:[+-](\d{2})(?::?(\d{2})(?::?(\d{2})(?:[.,]\d+)?)?)?)?$",
        )
        .expect("static time pattern")
    });
    let value = value.replace('Z', "+00:00");
    let Some(captures) = DATE.captures(&value) else {
        return false;
    };
    let number = |index: usize| {
        captures
            .get(index)
            .map(|m| m.as_str().parse::<i32>().unwrap())
    };
    let calendar = if number(1).is_some() {
        (number(1), number(2), number(3))
    } else {
        (number(4), number(5), number(6))
    };
    let date_ok = if let (Some(y), Some(m), Some(d)) = calendar {
        u8::try_from(m)
            .ok()
            .and_then(|m| time::Month::try_from(m).ok())
            .zip(u8::try_from(d).ok())
            .is_some_and(|(m, d)| time::Date::from_calendar_date(y, m, d).is_ok())
    } else {
        let (year, week, day) = if number(7).is_some() {
            (number(7), number(8), number(9))
        } else {
            (number(10), number(11), number(12))
        };
        match (year, week, u8::try_from(day.unwrap_or(1)).ok()) {
            (Some(y), Some(w), Some(d)) => {
                let weekday = match d {
                    1 => Some(time::Weekday::Monday),
                    2 => Some(time::Weekday::Tuesday),
                    3 => Some(time::Weekday::Wednesday),
                    4 => Some(time::Weekday::Thursday),
                    5 => Some(time::Weekday::Friday),
                    6 => Some(time::Weekday::Saturday),
                    7 => Some(time::Weekday::Sunday),
                    _ => None,
                };
                u8::try_from(w)
                    .ok()
                    .zip(weekday)
                    .is_some_and(|(w, wd)| time::Date::from_iso_week_date(y, w, wd).is_ok())
            }
            _ => false,
        }
    };
    if !date_ok {
        return false;
    }
    let rest = &value[captures.get(0).unwrap().end()..];
    let mut chars = rest.chars();
    if chars.next().is_none() {
        return true;
    }
    let time_part = chars.as_str();
    let Some(time) = TIME.captures(time_part) else {
        return false;
    };
    let field = |index: usize| time.get(index).map(|m| m.as_str().parse::<u32>().unwrap());
    let hour = field(1).unwrap();
    let minute = field(2).or(field(4)).unwrap_or(0);
    let second = field(3).or(field(5)).unwrap_or(0);
    hour < 24
        && minute < 60
        && second < 60
        && field(6).is_none_or(|h| h < 24)
        && field(7).is_none_or(|m| m < 60)
        && field(8).is_none_or(|s| s < 60)
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
        .map(python_repr)
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn python_repr(value: &Value) -> String {
    match value {
        Value::String(text) => {
            let quote = if text.contains('\'') && !text.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = String::from(quote);
            for character in text.chars() {
                match character {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c => out.push(c),
                }
            }
            out.push(quote);
            out
        }
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        Value::Array(items) => python_list_repr(items),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, value)| format!(
                    "{}: {}",
                    python_repr(&Value::String(key.clone())),
                    python_repr(value)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        number => number.to_string(),
    }
}

/// Python `==` semantics for JSON-shaped values: `1 == 1.0 == True`.
fn python_eq(left: &Value, right: &Value) -> bool {
    let numeric = |value: &Value| match value {
        Value::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        Value::Number(number) => number.as_f64(),
        _ => None,
    };
    if let (Some(a), Some(b)) = (numeric(left), numeric(right)) {
        return a == b;
    }
    match (left, right) {
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| python_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| python_eq(value, other)))
        }
        _ => left == right,
    }
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
                    field.is_empty() && !is_ascii_digits(index.trim_end_matches(']'))
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

fn is_ascii_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn nested_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        let (field, index) = parse_segment(segment)?;
        if !field.is_empty() {
            current = current.get(field)?;
        }
        if let Some(index) = index {
            let items = current.as_array()?;
            // Python indexes from the end for negative values.
            let index = if index < 0 {
                items.len().checked_sub(index.unsigned_abs() as usize)?
            } else {
                index as usize
            };
            current = items.get(index)?;
        }
    }
    Some(current)
}

fn parse_segment(segment: &str) -> Option<(&str, Option<i64>)> {
    if let Some((field, raw_index)) = segment.split_once('[') {
        let index = raw_index.trim_end_matches(']').parse().ok()?;
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

    #[test]
    fn python_edge_cases_for_paths_types_enums_and_formats() {
        let ok = |doc: Value, schema: Value| validate_json(&doc, &schema);
        // Invalid schema paths: empty index, multiple closing brackets are fine.
        for (path, valid) in [
            ("[", false),
            ("[]", false),
            ("[0]", true),
            ("[0]]", true),
            ("a[x]", true),
            ("a..b", false),
        ] {
            let schema = json!({ path: {"type": "string"} });
            assert_eq!(
                validate_schema_paths(schema.as_object().unwrap(), "").is_ok(),
                valid,
                "{path}"
            );
        }
        // Present-but-null nested field: "Field is required", not "is missing".
        let nested = json!({"o": {"type": "object", "nested_schema": {"k": {"type": "string", "required": true}}}});
        assert_eq!(
            ok(json!({"o": {"k": null}}), nested.clone()).unwrap_err(),
            "Field is required"
        );
        assert_eq!(
            ok(json!({"o": {}}), nested).unwrap_err(),
            "Required field k is missing"
        );
        // Negative indexes read from the end.
        let idx = json!({"a[-1]": {"type": "number", "min": 5}});
        assert!(ok(json!({"a": [1, 9]}), idx.clone()).is_ok());
        assert_eq!(
            ok(json!({"a": [9, 1]}), idx).unwrap_err(),
            "Value must be at least 5"
        );
        // Empty enum is ignored; 1 == 1.0 == True; repr of nested values.
        assert!(
            ok(
                json!({"x": "q"}),
                json!({"x": {"type": "string", "enum": []}})
            )
            .is_ok()
        );
        assert!(
            ok(
                json!({"x": 1.0}),
                json!({"x": {"type": "number", "enum": [1]}})
            )
            .is_ok()
        );
        assert_eq!(
            ok(
                json!({"x": "z"}),
                json!({"x": {"type": "string", "enum": ["a", "it's", 2, true, null]}})
            )
            .unwrap_err(),
            "Value must be one of ['a', \"it's\", 2, True, None]"
        );
        // Constraints only apply for the declared type.
        assert!(
            ok(
                json!({"x": "ab"}),
                json!({"x": {"type": "other", "min": 5}})
            )
            .is_ok()
        );
        // strptime-style dates, permissive UUID normalisation, trailing newline in `$` formats.
        for (format, value, valid) in [
            ("date", "2024-1-5", true),
            ("date", "2024-02-30", false),
            ("date", "2024-02-29", true),
            ("date", "2023-02-29", false),
            ("date", "2024-01-05T00:00", false),
            ("date", "0000-01-01", false),
            ("uuid", "12345678123456781234567812345678", true),
            ("uuid", "{12345678-1234-5678-1234-567812345678}", true),
            (
                "uuid",
                "urn:uuid:12345678-1234-5678-1234-567812345678",
                true,
            ),
            ("uuid", "1234-5678", false),
            ("uuid", "1234567-8123-4567-8123-4567812345678", true),
            ("datetime", "2024-1-5", false),
            ("datetime", "2024-01-05", true),
            ("datetime", "2024-01-05T10", true),
            ("datetime", "2024-01-05 10:30:15.123456789", true),
            ("datetime", "20240105T103015", true),
            ("datetime", "2024-W01-1T10:00", true),
            ("datetime", "2024W011", true),
            ("datetime", "2024-01-05T10:00:00Z", true),
            ("datetime", "2024-01-05T10:00:00+0530", true),
            ("datetime", "2024-01-05T10:00:00,5", true),
            ("datetime", "2024-01-05*10:00", true),
            ("datetime", "2024-13-01", false),
            ("datetime", "2024-02-30", false),
            ("datetime", "2024-01-05T24:00", false),
            ("datetime", "2024-01-05T10:60", false),
            ("datetime", "2024-01-05T", false),
            ("datetime", "2024-01-05T10:00+24:00", false),
            ("datetime", "2024-01-05T10:0000", false),
            ("datetime", "10:00", false),
            ("email", "a@b.com\n", true),
            ("email", "a@b.com\n\n", false),
        ] {
            let schema = json!({"v": {"type": "string", "format": format}});
            assert_eq!(
                ok(json!({"v": value}), schema).is_ok(),
                valid,
                "{format} {value:?}"
            );
        }
    }
}
