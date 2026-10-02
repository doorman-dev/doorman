use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::Value;

#[derive(Clone, Debug, Default)]
pub struct TransformConfig {
    pub request: Option<Value>,
    pub response: Option<Value>,
}

pub fn transform_request(
    headers: HeaderMap,
    body: Vec<u8>,
    query: Option<&str>,
    config: Option<&Value>,
) -> (HeaderMap, Vec<u8>, String) {
    let Some(config) = config else {
        return (headers, body, query.unwrap_or_default().to_owned());
    };
    let direction = config.get("request").unwrap_or(config);
    let headers = transform_headers(headers, direction.get("headers"));
    let body = transform_body_bytes(body, direction.get("body"));
    let query = transform_query(query, direction.get("query"));
    (headers, body, query)
}

pub fn transform_response(
    headers: HeaderMap,
    body: Vec<u8>,
    status: StatusCode,
    config: Option<&Value>,
) -> (HeaderMap, Vec<u8>, StatusCode) {
    let Some(config) = config else {
        return (headers, body, status);
    };
    let direction = config.get("response").unwrap_or(config);
    let headers = transform_headers(headers, direction.get("headers"));
    let body = transform_body_bytes(body, direction.get("body"));
    let status = direction
        .get("status_map")
        .and_then(|mapping| mapping.get(status.as_u16().to_string()))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .and_then(|value| u16::try_from(value).ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .unwrap_or(status);
    (headers, body, status)
}

fn transform_headers(mut headers: HeaderMap, config: Option<&Value>) -> HeaderMap {
    let Some(config) = config else {
        return headers;
    };
    if let Some(remove) = config.get("remove").and_then(Value::as_array) {
        for name in remove.iter().filter_map(Value::as_str) {
            if let Ok(name) = HeaderName::try_from(name) {
                headers.remove(name);
            }
        }
    }
    if let Some(rename) = config.get("rename").and_then(Value::as_object) {
        for (old, new) in rename {
            let Some(new) = new.as_str() else { continue };
            let (Ok(old), Ok(new)) = (HeaderName::try_from(old), HeaderName::try_from(new)) else {
                continue;
            };
            if let Some(value) = headers.remove(old) {
                headers.insert(new, value);
            }
        }
    }
    if let Some(add) = config.get("add").and_then(Value::as_object) {
        for (name, value) in add {
            let (Ok(name), Ok(value)) = (
                HeaderName::try_from(name),
                HeaderValue::from_str(&python_string(value)),
            ) else {
                continue;
            };
            headers.insert(name, value);
        }
    }
    headers
}

fn transform_body_bytes(body: Vec<u8>, config: Option<&Value>) -> Vec<u8> {
    let Some(config) = config else {
        return body;
    };
    let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
        return body;
    };
    if let Some(key) = config.get("wrap").and_then(Value::as_str) {
        value = serde_json::json!({ key: value });
    }
    if let Some(remove) = config.get("remove").and_then(Value::as_array) {
        for path in remove.iter().filter_map(Value::as_str) {
            remove_path(&mut value, path);
        }
    }
    if let Some(rename) = config.get("rename").and_then(Value::as_object) {
        for (old, new) in rename {
            if let Some(new) = new.as_str() {
                if let Some(found) = take_path(&mut value, old) {
                    set_path(&mut value, new, found);
                }
            }
        }
    }
    if let Some(set) = config.get("set").and_then(Value::as_object) {
        for (path, replacement) in set {
            set_path(&mut value, path, replacement.clone());
        }
    }
    serde_json::to_vec(&value).unwrap_or(body)
}

fn transform_query(query: Option<&str>, config: Option<&Value>) -> String {
    let mut pairs = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .into_owned()
        .collect::<Vec<_>>();
    let Some(config) = config else {
        return encode_query(&pairs);
    };
    if let Some(remove) = config.get("remove").and_then(Value::as_array) {
        let names = remove.iter().filter_map(Value::as_str).collect::<Vec<_>>();
        pairs.retain(|(name, _)| !names.iter().any(|removed| removed == name));
    }
    if let Some(rename) = config.get("rename").and_then(Value::as_object) {
        for (name, _) in &mut pairs {
            if let Some(new) = rename.get(name.as_str()).and_then(Value::as_str) {
                *name = new.to_owned();
            }
        }
    }
    if let Some(add) = config.get("add").and_then(Value::as_object) {
        for (name, value) in add {
            pairs.retain(|(existing, _)| existing != name);
            pairs.push((name.clone(), python_string(value)));
        }
    }
    encode_query(&pairs)
}

fn python_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        value => value.to_string(),
    }
}

fn encode_query(pairs: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(pairs.iter().map(|(key, value)| (key, value)));
    serializer.finish()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathPart {
    field: String,
    index: Option<usize>,
}

fn path_parts(path: &str) -> Option<Vec<PathPart>> {
    // Python: only "$." prefixed paths; each segment is either `word[digits]` or a plain key.
    let path = path.strip_prefix("$.")?;
    let mut parts = Vec::new();
    for raw in path.split('.') {
        if raw.is_empty() {
            continue;
        }
        let indexed = raw.strip_suffix(']').and_then(|head| {
            let (field, digits) = head.split_once('[')?;
            let word = !field.is_empty()
                && field
                    .chars()
                    .all(|character| character.is_alphanumeric() || character == '_');
            let numeric = !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit());
            (word && numeric).then_some((field, digits))
        });
        match indexed {
            Some((field, digits)) => parts.push(PathPart {
                field: field.to_owned(),
                index: Some(digits.parse().ok()?),
            }),
            None => parts.push(PathPart {
                field: raw.to_owned(),
                index: None,
            }),
        }
    }
    (!parts.is_empty()).then_some(parts)
}

fn set_path(root: &mut Value, path: &str, replacement: Value) {
    let Some(parts) = path_parts(path) else {
        return;
    };
    let Some((last, parents)) = parts.split_last() else {
        return;
    };
    let mut current = root;
    for part in parents {
        if !current.is_object() {
            return;
        }
        let child = current
            .as_object_mut()
            .expect("checked above")
            .entry(part.field.clone())
            .or_insert_with(|| {
                if part.index.is_some() {
                    serde_json::json!([])
                } else {
                    serde_json::json!({})
                }
            });
        if let Some(index) = part.index {
            if !child.is_array() {
                *child = serde_json::json!([]);
            }
            let array = child.as_array_mut().expect("array created above");
            while array.len() <= index {
                array.push(serde_json::json!({}));
            }
            if !array[index].is_object() {
                array[index] = serde_json::json!({});
            }
            current = &mut array[index];
        } else {
            if !child.is_object() {
                *child = serde_json::json!({});
            }
            current = child;
        }
    }
    if let Some(object) = current.as_object_mut() {
        if let Some(index) = last.index {
            let target = object
                .entry(last.field.clone())
                .or_insert_with(|| serde_json::json!([]));
            if !target.is_array() {
                *target = serde_json::json!([]);
            }
            let array = target.as_array_mut().expect("array created above");
            while array.len() <= index {
                array.push(Value::Null);
            }
            array[index] = replacement;
        } else {
            object.insert(last.field.clone(), replacement);
        }
    }
}

fn remove_path(root: &mut Value, path: &str) {
    let _ = take_path(root, path);
}

fn take_path(root: &mut Value, path: &str) -> Option<Value> {
    let parts = path_parts(path)?;
    let (last, parents) = parts.split_last()?;
    let mut current = root;
    for part in parents {
        current = current.get_mut(&part.field)?;
        if let Some(index) = part.index {
            current = current.as_array_mut()?.get_mut(index)?;
        }
    }
    if let Some(index) = last.index {
        let target = current.get_mut(&last.field)?.as_array_mut()?;
        (index < target.len()).then(|| target.remove(index))
    } else {
        current.as_object_mut()?.remove(&last.field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transforms_json_body_query_and_status() {
        let config = serde_json::json!({"request": {
            "body": {"set": {"$.source": "doorman"}},
            "query": {"rename": {"old": "new"}}
        }});
        let (_, body, query) = transform_request(
            HeaderMap::new(),
            br#"{"name":"Ada"}"#.to_vec(),
            Some("old=1"),
            Some(&config),
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["source"],
            "doorman"
        );
        assert_eq!(query, "new=1");

        let config = serde_json::json!({"response": {"status_map": {"500": 502}}});
        let (_, _, status) = transform_response(
            HeaderMap::new(),
            Vec::new(),
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(&config),
        );
        assert_eq!(status, StatusCode::BAD_GATEWAY);

        let config = serde_json::json!({"request": {
            "headers": {"add": {"x-enabled": true, "x-empty": null}},
            "query": {"add": {"enabled": false}}
        }});
        let (headers, _, query) =
            transform_request(HeaderMap::new(), Vec::new(), None, Some(&config));
        assert_eq!(headers["x-enabled"], "True");
        assert_eq!(headers["x-empty"], "None");
        assert_eq!(query, "enabled=False");

        let config = serde_json::json!({"response": {"status_map": {"500": "502"}}});
        let (_, _, status) = transform_response(
            HeaderMap::new(),
            Vec::new(),
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(&config),
        );
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn transforms_array_paths_like_the_python_gateway() {
        let config = serde_json::json!({"request": {"body": {
            "remove": ["$.items[0].secret"],
            "rename": {"$.items[0].old": "$.items[1].renamed"},
            "set": {"$.items[2].created": true, "$.tags[1]": "new"}
        }}});
        let (_, body, _) = transform_request(
            HeaderMap::new(),
            br#"{"items":[{"secret":1,"old":"value"}],"tags":["old"]}"#.to_vec(),
            None,
            Some(&config),
        );
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value["items"][0].get("secret").is_none());
        assert_eq!(value["items"][1]["renamed"], "value");
        assert_eq!(value["items"][2]["created"], true);
        assert_eq!(value["tags"], serde_json::json!(["old", "new"]));
    }

    #[test]
    fn jsonpath_segments_accept_any_plain_key_like_python() {
        let config = serde_json::json!({"request": {"body": {
            "remove": ["$.a-b"],
            "set": {"$.first-name": "x", "$.p q.r": 1},
            "rename": {"$.old key": "$.new-key"}
        }}});
        let (_, body, _) = transform_request(
            HeaderMap::new(),
            br#"{"a-b":1,"old key":"v"}"#.to_vec(),
            None,
            Some(&config),
        );
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value.get("a-b").is_none());
        assert_eq!(value["first-name"], "x");
        assert_eq!(value["p q"]["r"], 1);
        assert_eq!(value["new-key"], "v");
        assert!(value.get("old key").is_none());
    }
}
