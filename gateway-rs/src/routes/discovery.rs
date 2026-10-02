use quick_xml::{Reader, events::BytesStart, events::Event};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

pub fn parse_openapi(spec: &Value) -> Result<Value, String> {
    let Some(_root) = spec.as_object() else {
        return Err("Invalid OpenAPI spec".to_owned());
    };
    let endpoints = openapi_endpoints(spec);
    Ok(json!({
        "title": spec.pointer("/info/title").and_then(Value::as_str).unwrap_or("Unknown"),
        "version": spec.pointer("/info/version").and_then(Value::as_str).unwrap_or("Unknown"),
        "endpoints_count": endpoints.len(),
        "endpoints": endpoints,
    }))
}

pub fn openapi_endpoints(spec: &Value) -> Vec<Value> {
    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut endpoints = Vec::new();
    for (uri, methods) in paths {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (method, details) in methods {
            let method = method.to_ascii_uppercase();
            if !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                .contains(&method.as_str())
            {
                continue;
            }
            let details = details.as_object().cloned().unwrap_or_default();
            let description = details
                .get("summary")
                .or_else(|| details.get("description"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let parameters = details
                .get("parameters")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|parameter| {
                            json!({
                                "name": parameter.get("name").cloned().unwrap_or(Value::Null),
                                "in": parameter.get("in").cloned().unwrap_or(Value::Null),
                                "required": parameter.get("required").and_then(Value::as_bool).unwrap_or(false),
                                "type": parameter.pointer("/schema/type").and_then(Value::as_str).unwrap_or("string"),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let request_body = details
                .get("requestBody")
                .and_then(|body| body.get("content"))
                .and_then(Value::as_object)
                .and_then(|content| content.iter().next())
                .map(|(content_type, media)| {
                    json!({
                        "content_type": content_type,
                        "schema": media.get("schema").cloned().unwrap_or_else(|| json!({})),
                    })
                })
                .unwrap_or(Value::Null);
            let responses = details
                .get("responses")
                .and_then(Value::as_object)
                .map(|responses| {
                    responses
                        .iter()
                        .map(|(status, response)| {
                            (
                                status.clone(),
                                json!({"description": response.get("description").and_then(Value::as_str).unwrap_or("") }),
                            )
                        })
                        .collect::<Map<String, Value>>()
                })
                .unwrap_or_default();
            endpoints.push(json!({
                "endpoint_uri": uri,
                "endpoint_method": method,
                "endpoint_description": description,
                "endpoint_tags": details.get("tags").cloned().unwrap_or_else(|| json!([])),
                "endpoint_parameters": parameters,
                "endpoint_request_body": request_body,
                "endpoint_responses": responses,
            }));
        }
    }
    endpoints
}

/// The pinned `validate_wsdl_content`: well-formed XML whose root is a WSDL
/// `definitions` element containing at least one service or portType.
pub fn validate_wsdl(content: &str) -> Result<(), String> {
    if content.trim().is_empty() {
        return Err("Empty WSDL content".to_owned());
    }
    let mut reader = Reader::from_str(content);
    let mut root: Option<Vec<u8>> = None;
    let mut has_service = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event)) => {
                if root.is_none() {
                    root = Some(event.name().as_ref().to_ascii_lowercase());
                }
                let local = event.local_name();
                has_service |= matches!(local.as_ref(), b"service" | b"portType");
            }
            Ok(Event::DocType(_)) => return Err("DTD declarations are not allowed".to_owned()),
            Ok(Event::Eof) => break,
            Err(error) => return Err(format!("Invalid XML: {error}")),
            _ => {}
        }
    }
    let Some(root) = root else {
        return Err("Invalid XML: no element found".to_owned());
    };
    if !String::from_utf8_lossy(&root).contains("definitions") {
        return Err("Root element must be wsdl:definitions".to_owned());
    }
    if !has_service {
        return Err("WSDL must contain at least one service or portType".to_owned());
    }
    Ok(())
}

pub fn parse_wsdl(content: &str) -> Result<Value, String> {
    let lowered = content.to_ascii_lowercase();
    if lowered.contains("<!doctype") || lowered.contains("<!entity") {
        return Err("DTD and entity declarations are not allowed".to_owned());
    }
    if content.trim().is_empty() {
        return Err("Empty WSDL content".to_owned());
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Section {
        None,
        PortType,
        Binding,
    }

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut section = Section::None;
    let mut service_name = String::new();
    let mut target_namespace = String::new();
    let mut operations = Vec::<Map<String, Value>>::new();
    let mut current_operation: Option<Map<String, Value>> = None;
    let mut binding_operation = String::new();
    let mut actions = HashMap::<String, String>::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let local = event.local_name();
                let name = local.as_ref();
                if name == b"definitions" {
                    target_namespace = attribute(&event, b"targetNamespace").unwrap_or_default();
                } else if name == b"service" && service_name.is_empty() {
                    service_name = attribute(&event, b"name").unwrap_or_default();
                } else if name == b"portType" {
                    section = Section::PortType;
                } else if name == b"binding" {
                    section = Section::Binding;
                } else if name == b"operation" {
                    if section == Section::PortType {
                        if let Some(operation_name) = attribute(&event, b"name") {
                            current_operation = Some(Map::from_iter([
                                ("name".to_owned(), Value::String(operation_name)),
                                ("soap_action".to_owned(), Value::String(String::new())),
                                ("input_message".to_owned(), Value::String(String::new())),
                                ("output_message".to_owned(), Value::String(String::new())),
                            ]));
                        }
                    } else if section == Section::Binding {
                        if let Some(action) = attribute(&event, b"soapAction") {
                            if !binding_operation.is_empty() {
                                actions.insert(binding_operation.clone(), action);
                            }
                        } else if let Some(operation_name) = attribute(&event, b"name") {
                            binding_operation = operation_name;
                        }
                    }
                } else if section == Section::PortType && (name == b"input" || name == b"output") {
                    if let (Some(operation), Some(message)) =
                        (current_operation.as_mut(), attribute(&event, b"message"))
                    {
                        let message = message.rsplit(":").next().unwrap_or(&message).to_owned();
                        operation.insert(
                            if name == b"input" {
                                "input_message"
                            } else {
                                "output_message"
                            }
                            .to_owned(),
                            Value::String(message),
                        );
                    }
                }
            }
            Ok(Event::Empty(event)) => {
                let local = event.local_name();
                let name = local.as_ref();
                if name == b"service" && service_name.is_empty() {
                    service_name = attribute(&event, b"name").unwrap_or_default();
                } else if section == Section::Binding && name == b"operation" {
                    if let Some(action) = attribute(&event, b"soapAction") {
                        if !binding_operation.is_empty() {
                            actions.insert(binding_operation.clone(), action);
                        }
                    }
                } else if section == Section::PortType && (name == b"input" || name == b"output") {
                    if let (Some(operation), Some(message)) =
                        (current_operation.as_mut(), attribute(&event, b"message"))
                    {
                        let message = message.rsplit(":").next().unwrap_or(&message).to_owned();
                        operation.insert(
                            if name == b"input" {
                                "input_message"
                            } else {
                                "output_message"
                            }
                            .to_owned(),
                            Value::String(message),
                        );
                    }
                }
            }
            Ok(Event::End(event)) => {
                let local = event.local_name();
                let name = local.as_ref();
                if name == b"operation" {
                    if section == Section::PortType {
                        if let Some(operation) = current_operation.take() {
                            operations.push(operation);
                        }
                    } else if section == Section::Binding {
                        binding_operation.clear();
                    }
                } else if name == b"portType" || name == b"binding" {
                    section = Section::None;
                }
            }
            Ok(Event::DocType(_)) => {
                return Err("DTD declarations are not allowed".to_owned());
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(format!("Invalid XML: {error}")),
            _ => {}
        }
    }

    for operation in &mut operations {
        if let Some(name) = operation.get("name").and_then(Value::as_str)
            && let Some(action) = actions.get(name)
        {
            operation.insert("soap_action".to_owned(), Value::String(action.clone()));
        }
    }
    let endpoints = operations
        .iter()
        .filter_map(|operation| {
            let name = operation.get("name")?.as_str()?;
            Some(json!({
                "uri": format!("/{name}"),
                "method": "POST",
                "soap_action": operation.get("soap_action").cloned().unwrap_or_else(|| Value::String(String::new())),
                "description": format!("SOAP operation: {name}"),
            }))
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "service_name": service_name,
        "target_namespace": target_namespace,
        "operations": operations,
        "endpoints": endpoints,
    }))
}

fn attribute(event: &BytesStart<'_>, name: &[u8]) -> Option<String> {
    event.attributes().flatten().find_map(|attribute| {
        (attribute.key.local_name().as_ref() == name)
            .then(|| String::from_utf8_lossy(attribute.value.as_ref()).into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::{openapi_endpoints, parse_wsdl};
    use serde_json::json;

    #[test]
    fn extracts_complete_openapi_endpoint_metadata() {
        let endpoints = openapi_endpoints(&json!({
            "paths": {"/pets": {"post": {
                "summary": "Create pet",
                "tags": ["pets"],
                "parameters": [{"name": "trace", "in": "header", "schema": {"type": "string"}}],
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"201": {"description": "created"}}
            }}}
        }));
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["endpoint_method"], "POST");
        assert_eq!(
            endpoints[0]["endpoint_request_body"]["content_type"],
            "application/json"
        );
    }

    #[test]
    fn parses_wsdl_operations_and_rejects_doctypes() {
        let wsdl = r#"<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" targetNamespace="urn:test"><service name="Billing"/><portType name="BillingPort"><operation name="Charge"><input message="tns:ChargeRequest"/><output message="tns:ChargeResponse"/></operation></portType><binding name="BillingBinding"><operation name="Charge"><soap:operation soapAction="urn:charge"/></operation></binding></definitions>"#;
        let parsed = parse_wsdl(wsdl).unwrap();
        assert_eq!(parsed["service_name"], "Billing");
        assert_eq!(parsed["operations"][0]["soap_action"], "urn:charge");
        assert_eq!(parsed["endpoints"][0]["uri"], "/Charge");
        assert!(parse_wsdl("<!DOCTYPE x><definitions/>").is_err());
    }
}
