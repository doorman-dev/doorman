//! Safe SOAP body conversion used by endpoint validation.

use quick_xml::{Reader, events::Event};
use serde_json::{Map, Value};

#[derive(Debug)]
struct Node {
    name: String,
    text: Option<String>,
    children: Vec<Node>,
}

pub fn soap_body_object(xml: &str) -> Result<Value, String> {
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err("XML DTD/entities are not allowed".to_owned());
    }
    let root = parse(xml)?;
    let body = find_named(&root, "Body").ok_or_else(|| "SOAP Body not found".to_owned())?;
    let operation = body
        .children
        .first()
        .ok_or_else(|| "SOAP Body not found".to_owned())?;
    Ok(Value::Object(children_to_object(operation)))
}

fn parse(xml: &str) -> Result<Node, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<Node>::new();
    let mut root = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => stack.push(Node {
                name: local_name(event.name().as_ref()),
                text: None,
                children: Vec::new(),
            }),
            Ok(Event::Empty(event)) => {
                let node = Node {
                    name: local_name(event.name().as_ref()),
                    text: None,
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            }
            Ok(Event::Text(event)) => {
                if let Some(node) = stack.last_mut() {
                    let text = event
                        .decode()
                        .map_err(|_| "Invalid SOAP envelope".to_owned())?;
                    node.text.get_or_insert_with(String::new).push_str(&text);
                }
            }
            Ok(Event::CData(event)) => {
                if let Some(node) = stack.last_mut() {
                    let text = event
                        .decode()
                        .map_err(|_| "Invalid SOAP envelope".to_owned())?;
                    node.text.get_or_insert_with(String::new).push_str(&text);
                }
            }
            Ok(Event::GeneralRef(event)) => {
                if let Some(node) = stack.last_mut() {
                    let resolved = match event
                        .resolve_char_ref()
                        .map_err(|_| "Invalid SOAP envelope".to_owned())?
                    {
                        Some(character) => character,
                        None => match event
                            .decode()
                            .map_err(|_| "Invalid SOAP envelope".to_owned())?
                            .as_ref()
                        {
                            "lt" => '<',
                            "gt" => '>',
                            "amp" => '&',
                            "apos" => '\'',
                            "quot" => '"',
                            _ => return Err("Invalid SOAP envelope".to_owned()),
                        },
                    };
                    node.text.get_or_insert_with(String::new).push(resolved);
                }
            }
            Ok(Event::End(_)) => {
                let node = stack
                    .pop()
                    .ok_or_else(|| "Invalid SOAP envelope".to_owned())?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            }
            Ok(Event::DocType(_)) => return Err("XML DTD/entities are not allowed".to_owned()),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err("Invalid SOAP envelope".to_owned()),
        }
    }
    if !stack.is_empty() {
        return Err("Invalid SOAP envelope".to_owned());
    }
    root.ok_or_else(|| "Invalid SOAP envelope".to_owned())
}

fn local_name(name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    name.rsplit(':').next().unwrap_or(&name).to_owned()
}

fn find_named<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    if node.name == name {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_named(child, name))
}

fn children_to_object(node: &Node) -> Map<String, Value> {
    let mut output = Map::new();
    for child in &node.children {
        let value = if child.children.is_empty() {
            child
                .text
                .as_ref()
                .map_or(Value::Null, |text| Value::String(text.clone()))
        } else {
            Value::Object(children_to_object(child))
        };
        // Python's legacy converter overwrites duplicate sibling names.
        output.insert(child.name.clone(), value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_first_soap_body_operation_for_legacy_contract() {
        let xml = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Create><user><name>Ada</name></user></Create></soap:Body></soap:Envelope>"#;
        assert_eq!(
            soap_body_object(xml).unwrap(),
            serde_json::json!({"user": {"name": "Ada"}})
        );
    }

    #[test]
    fn preserves_leaf_text_exactly_like_element_tree() {
        let xml = r#"<E xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><Op><a> x &amp; y &#65;<![CDATA[<z>]]> </a><b> </b><c></c><d/><e>1</e><e>2</e></Op></s:Body></E>"#;
        assert_eq!(
            soap_body_object(xml).unwrap(),
            serde_json::json!({"a": " x & y A<z> ", "b": " ", "c": null, "d": null, "e": "2"})
        );
    }

    #[test]
    fn rejects_dtd_and_missing_bodies_when_validation_is_enabled() {
        assert!(soap_body_object("<!DOCTYPE x><x/>").is_err());
        assert!(soap_body_object("<Envelope/>").is_err());
    }

    #[test]
    fn validates_structural_soap_fields_without_a_wsdl_like_python() {
        let xml = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><CreateUser><username>alice</username><email>alice@example.com</email></CreateUser></soap:Body></soap:Envelope>"#;
        let document = soap_body_object(xml).unwrap();
        let schema = serde_json::json!({
            "username": {"required": true, "type": "string", "min": 3, "max": 50},
            "email": {"required": true, "type": "string", "format": "email"},
        });
        assert!(crate::validation::json::validate_json(&document, &schema).is_ok());

        let missing_username = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><CreateUser><email>no-user@example.com</email></CreateUser></soap:Body></soap:Envelope>"#;
        let document = soap_body_object(missing_username).unwrap();
        assert!(crate::validation::json::validate_json(&document, &schema).is_err());
    }
}
