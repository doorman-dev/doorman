use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    response::{IntoResponse, Response},
};
use base64::Engine;
use http::{StatusCode, header};
use prost::Message;
use regex::Regex;
use serde_json::Value;

use crate::{
    error::GatewayError,
    middleware::body_limit::BodyLimits,
    policy::{PolicyDecision, PolicyErrorBody},
    routes::rest::{DataPlaneProtocol, graphql_depth, valid_collection_name, validate_crud_schema},
    state::AppState,
    storage::runtime::StorageError,
};

#[derive(Clone, PartialEq, Message)]
struct CrudGrpcRequest {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    input: String,
}

#[derive(Clone, PartialEq, Message)]
struct CrudGrpcReply {
    #[prost(string, tag = "1")]
    result: String,
    #[prost(bool, tag = "2")]
    ok: bool,
}

pub async fn execute(
    state: &AppState,
    request: Request,
    decision: &PolicyDecision,
    protocol: DataPlaneProtocol,
) -> Result<Response, GatewayError> {
    if state.storage.is_none() {
        return Ok(policy_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "GTW006",
            "Gateway state store unavailable",
        ));
    }
    let query = request.uri().query().unwrap_or_default().to_owned();
    let request_path = request.uri().path().to_owned();
    let is_get = request.method() == http::Method::GET;
    let grpc_web_target = request
        .extensions()
        .get::<crate::routes::grpc_web::GrpcWebTarget>()
        .cloned();
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (_, body) = request.into_parts();
    let limit = match protocol {
        DataPlaneProtocol::Graphql => BodyLimits::from_env().graphql,
        DataPlaneProtocol::Soap => BodyLimits::from_env().soap,
        DataPlaneProtocol::Grpc | DataPlaneProtocol::GrpcWeb => BodyLimits::from_env().grpc,
        DataPlaneProtocol::Rest => BodyLimits::from_env().rest,
    };
    let body = match to_bytes(body, BodyLimits::for_path(&request_path, limit)).await {
        Ok(body) => body,
        Err(_) => {
            return Ok(policy_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "REQ001",
                &format!("Request entity too large (max: {limit} bytes)"),
            ));
        }
    };
    let response = match protocol {
        DataPlaneProtocol::Graphql => execute_graphql(state, decision, &body).await,
        DataPlaneProtocol::Soap => execute_soap(state, decision, is_get, &query, &body).await,
        DataPlaneProtocol::Grpc => execute_grpc(state, decision, is_get, &query, &body).await,
        DataPlaneProtocol::GrpcWeb => {
            execute_grpc_web(
                state,
                decision,
                grpc_web_target.as_ref(),
                &content_type,
                &body,
            )
            .await
        }
        DataPlaneProtocol::Rest => Ok(policy_error(
            StatusCode::NOT_IMPLEMENTED,
            "CRUD501",
            "CRUD is not supported for this protocol",
        )),
    };
    Ok(match response {
        Ok(response) => response,
        // Python's CRUD SOAP handler turns every failure into a 500 fault that
        // `process_soap_response` renders as the generic unknown-error message.
        Err(error) if protocol == DataPlaneProtocol::Soap => {
            tracing::debug!(error = %error, "SOAP CRUD failed");
            soap_python_fault()
        }
        Err(StorageError::InvalidDocument(error)) => {
            if protocol == DataPlaneProtocol::GrpcWeb {
                crate::protocol::grpc::web_trailer_response(
                    content_type.starts_with("application/grpc-web-text"),
                    tonic::Code::InvalidArgument,
                    &error,
                )
            } else {
                protocol_error(protocol, StatusCode::BAD_REQUEST, "CRUD400", &error)
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "protocol CRUD storage operation failed");
            if protocol == DataPlaneProtocol::GrpcWeb {
                crate::protocol::grpc::web_trailer_response(
                    content_type.starts_with("application/grpc-web-text"),
                    tonic::Code::Unavailable,
                    "Gateway state store unavailable",
                )
            } else {
                policy_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "GTW006",
                    "Gateway state store unavailable",
                )
            }
        }
    })
}

async fn execute_grpc_web(
    state: &AppState,
    decision: &PolicyDecision,
    target: Option<&crate::routes::grpc_web::GrpcWebTarget>,
    content_type: &str,
    body: &[u8],
) -> Result<Response, StorageError> {
    let text_mode = content_type.starts_with("application/grpc-web-text");
    if !content_type.starts_with("application/grpc-web") {
        return Ok((StatusCode::UNSUPPORTED_MEDIA_TYPE, "Invalid Content-Type").into_response());
    }
    if !decision.grpc_web_enabled {
        return Ok(crate::protocol::grpc::web_trailer_response(
            text_mode,
            tonic::Code::PermissionDenied,
            "gRPC-Web disabled",
        ));
    }
    let target = target
        .ok_or_else(|| StorageError::InvalidDocument("Invalid gRPC-Web CRUD target".to_owned()))?;
    if target
        .service
        .rsplit('.')
        .next()
        .is_none_or(|name| name != "CrudService")
    {
        return Ok(crate::protocol::grpc::web_trailer_response(
            text_mode,
            tonic::Code::Unimplemented,
            "CRUD service not found",
        ));
    }
    let raw = if text_mode {
        let compact = body
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|_| StorageError::InvalidDocument("Invalid base64 body".to_owned()))?
    } else {
        body.to_vec()
    };
    let payload = crate::protocol::grpc::decode_web_data_frame(&raw)
        .map_err(|message| StorageError::InvalidDocument(message.to_owned()))?;
    let request = CrudGrpcRequest::decode(payload.as_slice())
        .map_err(|_| StorageError::InvalidDocument("Invalid protobuf request".to_owned()))?;
    let (storage, collection) = storage_collection(state, decision)?;
    let reply = match target.method.as_str() {
        "ListItems" | "List" => CrudGrpcReply {
            result: serde_json::to_string(&storage.crud_list(collection).await?)?,
            ok: true,
        },
        "GetItem" | "Read" => {
            if request.id.is_empty() {
                return Err(StorageError::InvalidDocument("id is required".to_owned()));
            }
            let value = storage.crud_find_one(collection, &request.id).await?;
            CrudGrpcReply {
                result: serde_json::to_string(&value.clone().unwrap_or(Value::Null))?,
                ok: value.is_some(),
            }
        }
        "CreateItem" | "Create" => {
            let mut input: Value = serde_json::from_str(&request.input)?;
            validate_crud_schema(decision.crud_schema.as_ref(), &input, false)?;
            if input.get("_id").is_none() {
                input["_id"] = Value::String(uuid::Uuid::new_v4().to_string());
            }
            storage.crud_insert(collection, &input).await?;
            CrudGrpcReply {
                result: serde_json::to_string(&input)?,
                ok: true,
            }
        }
        "UpdateItem" | "Update" => {
            if request.id.is_empty() {
                return Err(StorageError::InvalidDocument("id is required".to_owned()));
            }
            let input: Value = serde_json::from_str(&request.input)?;
            validate_crud_schema(decision.crud_schema.as_ref(), &input, true)?;
            let value = storage.crud_update(collection, &request.id, &input).await?;
            CrudGrpcReply {
                result: serde_json::to_string(&value.clone().unwrap_or(Value::Null))?,
                ok: value.is_some(),
            }
        }
        "DeleteItem" | "Delete" => CrudGrpcReply {
            result: String::new(),
            ok: if request.id.is_empty() {
                return Err(StorageError::InvalidDocument("id is required".to_owned()));
            } else {
                storage.crud_delete(collection, &request.id).await?
            },
        },
        _ => {
            return Ok(crate::protocol::grpc::web_trailer_response(
                text_mode,
                tonic::Code::Unimplemented,
                "Unknown gRPC CRUD operation",
            ));
        }
    };
    let mut framed = crate::protocol::grpc::web_data_frame(&reply.encode_to_vec());
    let trailer = b"grpc-status: 0\r\ngrpc-message: \r\n";
    framed.push(0x80);
    framed.extend((trailer.len() as u32).to_be_bytes());
    framed.extend(trailer);
    Ok(crate::protocol::grpc::web_body_response(text_mode, framed))
}

async fn execute_graphql(
    state: &AppState,
    decision: &PolicyDecision,
    body: &[u8],
) -> Result<Response, StorageError> {
    let document: Value = serde_json::from_slice(body)
        .map_err(|error| StorageError::InvalidDocument(error.to_string()))?;
    let query = document
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let variables = document
        .get("variables")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let depth = graphql_depth(query)
        .ok_or_else(|| StorageError::InvalidDocument("Invalid GraphQL query".to_owned()))?;
    if decision.graphql_max_depth > 0 && depth > decision.graphql_max_depth {
        return Err(StorageError::InvalidDocument(format!(
            "Query depth {depth} exceeds maximum allowed depth of {}",
            decision.graphql_max_depth
        )));
    }
    if let Some(schema) = decision.endpoint_validation.as_ref() {
        crate::validation::json::validate_json(&Value::Object(variables.clone()), schema)
            .map_err(|error| StorageError::InvalidDocument(error.to_owned()))?;
    }
    let (storage, collection) = storage_collection(state, decision)?;
    let (field, value) = if has_operation(query, "listItems") {
        (
            "listItems",
            Value::Array(storage.crud_list(collection).await?),
        )
    } else if has_operation(query, "getItem") {
        let id = variable_string(&variables, "id")?;
        (
            "getItem",
            storage
                .crud_find_one(collection, id)
                .await?
                .unwrap_or(Value::Null),
        )
    } else if has_operation(query, "createItem") {
        let mut input = variable_object(&variables, "input")?;
        validate_crud_schema(decision.crud_schema.as_ref(), &input, false)?;
        if input.get("_id").is_none() {
            input["_id"] = Value::String(uuid::Uuid::new_v4().to_string());
        }
        storage.crud_insert(collection, &input).await?;
        ("createItem", input)
    } else if has_operation(query, "updateItem") {
        let id = variable_string(&variables, "id")?;
        let input = variable_object(&variables, "input")?;
        validate_crud_schema(decision.crud_schema.as_ref(), &input, true)?;
        (
            "updateItem",
            storage
                .crud_update(collection, id, &input)
                .await?
                .unwrap_or(Value::Null),
        )
    } else if has_operation(query, "deleteItem") {
        let id = variable_string(&variables, "id")?;
        (
            "deleteItem",
            Value::Bool(storage.crud_delete(collection, id).await?),
        )
    } else {
        return Err(StorageError::InvalidDocument(
            "Unknown GraphQL CRUD operation".to_owned(),
        ));
    };
    Ok(Json(serde_json::json!({ "data": { field: value } })).into_response())
}

async fn execute_soap(
    state: &AppState,
    decision: &PolicyDecision,
    is_get: bool,
    query: &str,
    body: &[u8],
) -> Result<Response, StorageError> {
    if is_get
        && query
            .split('&')
            .any(|part| part.split('=').next().is_some_and(|key| key == "wsdl"))
    {
        return Ok(soap_xml_response(soap_wsdl(decision)));
    }
    let xml = std::str::from_utf8(body)
        .map_err(|error| StorageError::InvalidDocument(error.to_string()))?;
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err(StorageError::InvalidDocument(
            "XML DTD/entities are not allowed".to_owned(),
        ));
    }
    if !(lower.contains(":envelope") || lower.contains("<envelope"))
        || !(lower.contains("http://schemas.xmlsoap.org/soap/envelope/")
            || lower.contains("http://www.w3.org/2003/05/soap-envelope"))
        || !(lower.contains(":body") || lower.contains("<body"))
    {
        return Err(StorageError::InvalidDocument(
            "Invalid SOAP envelope".to_owned(),
        ));
    }
    // Python's CRUD SOAP handler implements only createItem and listItems;
    // getItem is "not supported yet" and everything else is unknown.
    static OPERATION: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?s)<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?(createItem|listItems)\b")
            .expect("static SOAP operation regex")
    });
    let operation = OPERATION
        .captures(xml)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str())
        .ok_or_else(|| StorageError::InvalidDocument("Unknown SOAP CRUD operation".to_owned()))?;
    let (storage, collection) = storage_collection(state, decision)?;
    let (response_tag, result_xml) = match operation {
        "listItems" => (
            "listItemsResponse",
            format!(
                "<tns:items>{}</tns:items>",
                python_json_dumps(&Value::Array(storage.crud_list(collection).await?))
            ),
        ),
        _ => {
            let input = xml_element(xml, "input")?;
            if input.is_empty() {
                return Err(StorageError::InvalidDocument(
                    "Missing input element or empty".to_owned(),
                ));
            }
            let mut input: Value = serde_json::from_str(&xml_unescape(&input))?;
            if !input.is_object() {
                return Err(StorageError::InvalidDocument(
                    "SOAP CRUD input must be a JSON object".to_owned(),
                ));
            }
            validate_crud_schema(decision.crud_schema.as_ref(), &input, false)?;
            if input.get("_id").is_none() {
                input["_id"] = Value::String(uuid::Uuid::new_v4().to_string());
            }
            storage.crud_insert(collection, &input).await?;
            (
                "createItemResponse",
                format!("<tns:result>{}</tns:result>", python_json_dumps(&input)),
            )
        }
    };
    let api_name = decision.api_name.as_deref().unwrap_or_default();
    let tns = format!("http://doorman.dev/{}", xml_escape(api_name));
    Ok(soap_xml_response(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tns=\"{tns}\">\n    <soap:Body>\n        <tns:{response_tag}>\n            {result_xml}\n        </tns:{response_tag}>\n    </soap:Body>\n</soap:Envelope>"
    )))
}

async fn execute_grpc(
    state: &AppState,
    decision: &PolicyDecision,
    is_get: bool,
    query: &str,
    body: &[u8],
) -> Result<Response, StorageError> {
    if is_get
        && query
            .split('&')
            .any(|part| part.split('=').next().is_some_and(|key| key == "proto"))
    {
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            crud_proto(decision),
        )
            .into_response());
    }
    let document: Value = serde_json::from_slice(body)?;
    let method = document
        .get("method")
        .and_then(Value::as_str)
        .and_then(|method| method.rsplit('.').next())
        .unwrap_or_default();
    let message = document.get("message").cloned().unwrap_or(Value::Null);
    let (storage, collection) = storage_collection(state, decision)?;
    let result = match method {
        "ListItems" | "List" => {
            serde_json::json!({ "items": storage.crud_list(collection).await? })
        }
        "GetItem" | "Read" => {
            let id = message
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StorageError::InvalidDocument("id is required".to_owned()))?;
            storage
                .crud_find_one(collection, id)
                .await?
                .unwrap_or(Value::Null)
        }
        "CreateItem" | "Create" => {
            let mut input = message.get("input").cloned().unwrap_or(message);
            validate_crud_schema(decision.crud_schema.as_ref(), &input, false)?;
            if input.get("_id").is_none() {
                input["_id"] = Value::String(uuid::Uuid::new_v4().to_string());
            }
            storage.crud_insert(collection, &input).await?;
            input
        }
        "UpdateItem" | "Update" => {
            let id = message
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StorageError::InvalidDocument("id is required".to_owned()))?;
            let input = message
                .get("input")
                .cloned()
                .unwrap_or_else(|| message.clone());
            validate_crud_schema(decision.crud_schema.as_ref(), &input, true)?;
            storage
                .crud_update(collection, id, &input)
                .await?
                .unwrap_or(Value::Null)
        }
        "DeleteItem" | "Delete" => {
            let id = message
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| StorageError::InvalidDocument("id is required".to_owned()))?;
            serde_json::json!({ "ok": storage.crud_delete(collection, id).await? })
        }
        _ => {
            return Err(StorageError::InvalidDocument(
                "Unknown gRPC CRUD operation".to_owned(),
            ));
        }
    };
    Ok(Json(result).into_response())
}

fn storage_collection<'a>(
    state: &'a AppState,
    decision: &'a PolicyDecision,
) -> Result<(&'a crate::storage::runtime::SharedStorage, &'a str), StorageError> {
    let storage = state.storage.as_deref().ok_or_else(|| {
        StorageError::InvalidDocument("Gateway state store unavailable".to_owned())
    })?;
    let collection = decision
        .crud_collection
        .as_deref()
        .filter(|name| valid_collection_name(name))
        .ok_or_else(|| {
            StorageError::InvalidDocument("CRUD collection is not configured".to_owned())
        })?;
    Ok((storage, collection))
}

/// Patterns here are built from a small fixed set of operation and element
/// names; compile each once instead of per request.
fn cached_regex(pattern: String) -> Option<Regex> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Regex>>> =
        std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().ok()?;
    if let Some(regex) = cache.get(&pattern) {
        return Some(regex.clone());
    }
    let regex = Regex::new(&pattern).ok()?;
    if cache.len() >= 256 {
        cache.clear();
    }
    cache.insert(pattern, regex.clone());
    Some(regex)
}

fn has_operation(query: &str, operation: &str) -> bool {
    cached_regex(format!(r"\b{}\b", regex::escape(operation)))
        .is_some_and(|regex| regex.is_match(query))
}

fn variable_string<'a>(
    variables: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, StorageError> {
    variables
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| StorageError::InvalidDocument(format!("Variable '{name}' is required")))
}

fn variable_object(
    variables: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Value, StorageError> {
    variables
        .get(name)
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            StorageError::InvalidDocument(format!("Variable '{name}' must be an object"))
        })
}

fn xml_element(xml: &str, name: &str) -> Result<String, StorageError> {
    cached_regex(format!(
        r"(?s)<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?{0}\b[^>]*>(.*?)</(?:[A-Za-z_][A-Za-z0-9_.-]*:)?{0}\s*>",
        regex::escape(name)
    ))
    .expect("escaped XML element regex")
    .captures(xml)
    .and_then(|captures| captures.get(1))
    .map(|value| value.as_str().trim().to_owned())
    .ok_or_else(|| StorageError::InvalidDocument(format!("Missing {name} element")))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn xml_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/xml; charset=utf-8")],
        body,
    )
        .into_response()
}

fn soap_wsdl(decision: &PolicyDecision) -> String {
    let name = xml_escape(decision.api_name.as_deref().unwrap_or_default());
    let tns = format!("http://doorman.dev/{name}");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="{tns}"
             xmlns:xs="http://www.w3.org/2001/XMLSchema"
             name="{name}Service"
             targetNamespace="{tns}">
             
    <types>
        <xs:schema targetNamespace="{tns}" elementFormDefault="qualified">
            <xs:element name="createItem">
                <xs:complexType>
                    <xs:sequence>
                        <xs:element name="input" type="xs:string"/> <!-- Simplified: Pass JSON string for now or generate fields -->
                    </xs:sequence>
                </xs:complexType>
            </xs:element>
            <xs:element name="createItemResponse">
                <xs:complexType>
                    <xs:sequence>
                       <xs:element name="result" type="xs:string"/>
                    </xs:sequence>
                </xs:complexType>
            </xs:element>
             <xs:element name="listItems">
                <xs:complexType/>
            </xs:element>
            <xs:element name="listItemsResponse">
                <xs:complexType>
                     <xs:sequence>
                        <xs:element name="items" type="xs:string"/>
                     </xs:sequence>
                </xs:complexType>
            </xs:element>
        </xs:schema>
    </types>

    <message name="createItemRequest">
        <part name="parameters" element="tns:createItem"/>
    </message>
    <message name="createItemResponse">
        <part name="parameters" element="tns:createItemResponse"/>
    </message>
    <message name="listItemsRequest">
        <part name="parameters" element="tns:listItems"/>
    </message>
    <message name="listItemsResponse">
        <part name="parameters" element="tns:listItemsResponse"/>
    </message>

    <portType name="{name}PortType">
        <operation name="createItem">
            <input message="tns:createItemRequest"/>
            <output message="tns:createItemResponse"/>
        </operation>
        <operation name="listItems">
             <input message="tns:listItemsRequest"/>
             <output message="tns:listItemsResponse"/>
        </operation>
    </portType>

    <binding name="{name}Binding" type="tns:{name}PortType">
        <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
        <operation name="createItem">
            <soap:operation soapAction="{tns}/createItem"/>
            <input><soap:body use="literal"/></input>
            <output><soap:body use="literal"/></output>
        </operation>
        <operation name="listItems">
            <soap:operation soapAction="{tns}/listItems"/>
            <input><soap:body use="literal"/></input>
            <output><soap:body use="literal"/></output>
        </operation>
    </binding>

    <service name="{name}Service">
        <port name="{name}Port" binding="tns:{name}Binding">
            <soap:address location="http://localhost:8080/api/soap/{name}"/>
        </port>
    </service>
</definitions>
        "#
    )
}

/// `text/xml` response carrying the raw body, as Python's SOAP CRUD returns it.
fn soap_xml_response(body: String) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/xml")], body).into_response()
}

/// What `process_soap_response` renders for the CRUD handler's 500 fault.
fn soap_python_fault() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "text/xml")],
        "<message>An unknown error occurred in SOAP response</message>",
    )
        .into_response()
}

/// Python `json.dumps` defaults: `", "` / `": "` separators and ASCII escaping.
fn python_json_dumps(value: &Value) -> String {
    fn dump(value: &Value, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Value::Number(number) => out.push_str(&number.to_string()),
            Value::String(text) => dump_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    dump(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    dump_string(key, out);
                    out.push_str(": ");
                    dump(item, out);
                }
                out.push('}');
            }
        }
    }
    fn dump_string(text: &str, out: &mut String) {
        out.push('"');
        for character in text.chars() {
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                character if (' '..='~').contains(&character) => out.push(character),
                character => {
                    let mut units = [0u16; 2];
                    for unit in character.encode_utf16(&mut units) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
        }
        out.push('"');
    }
    let mut out = String::new();
    dump(value, &mut out);
    out
}

fn crud_proto(decision: &PolicyDecision) -> String {
    let raw = decision.api_name.as_deref().unwrap_or_default();
    let mut package = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let mut service = package.chars();
    let service = service
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + &service.as_str().to_lowercase())
        .unwrap_or_default();
    if package.starts_with(|character: char| character.is_ascii_digit()) {
        package.insert(0, '_');
    }
    let type_map = |declared: &str| match declared {
        "number" => "double",
        "integer" => "int32",
        "boolean" => "bool",
        "array" => "repeated string",
        _ => "string",
    };
    let fields = decision
        .crud_schema
        .as_ref()
        .and_then(Value::as_object)
        .map(|schema| {
            schema
                .iter()
                .enumerate()
                .map(|(index, (field, rules))| {
                    let declared = rules
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("string");
                    format!("  {} {field} = {};", type_map(declared), index + 1)
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    format!(
        "syntax = \"proto3\";\n\npackage {package};\n\nservice {service}Service {{\n  rpc CreateItem (CreateItemRequest) returns (CreateItemResponse);\n  rpc ListItems (ListItemsRequest) returns (ListItemsResponse);\n}}\n\nmessage CreateItemRequest {{\n{fields}\n}}\n\nmessage CreateItemResponse {{\n  string result = 1; // JSON string of created object\n}}\n\nmessage ListItemsRequest {{}}\n\nmessage ListItemsResponse {{\n  string items = 1; // JSON string of list\n}}\n"
    )
}

fn protocol_error(
    protocol: DataPlaneProtocol,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response {
    match protocol {
        DataPlaneProtocol::Graphql => {
            Json(serde_json::json!({ "errors": [{ "message": message, "code": code }] }))
                .into_response()
        }
        DataPlaneProtocol::Soap => xml_response(
            status,
            format!(
                "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><soap:Fault><faultcode>{code}</faultcode><faultstring>{}</faultstring></soap:Fault></soap:Body></soap:Envelope>",
                xml_escape(message)
            ),
        ),
        _ => policy_error(status, code, message),
    }
}

fn policy_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(PolicyErrorBody {
            error_code: code.to_owned(),
            error_message: message.to_owned(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_documents_match_python_templates() {
        let decision = PolicyDecision {
            api_name: Some("customer-api".to_owned()),
            crud_schema: Some(serde_json::json!({
                "name": {"type": "string"}, "age": {"type": "integer"},
                "score": {"type": "number"}, "ok": {"type": "boolean"},
                "tags": {"type": "array"}, "meta": {"type": "object"}
            })),
            ..Default::default()
        };
        let wsdl = soap_wsdl(&decision);
        assert!(
            wsdl.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<definitions xmlns=")
        );
        assert!(wsdl.contains(
            "targetNamespace=\"http://doorman.dev/customer-api\">\n             \n    <types>"
        ));
        assert!(wsdl.contains("location=\"http://localhost:8080/api/soap/customer-api\""));
        assert!(wsdl.ends_with("</definitions>\n        "));
        assert!(!wsdl.contains("getItem"));
        assert_eq!(
            crud_proto(&decision),
            include_str!("../../tests/fixtures/crud_customer_api.proto")
        );
    }

    #[test]
    fn python_json_dumps_matches_json_dumps_defaults() {
        let value =
            serde_json::json!({"a": [1, 2.5, null, true], "n": "caf\u{e9} \u{1f600}\n\"q\""});
        assert_eq!(
            python_json_dumps(&value),
            r#"{"a": [1, 2.5, null, true], "n": "caf\u00e9 \ud83d\ude00\n\"q\""}"#
        );
    }

    #[test]
    fn escapes_or_sanitizes_api_names_in_discovery_documents() {
        let decision = PolicyDecision {
            api_name: Some("9<&bad-name".to_owned()),
            ..Default::default()
        };
        assert!(soap_wsdl(&decision).contains("9&lt;&amp;bad-nameService"));
        assert!(crud_proto(&decision).contains("package _9__bad_name;"));
    }
}
