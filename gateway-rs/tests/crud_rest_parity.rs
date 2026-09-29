use axum::body::{Body, to_bytes};
use doorman_gateway::{AppState, Config, build_router, storage::runtime::SharedStorage};
use http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn crud_app(schema: Value) -> axum::Router {
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_id": "crud-1", "api_name": "items", "api_version": "v1",
                "api_type": "REST", "api_public": true, "api_auth_required": false,
                "api_is_crud": true, "api_crud_collection": "crud_data_items",
                "api_crud_schema": schema, "active": true, "api_servers": []
            }),
        )
        .await
        .unwrap();
    for method in ["GET", "POST", "PUT", "PATCH"] {
        let uri = if method == "GET" || method == "POST" {
            "/items"
        } else {
            "/items/{id}"
        };
        storage
            .insert_one(
                "endpoints",
                json!({
                    "api_id": "crud-1", "api_name": "items", "api_version": "v1",
                    "endpoint_method": method, "endpoint_uri": uri,
                    "endpoint_id": format!("e-{method}")
                }),
            )
            .await
            .unwrap();
    }
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(Arc::new(storage));
    build_router(state)
}

async fn call(app: &axum::Router, method: Method, uri: &str, body: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn crud_validation_failure_body_omits_error_list_like_python() {
    let app = crud_app(json!({"name": {"type": "string", "required": true}})).await;
    let (status, body) = call(&app, Method::POST, "/api/rest/items/v1/items", "{}").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"error_code": "CRUD400", "error_message": "Validation failed"})
    );
}

#[tokio::test]
async fn crud_non_object_bodies_raise_python_internal_errors() {
    let app = crud_app(json!({})).await;
    for (body, message) in [
        ("[1]", "list indices must be integers or slices, not str"),
        ("\"abc\"", "'str' object does not support item assignment"),
        ("5", "argument of type 'int' is not iterable"),
        ("1.5", "argument of type 'float' is not iterable"),
        ("true", "argument of type 'bool' is not iterable"),
        ("null", "argument of type 'NoneType' is not iterable"),
    ] {
        let (status, json_body) = call(&app, Method::POST, "/api/rest/items/v1/items", body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(json_body["error_code"], "CRUD999", "{body}");
        assert_eq!(
            json_body["error_message"],
            format!("Internal CRUD error: {message}"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn crud_non_object_update_bodies_follow_python_order() {
    let app = crud_app(json!({})).await;
    let (status, created) = call(
        &app,
        Method::POST,
        "/api/rest/items/v1/items",
        r#"{"_id":"a","n":1}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["_id"], "a");
    // Missing resource is reported before the body is used.
    let (status, body) = call(&app, Method::PUT, "/api/rest/items/v1/items/zzz", "[1]").await;
    assert_eq!(
        (status, body["error_code"].as_str()),
        (StatusCode::NOT_FOUND, Some("CRUD404"))
    );
    // Truthy non-object body: `.items()` AttributeError.
    let (status, body) = call(&app, Method::PUT, "/api/rest/items/v1/items/a", "[1]").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["error_message"],
        "Internal CRUD error: 'list' object has no attribute 'items'"
    );
    // Falsy body is a no-op update returning the stored document.
    let (status, body) = call(&app, Method::PATCH, "/api/rest/items/v1/items/a", "null").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["n"], 1);
}

#[tokio::test]
async fn crud_non_object_update_with_schema_raises_get_attribute_error() {
    let app = crud_app(json!({"name": {"type": "string"}})).await;
    let (status, body) = call(&app, Method::PUT, "/api/rest/items/v1/items/a", "[1]").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body["error_message"],
        "Internal CRUD error: 'list' object has no attribute 'get'"
    );
}

async fn soap_app() -> axum::Router {
    let config = Config::for_test("removed-internal-backend".to_owned());
    let storage = SharedStorage::connect(&config.shared_storage)
        .await
        .unwrap();
    storage
        .insert_one(
            "apis",
            json!({
                "api_id": "crud-s", "api_name": "sitems", "api_version": "v1",
                "api_type": "SOAP", "api_public": true, "api_auth_required": false,
                "api_is_crud": true, "api_crud_collection": "crud_data_sitems",
                "api_crud_schema": {"name": {"type": "string", "required": true}},
                "active": true, "api_servers": []
            }),
        )
        .await
        .unwrap();
    for method in ["GET", "POST"] {
        storage
            .insert_one(
                "endpoints",
                json!({
                    "api_id": "crud-s", "api_name": "sitems", "api_version": "v1",
                    "endpoint_method": method, "endpoint_uri": "/soap",
                    "endpoint_id": format!("s-{method}")
                }),
            )
            .await
            .unwrap();
    }
    let mut state = AppState::new(config).unwrap();
    state.storage = Some(Arc::new(storage));
    build_router(state)
}

async fn soap_call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: &str,
) -> (StatusCode, String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "text/xml")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        content_type,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

fn envelope(operation: &str) -> String {
    format!(
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>{operation}</soap:Body></soap:Envelope>"
    )
}

#[tokio::test]
async fn crud_soap_matches_python_envelope_wsdl_and_fault() {
    let app = soap_app().await;
    let (status, content_type, body) =
        soap_call(&app, Method::GET, "/api/soap/sitems/v1/soap?wsdl", "").await;
    assert_eq!(
        (status, content_type.as_str()),
        (StatusCode::OK, "text/xml")
    );
    assert!(body.contains("name=\"sitemsService\"") && !body.contains("getItem"));

    let create = envelope(
        "<tns:createItem xmlns:tns=\"http://doorman.dev/sitems\"><input>{&quot;name&quot;: &quot;Ada&quot;, &quot;_id&quot;: &quot;x1&quot;}</input></tns:createItem>",
    );
    let (status, content_type, body) =
        soap_call(&app, Method::POST, "/api/soap/sitems/v1/soap", &create).await;
    assert_eq!(
        (status, content_type.as_str()),
        (StatusCode::OK, "text/xml")
    );
    assert_eq!(
        body,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tns=\"http://doorman.dev/sitems\">\n    <soap:Body>\n        <tns:createItemResponse>\n            <tns:result>{\"name\": \"Ada\", \"_id\": \"x1\"}</tns:result>\n        </tns:createItemResponse>\n    </soap:Body>\n</soap:Envelope>"
    );

    let list = envelope("<tns:listItems xmlns:tns=\"http://doorman.dev/sitems\"/>");
    let (_, _, body) = soap_call(&app, Method::POST, "/api/soap/sitems/v1/soap", &list).await;
    assert!(
        body.contains("<tns:items>[{\"name\": \"Ada\", \"_id\": \"x1\"}]</tns:items>"),
        "{body}"
    );

    let fault = "<message>An unknown error occurred in SOAP response</message>";
    for operation in [
        "<tns:getItem xmlns:tns=\"http://doorman.dev/sitems\"><id>x1</id></tns:getItem>",
        "<tns:deleteItem xmlns:tns=\"http://doorman.dev/sitems\"><id>x1</id></tns:deleteItem>",
        "<tns:createItem xmlns:tns=\"http://doorman.dev/sitems\"><input>{}</input></tns:createItem>",
        "<tns:createItem xmlns:tns=\"http://doorman.dev/sitems\"><input>not json</input></tns:createItem>",
    ] {
        let (status, content_type, body) = soap_call(
            &app,
            Method::POST,
            "/api/soap/sitems/v1/soap",
            &envelope(operation),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{operation}");
        assert_eq!(content_type, "text/xml", "{operation}");
        assert_eq!(body, fault, "{operation}");
    }
}
