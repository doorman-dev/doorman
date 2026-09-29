use axum::response::Response;
use http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::{
    config::DownstreamTlsMode,
    routes::platform::json_response,
    state::AppState,
    tls::{profiles::TlsProfiles, secrets, server_config_from_pem_with_roots},
};

fn reply(status: StatusCode, value: Value, request_id: &str) -> Response {
    json_response(status, value, request_id)
}

fn error(status: StatusCode, message: &str, request_id: &str) -> Response {
    reply(status, json!({"error_code": "TLSA002", "error_message": message}), request_id)
}

pub async fn dispatch(state: &AppState, path: &str, method: &Method, payload: Value, request_id: &str) -> Response {
    let Some(storage) = &state.storage else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "TLS profile storage is unavailable", request_id);
    };
    let _mutation_guard = if matches!(*method, Method::POST | Method::PUT | Method::DELETE) {
        match storage.tls_mutation_lock().await {
            Ok(guard) => Some(guard),
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "TLS profile mutation lock is unavailable", request_id),
        }
    } else {
        None
    };
    let documents = match storage.find_many("tls_profiles", &json!({})).await {
        Ok(documents) => documents,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "TLS profile storage is unavailable", request_id),
    };
    if path == "/tls/profiles" && *method == Method::GET {
        let mut items = Vec::new();
        let file = match TlsProfiles::load_file(state.config.tls_profiles_file.as_deref()) {
            Ok(file) => file,
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "File TLS profiles are unavailable", request_id),
        };
        for id in file.client_cas.keys() { items.push(json!({"id": id, "kind": "client_ca", "source": "file", "read_only": true})); }
        for id in file.upstreams.keys() { items.push(json!({"id": id, "kind": "upstream", "source": "file", "read_only": true})); }
        for doc in &documents {
            if doc.get("kind").and_then(Value::as_str) == Some("listener") { continue; }
            items.push(public_metadata(doc));
        }
        return reply(StatusCode::OK, json!({"profiles": items}), request_id);
    }
    if path == "/tls/listener" {
        if *method == Method::GET {
            let active = documents.iter().find(|doc| doc.get("kind").and_then(Value::as_str) == Some("listener"));
            let from_admin = state.tls_listener_from_admin();
            return reply(StatusCode::OK, json!({"source": if from_admin {"admin"} else {"file"}, "revision": if from_admin {active.and_then(|doc| doc.get("revision"))} else {None}, "has_override": active.is_some()}), request_id);
        }
        if *method == Method::DELETE {
            let Some(previous) = documents.iter().find(|doc| doc.get("kind").and_then(Value::as_str) == Some("listener")) else {
                return error(StatusCode::NOT_FOUND, "Listener override not found", request_id);
            };
            if !matches!(storage.delete_one("tls_profiles", &json!({"id": "listener"})).await, Ok(true)) {
                return error(StatusCode::SERVICE_UNAVAILABLE, "Listener override could not be removed", request_id);
            }
            if state.reload_tls_from_storage().await.is_err() {
                let _ = storage.insert_one("tls_profiles", previous.clone()).await;
                return error(StatusCode::SERVICE_UNAVAILABLE, "Mounted listener certificate could not be activated", request_id);
            }
            return reply(StatusCode::OK, json!({"message": "Mounted listener certificate activated"}), request_id);
        }
        if *method != Method::PUT {
            return error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed", request_id);
        }
        if state.config.downstream_tls_mode != DownstreamTlsMode::Native {
            return error(StatusCode::BAD_REQUEST, "Native TLS mode is required", request_id);
        }
        let (Some(cert), Some(key)) = (payload.get("cert_pem").and_then(Value::as_str), payload.get("key_pem").and_then(Value::as_str)) else {
            return error(StatusCode::BAD_REQUEST, "Certificate and key PEM are required", request_id);
        };
        if cert.len() > 256 * 1024 || key.len() > 256 * 1024 {
            return error(StatusCode::BAD_REQUEST, "TLS material is too large", request_id);
        }
        if server_config_from_pem_with_roots(cert.as_bytes(), key.as_bytes(), Some(state.tls_snapshot().profiles.combined_client_roots())).is_err() {
            return error(StatusCode::BAD_REQUEST, "Certificate and key are invalid", request_id);
        }
        let sealed_cert = match secrets::seal("listener", "cert_pem", cert.as_bytes()) {
            Ok(value) => value,
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "TLS secret encryption is not configured", request_id),
        };
        let sealed_key = match secrets::seal("listener", "key_pem", key.as_bytes()) {
            Ok(value) => value,
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "TLS secret encryption is not configured", request_id),
        };
        let previous = documents.iter().find(|doc| doc.get("kind").and_then(Value::as_str) == Some("listener"));
        let doc = json!({"id": "listener", "kind": "listener", "cert_pem": sealed_cert, "key_pem": sealed_key, "revision": previous.and_then(|doc| doc.get("revision")).and_then(Value::as_u64).unwrap_or(0) + 1});
        let result = if previous.is_some() {
            storage.update_one("tls_profiles", &json!({"id": "listener"}), &doc).await.map(|result| result.is_some())
        } else {
            storage.insert_one("tls_profiles", doc).await.map(|_| true)
        };
        if !matches!(result, Ok(true)) {
            return error(StatusCode::SERVICE_UNAVAILABLE, "Listener certificate could not be activated", request_id);
        }
        if state.reload_tls_from_storage().await.is_err() {
            if let Some(previous) = previous {
                let _ = storage.update_one("tls_profiles", &json!({"id": "listener"}), previous).await;
            } else {
                let _ = storage.delete_one("tls_profiles", &json!({"id": "listener"})).await;
            }
            return error(StatusCode::SERVICE_UNAVAILABLE, "Listener certificate could not be activated", request_id);
        }
        return reply(StatusCode::OK, json!({"message": "Listener certificate activated"}), request_id);
    }
    if path == "/tls/profiles" && *method == Method::POST {
        let Some(id) = payload.get("id").and_then(Value::as_str) else {
            return error(StatusCode::BAD_REQUEST, "Profile ID is required", request_id);
        };
        if documents.iter().any(|doc| doc.get("id").and_then(Value::as_str) == Some(id)) {
            return error(StatusCode::CONFLICT, "Profile ID already exists", request_id);
        }
        let Some(doc) = seal_profile(&payload) else {
            return error(StatusCode::BAD_REQUEST, "Invalid profile or TLS secret key", request_id);
        };
        let mut candidate = documents.clone();
        candidate.push(doc.clone());
        if !valid_candidate(state, &candidate) {
            return error(StatusCode::BAD_REQUEST, "Profile material is invalid or ID collides with a file profile", request_id);
        }
        if storage.insert_one("tls_profiles", doc).await.is_err() {
            return error(StatusCode::SERVICE_UNAVAILABLE, "Profile could not be stored", request_id);
        }
        if state.reload_tls_from_storage().await.is_err() {
            let _ = storage.delete_one("tls_profiles", &json!({"id": id})).await;
            return error(StatusCode::SERVICE_UNAVAILABLE, "Profile could not be activated", request_id);
        }
        return reply(StatusCode::CREATED, json!({"id": id}), request_id);
    }
    let Some(id) = path.strip_prefix("/tls/profiles/").filter(|id| !id.is_empty() && !id.contains('/')) else {
        return error(StatusCode::NOT_FOUND, "TLS route not found", request_id);
    };
    let Some(existing) = documents.iter().find(|doc| doc.get("id").and_then(Value::as_str) == Some(id)) else {
        return error(StatusCode::NOT_FOUND, "Profile not found", request_id);
    };
    if existing.get("kind").and_then(Value::as_str) == Some("listener") {
        return error(StatusCode::NOT_FOUND, "Profile not found", request_id);
    }
    if *method == Method::GET {
        return reply(StatusCode::OK, public_metadata(existing), request_id);
    }
    if *method == Method::DELETE {
        if profile_referenced(state, id).await {
            return error(StatusCode::CONFLICT, "Profile is referenced by an API or endpoint", request_id);
        }
        if !matches!(storage.delete_one("tls_profiles", &json!({"id": id})).await, Ok(true)) {
            return error(StatusCode::SERVICE_UNAVAILABLE, "Profile could not be deleted", request_id);
        }
        if state.reload_tls_from_storage().await.is_err() {
            let _ = storage.insert_one("tls_profiles", existing.clone()).await;
            return error(StatusCode::SERVICE_UNAVAILABLE, "Profile could not be deleted", request_id);
        }
        return reply(StatusCode::OK, json!({"message": "Profile deleted"}), request_id);
    }
    if *method == Method::PUT {
        let mut submitted = payload;
        submitted["id"] = json!(id);
        let Some(mut replacement) = seal_profile(&submitted) else {
            return error(StatusCode::BAD_REQUEST, "Invalid profile or TLS secret key", request_id);
        };
        if replacement.get("kind") != existing.get("kind") {
            return error(StatusCode::BAD_REQUEST, "Profile type cannot be changed", request_id);
        }
        replacement["revision"] = json!(existing.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1);
        let mut candidate = documents.clone();
        if let Some(target) = candidate.iter_mut().find(|doc| doc.get("id").and_then(Value::as_str) == Some(id)) {
            *target = replacement.clone();
        }
        if !valid_candidate(state, &candidate) {
            return error(StatusCode::BAD_REQUEST, "Profile material is invalid", request_id);
        }
        if !matches!(storage.update_one("tls_profiles", &json!({"id": id}), &replacement).await, Ok(Some(_))) {
            return error(StatusCode::SERVICE_UNAVAILABLE, "Profile could not be activated", request_id);
        }
        if state.reload_tls_from_storage().await.is_err() {
            let _ = storage.update_one("tls_profiles", &json!({"id": id}), existing).await;
            return error(StatusCode::SERVICE_UNAVAILABLE, "Profile could not be activated", request_id);
        }
        return reply(StatusCode::OK, json!({"id": id}), request_id);
    }
    error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed", request_id)
}

fn seal_profile(payload: &Value) -> Option<Value> {
    let id = payload.get("id")?.as_str()?;
    let kind = payload.get("kind")?.as_str()?;
    if !matches!(kind, "client_ca" | "upstream") { return None; }
    if kind == "client_ca" && (payload.get("cert_pem").and_then(Value::as_str).is_some() || payload.get("key_pem").and_then(Value::as_str).is_some() || payload.get("server_name").and_then(Value::as_str).is_some()) {
        return None;
    }
    let mut doc = json!({"id": id, "kind": kind, "source": "admin", "revision": 1});
    for field in ["ca_pem", "cert_pem", "key_pem"] {
        if let Some(value) = payload.get(field).and_then(Value::as_str) {
            if value.len() > 256 * 1024 { return None; }
            doc[field] = json!(secrets::seal(id, field, value.as_bytes()).ok()?);
        } else {
            doc[field] = Value::Null;
        }
    }
    if let Some(server_name) = payload.get("server_name").and_then(Value::as_str) {
        doc["server_name"] = json!(server_name);
    } else {
        doc["server_name"] = Value::Null;
    }
    Some(doc)
}

fn valid_candidate(state: &AppState, documents: &[Value]) -> bool {
    let Ok(mut profiles) = TlsProfiles::load_file(state.config.tls_profiles_file.as_deref()) else { return false; };
    profiles.merge_admin_documents(documents).is_ok()
}

fn public_metadata(doc: &Value) -> Value {
    json!({"id": doc.get("id"), "kind": doc.get("kind"), "source": "admin", "revision": doc.get("revision"), "read_only": false})
}

async fn profile_referenced(state: &AppState, id: &str) -> bool {
    let Some(storage) = &state.storage else { return true; };
    for (collection, prefix) in [("apis", "api"), ("endpoints", "endpoint")] {
        let Ok(documents) = storage.find_many(collection, &json!({})).await else { return true; };
        for doc in documents {
            if doc.get(format!("{prefix}_client_tls_policy")).and_then(|policy| policy.get("ca_profile_id")).and_then(Value::as_str) == Some(id)
                || doc.get(format!("{prefix}_upstream_tls_profile")).and_then(Value::as_str) == Some(id)
                || doc.get(format!("{prefix}_upstream_tls_profiles")).and_then(Value::as_object)
                    .is_some_and(|map| map.values().any(|value| value.as_str() == Some(id)))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::{process::{Command, Stdio}, sync::Arc};

    use super::*;
    use crate::{config::Config, storage::runtime::SharedStorage};

    #[tokio::test]
    async fn invalid_stored_listener_uses_mounted_certificate_and_can_be_reset() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let directory = std::env::temp_dir().join(format!("doorman-tls-recovery-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let cert = directory.join("listener.pem");
        let key = directory.join("listener.key");
        let generated = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost", "-keyout"])
            .arg(&key).arg("-out").arg(&cert)
            .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(generated.success());

        let mut config = Config::for_test(String::new());
        config.downstream_tls_mode = DownstreamTlsMode::Native;
        config.downstream_tls_cert_file = Some(cert);
        config.downstream_tls_key_file = Some(key);
        let storage = Arc::new(SharedStorage::connect(&config.shared_storage).await.unwrap());
        storage.insert_one("tls_profiles", json!({"id": "listener", "kind": "listener", "cert_pem": "invalid", "key_pem": "invalid"})).await.unwrap();
        let mut state = AppState::new(config).unwrap();
        state.storage = Some(storage.clone());

        assert!(state.reload_tls_from_storage().await.unwrap().is_some());
        assert!(!state.tls_listener_from_admin());
        let response = dispatch(&state, "/tls/listener", &Method::DELETE, Value::Null, "test").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(storage.find_one("tls_profiles", &json!({"id": "listener"})).await.unwrap().is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
