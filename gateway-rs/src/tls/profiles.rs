use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use x509_parser::parse_x509_certificate;

use super::secrets;

#[derive(Default)]
pub struct TlsProfiles {
    pub client_cas: HashMap<String, Arc<RootCertStore>>,
    pub upstreams: HashMap<String, UpstreamProfile>,
    client_ca_pem: HashMap<String, Vec<u8>>,
    client_ca_expiries: HashMap<String, i64>,
}

#[derive(Clone)]
pub struct UpstreamProfile {
    pub ca_pem: Vec<u8>,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub server_name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileProfiles {
    #[serde(default)]
    client_ca_profiles: Vec<FileClientCa>,
    #[serde(default)]
    upstream_profiles: Vec<FileUpstream>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileClientCa {
    id: String,
    ca_files: Vec<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpstream {
    id: String,
    #[serde(default)]
    ca_files: Vec<PathBuf>,
    client_cert_file: Option<PathBuf>,
    client_key_file: Option<PathBuf>,
    server_name: Option<String>,
}

#[derive(Debug, Error)]
pub enum TlsProfileError {
    #[error("TLS profile file could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS profile YAML is invalid: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid TLS profile: {0}")]
    Invalid(String),
    #[error("TLS profile secret could not be decrypted: {0}")]
    Secret(#[from] secrets::TlsSecretError),
}

impl TlsProfiles {
    pub fn load_file(path: Option<&Path>) -> Result<Self, TlsProfileError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let input: FileProfiles = serde_yaml::from_slice(&fs::read(path)?)?;
        let mut profiles = Self::default();
        let mut ids = HashSet::new();
        for entry in input.client_ca_profiles {
            validate_id(&entry.id, &mut ids)?;
            if entry.ca_files.is_empty() {
                return Err(TlsProfileError::Invalid(format!(
                    "{} has no CA files",
                    entry.id
                )));
            }
            let ca_pem = read_pem_files(&entry.ca_files)?;
            let expiry = crate::tls::certificate_expiry_timestamp(&ca_pem)?;
            profiles
                .client_cas
                .insert(entry.id.clone(), Arc::new(load_roots(&entry.ca_files)?));
            profiles.client_ca_pem.insert(entry.id.clone(), ca_pem);
            profiles.client_ca_expiries.insert(entry.id, expiry);
        }
        for entry in input.upstream_profiles {
            validate_id(&entry.id, &mut ids)?;
            if entry.client_cert_file.is_some() != entry.client_key_file.is_some() {
                return Err(TlsProfileError::Invalid(format!(
                    "{} needs both client certificate and key",
                    entry.id
                )));
            }
            if let Some(server_name) = &entry.server_name {
                if server_name.is_empty() || server_name.contains('/') || server_name.contains(':')
                {
                    return Err(TlsProfileError::Invalid(format!(
                        "{} has invalid server name",
                        entry.id
                    )));
                }
            }
            let ca_pem = read_pem_files(&entry.ca_files)?;
            if !entry.ca_files.is_empty() {
                load_roots(&entry.ca_files)?;
            }
            let client_cert_pem = entry.client_cert_file.map(fs::read).transpose()?;
            let client_key_pem = entry.client_key_file.map(fs::read).transpose()?;
            if let (Some(cert), Some(key)) = (&client_cert_pem, &client_key_pem) {
                validate_identity_certificate(cert, key)?;
            }
            profiles.upstreams.insert(
                entry.id,
                UpstreamProfile {
                    ca_pem,
                    client_cert_pem,
                    client_key_pem,
                    server_name: entry.server_name,
                },
            );
        }
        if profiles.client_cas.len() + profiles.upstreams.len() > 128 {
            return Err(TlsProfileError::Invalid(
                "at most 128 TLS profiles are supported".to_owned(),
            ));
        }
        Ok(profiles)
    }

    pub fn combined_client_roots(&self) -> RootCertStore {
        let mut combined = RootCertStore::empty();
        for roots in self.client_cas.values() {
            combined.roots.extend(roots.roots.iter().cloned());
        }
        combined
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut client_ids: Vec<_> = self.client_cas.keys().collect();
        client_ids.sort();
        for id in client_ids {
            hasher.update(b"client_ca");
            hasher.update(id.as_bytes());
            if let Some(pem) = self.client_ca_pem.get(id) {
                hasher.update(pem);
            }
            for root in &self.client_cas[id].roots {
                hasher.update(root.subject.as_ref());
                hasher.update(root.subject_public_key_info.as_ref());
            }
        }
        let mut upstream_ids: Vec<_> = self.upstreams.keys().collect();
        upstream_ids.sort();
        for id in upstream_ids {
            let profile = &self.upstreams[id];
            hasher.update(b"upstream");
            hasher.update(id.as_bytes());
            hasher.update(&profile.ca_pem);
            if let Some(cert) = &profile.client_cert_pem {
                hasher.update(cert);
            }
            if let Some(key) = &profile.client_key_pem {
                hasher.update(key);
            }
            if let Some(name) = &profile.server_name {
                hasher.update(name.as_bytes());
            }
        }
        hasher.finalize().into()
    }

    pub fn certificate_expiries(&self) -> std::collections::BTreeMap<String, i64> {
        let mut expiries = std::collections::BTreeMap::new();
        for (id, expiry) in &self.client_ca_expiries {
            expiries.insert(format!("client_ca/{id}"), *expiry);
        }
        for (id, profile) in &self.upstreams {
            let mut expiry = None;
            for pem in [Some(&profile.ca_pem), profile.client_cert_pem.as_ref()] {
                if let Some(pem) = pem.filter(|pem| !pem.is_empty()) {
                    if let Ok(value) = crate::tls::certificate_expiry_timestamp(pem) {
                        expiry = Some(expiry.map_or(value, |prior: i64| prior.min(value)));
                    }
                }
            }
            if let Some(expiry) = expiry {
                expiries.insert(format!("upstream/{id}"), expiry);
            }
        }
        expiries
    }

    pub fn merge_admin_documents(&mut self, documents: &[Value]) -> Result<(), TlsProfileError> {
        for document in documents {
            let id = document.get("id").and_then(Value::as_str).ok_or_else(|| {
                TlsProfileError::Invalid("admin TLS profile has no ID".to_owned())
            })?;
            let mut ids = self
                .client_cas
                .keys()
                .chain(self.upstreams.keys())
                .cloned()
                .collect();
            validate_id(id, &mut ids)?;
            let kind = document
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| TlsProfileError::Invalid(format!("{id} has no kind")))?;
            let decrypt = |field: &str| -> Result<Option<Vec<u8>>, TlsProfileError> {
                document
                    .get(field)
                    .and_then(Value::as_str)
                    .map(|sealed| secrets::open(id, field, sealed).map_err(TlsProfileError::from))
                    .transpose()
            };
            match kind {
                "client_ca" => {
                    let pem = decrypt("ca_pem")?.ok_or_else(|| {
                        TlsProfileError::Invalid(format!("{id} has no CA bundle"))
                    })?;
                    let expiry = crate::tls::certificate_expiry_timestamp(&pem)?;
                    self.client_cas
                        .insert(id.to_owned(), Arc::new(roots_from_pem(&pem)?));
                    self.client_ca_pem.insert(id.to_owned(), pem);
                    self.client_ca_expiries.insert(id.to_owned(), expiry);
                }
                "upstream" => {
                    let ca_pem = decrypt("ca_pem")?.unwrap_or_default();
                    if !ca_pem.is_empty() {
                        roots_from_pem(&ca_pem)?;
                    }
                    let client_cert_pem = decrypt("cert_pem")?;
                    let client_key_pem = decrypt("key_pem")?;
                    if client_cert_pem.is_some() != client_key_pem.is_some() {
                        return Err(TlsProfileError::Invalid(format!(
                            "{id} needs both client certificate and key"
                        )));
                    }
                    if let (Some(cert), Some(key)) = (&client_cert_pem, &client_key_pem) {
                        validate_identity_certificate(cert, key)?;
                    }
                    let server_name = document
                        .get("server_name")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if server_name.as_deref().is_some_and(|name| {
                        name.is_empty() || name.contains('/') || name.contains(':')
                    }) {
                        return Err(TlsProfileError::Invalid(format!(
                            "{id} has invalid server name"
                        )));
                    }
                    self.upstreams.insert(
                        id.to_owned(),
                        UpstreamProfile {
                            ca_pem,
                            client_cert_pem,
                            client_key_pem,
                            server_name,
                        },
                    );
                }
                "listener" => {}
                _ => return Err(TlsProfileError::Invalid(format!("{id} has invalid kind"))),
            }
        }
        if self.client_cas.len() + self.upstreams.len() > 128 {
            return Err(TlsProfileError::Invalid(
                "at most 128 TLS profiles are supported".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn select_upstream_profile(
    api: &Value,
    endpoint: Option<&Value>,
    upstream: &str,
) -> Result<Option<String>, TlsProfileError> {
    let url = url::Url::parse(upstream)
        .map_err(|_| TlsProfileError::Invalid("upstream URL is invalid".to_owned()))?;
    let host = url
        .host_str()
        .ok_or_else(|| TlsProfileError::Invalid("upstream host is missing".to_owned()))?;
    let port = url
        .port()
        .or_else(|| match url.scheme() {
            "https" | "grpcs" => Some(443),
            "http" | "grpc" => Some(80),
            _ => None,
        })
        .ok_or_else(|| TlsProfileError::Invalid("upstream port is missing".to_owned()))?;
    let origin = format!("{}://{}:{}", url.scheme(), host.to_ascii_lowercase(), port);
    for (document, field) in [
        (endpoint, "endpoint_upstream_tls_profiles"),
        (Some(api), "api_upstream_tls_profiles"),
    ] {
        if let Some(map) = document
            .and_then(|document| document.get(field))
            .filter(|value| !value.is_null())
        {
            let entries = map
                .as_object()
                .ok_or_else(|| TlsProfileError::Invalid(format!("{field} must be an object")))?;
            for (key, value) in entries {
                let key_url = url::Url::parse(key).map_err(|_| {
                    TlsProfileError::Invalid(format!("invalid upstream TLS binding: {key}"))
                })?;
                let key_host = key_url.host_str().ok_or_else(|| {
                    TlsProfileError::Invalid(format!("invalid upstream TLS binding: {key}"))
                })?;
                let key_port = key_url
                    .port()
                    .or_else(|| match key_url.scheme() {
                        "https" | "grpcs" => Some(443),
                        "http" | "grpc" => Some(80),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        TlsProfileError::Invalid(format!("invalid upstream TLS binding: {key}"))
                    })?;
                if format!(
                    "{}://{}:{}",
                    key_url.scheme(),
                    key_host.to_ascii_lowercase(),
                    key_port
                ) == origin
                {
                    return value.as_str().map(|id| Some(id.to_owned())).ok_or_else(|| {
                        TlsProfileError::Invalid(format!("{field} profile ID must be a string"))
                    });
                }
            }
        }
    }
    for (document, field) in [
        (endpoint, "endpoint_upstream_tls_profile"),
        (Some(api), "api_upstream_tls_profile"),
    ] {
        if let Some(value) = document
            .and_then(|document| document.get(field))
            .filter(|value| !value.is_null())
        {
            return value
                .as_str()
                .map(|id| Some(id.to_owned()))
                .ok_or_else(|| TlsProfileError::Invalid(format!("{field} must be a string")));
        }
    }
    Ok(None)
}

pub fn validate_upstream_bindings(
    document: &Value,
    prefix: &str,
    profiles: &TlsProfiles,
) -> Result<(), TlsProfileError> {
    let default_field = format!("{prefix}_upstream_tls_profile");
    if let Some(value) = document
        .get(&default_field)
        .filter(|value| !value.is_null())
    {
        let id = value
            .as_str()
            .ok_or_else(|| TlsProfileError::Invalid(format!("{default_field} must be a string")))?;
        if !profiles.upstreams.contains_key(id) {
            return Err(TlsProfileError::Invalid(format!(
                "unknown upstream TLS profile: {id}"
            )));
        }
    }
    let map_field = format!("{prefix}_upstream_tls_profiles");
    if let Some(value) = document.get(&map_field).filter(|value| !value.is_null()) {
        let map = value
            .as_object()
            .ok_or_else(|| TlsProfileError::Invalid(format!("{map_field} must be an object")))?;
        for (origin, id) in map {
            let url = url::Url::parse(origin)
                .map_err(|_| TlsProfileError::Invalid(format!("invalid TLS origin: {origin}")))?;
            if !matches!(url.scheme(), "https" | "grpcs")
                || url.host_str().is_none()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(TlsProfileError::Invalid(format!(
                    "TLS binding requires an HTTPS/grpcs origin: {origin}"
                )));
            }
            let id = id.as_str().ok_or_else(|| {
                TlsProfileError::Invalid(format!("{map_field} profile ID must be a string"))
            })?;
            if !profiles.upstreams.contains_key(id) {
                return Err(TlsProfileError::Invalid(format!(
                    "unknown upstream TLS profile: {id}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_id(id: &str, ids: &mut HashSet<String>) -> Result<(), TlsProfileError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        return Err(TlsProfileError::Invalid(format!(
            "invalid profile ID: {id}"
        )));
    }
    if !ids.insert(id.to_owned()) {
        return Err(TlsProfileError::Invalid(format!(
            "duplicate profile ID: {id}"
        )));
    }
    Ok(())
}

fn read_pem_files(paths: &[PathBuf]) -> Result<Vec<u8>, TlsProfileError> {
    let mut pem = Vec::new();
    for path in paths {
        pem.extend_from_slice(&fs::read(path)?);
        pem.push(b'\n');
    }
    Ok(pem)
}

fn load_roots(paths: &[PathBuf]) -> Result<RootCertStore, TlsProfileError> {
    let mut roots = RootCertStore::empty();
    for path in paths {
        let pem = fs::read(path)?;
        let loaded = roots_from_pem(&pem)?;
        roots.roots.extend(loaded.roots);
    }
    Ok(roots)
}

fn roots_from_pem(pem: &[u8]) -> Result<RootCertStore, TlsProfileError> {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsProfileError::Invalid(error.to_string()))?;
    if certs.is_empty() {
        return Err(TlsProfileError::Invalid(
            "CA bundle contains no certificates".to_owned(),
        ));
    }
    for cert in certs {
        let (_, parsed) = parse_x509_certificate(cert.as_ref())
            .map_err(|_| TlsProfileError::Invalid("CA certificate is not X.509".to_owned()))?;
        if !parsed.validity().is_valid() {
            return Err(TlsProfileError::Invalid(
                "CA certificate is not currently valid".to_owned(),
            ));
        }
        roots
            .add(cert)
            .map_err(|error| TlsProfileError::Invalid(error.to_string()))?;
    }
    Ok(roots)
}

fn validate_identity_certificate(pem: &[u8], key_pem: &[u8]) -> Result<(), TlsProfileError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsProfileError::Invalid(error.to_string()))?;
    let cert = certs
        .first()
        .ok_or_else(|| TlsProfileError::Invalid("client certificate is missing".to_owned()))?;
    let (_, parsed) = parse_x509_certificate(cert.as_ref())
        .map_err(|_| TlsProfileError::Invalid("client certificate is not X.509".to_owned()))?;
    if !parsed.validity().is_valid() {
        return Err(TlsProfileError::Invalid(
            "client certificate is not currently valid".to_owned(),
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|error| TlsProfileError::Invalid(error.to_string()))?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| {
            TlsProfileError::Invalid(format!("client certificate/key mismatch: {error}"))
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn renewed_client_ca_material_changes_fingerprint() {
        let mut profiles = TlsProfiles::default();
        profiles
            .client_cas
            .insert("internal".to_owned(), Arc::new(RootCertStore::empty()));
        profiles
            .client_ca_pem
            .insert("internal".to_owned(), b"original certificate".to_vec());
        let original = profiles.fingerprint();
        profiles.client_ca_pem.insert(
            "internal".to_owned(),
            b"renewed certificate with the same trust key".to_vec(),
        );
        assert_ne!(profiles.fingerprint(), original);
    }

    #[test]
    fn endpoint_origin_binding_precedes_api_default() {
        let api = json!({"api_upstream_tls_profile": "api-default"});
        let endpoint =
            json!({"endpoint_upstream_tls_profiles": {"https://service.example:443": "endpoint"}});
        assert_eq!(
            select_upstream_profile(&api, Some(&endpoint), "https://service.example/path").unwrap(),
            Some("endpoint".to_owned()),
        );
        let cleared =
            json!({"endpoint_upstream_tls_profile": null, "endpoint_upstream_tls_profiles": null});
        assert_eq!(
            select_upstream_profile(&api, Some(&cleared), "https://service.example/path").unwrap(),
            Some("api-default".to_owned()),
        );
        assert_eq!(
            select_upstream_profile(
                &json!({"api_upstream_tls_profile": null}),
                None,
                "https://service.example/path"
            )
            .unwrap(),
            None,
        );
    }

    #[test]
    fn bindings_reject_plaintext_origins_and_unknown_profiles() {
        let profiles = TlsProfiles::default();
        assert!(
            validate_upstream_bindings(
                &json!({"api_upstream_tls_profiles": {"http://service.example": "missing"}}),
                "api",
                &profiles,
            )
            .is_err()
        );
        assert!(
            validate_upstream_bindings(
                &json!({"api_upstream_tls_profile": "missing"}),
                "api",
                &profiles,
            )
            .is_err()
        );
    }
}
