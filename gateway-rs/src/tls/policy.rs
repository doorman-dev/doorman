use serde::Deserialize;
use serde_json::Value;
use tokio_rustls::rustls::{pki_types::{CertificateDer, UnixTime}, server::WebPkiClientVerifier};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use super::profiles::TlsProfiles;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientTlsMode {
    #[default]
    Off,
    Optional,
    Required,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTlsPolicy {
    pub mode: ClientTlsMode,
    pub ca_profile_id: Option<String>,
    #[serde(default)]
    pub allowed_dns_sans: Vec<String>,
    #[serde(default)]
    pub allowed_uri_sans: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTlsFailure {
    Missing,
    Invalid,
    Configuration,
}

impl ClientTlsPolicy {
    pub fn validate_value(value: &Value, profiles: &TlsProfiles, native_tls: bool) -> Result<(), ClientTlsFailure> {
        let policy: Self = serde_json::from_value(value.clone()).map_err(|_| ClientTlsFailure::Configuration)?;
        if matches!(policy.mode, ClientTlsMode::Off) {
            return Ok(());
        }
        if !native_tls || policy.ca_profile_id.as_deref().is_none_or(str::is_empty)
            || (policy.allowed_dns_sans.is_empty() && policy.allowed_uri_sans.is_empty())
        {
            return Err(ClientTlsFailure::Configuration);
        }
        if !profiles.client_cas.contains_key(policy.ca_profile_id.as_deref().unwrap_or_default()) {
            return Err(ClientTlsFailure::Configuration);
        }
        if policy.allowed_dns_sans.iter().chain(policy.allowed_uri_sans.iter()).any(|san| san.is_empty() || san.contains('*')) {
            return Err(ClientTlsFailure::Configuration);
        }
        Ok(())
    }

    pub fn from_documents(api: &Value, endpoint: Option<&Value>) -> Result<Self, ClientTlsFailure> {
        let value = endpoint
            .and_then(|endpoint| endpoint.get("endpoint_client_tls_policy"))
            .filter(|value| !value.is_null())
            .or_else(|| api.get("api_client_tls_policy").filter(|value| !value.is_null()));
        let Some(value) = value else { return Ok(Self::default()); };
        let policy: Self = serde_json::from_value(value.clone()).map_err(|_| ClientTlsFailure::Configuration)?;
        if !matches!(policy.mode, ClientTlsMode::Off)
            && (policy.ca_profile_id.as_deref().is_none_or(str::is_empty)
                || (policy.allowed_dns_sans.is_empty() && policy.allowed_uri_sans.is_empty()))
        {
            return Err(ClientTlsFailure::Configuration);
        }
        Ok(policy)
    }

    pub fn enforce(&self, chain: &[Vec<u8>], profiles: &TlsProfiles, native_tls: bool) -> Result<(), ClientTlsFailure> {
        if matches!(self.mode, ClientTlsMode::Off) {
            return Ok(());
        }
        if !native_tls {
            return Err(ClientTlsFailure::Configuration);
        }
        let roots = profiles.client_cas.get(self.ca_profile_id.as_deref().unwrap_or_default())
            .ok_or(ClientTlsFailure::Configuration)?;
        if chain.is_empty() {
            return if matches!(self.mode, ClientTlsMode::Required) { Err(ClientTlsFailure::Missing) } else { Ok(()) };
        }
        let certs: Vec<_> = chain.iter().cloned().map(CertificateDer::from).collect();
        let verifier = WebPkiClientVerifier::builder(roots.clone())
            .build()
            .map_err(|_| ClientTlsFailure::Configuration)?;
        verifier.verify_client_cert(&certs[0], &certs[1..], UnixTime::now())
            .map_err(|_| ClientTlsFailure::Invalid)?;
        let (_, leaf) = parse_x509_certificate(&chain[0]).map_err(|_| ClientTlsFailure::Invalid)?;
        let sans = leaf.subject_alternative_name()
            .map_err(|_| ClientTlsFailure::Invalid)?
            .ok_or(ClientTlsFailure::Invalid)?;
        let allowed = sans.value.general_names.iter().any(|name| match name {
            GeneralName::DNSName(dns) => self.allowed_dns_sans.iter().any(|allowed| allowed.eq_ignore_ascii_case(dns)),
            GeneralName::URI(uri) => self.allowed_uri_sans.iter().any(|allowed| allowed == uri),
            _ => false,
        });
        allowed.then_some(()).ok_or(ClientTlsFailure::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use tokio_rustls::rustls::RootCertStore;

    use super::*;

    #[test]
    fn required_policy_rejects_missing_certificate() {
        let mut profiles = TlsProfiles::default();
        profiles.client_cas.insert("internal".to_owned(), Arc::new(RootCertStore::empty()));
        let policy = ClientTlsPolicy::from_documents(
            &json!({"api_client_tls_policy": {
                "mode": "required", "ca_profile_id": "internal", "allowed_dns_sans": ["client.example"]
            }}),
            None,
        ).unwrap();
        assert_eq!(policy.enforce(&[], &profiles, true), Err(ClientTlsFailure::Missing));
        assert_eq!(policy.enforce(&[], &profiles, false), Err(ClientTlsFailure::Configuration));
    }

    #[test]
    fn endpoint_policy_overrides_api_policy() {
        let mut profiles = TlsProfiles::default();
        profiles.client_cas.insert("internal".to_owned(), Arc::new(RootCertStore::empty()));
        let api = json!({"api_client_tls_policy": {
            "mode": "required", "ca_profile_id": "internal", "allowed_dns_sans": ["client.example"]
        }});
        let endpoint = json!({"endpoint_client_tls_policy": {"mode": "off"}});
        let policy = ClientTlsPolicy::from_documents(&api, Some(&endpoint)).unwrap();
        assert_eq!(policy.enforce(&[], &profiles, true), Ok(()));
        let cleared = json!({"endpoint_client_tls_policy": null});
        let policy = ClientTlsPolicy::from_documents(&api, Some(&cleared)).unwrap();
        assert_eq!(policy.enforce(&[], &profiles, true), Err(ClientTlsFailure::Missing));
    }

    #[test]
    fn configured_policy_requires_native_mode_and_san_allowlist() {
        let mut profiles = TlsProfiles::default();
        profiles.client_cas.insert("internal".to_owned(), Arc::new(RootCertStore::empty()));
        let policy = json!({"mode": "required", "ca_profile_id": "internal", "allowed_uri_sans": ["spiffe://example/client"]});
        assert_eq!(ClientTlsPolicy::validate_value(&policy, &profiles, true), Ok(()));
        assert_eq!(ClientTlsPolicy::validate_value(&policy, &profiles, false), Err(ClientTlsFailure::Configuration));
        assert_eq!(ClientTlsPolicy::validate_value(&json!({"mode": "required", "ca_profile_id": "internal"}), &profiles, true), Err(ClientTlsFailure::Configuration));
    }
}
