use std::{env, net::IpAddr};

use http::{HeaderMap, Method, StatusCode};
use serde_json::Value;

use super::{
    PolicyDecision, PolicyFailure, PolicyStage,
    auth::verify_request_token,
    bandwidth::enforce_pre_request_limit,
    credits::evaluate_credits,
    groups::enforce_group_access,
    ip::enforce_configured_api_ip_policy,
    rate_limit::enforce_rate_limit,
    roles::enforce_allowed_roles,
    subscription::enforce_subscription,
    throttle::{enforce_throttle, throttle_wait_millis},
};
use crate::{
    config::SharedStorageConfig,
    gateway::{
        resolution::{endpoint_pattern_matches, resolve_rest_path},
        routing::select_upstream,
    },
    storage::{
        cache::{TokenBucketCounter, WindowCounter},
        models::{
            PolicyDocuments, bool_field, bool_field_default, find_api, find_endpoint, string_field,
            u64_field,
        },
        redis::{bandwidth_key, rate_limit_key, throttle_key},
        runtime::SharedStorage,
    },
    tls::{
        policy::{ClientTlsFailure, ClientTlsPolicy},
        profiles::{TlsProfiles, select_upstream_profile},
    },
};

#[derive(Clone, Debug)]
pub struct PolicyRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub direct_ip: Option<IpAddr>,
    pub now_millis: u64,
    pub content_length: u64,
    pub peer_certificates: Vec<Vec<u8>>,
    pub native_tls: bool,
    pub is_preflight: bool,
    /// The pinned group check resolves a gRPC API under `X-API-Version`
    /// defaulting to `v0`, so a request without the header fails it.
    pub group_version_missing: bool,
    /// The pinned REST route matches the endpoint before authenticating
    /// (GTW003, even when the API has no endpoints at all).
    pub route_endpoint_check: bool,
    /// Only the pinned REST and SOAP gateways require a registered endpoint;
    /// GraphQL and gRPC forward any call for an existing API.
    pub endpoint_required: bool,
}

#[derive(Clone, Default)]
pub struct PolicyRuntime {
    pub rate_counter: WindowCounter,
    pub rate_bucket_counter: TokenBucketCounter,
    pub throttle_counter: WindowCounter,
    pub bandwidth_counter: WindowCounter,
    pub tls_profiles: std::sync::Arc<TlsProfiles>,
}

pub fn evaluate_rest_policy(
    documents: &mut PolicyDocuments,
    request: &PolicyRequest,
    storage_config: &SharedStorageConfig,
    runtime: &PolicyRuntime,
) -> Result<Option<PolicyDecision>, PolicyFailure> {
    match evaluate_rest_policy_staged(documents, request, storage_config, runtime)? {
        Some(decision) if decision.deferred_failure.is_some() => {
            Err(decision.deferred_failure.expect("checked above"))
        }
        other => Ok(other),
    }
}

/// Evaluates in the pinned order: IP policy and CORS preflight, then the
/// route-level identity checks for private APIs (authentication, subscription,
/// group, user limits), and only then the service-level checks (API active,
/// endpoint existence, credits).  A service-level failure is returned as
/// `deferred_failure` so the caller can first apply the tier limits that the
/// pinned middleware enforces ahead of every route.
pub fn evaluate_rest_policy_staged(
    documents: &mut PolicyDocuments,
    request: &PolicyRequest,
    storage_config: &SharedStorageConfig,
    runtime: &PolicyRuntime,
) -> Result<Option<PolicyDecision>, PolicyFailure> {
    let Some(route) = resolve_rest_path(&request.path, &request.headers) else {
        return Ok(None);
    };
    let Some(api) = find_api(&documents.apis, &route.api_name, &route.api_version).cloned() else {
        return Ok(None);
    };
    let settings = documents
        .settings
        .iter()
        .find(|settings| settings.get("type").and_then(Value::as_str) == Some("security_settings"));
    enforce_configured_api_ip_policy(
        &api,
        settings,
        &request.headers,
        request.direct_ip,
        storage_config,
    )?;

    if request
        .headers
        .contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        return Ok(Some(PolicyDecision {
            route: Some("gateway.rest.preflight".to_owned()),
            api_id: string_field(&api, "api_id").map(str::to_owned),
            api_name: string_field(&api, "api_name").map(str::to_owned),
            cors_allow_origins: optional_string_list(&api, "api_cors_allow_origins"),
            cors_allow_methods: optional_string_list(&api, "api_cors_allow_methods"),
            cors_allow_headers: optional_string_list(&api, "api_cors_allow_headers"),
            cors_allow_credentials: bool_field_default(&api, "api_cors_allow_credentials", false),
            cors_expose_headers: crate::storage::models::string_list_field(
                &api,
                "api_cors_expose_headers",
            ),
            ..Default::default()
        }));
    }
    let method = if request.method == Method::HEAD {
        "GET"
    } else {
        request.method.as_str()
    };
    if request.route_endpoint_check
        && !endpoint_exists(&documents.endpoints, &api, method, &route.endpoint_uri)
    {
        return Ok(Some(PolicyDecision {
            deferred_failure: Some(PolicyFailure::new(
                PolicyStage::Resolution,
                StatusCode::NOT_FOUND,
                "GTW003",
                "Endpoint does not exist for the requested API",
            )),
            ..Default::default()
        }));
    }
    let api_public = bool_field(&api, "api_public").unwrap_or(false);
    let api_auth_required = bool_field(&api, "api_auth_required").unwrap_or(true);
    let mut authenticated: Option<(String, Option<u64>)> = None;
    if !api_public && api_auth_required {
        let claims = verify_request_token(&request.headers, storage_config)?;
        let username = claims.sub.as_deref().unwrap_or_default();
        if is_revoked(&documents.revocations, username, claims.jti.as_deref()) {
            // auth_required's broad except re-raises every failure as a bare Unauthorized.
            return Err(super::auth::unauthorized("Unauthorized"));
        }
        let user = documents
            .users
            .iter()
            .find(|item| string_field(item, "username") == Some(username))
            .cloned()
            .ok_or_else(|| {
                PolicyFailure::new(
                    PolicyStage::Authentication,
                    StatusCode::NOT_FOUND,
                    "User not found",
                    "User not found",
                )
            })?;
        if bool_field(&user, "active") == Some(false) {
            return Err(super::auth::unauthorized("Unauthorized"));
        }

        let enforce_admin_sub = std::env::var("ENFORCE_ADMIN_SUBSCRIPTION")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or_else(|_| {
                api.get("enforce_admin_subscription")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });

        enforce_subscription(
            &format!("{}/{}", route.api_name, route.api_version),
            &user,
            &documents.roles,
            &documents.subscriptions,
            enforce_admin_sub,
        )?;
        if request.group_version_missing {
            return Err(PolicyFailure::new(
                PolicyStage::Group,
                StatusCode::NOT_FOUND,
                "API not found",
                "API not found",
            ));
        }
        enforce_group_access(&api, &user)?;
        enforce_rate_limit(
            username,
            &user,
            &runtime.rate_counter,
            &runtime.rate_bucket_counter,
            request.now_millis,
        )?;
        let throttle = enforce_throttle(
            username,
            &user,
            &runtime.throttle_counter,
            request.now_millis,
        )?;
        enforce_allowed_roles(&api, &user)?;
        enforce_pre_request_limit(
            username,
            &user,
            &runtime.bandwidth_counter,
            request.now_millis / 1000,
            request.content_length,
        )?;
        authenticated = Some((username.to_owned(), throttle.delay_ms));
    }

    let deferred = if bool_field(&api, "active") == Some(false) {
        Some(PolicyFailure::new(
            PolicyStage::Resolution,
            StatusCode::FORBIDDEN,
            "GTW012",
            "API is disabled",
        ))
    } else if request.endpoint_required
        && !documents
            .endpoints
            .iter()
            .any(|endpoint| endpoint_belongs_to_api(endpoint, &api))
    {
        Some(PolicyFailure::new(
            PolicyStage::Resolution,
            StatusCode::NOT_FOUND,
            "GTW002",
            "No endpoints found for the requested API",
        ))
    } else if request.endpoint_required
        && !endpoint_exists(&documents.endpoints, &api, method, &route.endpoint_uri)
    {
        Some(PolicyFailure::new(
            PolicyStage::Resolution,
            StatusCode::NOT_FOUND,
            "GTW003",
            "Endpoint does not exist for the requested API",
        ))
    } else {
        None
    };
    let username = authenticated.as_ref().map(|(name, _)| name.clone());
    let tier_username = username.clone().or_else(|| {
        verify_request_token(&request.headers, storage_config)
            .ok()
            .and_then(|claims| claims.sub)
    });
    if let Some(failure) = deferred {
        return Ok(Some(PolicyDecision {
            username,
            tier_username,
            tier_rate_limit_enabled: !storage_config.skip_tier_rate_limit,
            deferred_failure: Some(failure),
            ..Default::default()
        }));
    }
    let endpoint = find_endpoint(&documents.endpoints, &api, method, &route.endpoint_uri).cloned();
    if !request.is_preflight {
        let policy =
            ClientTlsPolicy::from_documents(&api, endpoint.as_ref()).map_err(client_tls_failure)?;
        policy
            .enforce(
                &request.peer_certificates,
                &runtime.tls_profiles,
                request.native_tls,
            )
            .map_err(client_tls_failure)?;
    }

    let endpoint_id = endpoint
        .as_ref()
        .and_then(|item| string_field(item, "endpoint_id"));
    let endpoint_validation = endpoint_id.and_then(|endpoint_id| {
        documents
            .endpoint_validations
            .iter()
            .find(|validation| {
                string_field(validation, "endpoint_id") == Some(endpoint_id)
                    && bool_field_default(validation, "validation_enabled", false)
            })
            .and_then(|validation| validation.get("validation_schema"))
            .cloned()
    });
    let mut decision = PolicyDecision {
        route: Some("gateway.rest".to_owned()),
        api_id: string_field(&api, "api_id").map(str::to_owned),
        api_name: string_field(&api, "api_name").map(str::to_owned),
        endpoint_id: endpoint_id.map(str::to_owned),
        upstream_path: Some(
            endpoint
                .as_ref()
                .and_then(|item| string_field(item, "endpoint_uri"))
                .unwrap_or(&route.endpoint_uri)
                .to_owned(),
        ),
        allowed_headers: crate::storage::models::string_list_field(&api, "api_allowed_headers"),
        retry_count: u64_field(&api, "api_allowed_retry_count")
            .unwrap_or(0)
            .min(10) as u32,
        request_timeout_ms: api
            .get("api_read_timeout")
            .and_then(Value::as_f64)
            .map(|seconds| (seconds.max(0.001) * 1000.0) as u64)
            .unwrap_or_else(default_http_read_timeout_ms),
        graphql_max_depth: u64_field(&api, "api_graphql_max_depth").unwrap_or(10),
        authorization_field_swap: string_field(&api, "api_authorization_field_swap")
            .map(str::to_owned),
        endpoint_validation,
        cors_allow_origins: optional_string_list(&api, "api_cors_allow_origins"),
        cors_allow_methods: optional_string_list(&api, "api_cors_allow_methods"),
        cors_allow_headers: optional_string_list(&api, "api_cors_allow_headers"),
        cors_allow_credentials: bool_field_default(&api, "api_cors_allow_credentials", false),
        cors_expose_headers: crate::storage::models::string_list_field(
            &api,
            "api_cors_expose_headers",
        ),
        request_transform: api.get("api_request_transform").cloned(),
        response_transform: api.get("api_response_transform").cloned(),
        soap_version: string_field(&api, "api_soap_version").map(str::to_owned),
        ws_security: api.get("api_ws_security").cloned(),
        grpc_web_enabled: bool_field_default(&api, "api_grpc_web_enabled", false),
        grpc_descriptor_set: string_field(&api, "api_grpc_descriptor_set").map(str::to_owned),
        grpc_package: string_field(&api, "api_grpc_package").map(str::to_owned),
        grpc_allowed_packages: crate::storage::models::string_list_field(
            &api,
            "api_grpc_allowed_packages",
        ),
        grpc_allowed_services: crate::storage::models::string_list_field(
            &api,
            "api_grpc_allowed_services",
        ),
        grpc_allowed_methods: crate::storage::models::string_list_field(
            &api,
            "api_grpc_allowed_methods",
        ),
        tier_rate_limit_enabled: !storage_config.skip_tier_rate_limit,
        is_crud: bool_field_default(&api, "api_is_crud", false),
        crud_collection: string_field(&api, "api_crud_collection")
            .map(str::to_owned)
            .or_else(|| {
                bool_field_default(&api, "api_is_crud", false).then(|| {
                    format!(
                        "crud_data_{}",
                        string_field(&api, "api_id")
                            .unwrap_or("default")
                            .replace('-', "_")
                    )
                })
            }),
        crud_schema: api.get("api_crud_schema").cloned(),
        ..Default::default()
    };

    if let Some((username, throttle_delay_ms)) = authenticated {
        let credit = evaluate_credits(
            &api,
            Some(&username),
            &documents.credit_defs,
            &documents.user_credits,
        )?;
        decision.throttle_delay_ms = throttle_delay_ms;
        decision.credit_required = credit.required;
        decision.credit_group = string_field(&api, "api_credit_group").map(str::to_owned);
        decision.credit_header_name = credit.header_name;
        decision.credit_header_value = credit.header_value;
        decision.user_credit_header_value = credit.user_header_value;
        decision.username = Some(username);
    }
    decision.tier_username = tier_username;

    let client_key = request
        .headers
        .get("client-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(upstream) = select_upstream(
        documents,
        &api,
        endpoint.as_ref(),
        method,
        &route.endpoint_uri,
        client_key,
    ) {
        let profile =
            select_upstream_profile(&api, endpoint.as_ref(), &upstream.url).map_err(|_| {
                PolicyFailure::new(
                    PolicyStage::Resolution,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TLS004",
                    "Upstream TLS binding is invalid",
                )
            })?;
        if let Some(id) = profile.as_deref() {
            if !matches!(
                url::Url::parse(&upstream.url)
                    .ok()
                    .map(|url| url.scheme().to_owned())
                    .as_deref(),
                Some("https" | "grpcs")
            ) || !runtime.tls_profiles.upstreams.contains_key(id)
            {
                return Err(PolicyFailure::new(
                    PolicyStage::Resolution,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "TLS004",
                    "Upstream TLS profile is unavailable",
                ));
            }
        }
        decision.upstream_tls_profile_id = profile;
        decision.upstream = Some(upstream.url);
        decision.routing_key = Some(upstream.key);
        decision.routing_servers = upstream.servers;
        decision.routing_cache_value = upstream.cache_value;
    }

    Ok(Some(decision))
}

fn client_tls_failure(failure: ClientTlsFailure) -> PolicyFailure {
    let (status, code, message) = match failure {
        ClientTlsFailure::Missing => (
            StatusCode::UNAUTHORIZED,
            "TLS001",
            "Client certificate required",
        ),
        ClientTlsFailure::Invalid => (
            StatusCode::FORBIDDEN,
            "TLS002",
            "Client certificate is not authorized",
        ),
        ClientTlsFailure::Configuration => (
            StatusCode::SERVICE_UNAVAILABLE,
            "TLS003",
            "Client TLS policy is unavailable",
        ),
    };
    PolicyFailure::new(PolicyStage::Authentication, status, code, message)
}

fn default_http_read_timeout_ms() -> u64 {
    env::var("HTTP_READ_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(|seconds| (seconds * 1000.0) as u64)
        .unwrap_or(30_000)
}

pub async fn evaluate_shared_effects(
    documents: &PolicyDocuments,
    request: &PolicyRequest,
    decision: &mut PolicyDecision,
    storage: &SharedStorage,
    mutate: bool,
) -> Result<(), PolicyFailure> {
    if decision.tier_rate_limit_enabled
        && let Some(username) = decision.tier_username.as_deref()
    {
        decision.tier_limit_status = super::tier::enforce(
            documents,
            storage,
            username,
            request.now_millis / 1_000,
            mutate,
        )
        .await?;
    }

    if let Some(username) = decision.username.as_deref() {
        let user = documents
            .users
            .iter()
            .find(|item| string_field(item, "username") == Some(username))
            .ok_or_else(|| {
                PolicyFailure::new(
                    PolicyStage::Authentication,
                    StatusCode::NOT_FOUND,
                    "User not found",
                    "User not found",
                )
            })?;

        let rate_enabled = bool_field_default(user, "rate_limit_enabled", false)
            || super::rate_limit::truthy_count(user, "rate_limit_duration").is_some();
        if rate_enabled {
            let limit = super::rate_limit::truthy_count(user, "rate_limit_duration").unwrap_or(60);
            let window = super::rate_limit::duration_to_seconds(
                string_field(user, "rate_limit_duration_type").unwrap_or("minute"),
            )
            .max(1);
            let key = rate_limit_key(username, request.now_millis / (window * 1000));
            let count = shared_counter(storage, &key, window, mutate).await?;
            if count > limit {
                return Err(PolicyFailure::new(
                    PolicyStage::RateLimit,
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded",
                    "Rate limit exceeded",
                ));
            }
        }

        let throttle_enabled = bool_field_default(user, "throttle_enabled", false)
            || super::rate_limit::truthy_count(user, "throttle_duration").is_some()
            || super::rate_limit::truthy_count(user, "throttle_queue_limit").is_some();
        if throttle_enabled {
            let limit = super::rate_limit::truthy_count(user, "throttle_duration").unwrap_or(10);
            let window = super::rate_limit::duration_to_seconds(
                string_field(user, "throttle_duration_type").unwrap_or("second"),
            )
            .max(1);
            let key = throttle_key(username, request.now_millis / (window * 1000));
            let count = shared_counter(storage, &key, window, mutate).await?;
            let queue_limit =
                super::rate_limit::truthy_count(user, "throttle_queue_limit").unwrap_or(10);
            let excess = count.saturating_sub(limit);
            if queue_limit > 0 && (count > queue_limit || excess > queue_limit) {
                return Err(PolicyFailure::new(
                    PolicyStage::Throttle,
                    StatusCode::TOO_MANY_REQUESTS,
                    "Throttle queue limit exceeded",
                    "Throttle queue limit exceeded",
                ));
            }
            if count > limit {
                decision.throttle_delay_ms = Some(throttle_wait_millis(user, excess));
            }
        }

        if bool_field(user, "bandwidth_limit_enabled") != Some(false) {
            if let Some(limit) = u64_field(user, "bandwidth_limit_bytes").filter(|limit| *limit > 0)
            {
                let window = super::bandwidth::window_seconds(
                    string_field(user, "bandwidth_limit_window").unwrap_or("day"),
                );
                let now_seconds = request.now_millis / 1000;
                let bucket = (now_seconds / window) * window;
                let key = bandwidth_key(username, window, bucket);
                let used = storage
                    .current_counter(&key)
                    .await
                    .map_err(storage_failure)?;
                let total = used.saturating_add(request.content_length);
                decision.bandwidth_key = Some(key);
                decision.bandwidth_ttl_seconds = Some(window);
                if used >= limit || total > limit {
                    return Err(PolicyFailure::new(
                        PolicyStage::Bandwidth,
                        StatusCode::TOO_MANY_REQUESTS,
                        "Bandwidth limit exceeded",
                        "Bandwidth limit exceeded",
                    ));
                }
            }
        }

        if mutate && decision.credit_required {
            let group = decision.credit_group.as_deref().unwrap_or_default();
            if group.is_empty()
                || !storage
                    .deduct_credit(username, group)
                    .await
                    .map_err(storage_failure)?
            {
                return Err(PolicyFailure::new(
                    PolicyStage::Credits,
                    StatusCode::UNAUTHORIZED,
                    "GTW008",
                    "User does not have any credits",
                ));
            }
        }
    }

    if let (Some(key), true) = (
        decision.routing_key.as_deref(),
        decision.routing_servers.is_empty(),
    ) {
        tracing::warn!(routing_key = key, "routing intent has no servers");
    } else if let Some(key) = decision.routing_key.as_deref() {
        let index = if let Some(initial) = decision.routing_cache_value.as_ref() {
            if mutate {
                storage
                    .next_client_routing_index(key, initial, decision.routing_servers.len())
                    .await
            } else {
                storage.current_client_routing_index(key, initial).await
            }
        } else if mutate {
            storage
                .next_routing_index(key, decision.routing_servers.len())
                .await
        } else {
            storage.current_routing_index(key).await
        }
        .map_err(storage_failure)?;
        decision.upstream = decision
            .routing_servers
            .get(index % decision.routing_servers.len())
            .cloned();
    }

    Ok(())
}

async fn shared_counter(
    storage: &SharedStorage,
    key: &str,
    ttl_seconds: u64,
    mutate: bool,
) -> Result<u64, PolicyFailure> {
    if mutate {
        storage
            .increment_window(key, ttl_seconds)
            .await
            .map_err(storage_failure)
    } else {
        storage
            .current_counter(key)
            .await
            .map(|count| count.saturating_add(1))
            .map_err(storage_failure)
    }
}

fn storage_failure(error: crate::storage::runtime::StorageError) -> PolicyFailure {
    tracing::error!(error = %error, "shared policy storage operation failed");
    PolicyFailure::new(
        PolicyStage::Resolution,
        StatusCode::SERVICE_UNAVAILABLE,
        "GTW006",
        "Gateway state store unavailable",
    )
}

fn endpoint_exists(endpoints: &[Value], api: &Value, method: &str, endpoint_uri: &str) -> bool {
    endpoints.iter().any(|endpoint| {
        let same_api = endpoint_belongs_to_api(endpoint, api);
        let same_method = string_field(endpoint, "endpoint_method")
            .is_some_and(|actual| actual.eq_ignore_ascii_case(method));
        let uri =
            string_field(endpoint, "client_uri").or_else(|| string_field(endpoint, "endpoint_uri"));
        same_api
            && same_method
            && uri.is_some_and(|pattern| endpoint_pattern_matches(pattern, endpoint_uri))
    })
}

fn endpoint_belongs_to_api(endpoint: &Value, api: &Value) -> bool {
    match (
        string_field(endpoint, "api_id"),
        string_field(api, "api_id"),
    ) {
        (Some(endpoint_id), Some(api_id)) => endpoint_id == api_id,
        _ => {
            string_field(endpoint, "api_name") == string_field(api, "api_name")
                && string_field(endpoint, "api_version") == string_field(api, "api_version")
        }
    }
}

fn optional_string_list(value: &Value, field: &str) -> Option<Vec<String>> {
    value.get(field).and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

pub(crate) fn is_revoked(revocations: &[Value], username: &str, jti: Option<&str>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    revocations
        .iter()
        .any(|revocation| match string_field(revocation, "type") {
            Some("revoke_all") => {
                string_field(revocation, "username") == Some(username)
                    && bool_field(revocation, "revoke_all").unwrap_or(true)
            }
            Some("jti") => {
                string_field(revocation, "username") == Some(username)
                    && jti.is_some_and(|jti| string_field(revocation, "jti") == Some(jti))
                    && revocation
                        .get("expires_at")
                        .and_then(Value::as_u64)
                        .is_some_and(|expires_at| expires_at > now)
            }
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;

    #[test]
    fn expired_or_malformed_jti_revocations_do_not_block_requests() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!is_revoked(
            &[json!({"type":"jti", "username":"alice", "jti":"old", "expires_at": now})],
            "alice",
            Some("old")
        ));
        assert!(!is_revoked(
            &[json!({"type":"jti", "username":"alice", "jti":"missing"})],
            "alice",
            Some("missing")
        ));
        assert!(is_revoked(
            &[json!({"type":"jti", "username":"alice", "jti":"live", "expires_at": now + 60})],
            "alice",
            Some("live")
        ));
    }

    #[test]
    fn mixed_settings_records_cannot_override_api_proxy_policy() {
        let mut documents = PolicyDocuments {
            apis: vec![
                json!({"api_id":"typed-policy", "api_name":"demo", "api_version":"v1",
                "api_public":true, "api_ip_blacklist":["203.0.113.9"]}),
            ],
            endpoints: vec![
                json!({"api_name":"demo", "api_version":"v1", "endpoint_method":"GET", "client_uri":"/known"}),
            ],
            settings: vec![
                json!({"type":"other", "trust_x_forwarded_for":false}),
                json!({"type":"security_settings", "trust_x_forwarded_for":true,
                    "xff_trusted_proxies":["10.0.0.0/8"], "allow_localhost_bypass":false}),
            ],
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        let request = PolicyRequest {
            method: Method::GET,
            path: "/api/rest/demo/v1/known".to_owned(),
            headers,
            direct_ip: Some("10.0.0.2".parse().unwrap()),
            now_millis: 0,
            content_length: 0,
            peer_certificates: Vec::new(),
            native_tls: false,
            is_preflight: false,
            group_version_missing: false,
            route_endpoint_check: false,
            endpoint_required: true,
        };
        let failure = evaluate_rest_policy(
            &mut documents,
            &request,
            &SharedStorageConfig::default(),
            &PolicyRuntime::default(),
        )
        .unwrap_err();
        assert_eq!(failure.error_code, "API011");
        // Order is irrelevant, and an unrelated restrictive record is ignored
        // when the security record does not enable forwarded-header trust.
        documents.settings.reverse();
        documents.settings[0]["trust_x_forwarded_for"] = json!(false);
        documents.settings[1]["trust_x_forwarded_for"] = json!(true);
        assert!(
            evaluate_rest_policy(
                &mut documents,
                &request,
                &SharedStorageConfig::default(),
                &PolicyRuntime::default()
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn returns_endpoint_not_found_for_missing_endpoint() {
        let mut documents = PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-1",
                "api_name": "demo",
                "api_version": "v1",
                "api_public": true,
            })],
            endpoints: vec![json!({
                "api_name": "demo",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/known",
            })],
            ..Default::default()
        };
        let request = PolicyRequest {
            method: Method::GET,
            path: "/api/rest/demo/v1/missing".to_owned(),
            headers: HeaderMap::new(),
            direct_ip: None,
            now_millis: 0,
            content_length: 0,
            peer_certificates: Vec::new(),
            native_tls: false,
            is_preflight: false,
            group_version_missing: false,
            route_endpoint_check: false,
            endpoint_required: true,
        };
        let failure = evaluate_rest_policy(
            &mut documents,
            &request,
            &SharedStorageConfig::default(),
            &PolicyRuntime::default(),
        )
        .unwrap_err();
        assert_eq!(failure.error_code, "GTW003");
    }

    #[test]
    fn returns_no_endpoints_for_api_without_registered_endpoints() {
        let mut documents = PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-1",
                "api_name": "demo",
                "api_version": "v1",
                "api_public": true,
            })],
            ..Default::default()
        };
        let request = PolicyRequest {
            method: Method::GET,
            path: "/api/rest/demo/v1/missing".to_owned(),
            headers: HeaderMap::new(),
            direct_ip: None,
            now_millis: 0,
            content_length: 0,
            peer_certificates: Vec::new(),
            native_tls: false,
            is_preflight: false,
            group_version_missing: false,
            route_endpoint_check: false,
            endpoint_required: true,
        };
        let failure = evaluate_rest_policy(
            &mut documents,
            &request,
            &SharedStorageConfig::default(),
            &PolicyRuntime::default(),
        )
        .unwrap_err();
        assert_eq!(failure.error_code, "GTW002");
        assert_eq!(
            failure.error_message,
            "No endpoints found for the requested API"
        );
    }

    #[test]
    fn records_client_key_upstream_selection() {
        let mut headers = HeaderMap::new();
        headers.insert("client-key", HeaderValue::from_static("client-a"));
        let mut documents = PolicyDocuments {
            apis: vec![json!({
                "api_id": "api-1",
                "api_name": "demo",
                "api_version": "v1",
                "api_public": true,
            })],
            endpoints: vec![json!({
                "api_name": "demo",
                "api_version": "v1",
                "endpoint_method": "GET",
                "client_uri": "/items",
            })],
            routings: vec![json!({
                "client_key": "client-a",
                "routing_servers": ["http://route-a", "http://route-b"],
                "server_index": 0,
            })],
            ..Default::default()
        };
        let request = PolicyRequest {
            method: Method::GET,
            path: "/api/rest/demo/v1/items".to_owned(),
            headers,
            direct_ip: None,
            now_millis: 0,
            content_length: 0,
            peer_certificates: Vec::new(),
            native_tls: false,
            is_preflight: false,
            group_version_missing: false,
            route_endpoint_check: false,
            endpoint_required: true,
        };
        let decision = evaluate_rest_policy(
            &mut documents,
            &request,
            &SharedStorageConfig::default(),
            &PolicyRuntime::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(decision.upstream, Some("http://route-a".to_owned()));
    }
}
