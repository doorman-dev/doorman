use http::StatusCode;
use serde::Serialize;
use serde_json::Value;

pub mod auth;
pub mod bandwidth;
pub mod credits;
pub mod evaluator;
pub mod geo;
pub mod groups;
pub mod ip;
pub mod quota;
pub mod rate_limit;
pub mod rate_limit_models;
pub mod roles;
pub mod simulator;
pub mod subscription;
pub mod throttle;
pub mod tier;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyStage {
    Resolution,
    Ip,
    Subscription,
    Group,
    RateLimit,
    Throttle,
    Authentication,
    Role,
    Bandwidth,
    Credits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFailure {
    pub stage: PolicyStage,
    pub status: StatusCode,
    pub error_code: String,
    pub error_message: String,
    pub tier_limit: Option<Box<(tier::TierLimitBody, tier::TierLimitStatus)>>,
}

impl PolicyFailure {
    pub fn new(
        stage: PolicyStage,
        status: StatusCode,
        error_code: impl Into<String>,
        error_message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            status,
            error_code: error_code.into(),
            error_message: error_message.into(),
            tier_limit: None,
        }
    }

    pub fn tier_limit(body: tier::TierLimitBody, status: tier::TierLimitStatus) -> Self {
        Self {
            stage: PolicyStage::RateLimit,
            status: StatusCode::TOO_MANY_REQUESTS,
            error_code: body.error_code.to_owned(),
            error_message: body.message.clone(),
            tier_limit: Some(Box::new((body, status))),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyDecision {
    /// A service-level failure (API disabled, endpoint missing) to report after
    /// the tier limits the pinned middleware applies first.
    pub deferred_failure: Option<PolicyFailure>,
    pub route: Option<String>,
    pub api_id: Option<String>,
    pub api_name: Option<String>,
    pub endpoint_id: Option<String>,
    pub username: Option<String>,
    pub tier_username: Option<String>,
    pub tier_rate_limit_enabled: bool,
    pub tier_limit_status: Option<tier::TierLimitStatus>,
    pub upstream: Option<String>,
    pub upstream_tls_profile_id: Option<String>,
    pub upstream_path: Option<String>,
    pub allowed_headers: Vec<String>,
    pub throttle_delay_ms: Option<u64>,
    pub credit_required: bool,
    pub credit_group: Option<String>,
    pub credit_header_name: Option<String>,
    pub credit_header_value: Option<String>,
    pub user_credit_header_value: Option<String>,
    pub routing_key: Option<String>,
    pub routing_servers: Vec<String>,
    pub routing_cache_value: Option<Value>,
    pub bandwidth_key: Option<String>,
    pub bandwidth_ttl_seconds: Option<u64>,
    pub retry_count: u32,
    pub request_timeout_ms: u64,
    pub graphql_max_depth: u64,
    pub authorization_field_swap: Option<String>,
    pub is_crud: bool,
    pub crud_collection: Option<String>,
    pub crud_schema: Option<Value>,
    pub endpoint_validation: Option<Value>,
    pub cors_allow_origins: Option<Vec<String>>,
    pub cors_allow_methods: Option<Vec<String>>,
    pub cors_allow_headers: Option<Vec<String>>,
    pub cors_allow_credentials: bool,
    pub cors_expose_headers: Vec<String>,
    pub request_transform: Option<Value>,
    pub response_transform: Option<Value>,
    pub soap_version: Option<String>,
    pub ws_security: Option<Value>,
    pub grpc_web_enabled: bool,
    pub grpc_descriptor_set: Option<String>,
    pub grpc_package: Option<String>,
    pub grpc_allowed_packages: Vec<String>,
    pub grpc_allowed_services: Vec<String>,
    pub grpc_allowed_methods: Vec<String>,
}

#[derive(Serialize)]
pub struct PolicyErrorBody {
    pub error_code: String,
    pub error_message: String,
}
