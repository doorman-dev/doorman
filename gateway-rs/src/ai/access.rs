//! Which AI APIs a user can use, and which of them serves a model on the
//! unified endpoint (step 5, decision 4). Shared by My AI, `/api/ai/v1` and
//! the admin "who serves what" preview.

use serde_json::Value;

use crate::{
    ai::{
        adapter::AiProvider,
        config::{AiApiConfig, model_allowed},
    },
    storage::models::PolicyDocuments,
};

/// Auto-routing preference when several APIs allow the same model.
pub const PROVIDER_ORDER: [AiProvider; 7] = [
    AiProvider::Openai,
    AiProvider::AzureOpenai,
    AiProvider::Anthropic,
    AiProvider::Gemini,
    AiProvider::Vertex,
    AiProvider::Bedrock,
    AiProvider::OpenaiCompatible,
];

pub const MAX_ROUTES: usize = 50;
pub const MAX_ROUTE_TARGETS: usize = 5;

/// An active AI API the user may call (group access, and a subscription when required).
#[derive(Clone, Debug)]
pub struct UsableApi {
    pub name: String,
    pub version: String,
    pub provider: AiProvider,
    pub config: AiApiConfig,
}

impl UsableApi {
    pub fn label(&self) -> String {
        format!("{}/{}", self.name, self.version)
    }

    /// The model this API would actually call for `requested` (alias resolved),
    /// or None when the API doesn't allow it.
    pub fn serves(&self, requested: &str) -> Option<String> {
        let model = self
            .config
            .model_aliases
            .get(requested)
            .cloned()
            .unwrap_or_else(|| requested.to_owned());
        model_allowed(&model, &self.config.allowed_models).then_some(model)
    }

    /// Concrete model IDs and aliases (patterns like `gpt-*` are not names).
    pub fn model_names(&self) -> Vec<String> {
        let mut models: Vec<String> = self
            .config
            .allowed_models
            .iter()
            .filter(|model| !model.ends_with('*'))
            .cloned()
            .collect();
        models.extend(self.config.model_aliases.keys().cloned());
        models
    }
}

/// One place a unified request can be sent, in try order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub api_name: String,
    pub api_version: String,
    pub provider: AiProvider,
    /// The model sent in the native request, with the API's alias already resolved
    /// (Vertex picks the Anthropic or Gemini format from it).
    pub model: String,
    /// "route" or "auto".
    pub via: &'static str,
}

pub fn find_user<'a>(documents: &'a PolicyDocuments, username: &str) -> Option<&'a Value> {
    documents
        .users
        .iter()
        .find(|user| user.get("username").and_then(Value::as_str) == Some(username))
}

/// AI APIs `user` can call, sorted by `name/version`.
pub fn usable_ai_apis(documents: &PolicyDocuments, user: &Value) -> Vec<UsableApi> {
    let mut apis: Vec<UsableApi> = documents
        .apis
        .iter()
        .filter(|api| crate::platform_contract::is_ai_api(api))
        .filter(|api| api.get("active").and_then(Value::as_bool) != Some(false))
        .filter(|api| crate::policy::groups::enforce_group_access(api, user).is_ok())
        .filter_map(|api| {
            let name = api.get("api_name").and_then(Value::as_str)?;
            let version = api.get("api_version").and_then(Value::as_str)?;
            let provider = api
                .get("api_ai_provider")
                .and_then(Value::as_str)
                .and_then(AiProvider::parse)?;
            let config = api
                .get("api_ai_config")
                .and_then(|config| AiApiConfig::from_value(config).ok())?;
            if config.require_subscription
                && crate::policy::subscription::enforce_subscription(
                    &format!("{name}/{version}"),
                    user,
                    &documents.roles,
                    &documents.subscriptions,
                    false,
                )
                .is_err()
            {
                return None;
            }
            Some(UsableApi {
                name: name.to_owned(),
                version: version.to_owned(),
                provider,
                config,
            })
        })
        .collect();
    apis.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    apis
}

/// Keeps only the APIs a key's `api_scope` covers (empty scope = all).
pub fn within_scope(apis: Vec<UsableApi>, scope: &[String]) -> Vec<UsableApi> {
    if scope.is_empty() {
        return apis;
    }
    apis.into_iter()
        .filter(|api| scope.iter().any(|entry| *entry == api.label()))
        .collect()
}

/// `ai_settings.unified` (merged settings).
pub fn unified_enabled(settings: &Value) -> bool {
    settings["unified"]["enabled"].as_bool().unwrap_or(true)
}

fn routes(settings: &Value) -> &[Value] {
    settings["unified"]["routes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn provider_rank(provider: AiProvider) -> usize {
    PROVIDER_ORDER
        .iter()
        .position(|item| *item == provider)
        .unwrap_or(PROVIDER_ORDER.len())
}

/// Where a unified request for `requested` goes, in try order. An admin route
/// with that name wins (its targets the user can't use are skipped); otherwise
/// the single best auto match. Empty = no provider serves it for this user.
pub fn resolve(settings: &Value, usable: &[UsableApi], requested: &str) -> Vec<Candidate> {
    if let Some(route) = routes(settings)
        .iter()
        .find(|route| route["model"].as_str() == Some(requested))
    {
        return route["targets"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|target| {
                let label = target["api"].as_str()?;
                let model = target["model"].as_str()?;
                let api = usable.iter().find(|api| api.label() == label)?;
                let model = api.serves(model)?;
                Some(Candidate {
                    api_name: api.name.clone(),
                    api_version: api.version.clone(),
                    provider: api.provider,
                    model,
                    via: "route",
                })
            })
            .collect();
    }
    usable
        .iter()
        .filter_map(|api| api.serves(requested).map(|model| (api, model)))
        .min_by_key(|(api, _)| provider_rank(api.provider))
        .map(|(api, model)| Candidate {
            api_name: api.name.clone(),
            api_version: api.version.clone(),
            provider: api.provider,
            model,
            via: "auto",
        })
        .into_iter()
        .collect()
}

/// Every name the user can send to the unified endpoint, sorted and unique:
/// route names with at least one usable target, then model IDs and aliases.
pub fn unified_models(settings: &Value, usable: &[UsableApi]) -> Vec<String> {
    let mut models: Vec<String> = routes(settings)
        .iter()
        .filter_map(|route| route["model"].as_str())
        .filter(|name| !resolve(settings, usable, name).is_empty())
        .map(str::to_owned)
        .collect();
    models.extend(usable.iter().flat_map(UsableApi::model_names));
    models.sort();
    models.dedup();
    models
}

/// Validates `unified` from a settings PUT. Returns the normalised value.
pub fn validate_unified(value: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or("unified: must be an object with enabled and routes")?;
    let enabled = match object.get("enabled") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(enabled)) => *enabled,
        Some(_) => return Err("unified.enabled: must be true or false".into()),
    };
    let routes = match object.get("routes") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(routes)) => routes.clone(),
        Some(_) => return Err("unified.routes: must be a list".into()),
    };
    if routes.len() > MAX_ROUTES {
        return Err(format!("unified.routes: at most {MAX_ROUTES} routes"));
    }
    let mut names = std::collections::HashSet::new();
    let mut clean = Vec::with_capacity(routes.len());
    for (index, route) in routes.iter().enumerate() {
        let name = route["model"]
            .as_str()
            .map(str::trim)
            .filter(|name| !name.is_empty() && name.len() <= 200)
            .ok_or_else(|| {
                format!("unified.routes[{index}].model: required, at most 200 characters")
            })?;
        if !names.insert(name.to_owned()) {
            return Err(format!(
                "unified.routes[{index}].model: duplicate route {name}"
            ));
        }
        let targets = route["targets"]
            .as_array()
            .filter(|targets| (1..=MAX_ROUTE_TARGETS).contains(&targets.len()))
            .ok_or_else(|| {
                format!("unified.routes[{index}].targets: 1 to {MAX_ROUTE_TARGETS} targets")
            })?;
        let mut clean_targets = Vec::with_capacity(targets.len());
        for (t, target) in targets.iter().enumerate() {
            let api = target["api"]
                .as_str()
                .map(str::trim)
                .filter(|api| {
                    api.split_once('/')
                        .is_some_and(|(n, v)| !n.is_empty() && !v.is_empty())
                })
                .ok_or_else(|| {
                    format!(
                        "unified.routes[{index}].targets[{t}].api: must be api_name/api_version"
                    )
                })?;
            let model = target["model"]
                .as_str()
                .map(str::trim)
                .filter(|model| !model.is_empty())
                .ok_or_else(|| format!("unified.routes[{index}].targets[{t}].model: required"))?;
            clean_targets.push(serde_json::json!({"api": api, "model": model}));
        }
        clean.push(serde_json::json!({"model": name, "targets": clean_targets}));
    }
    Ok(serde_json::json!({"enabled": enabled, "routes": clean}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn api(
        name: &str,
        provider: AiProvider,
        models: &[&str],
        aliases: &[(&str, &str)],
    ) -> UsableApi {
        UsableApi {
            name: name.into(),
            version: "v1".into(),
            provider,
            config: AiApiConfig {
                allowed_models: models.iter().map(|m| (*m).to_owned()).collect(),
                model_aliases: aliases
                    .iter()
                    .map(|(a, m)| ((*a).to_owned(), (*m).to_owned()))
                    .collect(),
                ..AiApiConfig::default()
            },
        }
    }

    fn usable() -> Vec<UsableApi> {
        vec![
            api("bedrock", AiProvider::Bedrock, &["anthropic.claude-*"], &[]),
            api(
                "claude",
                AiProvider::Anthropic,
                &["claude-*"],
                &[("smart", "claude-opus-5-5")],
            ),
            api(
                "compat",
                AiProvider::OpenaiCompatible,
                &["claude-sonnet-5-5"],
                &[],
            ),
            api("gpt", AiProvider::Openai, &["gpt-5", "gpt-5-mini"], &[]),
        ]
    }

    #[test]
    fn auto_picks_by_provider_order_then_name() {
        let settings = json!({"unified": {"enabled": true, "routes": []}});
        let picked = resolve(&settings, &usable(), "claude-sonnet-5-5");
        assert_eq!(picked.len(), 1);
        assert_eq!(
            (picked[0].api_name.as_str(), picked[0].via),
            ("claude", "auto")
        );
        assert_eq!(resolve(&settings, &usable(), "smart")[0].api_name, "claude");
        assert_eq!(
            resolve(&settings, &usable(), "smart")[0].model,
            "claude-opus-5-5"
        );
        assert!(resolve(&settings, &usable(), "gemini-3-pro").is_empty());
    }

    #[test]
    fn route_wins_and_skips_targets_the_user_cannot_use() {
        let settings = json!({"unified": {"routes": [{"model": "gpt-5", "targets": [
            {"api": "missing/v1", "model": "gpt-5"},
            {"api": "claude/v1", "model": "claude-haiku-4-5"},
            {"api": "gpt/v1", "model": "gpt-4o"},
            {"api": "gpt/v1", "model": "gpt-5-mini"}
        ]}]}});
        let picked = resolve(&settings, &usable(), "gpt-5");
        let order: Vec<_> = picked
            .iter()
            .map(|c| (c.api_name.as_str(), c.model.as_str(), c.via))
            .collect();
        assert_eq!(
            order,
            [
                ("claude", "claude-haiku-4-5", "route"),
                ("gpt", "gpt-5-mini", "route")
            ]
        );
    }

    #[test]
    fn unified_models_lists_routes_models_and_aliases() {
        let settings = json!({"unified": {"routes": [
            {"model": "fast", "targets": [{"api": "gpt/v1", "model": "gpt-5-mini"}]},
            {"model": "dead", "targets": [{"api": "missing/v1", "model": "x"}]}
        ]}});
        let models = unified_models(&settings, &usable());
        assert!(models.contains(&"fast".to_owned()) && models.contains(&"smart".to_owned()));
        assert!(!models.contains(&"dead".to_owned()));
        assert!(!models.iter().any(|m| m.ends_with('*')));
        assert_eq!(
            models.iter().filter(|m| *m == "claude-sonnet-5-5").count(),
            1
        );
    }

    #[test]
    fn validate_unified_rejects_bad_routes() {
        assert!(validate_unified(&json!({"routes": [{"model": "a", "targets": []}]})).is_err());
        assert!(
            validate_unified(
                &json!({"routes": [{"model": "a", "targets": [{"api": "x", "model": "m"}]}]})
            )
            .is_err()
        );
        let dup = json!({"routes": [
            {"model": "a", "targets": [{"api": "x/v1", "model": "m"}]},
            {"model": "a", "targets": [{"api": "x/v1", "model": "m"}]}
        ]});
        assert!(validate_unified(&dup).unwrap_err().contains("duplicate"));
        let ok = validate_unified(&json!({"enabled": false, "routes": [
            {"model": " fast ", "targets": [{"api": "gpt/v1", "model": "gpt-5-mini", "extra": 1}]}
        ]}))
        .unwrap();
        assert_eq!(
            ok,
            json!({"enabled": false, "routes": [{"model": "fast", "targets": [{"api": "gpt/v1", "model": "gpt-5-mini"}]}]})
        );
    }
}
