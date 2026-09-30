use std::env;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyLimits {
    pub default: usize,
    pub rest: usize,
    pub soap: usize,
    pub graphql: usize,
    pub grpc: usize,
}

impl BodyLimits {
    pub fn from_env() -> Self {
        if env_bool("DISABLE_BODY_SIZE_LIMIT", false) {
            return Self {
                default: usize::MAX,
                rest: usize::MAX,
                soap: usize::MAX,
                graphql: usize::MAX,
                grpc: usize::MAX,
            };
        }
        let default = env_usize("MAX_BODY_SIZE_BYTES", 1024 * 1024);
        Self {
            default,
            rest: env_usize("MAX_BODY_SIZE_BYTES_REST", default),
            soap: env_usize("MAX_BODY_SIZE_BYTES_SOAP", default),
            graphql: env_usize("MAX_BODY_SIZE_BYTES_GRAPHQL", default),
            grpc: env_usize("MAX_BODY_SIZE_BYTES_GRPC", default),
        }
    }

    pub fn for_path(path: &str, limit: usize) -> usize {
        if path.starts_with("/platform/monitor/") || path == "/platform/security/settings" {
            return usize::MAX;
        }
        let excluded = env::var("BODY_LIMIT_EXCLUDE_PATHS")
            .ok()
            .is_some_and(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .any(|pattern| {
                        path == pattern
                            || pattern
                                .strip_suffix('*')
                                .is_some_and(|prefix| path.starts_with(prefix))
                    })
            });
        if excluded { usize::MAX } else { limit }
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

/// A negative limit (accepted by the pinned `int()` parse) rejects every body.
fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map_or(default, |value| usize::try_from(value).unwrap_or(0))
}
