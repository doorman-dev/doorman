use http::HeaderMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedApi {
    pub name: String,
    pub version: String,
    pub api_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestRouteParts {
    pub api_name: String,
    pub api_version: String,
    pub endpoint_uri: String,
    pub api_lookup_key: String,
}

pub fn resolve_rest_path(path: &str, headers: &HeaderMap) -> Option<RestRouteParts> {
    let rest_path = path.strip_prefix("/api/rest/")?;
    let parts: Vec<&str> = rest_path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();

    if parts.len() >= 2 && is_path_version(parts[1]) {
        return Some(route_parts(parts[0], parts[1], &parts[2..]));
    }

    let version = headers
        .get("x-api-version")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())?;
    let api_name = parts.first()?;
    Some(route_parts(api_name, version, &parts[1..]))
}

fn route_parts(api_name: &str, api_version: &str, endpoint_parts: &[&str]) -> RestRouteParts {
    let endpoint_uri = if endpoint_parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", endpoint_parts.join("/"))
    };
    RestRouteParts {
        api_name: api_name.to_owned(),
        api_version: api_version.to_owned(),
        endpoint_uri,
        api_lookup_key: format!("/{api_name}/{api_version}"),
    }
}

fn is_path_version(value: &str) -> bool {
    ApiVersion::parse(value).is_some()
}

/// A `v<major>[.<minor>[.<patch>]]` API version. A bare `v1` names the whole
/// major line; dotted forms name one release within it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub major_only: bool,
}

impl ApiVersion {
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.strip_prefix('v')?.split('.').collect();
        if parts.len() > 3
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()))
        {
            return None;
        }
        let number = |index: usize| parts.get(index).map_or(Some(0), |part| part.parse().ok());
        Some(Self {
            major: number(0)?,
            minor: number(1)?,
            patch: number(2)?,
            major_only: parts.len() == 1,
        })
    }

    pub fn release(&self) -> (u64, u64, u64) {
        (self.major, self.minor, self.patch)
    }
}

pub fn endpoint_pattern_matches(pattern: &str, actual: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    let actual = actual.trim_matches('/');
    if pattern.is_empty() || actual.is_empty() {
        return pattern == actual;
    }

    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let actual_parts: Vec<&str> = actual.split('/').collect();
    pattern_parts.len() == actual_parts.len()
        && pattern_parts
            .iter()
            .zip(actual_parts.iter())
            .all(|(left, right)| (left.starts_with('{') && left.ends_with('}')) || left == right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn resolves_path_version_rest_routes() {
        let route = resolve_rest_path("/api/rest/demo/v1/items/7", &HeaderMap::new()).unwrap();
        assert_eq!(route.api_name, "demo");
        assert_eq!(route.api_version, "v1");
        assert_eq!(route.endpoint_uri, "/items/7");
        assert_eq!(route.api_lookup_key, "/demo/v1");
    }

    #[test]
    fn resolves_header_version_rest_routes() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-version", HeaderValue::from_static("v2"));
        let route = resolve_rest_path("/api/rest/demo/items", &headers).unwrap();
        assert_eq!(route.api_name, "demo");
        assert_eq!(route.api_version, "v2");
        assert_eq!(route.endpoint_uri, "/items");
    }

    #[test]
    fn resolves_semver_path_versions() {
        let route = resolve_rest_path("/api/rest/demo/v1.2.3/items", &HeaderMap::new()).unwrap();
        assert_eq!(route.api_version, "v1.2.3");
        assert_eq!(route.endpoint_uri, "/items");
        assert!(resolve_rest_path("/api/rest/demo/v1.x/items", &HeaderMap::new()).is_none());
    }

    #[test]
    fn parses_api_versions() {
        let major = ApiVersion::parse("v2").unwrap();
        assert_eq!((major.release(), major.major_only), ((2, 0, 0), true));
        let release = ApiVersion::parse("v1.4.2").unwrap();
        assert_eq!((release.release(), release.major_only), ((1, 4, 2), false));
        assert_eq!(ApiVersion::parse("v1.4").unwrap().release(), (1, 4, 0));
        for invalid in ["1", "v", "v1.", "v1..2", "v1.2.3.4", "vbeta", "V1"] {
            assert!(ApiVersion::parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn matches_python_path_parameters() {
        assert!(endpoint_pattern_matches("/items/{id}", "/items/7"));
        assert!(!endpoint_pattern_matches("/items/{id}", "/items/7/extra"));
    }
}
