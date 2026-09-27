//! Placeholder geographic lookup and country policy from the Python backend.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip: String,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

#[derive(Clone, Debug)]
struct Expiring<T> {
    value: T,
    expires_at: Instant,
}

#[derive(Clone, Debug, Default)]
struct GeoState {
    cache: HashMap<String, Expiring<GeoLocation>>,
    blocked: HashSet<String>,
    allowed: HashSet<String>,
    rate_limits: HashMap<String, i64>,
    requests: HashMap<String, Expiring<u64>>,
}

#[derive(Clone, Debug)]
pub struct GeoLookup {
    state: Arc<Mutex<GeoState>>,
    cache_ttl: Duration,
}

impl Default for GeoLookup {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(GeoState::default())),
            cache_ttl: Duration::from_secs(86_400),
        }
    }
}

impl GeoLookup {
    pub fn lookup_ip(&self, ip: &str) -> GeoLocation {
        let mut state = self.state.lock().expect("geo state mutex poisoned");
        if state
            .cache
            .get(ip)
            .is_some_and(|entry| entry.expires_at <= Instant::now())
        {
            state.cache.remove(ip);
        }
        if let Some(entry) = state.cache.get(ip) {
            return entry.value.clone();
        }
        let geo = GeoLocation {
            ip: ip.to_owned(),
            country_code: Some("UNKNOWN".to_owned()),
            ..GeoLocation::default()
        };
        state.cache.insert(
            ip.to_owned(),
            Expiring {
                value: geo.clone(),
                expires_at: Instant::now() + self.cache_ttl,
            },
        );
        geo
    }

    pub fn cache_geo_data(&self, ip: &str, mut geo: GeoLocation) {
        geo.ip = ip.to_owned();
        // Python serializes zero coordinates as an empty string, which reloads
        // as None. Preserve that pinned edge case.
        if geo.latitude == Some(0.0) {
            geo.latitude = None;
        }
        if geo.longitude == Some(0.0) {
            geo.longitude = None;
        }
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .cache
            .insert(
                ip.to_owned(),
                Expiring {
                    value: geo,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
    }

    pub fn is_country_blocked(&self, country_code: &str) -> bool {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .blocked
            .contains(country_code)
    }

    pub fn is_country_allowed(&self, country_code: &str) -> bool {
        let state = self.state.lock().expect("geo state mutex poisoned");
        state.allowed.is_empty() || state.allowed.contains(country_code)
    }

    pub fn block_country(&self, country_code: &str) -> bool {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .blocked
            .insert(country_code.to_owned());
        true
    }

    pub fn unblock_country(&self, country_code: &str) -> bool {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .blocked
            .remove(country_code);
        true
    }

    pub fn add_to_allowlist(&self, country_code: &str) -> bool {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .allowed
            .insert(country_code.to_owned());
        true
    }

    pub fn remove_from_allowlist(&self, country_code: &str) -> bool {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .allowed
            .remove(country_code);
        true
    }

    pub fn get_country_rate_limit(&self, country_code: &str) -> Option<i64> {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .rate_limits
            .get(country_code)
            .copied()
    }

    pub fn set_country_rate_limit(&self, country_code: &str, limit: i64) -> bool {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .rate_limits
            .insert(country_code.to_owned(), limit);
        true
    }

    pub fn check_geographic_access(&self, ip: &str) -> (bool, Option<String>) {
        let geo = self.lookup_ip(ip);
        let Some(country) = geo
            .country_code
            .as_deref()
            .filter(|country| *country != "UNKNOWN")
        else {
            return (true, None);
        };
        if self.is_country_blocked(country) {
            return (false, Some(format!("Country {country} is blocked")));
        }
        if !self.is_country_allowed(country) {
            return (
                false,
                Some(format!("Country {country} is not in allowlist")),
            );
        }
        (true, None)
    }

    pub fn track_country_request(&self, country_code: &str) {
        let mut state = self.state.lock().expect("geo state mutex poisoned");
        let now = Instant::now();
        let entry = state
            .requests
            .entry(country_code.to_owned())
            .or_insert(Expiring {
                value: 0,
                expires_at: now + Duration::from_secs(86_400),
            });
        if entry.expires_at <= now {
            entry.value = 0;
        }
        entry.value = entry.value.saturating_add(1);
        entry.expires_at = now + Duration::from_secs(86_400);
    }

    pub fn get_geographic_distribution(&self) -> Vec<(String, u64)> {
        let now = Instant::now();
        let mut state = self.state.lock().expect("geo state mutex poisoned");
        state.requests.retain(|_, entry| entry.expires_at > now);
        let mut values = state
            .requests
            .iter()
            .map(|(country, entry)| (country.clone(), entry.value))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| right.1.cmp(&left.1));
        values
    }

    pub fn get_blocked_countries(&self) -> HashSet<String> {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .blocked
            .clone()
    }

    pub fn get_allowed_countries(&self) -> HashSet<String> {
        self.state
            .lock()
            .expect("geo state mutex poisoned")
            .allowed
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_locations_fail_open_like_python() {
        let lookup = GeoLookup::default();
        assert_eq!(
            lookup.lookup_ip("203.0.113.2").country_code.as_deref(),
            Some("UNKNOWN")
        );
        assert_eq!(lookup.check_geographic_access("203.0.113.2"), (true, None));
    }

    #[test]
    fn country_lists_limits_and_distribution_match_python() {
        let lookup = GeoLookup::default();
        lookup.cache_geo_data(
            "203.0.113.3",
            GeoLocation {
                country_code: Some("CA".to_owned()),
                ..GeoLocation::default()
            },
        );
        lookup.block_country("CA");
        assert_eq!(
            lookup.check_geographic_access("203.0.113.3"),
            (false, Some("Country CA is blocked".to_owned()))
        );
        lookup.unblock_country("CA");
        lookup.add_to_allowlist("US");
        assert_eq!(
            lookup.check_geographic_access("203.0.113.3"),
            (false, Some("Country CA is not in allowlist".to_owned()))
        );
        assert!(lookup.set_country_rate_limit("CA", 25));
        assert_eq!(lookup.get_country_rate_limit("CA"), Some(25));
        lookup.track_country_request("CA");
        lookup.track_country_request("CA");
        lookup.track_country_request("US");
        assert_eq!(
            lookup.get_geographic_distribution()[0],
            ("CA".to_owned(), 2)
        );
    }
}
