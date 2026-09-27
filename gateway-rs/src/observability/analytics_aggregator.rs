use std::{
    collections::{HashMap, VecDeque},
    fs, io,
    path::Path,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AggregatedPoint {
    pub timestamp: u64,
    pub requests: u64,
    pub errors: u64,
    pub latency_ms: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EntityCounter {
    pub name: String,
    pub count: u64,
    pub error_count: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PythonMetricFile {
    #[serde(default)]
    total_requests: u64,
    #[serde(default)]
    total_ms: f64,
    #[serde(default)]
    total_bytes_in: u64,
    #[serde(default)]
    total_bytes_out: u64,
    #[serde(default)]
    status_counts: HashMap<String, u64>,
    #[serde(default)]
    username_counts: HashMap<String, u64>,
    #[serde(default)]
    api_counts: HashMap<String, u64>,
    #[serde(default)]
    buckets: Vec<PythonMetricBucket>,
    #[serde(default)]
    endpoint_counts: HashMap<String, u64>,
    #[serde(default)]
    api_error_counts: HashMap<String, u64>,
    #[serde(default)]
    user_error_counts: HashMap<String, u64>,
    #[serde(default)]
    endpoint_error_counts: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PythonMetricBucket {
    #[serde(default, alias = "timestamp")]
    start_ts: u64,
    #[serde(default, alias = "requests")]
    count: u64,
    #[serde(default, alias = "errors")]
    error_count: u64,
    #[serde(default)]
    total_ms: f64,
    #[serde(default)]
    latency_ms: f64,
    #[serde(default)]
    bytes_in: u64,
    #[serde(default)]
    bytes_out: u64,
    #[serde(default)]
    status_counts: HashMap<String, u64>,
    #[serde(default)]
    api_counts: HashMap<String, u64>,
    #[serde(default)]
    api_error_counts: HashMap<String, u64>,
    #[serde(default)]
    user_counts: HashMap<String, u64>,
    #[serde(default)]
    unique_users_list: Vec<String>,
    #[serde(default)]
    endpoint_metrics: HashMap<String, serde_json::Value>,
}

pub struct AnalyticsAggregator {
    points: RwLock<VecDeque<AggregatedPoint>>,
    api_counters: RwLock<HashMap<String, u64>>,
    api_error_counters: RwLock<HashMap<String, u64>>,
    user_counters: RwLock<HashMap<String, u64>>,
    user_error_counters: RwLock<HashMap<String, u64>>,
    endpoint_counters: RwLock<HashMap<String, u64>>,
    endpoint_error_counters: RwLock<HashMap<String, u64>>,
    status_counters: RwLock<HashMap<u16, u64>>,
}

impl AnalyticsAggregator {
    pub fn new() -> Self {
        Self {
            points: RwLock::new(VecDeque::with_capacity(43_200)),
            api_counters: RwLock::new(HashMap::new()),
            api_error_counters: RwLock::new(HashMap::new()),
            user_counters: RwLock::new(HashMap::new()),
            user_error_counters: RwLock::new(HashMap::new()),
            endpoint_counters: RwLock::new(HashMap::new()),
            endpoint_error_counters: RwLock::new(HashMap::new()),
            status_counters: RwLock::new(HashMap::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        api_name: Option<&str>,
        username: Option<&str>,
        endpoint: Option<&str>,
        status: u16,
        duration_ms: f64,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let minute_ts = (now / 60) * 60;
        let is_error = status >= 400;

        increment(&self.status_counters, status, true);
        if let Some(api) = api_name {
            increment(&self.api_counters, api.to_owned(), true);
            increment(&self.api_error_counters, api.to_owned(), is_error);
        }
        if let Some(user) = username {
            increment(&self.user_counters, user.to_owned(), true);
            increment(&self.user_error_counters, user.to_owned(), is_error);
        }
        if let Some(endpoint) = endpoint {
            increment(&self.endpoint_counters, endpoint.to_owned(), true);
            increment(&self.endpoint_error_counters, endpoint.to_owned(), is_error);
        }

        if let Ok(mut points) = self.points.write() {
            if let Some(last) = points.back_mut()
                && last.timestamp == minute_ts
            {
                let previous = last.requests;
                last.requests += 1;
                if is_error {
                    last.errors += 1;
                }
                last.bytes_in += bytes_in;
                last.bytes_out += bytes_out;
                last.latency_ms =
                    ((last.latency_ms * previous as f64) + duration_ms) / last.requests as f64;
                return;
            }
            if points.len() >= 43_200 {
                points.pop_front();
            }
            points.push_back(AggregatedPoint {
                timestamp: minute_ts,
                requests: 1,
                errors: u64::from(is_error),
                latency_ms: duration_ms,
                bytes_in,
                bytes_out,
            });
        }
    }

    pub fn get_timeseries(&self) -> Vec<AggregatedPoint> {
        self.points
            .read()
            .map(|points| points.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_timeseries_range(&self, start_ts: u64, end_ts: u64) -> Vec<AggregatedPoint> {
        let interval = match end_ts.saturating_sub(start_ts) {
            seconds if seconds <= 86_400 => 300,
            seconds if seconds <= 604_800 => 3_600,
            _ => 86_400,
        };
        aggregate_points(
            self.get_timeseries()
                .into_iter()
                .filter(|point| point.timestamp >= start_ts && point.timestamp <= end_ts)
                .collect(),
            interval,
        )
    }

    pub fn get_status_distribution(&self) -> HashMap<String, u64> {
        self.status_counters
            .read()
            .map(|values| {
                values
                    .iter()
                    .map(|(status, count)| (status.to_string(), *count))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn api_count(&self) -> usize {
        map_len(&self.api_counters)
    }

    pub fn user_count(&self) -> usize {
        map_len(&self.user_counters)
    }

    pub fn endpoint_count(&self) -> usize {
        map_len(&self.endpoint_counters)
    }
    pub fn get_top_apis(&self, limit: usize) -> Vec<EntityCounter> {
        top_entities(&self.api_counters, &self.api_error_counters, limit)
    }

    pub fn get_top_users(&self, limit: usize) -> Vec<EntityCounter> {
        top_entities(&self.user_counters, &self.user_error_counters, limit)
    }

    pub fn get_top_endpoints(&self, limit: usize) -> Vec<EntityCounter> {
        top_entities(
            &self.endpoint_counters,
            &self.endpoint_error_counters,
            limit,
        )
    }

    pub fn save_to_file(&self, path: &Path) -> io::Result<()> {
        let points = self.get_timeseries();
        let api_counts = cloned_map(&self.api_counters);
        let username_counts = cloned_map(&self.user_counters);
        let endpoint_counts = cloned_map(&self.endpoint_counters);
        let api_error_counts = cloned_map(&self.api_error_counters);
        let user_error_counts = cloned_map(&self.user_error_counters);
        let endpoint_error_counts = cloned_map(&self.endpoint_error_counters);
        let status_counts = self
            .status_counters
            .read()
            .map(|values| {
                values
                    .iter()
                    .map(|(status, count)| (status.to_string(), *count))
                    .collect()
            })
            .unwrap_or_default();

        let file = PythonMetricFile {
            total_requests: points.iter().map(|point| point.requests).sum(),
            total_ms: points
                .iter()
                .map(|point| point.latency_ms * point.requests as f64)
                .sum(),
            total_bytes_in: points.iter().map(|point| point.bytes_in).sum(),
            total_bytes_out: points.iter().map(|point| point.bytes_out).sum(),
            status_counts,
            username_counts,
            api_counts,
            buckets: points
                .into_iter()
                .map(|point| PythonMetricBucket {
                    start_ts: point.timestamp,
                    count: point.requests,
                    error_count: point.errors,
                    total_ms: point.latency_ms * point.requests as f64,
                    latency_ms: point.latency_ms,
                    bytes_in: point.bytes_in,
                    bytes_out: point.bytes_out,
                    ..PythonMetricBucket::default()
                })
                .collect(),
            endpoint_counts,
            api_error_counts,
            user_error_counts,
            endpoint_error_counts,
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(&file).map_err(io::Error::other)?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)
    }

    pub fn load_from_file(&self, path: &Path) -> io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let bytes = fs::read(path)?;
        let file: PythonMetricFile = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let mut points = file
            .buckets
            .iter()
            .map(|bucket| AggregatedPoint {
                timestamp: bucket.start_ts,
                requests: bucket.count,
                errors: bucket.error_count,
                latency_ms: if bucket.count > 0 {
                    if bucket.total_ms > 0.0 {
                        bucket.total_ms / bucket.count as f64
                    } else {
                        bucket.latency_ms
                    }
                } else {
                    0.0
                },
                bytes_in: bucket.bytes_in,
                bytes_out: bucket.bytes_out,
            })
            .collect::<VecDeque<_>>();
        while points.len() > 43_200 {
            points.pop_front();
        }

        replace_map(&self.points, points);
        replace_map(&self.api_counters, file.api_counts);
        replace_map(&self.user_counters, file.username_counts);
        replace_map(&self.endpoint_counters, file.endpoint_counts);
        replace_map(&self.api_error_counters, file.api_error_counts);
        replace_map(&self.user_error_counters, file.user_error_counts);
        replace_map(&self.endpoint_error_counters, file.endpoint_error_counts);
        replace_map(
            &self.status_counters,
            file.status_counts
                .into_iter()
                .filter_map(|(status, count)| {
                    status.parse::<u16>().ok().map(|status| (status, count))
                })
                .collect(),
        );
        Ok(())
    }
}

fn aggregate_points(points: Vec<AggregatedPoint>, interval: u64) -> Vec<AggregatedPoint> {
    let mut buckets = std::collections::BTreeMap::<u64, AggregatedPoint>::new();
    for point in points {
        let timestamp = (point.timestamp / interval) * interval;
        let bucket = buckets.entry(timestamp).or_insert_with(|| AggregatedPoint {
            timestamp,
            ..AggregatedPoint::default()
        });
        let previous_requests = bucket.requests;
        bucket.requests = bucket.requests.saturating_add(point.requests);
        bucket.errors = bucket.errors.saturating_add(point.errors);
        bucket.bytes_in = bucket.bytes_in.saturating_add(point.bytes_in);
        bucket.bytes_out = bucket.bytes_out.saturating_add(point.bytes_out);
        if bucket.requests > 0 {
            bucket.latency_ms = ((bucket.latency_ms * previous_requests as f64)
                + (point.latency_ms * point.requests as f64))
                / bucket.requests as f64;
        }
    }
    buckets.into_values().collect()
}

impl Default for AnalyticsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

fn increment<K>(map: &RwLock<HashMap<K, u64>>, key: K, enabled: bool)
where
    K: Eq + std::hash::Hash,
{
    if !enabled {
        return;
    }
    if let Ok(mut values) = map.write() {
        *values.entry(key).or_insert(0) += 1;
    }
}

fn top_entities(
    counters: &RwLock<HashMap<String, u64>>,
    errors: &RwLock<HashMap<String, u64>>,
    limit: usize,
) -> Vec<EntityCounter> {
    let errors = cloned_map(errors);
    let mut items = counters
        .read()
        .map(|values| {
            values
                .iter()
                .map(|(name, count)| EntityCounter {
                    name: name.clone(),
                    count: *count,
                    error_count: errors.get(name).copied().unwrap_or_default(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    items.truncate(limit);
    items
}

fn cloned_map<K>(map: &RwLock<HashMap<K, u64>>) -> HashMap<K, u64>
where
    K: Clone + Eq + std::hash::Hash,
{
    map.read().map(|values| values.clone()).unwrap_or_default()
}

fn map_len<K>(map: &RwLock<HashMap<K, u64>>) -> usize
where
    K: Eq + std::hash::Hash,
{
    map.read().map(|values| values.len()).unwrap_or_default()
}

fn replace_map<T>(target: &RwLock<T>, value: T) {
    if let Ok(mut target) = target.write() {
        *target = value;
    }
}

pub static GLOBAL_ANALYTICS: std::sync::OnceLock<Arc<AnalyticsAggregator>> =
    std::sync::OnceLock::new();

pub fn global_analytics() -> &'static Arc<AnalyticsAggregator> {
    GLOBAL_ANALYTICS.get_or_init(|| Arc::new(AnalyticsAggregator::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_restores_python_compatible_metrics() {
        let directory =
            std::env::temp_dir().join(format!("doorman-analytics-{}", uuid::Uuid::new_v4()));
        let path = directory.join("enhanced_metrics.json");
        let original = AnalyticsAggregator::new();
        original.record_request(
            Some("rest:orders"),
            Some("alice"),
            Some("/orders"),
            503,
            12.5,
            10,
            20,
        );
        let before_points = original.get_timeseries();
        let before_statuses = original.get_status_distribution();
        let before_apis = original.get_top_apis(10);
        let before_users = original.get_top_users(10);
        let before_endpoints = original.get_top_endpoints(10);
        original.save_to_file(&path).unwrap();
        assert!(path.is_file());
        assert!(fs::metadata(&path).unwrap().len() > 0);

        let empty_path = directory.join("empty.json");
        fs::write(&empty_path, "{}").unwrap();
        original.load_from_file(&empty_path).unwrap();
        assert!(original.get_timeseries().is_empty());
        assert!(original.get_status_distribution().is_empty());
        assert!(original.get_top_apis(10).is_empty());
        assert!(original.get_top_users(10).is_empty());
        assert!(original.get_top_endpoints(10).is_empty());

        original.load_from_file(&path).unwrap();
        assert_eq!(original.get_timeseries(), before_points);
        assert_eq!(original.get_status_distribution(), before_statuses);
        assert_eq!(original.get_top_apis(10), before_apis);
        assert_eq!(original.get_top_users(10), before_users);
        assert_eq!(original.get_top_endpoints(10), before_endpoints);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn range_queries_use_python_aggregation_levels() {
        let points = vec![
            AggregatedPoint {
                timestamp: 301,
                requests: 2,
                errors: 1,
                latency_ms: 10.0,
                bytes_in: 3,
                bytes_out: 4,
            },
            AggregatedPoint {
                timestamp: 599,
                requests: 1,
                errors: 0,
                latency_ms: 40.0,
                bytes_in: 5,
                bytes_out: 6,
            },
            AggregatedPoint {
                timestamp: 601,
                requests: 1,
                errors: 1,
                latency_ms: 20.0,
                bytes_in: 7,
                bytes_out: 8,
            },
        ];
        let five_minute = aggregate_points(points.clone(), 300);
        assert_eq!(five_minute.len(), 2);
        assert_eq!(five_minute[0].timestamp, 300);
        assert_eq!(five_minute[0].requests, 3);
        assert_eq!(five_minute[0].errors, 1);
        assert_eq!(five_minute[0].latency_ms, 20.0);
        assert_eq!(five_minute[0].bytes_in, 8);
        assert_eq!(aggregate_points(points.clone(), 3_600).len(), 1);
        assert_eq!(aggregate_points(points, 86_400).len(), 1);
    }
}
