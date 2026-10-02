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
    /// Bounded ring buffer of raw per-request latencies for this minute bucket,
    /// mirroring Python's `MinuteBucket.latencies` deque. Not persisted to disk,
    /// matching Python's `to_dict`/`from_dict`, which omit it.
    #[serde(skip)]
    pub latencies_ms: VecDeque<f64>,
}

/// Mirrors Python's `os.getenv('METRICS_PCT_SAMPLES', '500')` cap on the
/// per-bucket raw-latency sample deque.
fn metrics_pct_samples() -> usize {
    std::env::var("METRICS_PCT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(500)
}

impl AggregatedPoint {
    /// Python's `snapshot()` percentile formula: sort the retained samples and
    /// index at `max(0, int(0.95 * len) - 1)`.
    pub fn p95_ms(&self) -> f64 {
        if self.latencies_ms.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.latencies_ms.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let index = ((0.95 * sorted.len() as f64) as usize).saturating_sub(1);
        sorted[index.min(sorted.len() - 1)]
    }

    fn push_latency_sample(&mut self, duration_ms: f64) {
        let cap = metrics_pct_samples();
        self.latencies_ms.push_back(duration_ms);
        while self.latencies_ms.len() > cap {
            self.latencies_ms.pop_front();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EntityCounter {
    pub name: String,
    pub count: u64,
    pub error_count: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EndpointEntity {
    pub name: String,
    pub count: u64,
    pub error_count: u64,
    pub avg_ms: f64,
    /// (p50, p75, p90, p95, p99) over the range's pooled raw-latency samples,
    /// using Python's `PercentileMetrics.calculate` sorted-index formula.
    pub percentiles: (f64, f64, f64, f64, f64),
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

/// Per-minute (count, error_count) for every entity name seen in that minute,
/// mirroring Python's `MinuteBucket.api_counts`/`user_counts`/per-endpoint
/// metrics. Kept in lockstep with `points` (same timestamps, same pruning) so
/// a time-scoped top-N query can be reconstructed for any [start, end] window
/// instead of only a process-global all-time total.
#[derive(Debug, Clone, Default)]
struct MinuteEntities {
    timestamp: u64,
    api: HashMap<String, (u64, u64)>,
    user: HashMap<String, (u64, u64)>,
    endpoint: HashMap<String, EndpointBucket>,
}

/// Per-endpoint, per-minute totals plus a capped raw-latency sample deque, so
/// a range-scoped query can compute both a real `avg_ms` (`total_ms / count`)
/// and real percentiles, matching Python's `EndpointMetrics.total_ms/count`
/// and `EndpointMetrics.get_percentiles()` instead of the fixed placeholders
/// the route used to return.
#[derive(Debug, Clone, Default)]
struct EndpointBucket {
    count: u64,
    errors: u64,
    total_ms: f64,
    latencies_ms: VecDeque<f64>,
}

pub struct AnalyticsAggregator {
    points: RwLock<VecDeque<AggregatedPoint>>,
    entity_minutes: RwLock<VecDeque<MinuteEntities>>,
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
            entity_minutes: RwLock::new(VecDeque::with_capacity(43_200)),
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
        self.record_request_at(
            now,
            api_name,
            username,
            endpoint,
            status,
            duration_ms,
            bytes_in,
            bytes_out,
        );
    }

    /// Like `record_request`, but files the sample under an explicit unix
    /// timestamp rather than "now". Used by the demo seed to backfill
    /// historical minute buckets the way Python's `seed_metrics` does, so a
    /// freshly seeded instance shows a real multi-hour timeseries instead of
    /// one spike in the current minute. Callers must invoke this in
    /// non-decreasing `timestamp_secs` order, matching the append-only
    /// bucket layout `record_request` relies on.
    #[allow(clippy::too_many_arguments)]
    pub fn record_request_at(
        &self,
        timestamp_secs: u64,
        api_name: Option<&str>,
        username: Option<&str>,
        endpoint: Option<&str>,
        status: u16,
        duration_ms: f64,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let minute_ts = (timestamp_secs / 60) * 60;
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
                last.push_latency_sample(duration_ms);
            } else {
                if points.len() >= 43_200 {
                    points.pop_front();
                }
                let mut point = AggregatedPoint {
                    timestamp: minute_ts,
                    requests: 1,
                    errors: u64::from(is_error),
                    latency_ms: duration_ms,
                    bytes_in,
                    bytes_out,
                    latencies_ms: VecDeque::new(),
                };
                point.push_latency_sample(duration_ms);
                points.push_back(point);
            }
        }

        if let Ok(mut minutes) = self.entity_minutes.write() {
            let bucket = if minutes
                .back()
                .is_some_and(|last| last.timestamp == minute_ts)
            {
                minutes.back_mut().unwrap()
            } else {
                if minutes.len() >= 43_200 {
                    minutes.pop_front();
                }
                minutes.push_back(MinuteEntities {
                    timestamp: minute_ts,
                    ..Default::default()
                });
                minutes.back_mut().unwrap()
            };
            if let Some(api) = api_name {
                let entry = bucket.api.entry(api.to_owned()).or_default();
                entry.0 += 1;
                entry.1 += u64::from(is_error);
            }
            if let Some(user) = username {
                let entry = bucket.user.entry(user.to_owned()).or_default();
                entry.0 += 1;
                entry.1 += u64::from(is_error);
            }
            if let Some(endpoint) = endpoint {
                let entry = bucket.endpoint.entry(endpoint.to_owned()).or_default();
                entry.count += 1;
                entry.errors += u64::from(is_error);
                entry.total_ms += duration_ms;
                let cap = metrics_pct_samples();
                entry.latencies_ms.push_back(duration_ms);
                while entry.latencies_ms.len() > cap {
                    entry.latencies_ms.pop_front();
                }
            }
        }
    }

    /// Time-scoped equivalent of `get_top_apis`/`get_top_users`/`get_top_endpoints`,
    /// reconstructing totals from only the minute buckets in `[start_ts, end_ts]`
    /// instead of the process-global all-time counters. Mirrors Python's
    /// `enhanced_metrics_store.get_snapshot(start_ts, end_ts)`-backed top lists.
    fn top_entities_in_range(
        &self,
        start_ts: u64,
        end_ts: u64,
        limit: usize,
        select: impl Fn(&MinuteEntities) -> &HashMap<String, (u64, u64)>,
    ) -> Vec<EntityCounter> {
        let mut totals: HashMap<String, (u64, u64)> = HashMap::new();
        if let Ok(minutes) = self.entity_minutes.read() {
            for bucket in minutes
                .iter()
                .filter(|bucket| bucket.timestamp >= start_ts && bucket.timestamp <= end_ts)
            {
                for (name, (count, errors)) in select(bucket) {
                    let entry = totals.entry(name.clone()).or_default();
                    entry.0 += count;
                    entry.1 += errors;
                }
            }
        }
        let mut items = totals
            .into_iter()
            .map(|(name, (count, error_count))| EntityCounter {
                name,
                count,
                error_count,
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.name.cmp(&right.name))
        });
        items.truncate(limit);
        items
    }

    pub fn get_top_apis_in_range(
        &self,
        start_ts: u64,
        end_ts: u64,
        limit: usize,
    ) -> Vec<EntityCounter> {
        self.top_entities_in_range(start_ts, end_ts, limit, |bucket| &bucket.api)
    }

    pub fn get_top_users_in_range(
        &self,
        start_ts: u64,
        end_ts: u64,
        limit: usize,
    ) -> Vec<EntityCounter> {
        self.top_entities_in_range(start_ts, end_ts, limit, |bucket| &bucket.user)
    }

    /// Like `get_top_apis_in_range`/`get_top_users_in_range`, but also
    /// reconstructs a real `avg_ms` per endpoint from the range's pooled
    /// `total_ms`, matching Python's `EndpointMetrics.total_ms / count`
    /// (`enhanced_metrics_util.py`'s `top_endpoints` builder) instead of the
    /// fixed `0.0` the route previously returned.
    pub fn get_top_endpoints_in_range(
        &self,
        start_ts: u64,
        end_ts: u64,
        limit: usize,
    ) -> Vec<EndpointEntity> {
        let mut totals: HashMap<String, EndpointBucket> = HashMap::new();
        if let Ok(minutes) = self.entity_minutes.read() {
            for bucket in minutes
                .iter()
                .filter(|bucket| bucket.timestamp >= start_ts && bucket.timestamp <= end_ts)
            {
                for (name, sample) in &bucket.endpoint {
                    let entry = totals.entry(name.clone()).or_default();
                    entry.count += sample.count;
                    entry.errors += sample.errors;
                    entry.total_ms += sample.total_ms;
                    entry
                        .latencies_ms
                        .extend(sample.latencies_ms.iter().copied());
                }
            }
        }
        let mut items = totals
            .into_iter()
            .map(|(name, bucket)| EndpointEntity {
                name,
                count: bucket.count,
                error_count: bucket.errors,
                avg_ms: if bucket.count == 0 {
                    0.0
                } else {
                    bucket.total_ms / bucket.count as f64
                },
                percentiles: pooled_percentiles(bucket.latencies_ms.iter().copied()),
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.name.cmp(&right.name))
        });
        items.truncate(limit);
        items
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
                latencies_ms: VecDeque::new(),
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
        for sample in point.latencies_ms {
            bucket.push_latency_sample(sample);
        }
    }
    buckets.into_values().collect()
}

impl Default for AnalyticsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Python's `PercentileMetrics.calculate`: sort the pooled samples and index
/// each percentile at `max(0, int(p * n) - 1)`. Shared by the range-scoped
/// per-endpoint percentiles here and `routes::platform::analytics_percentiles`.
pub fn pooled_percentiles(samples: impl Iterator<Item = f64>) -> (f64, f64, f64, f64, f64) {
    let mut values: Vec<f64> = samples.collect();
    if values.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0);
    }
    values.sort_by(|left, right| left.total_cmp(right));
    let n = values.len();
    let percentile = |fraction: f64| values[((fraction * n as f64) as usize).saturating_sub(1)];
    (
        percentile(0.50),
        percentile(0.75),
        percentile(0.90),
        percentile(0.95),
        percentile(0.99),
    )
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

    /// `METRICS_PCT_SAMPLES` is process-global; Rust's default test harness
    /// runs tests in parallel threads within one process, so any test that
    /// sets it (or is sensitive to its ambient value while pushing several
    /// samples) must serialize against every other such test to avoid a
    /// cross-test race.
    static METRICS_PCT_SAMPLES_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    #[test]
    fn top_entities_in_range_reconstructs_from_only_the_selected_minutes() {
        let aggregator = AnalyticsAggregator::new();
        // Minute 0: alice hits `api-a` twice (one error).
        aggregator.record_request_at(0, Some("api-a"), Some("alice"), Some("/x"), 200, 1.0, 0, 0);
        aggregator.record_request_at(0, Some("api-a"), Some("alice"), Some("/x"), 500, 1.0, 0, 0);
        // Minute 120 (outside the queried window below): bob hits `api-b` three times.
        aggregator.record_request_at(120, Some("api-b"), Some("bob"), Some("/y"), 200, 1.0, 0, 0);
        aggregator.record_request_at(120, Some("api-b"), Some("bob"), Some("/y"), 200, 1.0, 0, 0);
        aggregator.record_request_at(120, Some("api-b"), Some("bob"), Some("/y"), 200, 1.0, 0, 0);

        // Query only minute 0's window: api-b/bob must not appear at all.
        let top_apis = aggregator.get_top_apis_in_range(0, 59, 10);
        assert_eq!(top_apis.len(), 1);
        assert_eq!(top_apis[0].name, "api-a");
        assert_eq!(top_apis[0].count, 2);
        assert_eq!(top_apis[0].error_count, 1);

        let top_users = aggregator.get_top_users_in_range(0, 59, 10);
        assert_eq!(
            top_users,
            vec![EntityCounter {
                name: "alice".to_owned(),
                count: 2,
                error_count: 1
            }]
        );

        // Querying the full range picks up both minutes, with api-b (3) ranked above api-a (2).
        let both = aggregator.get_top_apis_in_range(0, 200, 10);
        assert_eq!(both.len(), 2);
        assert_eq!(both[0].name, "api-b");
        assert_eq!(both[0].count, 3);
        assert_eq!(both[1].name, "api-a");
    }

    #[test]
    fn get_top_endpoints_in_range_computes_a_real_avg_ms_like_python() {
        let aggregator = AnalyticsAggregator::new();
        aggregator.record_request_at(0, None, None, Some("/orders"), 200, 10.0, 0, 0);
        aggregator.record_request_at(0, None, None, Some("/orders"), 500, 30.0, 0, 0);
        aggregator.record_request_at(120, None, None, Some("/orders"), 200, 1000.0, 0, 0);

        let endpoints = aggregator.get_top_endpoints_in_range(0, 59, 10);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "/orders");
        assert_eq!(endpoints[0].count, 2);
        assert_eq!(endpoints[0].error_count, 1);
        // (10 + 30) / 2 = 20, not diluted by the out-of-range 1000ms sample.
        assert_eq!(endpoints[0].avg_ms, 20.0);
    }

    #[test]
    fn get_top_endpoints_in_range_computes_real_percentiles_like_python() {
        // Sensitive to the ambient METRICS_PCT_SAMPLES cap (pushes samples
        // past a small cap set by another test would otherwise evict some).
        let _guard = METRICS_PCT_SAMPLES_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock();
        let aggregator = AnalyticsAggregator::new();
        for latency in [10.0, 20.0, 30.0, 40.0, 100.0] {
            aggregator.record_request_at(0, None, None, Some("/orders"), 200, latency, 0, 0);
        }
        // Out-of-range sample must not pollute the pooled percentiles.
        aggregator.record_request_at(120, None, None, Some("/orders"), 200, 99999.0, 0, 0);

        let endpoints = aggregator.get_top_endpoints_in_range(0, 59, 10);
        assert_eq!(endpoints.len(), 1);
        // Sorted: [10, 20, 30, 40, 100], n=5.
        // p50: k=max(0,int(0.5*5)-1)=1 -> 20
        // p95: k=max(0,int(0.95*5)-1)=3 -> 40
        // p99: k=max(0,int(0.99*5)-1)=3 -> 40
        let (p50, _p75, _p90, p95, p99) = endpoints[0].percentiles;
        assert_eq!(p50, 20.0);
        assert_eq!(p95, 40.0);
        assert_eq!(p99, 40.0);
    }

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
        // Raw latency samples are intentionally not persisted, matching Python's
        // MinuteBucket.to_dict()/from_dict(), which omit the `latencies` deque.
        let restored: Vec<AggregatedPoint> = original
            .get_timeseries()
            .into_iter()
            .map(|mut point| {
                point.latencies_ms.clear();
                point
            })
            .collect();
        let expected: Vec<AggregatedPoint> = before_points
            .into_iter()
            .map(|mut point| {
                point.latencies_ms.clear();
                point
            })
            .collect();
        assert_eq!(restored, expected);
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
                latencies_ms: VecDeque::new(),
            },
            AggregatedPoint {
                timestamp: 599,
                requests: 1,
                errors: 0,
                latency_ms: 40.0,
                bytes_in: 5,
                bytes_out: 6,
                latencies_ms: VecDeque::new(),
            },
            AggregatedPoint {
                timestamp: 601,
                requests: 1,
                errors: 1,
                latency_ms: 20.0,
                bytes_in: 7,
                bytes_out: 8,
                latencies_ms: VecDeque::new(),
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

    #[test]
    fn p95_matches_python_sorted_index_formula() {
        // Python: arr.sort(); k = max(0, int(0.95 * len(arr)) - 1); p95 = arr[k]
        let mut point = AggregatedPoint::default();
        for ms in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0] {
            point.push_latency_sample(ms);
        }
        // len=10 -> k = max(0, int(9.5)-1) = 8 -> sorted[8] = 90.0
        assert_eq!(point.p95_ms(), 90.0);

        let empty = AggregatedPoint::default();
        assert_eq!(empty.p95_ms(), 0.0);

        let mut single = AggregatedPoint::default();
        single.push_latency_sample(42.0);
        assert_eq!(single.p95_ms(), 42.0);
    }

    #[test]
    fn latency_sample_deque_is_capped_like_python_metrics_pct_samples() {
        let _guard = METRICS_PCT_SAMPLES_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock();
        unsafe {
            std::env::set_var("METRICS_PCT_SAMPLES", "3");
        }
        let mut point = AggregatedPoint::default();
        for ms in [1.0, 2.0, 3.0, 4.0, 5.0] {
            point.push_latency_sample(ms);
        }
        assert_eq!(point.latencies_ms, VecDeque::from([3.0, 4.0, 5.0]));
        unsafe {
            std::env::remove_var("METRICS_PCT_SAMPLES");
        }
    }

    #[test]
    fn record_request_tracks_raw_latency_samples_for_percentiles() {
        let aggregator = AnalyticsAggregator::new();
        aggregator.record_request(Some("api"), Some("user"), Some("/e"), 200, 10.0, 0, 0);
        aggregator.record_request(Some("api"), Some("user"), Some("/e"), 200, 90.0, 0, 0);
        let points = aggregator.get_timeseries();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].latencies_ms.len(), 2);
        assert_eq!(points[0].p95_ms(), 10.0); // k = max(0, int(0.95*2)-1) = 0 -> sorted[0]
    }
}
