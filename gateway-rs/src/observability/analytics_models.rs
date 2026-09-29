use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AggregationLevel {
    #[serde(rename = "minute")]
    Minute,
    #[serde(rename = "5minute")]
    FiveMinute,
    #[serde(rename = "hour")]
    Hour,
    #[serde(rename = "day")]
    Day,
}

impl AggregationLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::FiveMinute => "5minute",
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "minute" => Ok(Self::Minute),
            "5minute" => Ok(Self::FiveMinute),
            "hour" => Ok(Self::Hour),
            "day" => Ok(Self::Day),
            _ => Err(format!("{value:?} is not a valid AggregationLevel")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MetricType {
    #[serde(rename = "request_count")]
    RequestCount,
    #[serde(rename = "error_rate")]
    ErrorRate,
    #[serde(rename = "response_time")]
    ResponseTime,
    #[serde(rename = "bandwidth")]
    Bandwidth,
    #[serde(rename = "status_code")]
    StatusCode,
    #[serde(rename = "latency_percentile")]
    LatencyPercentile,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct PercentileMetrics {
    pub p50: f64,
    pub p75: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub min: f64,
    pub max: f64,
}

impl PercentileMetrics {
    pub fn calculate(latencies: &[f64]) -> Self {
        if latencies.is_empty() {
            return Self::default();
        }
        let mut sorted = latencies.to_vec();
        sorted.sort_by(f64::total_cmp);
        let percentile = |value: f64| {
            let index = ((value * sorted.len() as f64) as usize)
                .saturating_sub(1)
                .min(sorted.len() - 1);
            sorted[index]
        };
        Self {
            p50: percentile(0.50),
            p75: percentile(0.75),
            p90: percentile(0.90),
            p95: percentile(0.95),
            p99: percentile(0.99),
            min: sorted[0],
            max: sorted[sorted.len() - 1],
        }
    }

    pub fn to_dict(&self) -> Value {
        serde_json::to_value(self).expect("percentiles are JSON representable")
    }

    fn from_value(value: &Value) -> Self {
        Self {
            p50: float_field(value, "p50"),
            p75: float_field(value, "p75"),
            p90: float_field(value, "p90"),
            p95: float_field(value, "p95"),
            p99: float_field(value, "p99"),
            min: float_field(value, "min"),
            max: float_field(value, "max"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EndpointMetrics {
    pub endpoint_uri: String,
    pub method: String,
    pub count: i64,
    pub error_count: i64,
    pub total_ms: f64,
    pub latencies: VecDeque<f64>,
    pub status_counts: BTreeMap<i64, i64>,
}

impl EndpointMetrics {
    pub fn new(endpoint_uri: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            endpoint_uri: endpoint_uri.into(),
            method: method.into(),
            count: 0,
            error_count: 0,
            total_ms: 0.0,
            latencies: VecDeque::new(),
            status_counts: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, milliseconds: f64, status: i64, max_samples: usize) {
        self.count += 1;
        self.error_count += i64::from(status >= 400);
        self.total_ms += milliseconds;
        *self.status_counts.entry(status).or_default() += 1;
        push_bounded(&mut self.latencies, milliseconds, max_samples);
    }

    pub fn get_percentiles(&self) -> PercentileMetrics {
        PercentileMetrics::calculate(&self.latencies.iter().copied().collect::<Vec<_>>())
    }

    pub fn to_dict(&mut self) -> Value {
        let percentiles = self.get_percentiles();
        json!({
            "endpoint_uri": self.endpoint_uri,
            "method": self.method,
            "count": self.count,
            "error_count": self.error_count,
            "error_rate": ratio(self.error_count, self.count),
            "avg_ms": if self.count > 0 { self.total_ms / self.count as f64 } else { 0.0 },
            "percentiles": percentiles.to_dict(),
            "status_counts": integer_map(&self.status_counts),
        })
    }

    pub fn from_dict(value: &Value) -> Result<Self, String> {
        let count = int_field(value, "count")?;
        Ok(Self {
            endpoint_uri: string_field(value, "endpoint_uri"),
            method: string_field(value, "method"),
            count,
            error_count: int_field(value, "error_count")?,
            total_ms: float_field(value, "avg_ms") * count as f64,
            latencies: VecDeque::new(),
            status_counts: int_map(value.get("status_counts"))?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnhancedMinuteBucket {
    pub start_ts: i64,
    pub count: i64,
    pub error_count: i64,
    pub total_ms: f64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub upstream_timeouts: i64,
    pub retries: i64,
    pub status_counts: BTreeMap<i64, i64>,
    pub api_counts: BTreeMap<String, i64>,
    pub api_error_counts: BTreeMap<String, i64>,
    pub user_counts: BTreeMap<String, i64>,
    pub latencies: VecDeque<f64>,
    pub endpoint_metrics: BTreeMap<String, EndpointMetrics>,
    pub unique_users: BTreeSet<String>,
    pub request_sizes: VecDeque<i64>,
    pub response_sizes: VecDeque<i64>,
}

impl EnhancedMinuteBucket {
    pub fn new(start_ts: i64) -> Self {
        Self {
            start_ts,
            count: 0,
            error_count: 0,
            total_ms: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            upstream_timeouts: 0,
            retries: 0,
            status_counts: BTreeMap::new(),
            api_counts: BTreeMap::new(),
            api_error_counts: BTreeMap::new(),
            user_counts: BTreeMap::new(),
            latencies: VecDeque::new(),
            endpoint_metrics: BTreeMap::new(),
            unique_users: BTreeSet::new(),
            request_sizes: VecDeque::new(),
            response_sizes: VecDeque::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_request(
        &mut self,
        milliseconds: f64,
        status: i64,
        username: Option<&str>,
        api_key: Option<&str>,
        endpoint_uri: Option<&str>,
        method: Option<&str>,
        bytes_in: i64,
        bytes_out: i64,
        max_samples: usize,
    ) {
        self.count += 1;
        self.error_count += i64::from(status >= 400);
        self.total_ms += milliseconds;
        self.bytes_in += bytes_in;
        self.bytes_out += bytes_out;
        *self.status_counts.entry(status).or_default() += 1;
        if let Some(api_key) = api_key.filter(|value| !value.is_empty()) {
            *self.api_counts.entry(api_key.to_owned()).or_default() += 1;
            if status >= 400 {
                *self.api_error_counts.entry(api_key.to_owned()).or_default() += 1;
            }
        }
        if let Some(username) = username.filter(|value| !value.is_empty()) {
            *self.user_counts.entry(username.to_owned()).or_default() += 1;
            self.unique_users.insert(username.to_owned());
        }
        push_bounded(&mut self.latencies, milliseconds, max_samples);
        if let (Some(endpoint_uri), Some(method)) = (
            endpoint_uri.filter(|value| !value.is_empty()),
            method.filter(|value| !value.is_empty()),
        ) {
            self.endpoint_metrics
                .entry(format!("{method}:{endpoint_uri}"))
                .or_insert_with(|| EndpointMetrics::new(endpoint_uri, method))
                .add(milliseconds, status, max_samples);
        }
        if bytes_in > 0 {
            push_bounded(&mut self.request_sizes, bytes_in, max_samples);
        }
        if bytes_out > 0 {
            push_bounded(&mut self.response_sizes, bytes_out, max_samples);
        }
    }

    pub fn get_percentiles(&self) -> PercentileMetrics {
        PercentileMetrics::calculate(&self.latencies.iter().copied().collect::<Vec<_>>())
    }

    pub fn get_unique_user_count(&self) -> usize {
        self.unique_users.len()
    }

    pub fn get_top_endpoints(&mut self, limit: usize) -> Vec<Value> {
        let mut endpoints = self
            .endpoint_metrics
            .values_mut()
            .map(EndpointMetrics::to_dict)
            .collect::<Vec<_>>();
        endpoints.sort_by(|left, right| {
            int_value(right.get("count")).cmp(&int_value(left.get("count")))
        });
        endpoints.truncate(limit);
        endpoints
    }

    pub fn to_dict(&mut self) -> Value {
        let percentiles = self.get_percentiles();
        let endpoints = self
            .endpoint_metrics
            .iter_mut()
            .map(|(key, value)| (key.clone(), value.to_dict()))
            .collect::<Map<_, _>>();
        let average_response_size = if self.response_sizes.is_empty() {
            0.0
        } else {
            self.response_sizes.iter().sum::<i64>() as f64 / self.response_sizes.len() as f64
        };
        json!({
            "start_ts": self.start_ts, "count": self.count, "error_count": self.error_count,
            "total_ms": self.total_ms, "bytes_in": self.bytes_in, "bytes_out": self.bytes_out,
            "upstream_timeouts": self.upstream_timeouts, "retries": self.retries,
            "status_counts": integer_map(&self.status_counts), "api_counts": self.api_counts,
            "api_error_counts": self.api_error_counts, "user_counts": self.user_counts,
            "percentiles": percentiles.to_dict(), "unique_users": self.get_unique_user_count(),
            "unique_users_list": self.unique_users, "endpoint_metrics": endpoints,
            "avg_response_size": average_response_size,
        })
    }

    pub fn from_dict(value: &Value) -> Result<Self, String> {
        let mut bucket = Self::new(int_field(value, "start_ts")?);
        bucket.count = int_field(value, "count")?;
        bucket.error_count = int_field(value, "error_count")?;
        bucket.total_ms = float_field(value, "total_ms");
        bucket.bytes_in = int_field(value, "bytes_in")?;
        bucket.bytes_out = int_field(value, "bytes_out")?;
        bucket.upstream_timeouts = int_field(value, "upstream_timeouts")?;
        bucket.retries = int_field(value, "retries")?;
        bucket.status_counts = int_map(value.get("status_counts"))?;
        bucket.api_counts = string_int_map(value.get("api_counts"))?;
        bucket.api_error_counts = string_int_map(value.get("api_error_counts"))?;
        bucket.user_counts = string_int_map(value.get("user_counts"))?;
        if let Some(endpoints) = value.get("endpoint_metrics").and_then(Value::as_object) {
            for (key, endpoint) in endpoints {
                if let Ok(endpoint) = EndpointMetrics::from_dict(endpoint) {
                    bucket.endpoint_metrics.insert(key.clone(), endpoint);
                }
            }
        }
        bucket.unique_users = value
            .get("unique_users_list")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(py_string).collect())
            .unwrap_or_else(|| bucket.user_counts.keys().cloned().collect());
        Ok(bucket)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregatedMetrics {
    pub start_ts: i64,
    pub end_ts: i64,
    pub level: AggregationLevel,
    pub count: i64,
    pub error_count: i64,
    pub total_ms: f64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub unique_users: i64,
    pub status_counts: BTreeMap<i64, i64>,
    pub api_counts: BTreeMap<String, i64>,
    pub percentiles: Option<PercentileMetrics>,
    pub unique_users_set: BTreeSet<String>,
}

impl AggregatedMetrics {
    pub fn to_dict(&self) -> Value {
        json!({
            "start_ts": self.start_ts, "end_ts": self.end_ts, "level": self.level,
            "count": self.count, "error_count": self.error_count,
            "error_rate": ratio(self.error_count, self.count),
            "avg_ms": if self.count > 0 { self.total_ms / self.count as f64 } else { 0.0 },
            "bytes_in": self.bytes_in, "bytes_out": self.bytes_out,
            "unique_users": self.unique_users, "status_counts": integer_map(&self.status_counts),
            "api_counts": self.api_counts,
            "percentiles": self.percentiles.as_ref().map(PercentileMetrics::to_dict),
            "unique_users_list": self.unique_users_set,
        })
    }

    pub fn from_dict(value: &Value) -> Result<Self, String> {
        let level = AggregationLevel::parse(
            value
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("minute"),
        )?;
        Ok(Self {
            start_ts: int_field(value, "start_ts")?,
            end_ts: int_field(value, "end_ts")?,
            level,
            count: int_field(value, "count")?,
            error_count: int_field(value, "error_count")?,
            total_ms: float_field(value, "total_ms"),
            bytes_in: int_field(value, "bytes_in")?,
            bytes_out: int_field(value, "bytes_out")?,
            unique_users: int_field(value, "unique_users")?,
            status_counts: int_map(value.get("status_counts"))?,
            api_counts: string_int_map(value.get("api_counts"))?,
            percentiles: value
                .get("percentiles")
                .filter(|value| !value.is_null())
                .map(PercentileMetrics::from_value),
            unique_users_set: value
                .get("unique_users_list")
                .and_then(Value::as_array)
                .map(|items| items.iter().map(py_string).collect())
                .unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AnalyticsSnapshot {
    pub start_ts: i64,
    pub end_ts: i64,
    pub total_requests: i64,
    pub total_errors: i64,
    pub error_rate: f64,
    pub avg_response_ms: f64,
    pub percentiles: PercentileMetrics,
    pub total_bytes_in: i64,
    pub total_bytes_out: i64,
    pub unique_users: i64,
    pub series: Vec<Value>,
    pub top_apis: Vec<(String, i64)>,
    pub top_users: Vec<(String, i64)>,
    pub top_endpoints: Vec<Value>,
    pub status_distribution: BTreeMap<String, i64>,
}

impl AnalyticsSnapshot {
    pub fn to_dict(&self) -> Value {
        json!({
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "summary": {
                "total_requests": self.total_requests, "total_errors": self.total_errors,
                "error_rate": self.error_rate, "avg_response_ms": self.avg_response_ms,
                "percentiles": self.percentiles.to_dict(), "total_bytes_in": self.total_bytes_in,
                "total_bytes_out": self.total_bytes_out, "unique_users": self.unique_users,
            },
            "series": self.series,
            "top_apis": self.top_apis.iter().map(|(api, count)| json!({"api": api, "count": count})).collect::<Vec<_>>(),
            "top_users": self.top_users.iter().map(|(user, count)| json!({"user": user, "count": count})).collect::<Vec<_>>(),
            "top_endpoints": self.top_endpoints,
            "status_distribution": self.status_distribution,
        })
    }
}

fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator > 0 {
        numerator as f64 / denominator as f64
    } else {
        0.0
    }
}

fn push_bounded<T>(values: &mut VecDeque<T>, value: T, maximum: usize) {
    values.push_back(value);
    while values.len() > maximum {
        values.pop_front();
    }
}

fn integer_map(values: &BTreeMap<i64, i64>) -> Value {
    Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.to_string(), json!(value)))
            .collect(),
    )
}

fn int_map(value: Option<&Value>) -> Result<BTreeMap<i64, i64>, String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(key, value)| {
            Ok((
                key.parse::<i64>().map_err(|error| error.to_string())?,
                int_value(Some(value)),
            ))
        })
        .collect()
}

fn string_int_map(value: Option<&Value>) -> Result<BTreeMap<String, i64>, String> {
    Ok(value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(key, value)| (key.clone(), int_value(Some(value))))
        .collect())
}

fn int_field(value: &Value, key: &str) -> Result<i64, String> {
    Ok(value.get(key).map_or(0, |value| int_value(Some(value))))
}

fn int_value(value: Option<&Value>) -> i64 {
    value
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
        })
        .unwrap_or(0)
}

fn float_field(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<f64>().ok()))
        })
        .unwrap_or(0.0)
}

fn string_field(value: &Value, key: &str) -> String {
    value.get(key).map(py_string).unwrap_or_default()
}

fn py_string(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(value) => if *value { "True" } else { "False" }.to_owned(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_selection_matches_python_floor_index_algorithm() {
        assert_eq!(
            PercentileMetrics::calculate(&[]),
            PercentileMetrics::default()
        );
        let metrics = PercentileMetrics::calculate(&[50.0, 10.0, 40.0, 20.0, 30.0]);
        assert_eq!(metrics.p50, 20.0);
        assert_eq!(metrics.p75, 30.0);
        assert_eq!(metrics.p90, 40.0);
        assert_eq!(metrics.p95, 40.0);
        assert_eq!(metrics.p99, 40.0);
        assert_eq!((metrics.min, metrics.max), (10.0, 50.0));
    }

    #[test]
    fn endpoint_and_minute_bucket_tracking_round_trip_like_python() {
        let mut bucket = EnhancedMinuteBucket::new(1_700_000_000);
        for milliseconds in [10.0, 20.0, 30.0] {
            bucket.add_request(
                milliseconds,
                200,
                Some("alice"),
                Some("rest:demo"),
                Some("/items"),
                Some("GET"),
                5,
                10,
                2,
            );
        }
        bucket.add_request(
            40.0,
            500,
            Some("bob"),
            Some("rest:demo"),
            Some("/other"),
            Some("POST"),
            0,
            20,
            2,
        );
        assert_eq!(bucket.count, 4);
        assert_eq!(bucket.error_count, 1);
        assert_eq!(
            bucket.latencies.iter().copied().collect::<Vec<_>>(),
            vec![30.0, 40.0]
        );
        assert_eq!(bucket.get_unique_user_count(), 2);
        assert_eq!(bucket.get_top_endpoints(1)[0]["count"], 3);
        let value = bucket.to_dict();
        assert_eq!(value["avg_response_size"], 15.0);
        let restored = EnhancedMinuteBucket::from_dict(&value).unwrap();
        assert_eq!(restored.count, 4);
        assert_eq!(
            restored.unique_users,
            BTreeSet::from(["alice".to_owned(), "bob".to_owned()])
        );
        assert_eq!(restored.endpoint_metrics["GET:/items"].total_ms, 60.0);
        assert!(restored.latencies.is_empty());
    }

    #[test]
    fn aggregated_metrics_and_snapshot_shapes_match_python() {
        let aggregated = AggregatedMetrics::from_dict(&json!({
            "start_ts": "100", "end_ts": 200, "level": "5minute", "count": 4,
            "error_count": 1, "total_ms": 50.0, "bytes_in": 8, "bytes_out": 9,
            "unique_users": 2, "status_counts": {"200": 3, "500": 1},
            "api_counts": {"rest:demo": 4}, "percentiles": {"p95": 20},
            "unique_users_list": ["alice", "bob"]
        }))
        .unwrap();
        let value = aggregated.to_dict();
        assert_eq!(value["level"], "5minute");
        assert_eq!(value["error_rate"], 0.25);
        assert_eq!(value["avg_ms"], 12.5);
        assert_eq!(value["percentiles"]["p95"], 20.0);

        let snapshot = AnalyticsSnapshot {
            start_ts: 100,
            end_ts: 200,
            total_requests: 4,
            total_errors: 1,
            error_rate: 0.25,
            avg_response_ms: 12.5,
            percentiles: PercentileMetrics::default(),
            total_bytes_in: 8,
            total_bytes_out: 9,
            unique_users: 2,
            series: vec![json!({"count": 4})],
            top_apis: vec![("rest:demo".to_owned(), 4)],
            top_users: vec![("alice".to_owned(), 3)],
            top_endpoints: vec![json!({"endpoint_uri": "/items"})],
            status_distribution: BTreeMap::from([("200".to_owned(), 3)]),
        };
        let snapshot = snapshot.to_dict();
        assert_eq!(snapshot["summary"]["total_requests"], 4);
        assert_eq!(
            snapshot["top_apis"][0],
            json!({"api": "rest:demo", "count": 4})
        );
        assert_eq!(
            snapshot["top_users"][0],
            json!({"user": "alice", "count": 3})
        );
    }
}
