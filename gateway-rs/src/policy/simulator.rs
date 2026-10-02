//! Offline rate-limit simulation, translated from the Python utility.

use std::{
    collections::{BTreeMap, HashMap},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

#[derive(Clone, Debug, PartialEq)]
pub struct SimulationRequest {
    pub timestamp_seconds: f64,
    pub user_id: String,
    pub endpoint: String,
    pub ip: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SimulationRule {
    pub rule_id: String,
    pub rule_type: String,
    pub time_window: String,
    pub limit: u64,
    pub burst_allowance: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SimulationResult {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub burst_used_count: u64,
    pub success_rate: f64,
    pub average_remaining: f64,
    pub peak_usage: u64,
    pub requests_by_second: BTreeMap<i64, u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SimulationScenario {
    pub scenario_name: String,
    pub rule: SimulationRule,
    pub pattern: String,
    pub result: SimulationResult,
    pub report: String,
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn window_seconds(window: &str) -> u64 {
    match window {
        "second" => 1,
        "minute" => 60,
        "hour" => 3_600,
        "day" => 86_400,
        "month" => 2_592_000,
        _ => 60,
    }
}

pub fn generate_requests(
    num_requests: usize,
    duration_seconds: f64,
    pattern: &str,
    start_seconds: f64,
) -> Vec<SimulationRequest> {
    if num_requests == 0 {
        return Vec::new();
    }
    let mut seed = start_seconds.to_bits().wrapping_add(num_requests as u64);
    let mut requests = (0..num_requests)
        .filter_map(|index| {
            let offset = match pattern {
                "uniform" => index as f64 * duration_seconds / num_requests as f64,
                "burst" => index as f64 * (duration_seconds * 0.1) / num_requests as f64,
                "spike" => {
                    duration_seconds * 0.4
                        + index as f64 * (duration_seconds * 0.2) / num_requests as f64
                }
                "gradual" => {
                    let progress = index as f64 / num_requests as f64;
                    progress * progress * duration_seconds
                }
                "random" => {
                    // A local generator keeps this utility dependency-free; Python also
                    // deliberately leaves random simulations unseeded.
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    seed as f64 / u64::MAX as f64 * duration_seconds
                }
                _ => return None,
            };
            Some(SimulationRequest {
                timestamp_seconds: start_seconds + offset,
                user_id: "sim_user".to_owned(),
                endpoint: "/api/test".to_owned(),
                ip: "192.168.1.1".to_owned(),
            })
        })
        .collect::<Vec<_>>();
    if pattern == "random" {
        requests.sort_by(|left, right| left.timestamp_seconds.total_cmp(&right.timestamp_seconds));
    }
    requests
}

pub fn simulate_rule(rule: &SimulationRule, requests: &[SimulationRequest]) -> SimulationResult {
    let mut allowed_requests = 0_u64;
    let mut blocked_requests = 0_u64;
    let mut burst_used_count = 0_u64;
    let mut remaining_values = Vec::with_capacity(requests.len());
    let mut requests_by_second = BTreeMap::new();

    for request in requests {
        *requests_by_second
            .entry(request.timestamp_seconds as i64)
            .or_insert(0) += 1;
    }
    let window = window_seconds(&rule.time_window) as f64;
    for request in requests {
        let window_start = request.timestamp_seconds - window;
        let current_usage = requests
            .iter()
            .filter(|candidate| {
                candidate.timestamp_seconds >= window_start
                    && candidate.timestamp_seconds <= request.timestamp_seconds
            })
            .count() as u64;
        if current_usage <= rule.limit {
            allowed_requests += 1;
            remaining_values.push(rule.limit - current_usage);
        } else if rule.burst_allowance > 0
            && current_usage <= rule.limit.saturating_add(rule.burst_allowance)
        {
            allowed_requests += 1;
            burst_used_count += 1;
            remaining_values.push(
                rule.limit
                    .saturating_add(rule.burst_allowance)
                    .saturating_sub(current_usage),
            );
        } else {
            blocked_requests += 1;
            remaining_values.push(0);
        }
    }
    let total_requests = requests.len() as u64;
    let success_rate = if total_requests == 0 {
        0.0
    } else {
        allowed_requests as f64 / total_requests as f64 * 100.0
    };
    let average_remaining = if remaining_values.is_empty() {
        0.0
    } else {
        remaining_values.iter().sum::<u64>() as f64 / remaining_values.len() as f64
    };
    let peak_usage = requests_by_second.values().copied().max().unwrap_or(0);
    SimulationResult {
        total_requests,
        allowed_requests,
        blocked_requests,
        burst_used_count,
        success_rate,
        average_remaining,
        peak_usage,
        requests_by_second,
    }
}

pub fn compare_rules(
    rules: &[SimulationRule],
    requests: &[SimulationRequest],
) -> HashMap<String, SimulationResult> {
    rules
        .iter()
        .map(|rule| (rule.rule_id.clone(), simulate_rule(rule, requests)))
        .collect()
}

pub fn preview_rule_change(
    current_rule: &SimulationRule,
    new_rule: &SimulationRule,
    historical_pattern: &str,
    duration_minutes: u64,
) -> HashMap<String, SimulationResult> {
    let requests = generate_requests(
        (current_rule.limit as f64 * 1.5) as usize,
        duration_minutes as f64 * 60.0,
        historical_pattern,
        now_seconds(),
    );
    compare_rules(&[current_rule.clone(), new_rule.clone()], &requests)
}

pub fn test_burst_effectiveness(
    base_limit: u64,
    burst_allowances: &[u64],
    spike_intensity: f64,
) -> BTreeMap<u64, SimulationResult> {
    let requests = generate_requests(
        (base_limit as f64 * spike_intensity) as usize,
        60.0,
        "spike",
        now_seconds(),
    );
    burst_allowances
        .iter()
        .map(|burst| {
            let rule = SimulationRule {
                rule_id: format!("burst_{burst}"),
                rule_type: "per_user".to_owned(),
                time_window: "minute".to_owned(),
                limit: base_limit,
                burst_allowance: *burst,
            };
            (*burst, simulate_rule(&rule, &requests))
        })
        .collect()
}

pub fn generate_report(rule: &SimulationRule, result: &SimulationResult) -> String {
    let mut report = format!(
        "\nRate Limit Simulation Report\n{line}\n\nRule Configuration:\n  Rule ID: {id}\n  Type: {kind}\n  Time Window: {window}\n  Limit: {limit}\n  Burst Allowance: {burst}\n\nSimulation Results:\n  Total Requests: {total}\n  Allowed: {allowed} ({rate:.1}%)\n  Blocked: {blocked}\n  Burst Used: {burst_used}\n\nPerformance Metrics:\n  Success Rate: {rate:.1}%\n  Average Remaining: {remaining:.1}\n  Peak Usage: {peak} req/sec\n\nRecommendation:\n",
        line = "=".repeat(50),
        id = rule.rule_id,
        kind = rule.rule_type,
        window = rule.time_window,
        limit = rule.limit,
        burst = rule.burst_allowance,
        total = result.total_requests,
        allowed = result.allowed_requests,
        rate = result.success_rate,
        blocked = result.blocked_requests,
        burst_used = result.burst_used_count,
        remaining = result.average_remaining,
        peak = result.peak_usage,
    );
    if result.success_rate < 90.0 {
        report.push_str("  ⚠️  Consider increasing limit or burst allowance\n");
    } else if result.success_rate > 99.0 && result.average_remaining > rule.limit as f64 * 0.5 {
        report.push_str("  ℹ️  Limit may be too high, consider reducing\n");
    } else {
        report.push_str("  ✅ Rule configuration appears appropriate\n");
    }
    if result.burst_used_count > 0 {
        let percentage = result.burst_used_count as f64 / result.allowed_requests as f64 * 100.0;
        report.push_str(&format!(
            "  ℹ️  {percentage:.1}% of requests used burst tokens\n"
        ));
    }
    report
}

pub fn run_scenario(
    scenario_name: &str,
    rule: &SimulationRule,
    pattern: &str,
    duration_minutes: u64,
) -> SimulationScenario {
    let requests = generate_requests(
        rule.limit.saturating_mul(2) as usize,
        duration_minutes as f64 * 60.0,
        pattern,
        now_seconds(),
    );
    let result = simulate_rule(rule, &requests);
    let report = generate_report(rule, &result);
    SimulationScenario {
        scenario_name: scenario_name.to_owned(),
        rule: rule.clone(),
        pattern: pattern.to_owned(),
        result,
        report,
    }
}

pub fn quick_simulate(limit: u64, time_window: &str, burst: u64, pattern: &str) -> String {
    let rule = SimulationRule {
        rule_id: "quick_sim".to_owned(),
        rule_type: "per_user".to_owned(),
        time_window: time_window.to_owned(),
        limit,
        burst_allowance: burst,
    };
    let requests = generate_requests(
        limit.saturating_mul(2) as usize,
        60.0,
        pattern,
        now_seconds(),
    );
    generate_report(&rule, &simulate_rule(&rule, &requests))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(limit: u64, burst: u64) -> SimulationRule {
        SimulationRule {
            rule_id: "example".to_owned(),
            rule_type: "per_user".to_owned(),
            time_window: "minute".to_owned(),
            limit,
            burst_allowance: burst,
        }
    }

    #[test]
    fn generates_python_traffic_patterns() {
        let uniform = generate_requests(4, 100.0, "uniform", 1_000.0);
        assert_eq!(uniform[3].timestamp_seconds, 1_075.0);
        let spike = generate_requests(4, 100.0, "spike", 1_000.0);
        assert_eq!(spike[0].timestamp_seconds, 1_040.0);
        assert_eq!(spike[3].timestamp_seconds, 1_055.0);
        assert!(generate_requests(3, 10.0, "unknown", 0.0).is_empty());
    }

    #[test]
    fn simulates_limit_and_burst_like_python() {
        let requests = generate_requests(5, 1.0, "burst", 1_000.0);
        let result = simulate_rule(&rule(2, 1), &requests);
        assert_eq!(result.allowed_requests, 3);
        assert_eq!(result.blocked_requests, 2);
        assert_eq!(result.burst_used_count, 1);
        assert_eq!(result.peak_usage, 5);
        assert_eq!(result.success_rate, 60.0);
        assert!(generate_report(&rule(2, 1), &result).contains("Consider increasing limit"));
    }

    #[test]
    fn comparison_and_scenario_helpers_preserve_python_shapes() {
        let current = rule(4, 0);
        let mut proposed = rule(8, 2);
        proposed.rule_id = "proposed".to_owned();
        let comparison = preview_rule_change(&current, &proposed, "uniform", 1);
        assert_eq!(comparison.len(), 2);
        assert!(comparison.contains_key("example"));
        assert!(comparison.contains_key("proposed"));
        let bursts = test_burst_effectiveness(4, &[0, 2], 2.0);
        assert_eq!(bursts.len(), 2);
        let scenario = run_scenario("load", &current, "uniform", 5);
        assert_eq!(scenario.scenario_name, "load");
        assert_eq!(scenario.result.total_requests, 8);
        assert!(quick_simulate(4, "minute", 0, "uniform").contains("quick_sim"));
    }
}
