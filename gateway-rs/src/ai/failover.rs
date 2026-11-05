//! Failover and load balancing across an AI API's primary upstream and its
//! backup targets (`api_ai_config.fallback_targets`).
//!
//! Rule C3 (no account pooling to evade rate limits): a provider 429 is never
//! retried on another target, and load balancing only spreads traffic to
//! backups on a different server (another region or deployment), never to
//! another key on the same endpoint.
//!
//! A target that returns 502-504, times out or can't be reached is benched for
//! a short cool-down so later requests go elsewhere first. The bench is per
//! gateway process and kept in memory.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a target sits out after a server error, timeout or connection error.
pub const ERROR_COOL_DOWN: Duration = Duration::from_secs(15);
const MAX_COOL_DOWN: Duration = Duration::from_secs(300);

fn bench() -> &'static Mutex<HashMap<String, Instant>> {
    static BENCH: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    BENCH.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Bench key for target `index` of `api` (`name/version`).
pub fn target_key(api: &str, index: usize) -> String {
    format!("{api}#{index}")
}

pub fn bench_target(key: &str, cool_down: Duration) {
    let until = Instant::now() + cool_down.min(MAX_COOL_DOWN);
    if let Ok(mut map) = bench().lock() {
        map.retain(|_, until| *until > Instant::now());
        map.insert(key.to_owned(), until);
    }
}

pub fn is_benched(key: &str) -> bool {
    bench()
        .lock()
        .ok()
        .and_then(|map| map.get(key).copied())
        .is_some_and(|until| until > Instant::now())
}

/// Order in which to try targets. `weights[i]` is target i's weight (index 0
/// is the primary). Without load balancing the configured order is kept; with
/// it, the first target is drawn by weight (`roll` in `0..total weight`) from
/// the healthy targets that `balanced` allows (C3: the primary, plus backups on
/// a different server), and the rest follow in configured order. Benched
/// targets move to the end, so a request still goes out when all are benched.
pub fn attempt_order(
    weights: &[u32],
    load_balance: bool,
    roll: u64,
    balanced: impl Fn(usize) -> bool,
    benched: impl Fn(usize) -> bool,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..weights.len()).collect();
    let pool: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| (i == 0 || balanced(i)) && !benched(i))
        .collect();
    if load_balance && pool.len() > 1 {
        let total: u64 = pool.iter().map(|&i| u64::from(weights[i].max(1))).sum();
        let mut point = roll % total.max(1);
        let mut first = pool[0];
        for &i in &pool {
            let weight = u64::from(weights[i].max(1));
            if point < weight {
                first = i;
                break;
            }
            point -= weight;
        }
        order.retain(|&i| i != first);
        order.insert(0, first);
    }
    let (ready, waiting): (Vec<usize>, Vec<usize>) = order.into_iter().partition(|&i| !benched(i));
    ready.into_iter().chain(waiting).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: fn(usize) -> bool = |_| true;
    const NONE: fn(usize) -> bool = |_| false;

    #[test]
    fn keeps_configured_order_without_load_balancing() {
        assert_eq!(
            attempt_order(&[1, 1, 1], false, 2, ALL, NONE),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn benched_targets_move_to_the_end() {
        assert_eq!(
            attempt_order(&[1, 1, 1], false, 0, ALL, |i| i == 0),
            vec![1, 2, 0]
        );
        assert_eq!(attempt_order(&[1, 1], false, 0, ALL, ALL), vec![0, 1]);
    }

    #[test]
    fn load_balancing_draws_the_first_target_by_weight() {
        // Weights 1, 3: rolls 0 → primary, 1..=3 → backup.
        assert_eq!(attempt_order(&[1, 3], true, 0, ALL, NONE), vec![0, 1]);
        assert_eq!(attempt_order(&[1, 3], true, 1, ALL, NONE), vec![1, 0]);
        assert_eq!(attempt_order(&[1, 3], true, 3, ALL, NONE), vec![1, 0]);
        assert_eq!(attempt_order(&[1, 3], true, 4, ALL, NONE), vec![0, 1]);
        // A benched target is never drawn first while another is healthy.
        assert_eq!(attempt_order(&[1, 3], true, 2, ALL, |i| i == 1), vec![0, 1]);
    }

    #[test]
    fn load_balancing_never_spreads_to_another_key_on_the_same_server() {
        // C3: backup 1 shares the primary's server, so it only serves as failover.
        for roll in 0..8 {
            assert_eq!(attempt_order(&[1, 3], true, roll, NONE, NONE), vec![0, 1]);
        }
    }

    #[test]
    fn bench_expires() {
        let key = target_key("bench-test/v1", 3);
        assert!(!is_benched(&key));
        bench_target(&key, Duration::from_secs(60));
        assert!(is_benched(&key));
        bench_target(&key, Duration::ZERO);
        assert!(!is_benched(&key));
    }
}
