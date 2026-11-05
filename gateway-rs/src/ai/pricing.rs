//! Validated provider pricing with integer nano-USD accounting.

use crate::ai::{adapter::AiProvider, usage::AiUsage};
use serde_json::Value;
use time::{Date, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostResult {
    pub cost_nanos: u64,
    pub unpriced: bool,
}

struct Price {
    provider: String,
    pattern: String,
    effective_from: OffsetDateTime,
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
}

pub struct PriceTable {
    prices: Vec<Price>,
    /// Built-in prices, used only when no admin-entered price matches.
    builtin: Vec<Price>,
}

/// Built-in model prices generated from LiteLLM's MIT-licensed price list by
/// `scripts/update_ai_prices.py`.
const BUILTIN_PRICES: &str = include_str!("data/ai_prices.json");

/// The parsed built-in price list: metadata plus rows in `ai_pricing` shape.
/// Rows for providers this gateway doesn't support are skipped.
pub fn builtin_prices() -> &'static Value {
    static PARSED: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    PARSED.get_or_init(|| {
        let mut document: Value = serde_json::from_str(BUILTIN_PRICES).unwrap_or_default();
        if let Some(rows) = document.get_mut("prices").and_then(Value::as_array_mut) {
            rows.retain(|row| {
                row.get("provider")
                    .and_then(Value::as_str)
                    .and_then(AiProvider::parse)
                    .is_some()
            });
            for row in rows.iter_mut() {
                row["effective_from"] = Value::String("2000-01-01".to_owned());
                row["source"] = Value::String("builtin".to_owned());
            }
        }
        document
    })
}

/// Built-in prices are on unless `AI_BUILTIN_PRICES=false`.
pub fn builtin_prices_enabled() -> bool {
    !std::env::var("AI_BUILTIN_PRICES")
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("false"))
}

impl PriceTable {
    pub fn empty() -> Self {
        Self {
            prices: Vec::new(),
            builtin: Vec::new(),
        }
    }

    /// Admin-entered `docs` first, then the built-in list when enabled.
    pub fn with_builtin(mut self) -> Self {
        if builtin_prices_enabled() {
            self.builtin = builtin_prices()
                .get("prices")
                .and_then(Value::as_array)
                .map(|rows| {
                    rows.iter()
                        .filter_map(|row| parse_price(row).ok())
                        .collect()
                })
                .unwrap_or_default();
        }
        self
    }

    pub fn from_docs(docs: &[Value]) -> Result<Self, Vec<String>> {
        let mut prices = Vec::with_capacity(docs.len());
        let mut errors = Vec::new();
        for (index, doc) in docs.iter().enumerate() {
            match parse_price(doc) {
                Ok(price) => prices.push(price),
                Err(error) => errors.push(format!("pricing[{index}]: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(Self {
                prices,
                builtin: Vec::new(),
            })
        } else {
            Err(errors)
        }
    }

    pub fn cost(
        &self,
        provider: &str,
        model: &str,
        usage: &AiUsage,
        at: OffsetDateTime,
    ) -> CostResult {
        // Any matching admin price wins over the built-in list.
        let Some(price) = best_price(&self.prices, provider, model, at)
            .or_else(|| best_price(&self.builtin, provider, model, at))
        else {
            return CostResult {
                cost_nanos: 0,
                unpriced: true,
            };
        };
        let nanos = [
            (usage.input_tokens, price.input),
            (usage.output_tokens, price.output),
            (usage.cache_read_tokens, price.cache_read),
            (usage.cache_write_tokens, price.cache_write),
        ]
        .into_iter()
        .fold(0u128, |sum, (tokens, rate)| {
            sum.saturating_add(u128::from(tokens) * u128::from(rate))
        });
        CostResult {
            cost_nanos: u64::try_from(nanos).unwrap_or(u64::MAX),
            unpriced: false,
        }
    }
}

/// Exact model beats the longest `*` prefix; the latest effective date breaks ties.
fn best_price<'a>(
    prices: &'a [Price],
    provider: &str,
    model: &str,
    at: OffsetDateTime,
) -> Option<&'a Price> {
    prices
        .iter()
        .filter(|price| {
            price.provider == provider
                && price.effective_from <= at
                && (price.pattern == model
                    || price
                        .pattern
                        .strip_suffix('*')
                        .is_some_and(|prefix| model.starts_with(prefix)))
        })
        .max_by_key(|price| {
            (
                price.pattern == model,
                price.pattern.trim_end_matches('*').len(),
                price.effective_from,
            )
        })
}

pub fn validate_pricing_doc(doc: &Value) -> Result<(), String> {
    parse_price(doc).map(|_| ())
}

fn parse_price(doc: &Value) -> Result<Price, String> {
    let string_field = |field: &str| {
        doc.get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("{field} must be a nonempty string"))
    };
    let provider = string_field("provider")?;
    if AiProvider::parse(provider).is_none() {
        return Err("provider is unknown".into());
    }
    let pattern = string_field("model_pattern")?;
    if pattern.trim_end_matches('*').contains('*') || pattern.ends_with("**") {
        return Err("model_pattern only permits one trailing *".into());
    }
    let effective = string_field("effective_from")?;
    let effective_from = OffsetDateTime::parse(effective, &Rfc3339)
        .or_else(|_| {
            Date::parse(
                effective,
                time::macros::format_description!("[year]-[month]-[day]"),
            )
            .map(|date| date.midnight().assume_utc())
        })
        .map_err(|_| "effective_from must be an ISO date or RFC 3339 timestamp".to_owned())?;
    let input = parse_rate(doc.get("input_usd_per_mtok"), "input_usd_per_mtok")?;
    let output = parse_rate(doc.get("output_usd_per_mtok"), "output_usd_per_mtok")?;
    let optional_rate = |field: &str, default| match doc.get(field) {
        None | Some(Value::Null) => Ok(default),
        value => parse_rate(value, field),
    };
    Ok(Price {
        provider: provider.into(),
        pattern: pattern.into(),
        effective_from,
        input,
        output,
        cache_read: optional_rate("cache_read_usd_per_mtok", 0)?,
        cache_write: optional_rate("cache_write_usd_per_mtok", input)?,
    })
}

/// Parse the canonical JSON decimal rather than using floating-point cost math.
fn parse_rate(value: Option<&Value>, field: &str) -> Result<u64, String> {
    let invalid = || {
        format!(
            "{field} must be a nonnegative number with at most 6 decimal places and a representable nano-USD rate"
        )
    };
    let number = value.and_then(Value::as_number).ok_or_else(invalid)?;
    if number.as_f64().is_none_or(|value| value < 0.0) {
        return Err(invalid());
    }
    let repr = number.to_string();
    let repr = repr.trim_start_matches('-');
    let (mantissa, exponent) = match repr.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().map_err(|_| invalid())?),
        None => (repr, 0),
    };
    let mut scale = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len() as i32)
        - exponent;
    let digits = mantissa.replace('.', "");
    let mut digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    while digits.ends_with('0') {
        digits = &digits[..digits.len() - 1];
        scale -= 1;
    }
    if scale > 6 {
        return Err(invalid());
    }
    let integer = digits.parse::<u128>().map_err(|_| invalid())?;
    let nanos = if scale <= 3 {
        let factor = 10u128.checked_pow((3 - scale) as u32).ok_or_else(invalid)?;
        integer.checked_mul(factor).ok_or_else(invalid)?
    } else {
        let divisor = 10u128.pow((scale - 3) as u32);
        integer.checked_add(divisor / 2).ok_or_else(invalid)? / divisor
    };
    u64::try_from(nanos).map_err(|_| invalid())
}

/// USD rounded to six decimal places, without a currency symbol.
pub fn format_usd(nanos: u64) -> String {
    let micros = (u128::from(nanos) + 500) / 1000;
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    fn row(pattern: &str, input: Value, effective: &str) -> Value {
        json!({"provider":"openai","model_pattern":pattern,"input_usd_per_mtok":input,"output_usd_per_mtok":2,"effective_from":effective})
    }
    fn one_input() -> AiUsage {
        AiUsage {
            input_tokens: 1,
            ..AiUsage::default()
        }
    }

    #[test]
    fn pricing_prefers_exact_then_longest_prefix() {
        let table = PriceTable::from_docs(&[
            row("*",json!(1),"2026-01-01"), row("gpt-*",json!(2),"2026-01-01"),
            row("gpt-mini*",json!(3),"2026-01-01"), row("gpt-mini",json!(4),"2026-01-01"),
            json!({"provider":"anthropic","model_pattern":"gpt-mini","input_usd_per_mtok":99,"output_usd_per_mtok":99,"effective_from":"2026-01-01"}),
        ]).unwrap();
        for (model, rate) in [
            ("other", 1000),
            ("gpt-large", 2000),
            ("gpt-mini-latest", 3000),
            ("gpt-mini", 4000),
        ] {
            assert_eq!(
                table
                    .cost(
                        "openai",
                        model,
                        &one_input(),
                        datetime!(2026-10-18 0:00 UTC)
                    )
                    .cost_nanos,
                rate
            );
        }
    }
    #[test]
    fn pricing_respects_effective_from() {
        let table = PriceTable::from_docs(&[
            row("gpt-*", json!(1), "2026-01-01"),
            row("gpt-example", json!(2), "2026-06-01T00:00:00Z"),
            row("gpt-example", json!(3), "2026-11-01"),
            row("gpt-example", json!(4), "2026-10-01"),
        ])
        .unwrap();
        assert_eq!(
            table
                .cost(
                    "openai",
                    "gpt-example",
                    &one_input(),
                    datetime!(2026-05-01 0:00 UTC)
                )
                .cost_nanos,
            1000
        );
        assert_eq!(
            table
                .cost(
                    "openai",
                    "gpt-example",
                    &one_input(),
                    datetime!(2026-10-01 0:00 UTC)
                )
                .cost_nanos,
            4000
        );
    }
    #[test]
    fn cost_math_uses_integer_nanos() {
        let mut doc = row("gpt-example", json!(1.2345), "2026-01-01");
        doc["cache_read_usd_per_mtok"] = json!(0.1);
        let table = PriceTable::from_docs(&[doc]).unwrap();
        let usage = AiUsage {
            input_tokens: 3,
            output_tokens: 4,
            cache_read_tokens: 5,
            cache_write_tokens: 6,
            reasoning_tokens: 2,
            ..AiUsage::default()
        };
        assert_eq!(
            table
                .cost(
                    "openai",
                    "gpt-example",
                    &usage,
                    datetime!(2026-10-18 0:00 UTC)
                )
                .cost_nanos,
            3 * 1235 + 4 * 2000 + 5 * 100 + 6 * 1235
        );
        assert_eq!(format_usd(12_345_678_900), "12.345679");
        assert_eq!(format_usd(0), "0.000000");
        assert_eq!(format_usd(u64::MAX), "18446744073.709552");
    }
    #[test]
    fn unpriced_model_costs_zero_and_flags() {
        assert_eq!(
            PriceTable::empty().cost(
                "openai",
                "unknown",
                &one_input(),
                datetime!(2026-10-18 0:00 UTC)
            ),
            CostResult {
                cost_nanos: 0,
                unpriced: true
            }
        );
    }
    #[test]
    fn validate_rejects_negative_and_overprecise() {
        for rate in [
            json!(-1),
            json!(0.0000001),
            json!(1.2345678),
            json!("2"),
            json!(1e100),
        ] {
            assert!(validate_pricing_doc(&row("model", rate, "2026-01-01")).is_err());
        }
        for rate in [
            json!(0),
            json!(0.000001),
            json!(1.234567),
            json!(1e-6),
            json!(1000.0),
        ] {
            assert!(validate_pricing_doc(&row("model", rate, "2026-01-01")).is_ok());
        }
        assert!(validate_pricing_doc(&row("gpt-**", json!(1), "2026-01-01")).is_err());
        assert!(validate_pricing_doc(&row("model", json!(1), "yesterday")).is_err());
    }

    #[test]
    fn builtin_prices_all_parse_and_cover_major_providers() {
        let rows = builtin_prices()["prices"].as_array().unwrap();
        assert!(rows.len() > 100);
        for row in rows {
            parse_price(row).unwrap_or_else(|error| panic!("{row}: {error}"));
        }
        for provider in ["openai", "anthropic", "gemini", "azure_openai"] {
            assert!(
                rows.iter().any(|row| row["provider"] == provider),
                "{provider}"
            );
        }
    }

    #[test]
    fn admin_prices_win_over_builtin_and_builtin_fills_gaps() {
        let builtin_model = builtin_prices()["prices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["provider"] == "openai")
            .unwrap()["model_pattern"]
            .as_str()
            .unwrap()
            .to_owned();
        let at = datetime!(2026-06-01 0:00 UTC);
        let builtin_only = PriceTable::from_docs(&[]).unwrap().with_builtin();
        let priced = builtin_only.cost("openai", &builtin_model, &one_input(), at);
        assert!(!priced.unpriced);
        assert!(
            builtin_only
                .cost("openai", "not-a-real-model", &one_input(), at)
                .unpriced
        );
        // A broad admin pattern still beats the built-in exact entry.
        let custom = PriceTable::from_docs(&[row("*", json!(7), "2026-01-01")])
            .unwrap()
            .with_builtin();
        assert_eq!(
            custom
                .cost("openai", &builtin_model, &one_input(), at)
                .cost_nanos,
            7000
        );
    }
}
