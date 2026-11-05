//! Scoped, compiled text detectors. Outcomes contain only detector IDs and counts.

use crate::ai::adapter::AiProvider;
use regex::{Regex, RegexBuilder};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const REGEX_SIZE_LIMIT: usize = 1024 * 1024;
const MAX_PATTERN_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Input,
    Output,
}
#[derive(Clone, Copy, PartialEq)]
enum Action {
    Redact,
    Block,
    LogOnly,
}

struct Detector {
    id: String,
    regex: Regex,
    luhn: bool,
}

pub struct Guardrail {
    pub id: String,
    pub name: String,
    enabled: bool,
    input: bool,
    output: bool,
    apis: Vec<String>,
    groups: Vec<String>,
    detectors: Vec<Detector>,
    action: Action,
    dry_run: bool,
}

#[derive(Default)]
pub struct CompiledGuardrails {
    rails: Vec<Guardrail>,
}
#[derive(Default, Debug)]
pub struct GuardrailOutcome {
    pub blocked_by: Option<String>,
    pub redactions: Vec<(String, u32)>,
    pub dry_run_hits: Vec<(String, u32)>,
    pub log_only_hits: Vec<(String, u32)>,
}

impl CompiledGuardrails {
    pub fn compile(docs: &[Value]) -> (Self, Vec<String>) {
        let mut rails = Vec::new();
        let mut errors = Vec::new();
        for (index, doc) in docs.iter().enumerate() {
            match compile_rail(doc) {
                Ok(rail) => rails.push(rail),
                Err(error) => errors.push(format!("guardrails[{index}]: {error}")),
            }
        }
        (Self { rails }, errors)
    }

    /// API and group scopes both apply; `*` matches all in the corresponding scope.
    pub fn applicable(
        &self,
        api: &str,
        groups: &[String],
        direction: Direction,
    ) -> Vec<&Guardrail> {
        self.rails
            .iter()
            .filter(|rail| {
                rail.enabled
                    && match direction {
                        Direction::Input => rail.input,
                        Direction::Output => rail.output,
                    }
                    && rail
                        .apis
                        .iter()
                        .any(|target| target == "*" || target == api)
                    && rail
                        .groups
                        .iter()
                        .any(|target| target == "*" || groups.contains(target))
            })
            .collect()
    }
}

pub fn apply(
    provider: AiProvider,
    direction: Direction,
    body: &mut Value,
    rails: &[&Guardrail],
) -> GuardrailOutcome {
    let mut outcome = GuardrailOutcome::default();
    let rails: Vec<_> = rails
        .iter()
        .copied()
        .filter(|rail| {
            rail.enabled
                && match direction {
                    Direction::Input => rail.input,
                    Direction::Output => rail.output,
                }
        })
        .collect();
    // Blocking checks see the original body, regardless of rule order.
    for rail in rails
        .iter()
        .filter(|rail| !rail.dry_run && rail.action == Action::Block)
    {
        walk_body(provider, direction, body, &mut |text| {
            if outcome.blocked_by.is_none() && !find_hits(rail, text).is_empty() {
                outcome.blocked_by = Some(rail.name.clone());
            }
        });
        if outcome.blocked_by.is_some() {
            return outcome;
        }
    }
    walk_body(provider, direction, body, &mut |text| {
        let mut redaction_hits = Vec::new();
        for rail in &rails {
            let hits = find_hits(rail, text);
            if rail.dry_run {
                add_counts(&mut outcome.dry_run_hits, &hits);
            } else {
                match rail.action {
                    Action::Redact => {
                        add_counts(&mut outcome.redactions, &hits);
                        redaction_hits.extend(hits);
                    }
                    Action::Block => {}
                    Action::LogOnly => add_counts(&mut outcome.log_only_hits, &hits),
                }
            }
        }
        redaction_hits.sort_by_key(|hit| (hit.start, std::cmp::Reverse(hit.end)));
        if !redaction_hits.is_empty() {
            *text = redacted(text, &redaction_hits);
        }
    });
    outcome
}

pub fn redact_text(text: &str, rails: &[&Guardrail]) -> String {
    let mut hits = Vec::new();
    for rail in rails {
        if rail.enabled && !rail.dry_run && rail.action == Action::Redact {
            hits.extend(find_hits(rail, text));
        }
    }
    hits.sort_by_key(|hit| (hit.start, std::cmp::Reverse(hit.end)));
    redacted(text, &hits)
}

pub fn test_text(rail_doc: &Value, text: &str) -> Result<Value, Vec<String>> {
    let rail = compile_rail(rail_doc).map_err(|error| vec![error])?;
    let hits = find_hits(&rail, text);
    Ok(
        json!({"matches":hits.iter().map(|hit| json!({"detector":hit.detector,"start":hit.start,"end":hit.end})).collect::<Vec<_>>(),"redacted":redacted(text,&hits)}),
    )
}

pub fn validate_guardrail_doc(doc: &Value) -> Result<(), Vec<String>> {
    compile_rail(doc).map(|_| ()).map_err(|error| vec![error])
}

fn compile_rail(doc: &Value) -> Result<Guardrail, String> {
    let required_string = |field: &str| {
        doc.get(field)
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| format!("{field} must be a nonempty string"))
    };
    let name = required_string("name")?.to_owned();
    let (input, output) = match required_string("direction")? {
        "input" => (true, false),
        "output" => (false, true),
        "both" => (true, true),
        _ => return Err("direction must be input, output or both".into()),
    };
    let action = match required_string("action")? {
        "redact" => Action::Redact,
        "block" => Action::Block,
        "log_only" => Action::LogOnly,
        _ => return Err("action must be redact, block or log_only".into()),
    };
    let dry_run = match required_string("mode")? {
        "enforce" => false,
        "dry_run" => true,
        _ => return Err("mode must be enforce or dry_run".into()),
    };
    let enabled = doc
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or("enabled must be a boolean")?;
    let scope = |field: &str| -> Result<Vec<String>, String> {
        let values = doc["applies_to"][field]
            .as_array()
            .ok_or_else(|| format!("applies_to.{field} must be an array"))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| !text.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("applies_to.{field} must contain nonempty strings"))
            })
            .collect()
    };
    let apis = scope("apis")?;
    let groups = scope("groups")?;
    let docs = doc["detectors"]
        .as_array()
        .filter(|docs| !docs.is_empty())
        .ok_or("detectors must be a nonempty array")?;
    let mut detectors = Vec::new();
    for detector in docs {
        let (id, pattern, luhn, insensitive) = match detector["type"].as_str() {
            Some("builtin") => {
                let id = detector["id"]
                    .as_str()
                    .ok_or("builtin detector requires an id")?;
                let pattern = match id {
                    "email" => r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                    "us_ssn" => r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
                    "credit_card" => r"\b(?:[0-9][ -]?){12,18}[0-9]\b",
                    "aws_access_key" => r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
                    "private_key_pem" => {
                        r"(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
                    }
                    "generic_api_key" => {
                        r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{10,})\b"
                    }
                    _ => return Err("unknown builtin detector id".into()),
                };
                (
                    id.to_owned(),
                    pattern.to_owned(),
                    id == "credit_card",
                    false,
                )
            }
            Some("regex") => {
                let pattern = detector["pattern"]
                    .as_str()
                    .filter(|pattern| !pattern.is_empty())
                    .ok_or("regex pattern must be a nonempty string")?;
                if pattern.len() > MAX_PATTERN_BYTES {
                    return Err("regex pattern exceeds 1 KiB".into());
                }
                ("regex".into(), pattern.to_owned(), false, false)
            }
            Some("keywords") => {
                let values = detector["values"]
                    .as_array()
                    .filter(|values| !values.is_empty())
                    .ok_or("keywords values must be a nonempty array")?;
                let escaped: Result<Vec<_>, _> = values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|text| !text.is_empty())
                            .map(regex::escape)
                            .ok_or("keywords must be nonempty strings")
                    })
                    .collect();
                (
                    "keywords".into(),
                    format!("(?:{})", escaped?.join("|")),
                    false,
                    true,
                )
            }
            _ => return Err("unknown detector type".into()),
        };
        let regex = RegexBuilder::new(&pattern)
            .case_insensitive(insensitive)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|_| {
                "detector regex is invalid or exceeds the compiled size limit".to_owned()
            })?;
        detectors.push(Detector { id, regex, luhn });
    }
    Ok(Guardrail {
        id: doc["guardrail_id"].as_str().unwrap_or_default().to_owned(),
        name,
        enabled,
        input,
        output,
        apis,
        groups,
        detectors,
        action,
        dry_run,
    })
}

struct Hit {
    detector: String,
    start: usize,
    end: usize,
}
fn find_hits(rail: &Guardrail, text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for detector in &rail.detectors {
        for found in detector.regex.find_iter(text) {
            if found.start() == found.end() || (detector.luhn && !luhn_valid(found.as_str())) {
                continue;
            }
            hits.push(Hit {
                detector: detector.id.clone(),
                start: found.start(),
                end: found.end(),
            });
        }
    }
    hits.sort_by_key(|hit| (hit.start, std::cmp::Reverse(hit.end)));
    hits
}
fn luhn_valid(text: &str) -> bool {
    let digits: Vec<_> = text
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|byte| u32::from(byte - b'0'))
        .collect();
    if !(13..=19).contains(&digits.len()) || !digits.iter().any(|digit| *digit != 0) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            let value = if index % 2 == 1 { digit * 2 } else { *digit };
            if value > 9 { value - 9 } else { value }
        })
        .sum();
    sum % 10 == 0
}
fn redacted(text: &str, hits: &[Hit]) -> String {
    let mut merged: Vec<Hit> = Vec::new();
    for hit in hits {
        if let Some(last) = merged.last_mut() {
            if hit.start < last.end {
                last.end = last.end.max(hit.end);
                continue;
            }
        }
        merged.push(Hit {
            detector: hit.detector.clone(),
            start: hit.start,
            end: hit.end,
        });
    }
    let mut result = String::new();
    let mut cursor = 0;
    for hit in merged {
        result.push_str(&text[cursor..hit.start]);
        result.push_str(&format!("[REDACTED:{}]", hit.detector));
        cursor = hit.end;
    }
    result.push_str(&text[cursor..]);
    result
}
fn add_counts(target: &mut Vec<(String, u32)>, hits: &[Hit]) {
    let mut counts: BTreeMap<String, u32> = target.drain(..).collect();
    for hit in hits {
        let count = counts.entry(hit.detector.clone()).or_default();
        *count = count.saturating_add(1);
    }
    target.extend(counts);
}

fn walk_content(value: &mut Value, visit: &mut impl FnMut(&mut String)) {
    if let Some(text) = value.as_str().map(str::to_owned) {
        let mut text = text;
        visit(&mut text);
        *value = Value::String(text);
    } else if let Some(parts) = value.as_array_mut() {
        for part in parts {
            if matches!(
                part["type"].as_str(),
                Some("text" | "input_text" | "output_text")
            ) {
                if let Some(Value::String(text)) = part.get_mut("text") {
                    visit(text);
                }
            }
        }
    }
}
fn walk_messages(body: &mut Value, visit: &mut impl FnMut(&mut String)) {
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            if matches!(
                message["role"].as_str(),
                Some("system" | "developer" | "user" | "assistant")
            ) {
                if let Some(content) = message.get_mut("content") {
                    walk_content(content, visit);
                }
            }
        }
    }
}
fn walk_gemini_parts(content: &mut Value, visit: &mut impl FnMut(&mut String)) {
    if let Some(parts) = content.get_mut("parts").and_then(Value::as_array_mut) {
        for part in parts {
            if ["functionCall", "functionResponse", "inlineData", "fileData"]
                .iter()
                .any(|field| part.get(*field).is_some())
            {
                continue;
            }
            if part["thought"] == true {
                continue;
            }
            if let Some(Value::String(text)) = part.get_mut("text") {
                visit(text);
            }
        }
    }
}
fn walk_body(
    provider: AiProvider,
    direction: Direction,
    body: &mut Value,
    visit: &mut impl FnMut(&mut String),
) {
    match (provider, direction) {
        (AiProvider::Anthropic, Direction::Input) => {
            if let Some(system) = body.get_mut("system") {
                walk_content(system, visit);
            }
            walk_messages(body, visit);
        }
        (AiProvider::Anthropic, Direction::Output) => {
            if let Some(content) = body.get_mut("content") {
                walk_content(content, visit);
            }
        }
        (AiProvider::Gemini, Direction::Input) => {
            if let Some(system) = body.get_mut("systemInstruction") {
                walk_gemini_parts(system, visit);
            }
            if let Some(contents) = body.get_mut("contents").and_then(Value::as_array_mut) {
                for content in contents {
                    walk_gemini_parts(content, visit);
                }
            }
        }
        (AiProvider::Gemini, Direction::Output) => {
            if let Some(chunks) = body.as_array_mut() {
                for chunk in chunks {
                    walk_body(provider, direction, chunk, visit);
                }
            } else if let Some(candidates) =
                body.get_mut("candidates").and_then(Value::as_array_mut)
            {
                for candidate in candidates {
                    if let Some(content) = candidate.get_mut("content") {
                        walk_gemini_parts(content, visit);
                    }
                }
            }
        }
        (_, Direction::Input) => {
            walk_messages(body, visit);
            if let Some(instructions) = body.get_mut("instructions") {
                walk_content(instructions, visit);
            }
            if let Some(input) = body.get_mut("input") {
                if input.is_string() {
                    walk_content(input, visit);
                } else if let Some(items) = input.as_array_mut() {
                    for item in items {
                        if item
                            .get("type")
                            .and_then(Value::as_str)
                            .is_none_or(|kind| kind == "message")
                            && matches!(
                                item["role"].as_str(),
                                Some("system" | "developer" | "user" | "assistant")
                            )
                        {
                            if let Some(content) = item.get_mut("content") {
                                walk_content(content, visit);
                            }
                        }
                    }
                }
            }
        }
        (_, Direction::Output) => {
            if let Some(choices) = body.get_mut("choices").and_then(Value::as_array_mut) {
                for choice in choices {
                    if let Some(content) = choice
                        .get_mut("message")
                        .and_then(|message| message.get_mut("content"))
                    {
                        walk_content(content, visit);
                    }
                }
            }
            if let Some(output) = body.get_mut("output").and_then(Value::as_array_mut) {
                for item in output {
                    if item["type"] == "message" {
                        if let Some(content) = item.get_mut("content") {
                            walk_content(content, visit);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn doc(action: &str) -> Value {
        json!({"guardrail_id":"rail","name":"Protect email","enabled":true,"applies_to":{"apis":["*"],"groups":["*"]},"direction":"both","detectors":[{"type":"builtin","id":"email"}],"action":action,"mode":"enforce"})
    }
    fn compiled(doc: Value) -> CompiledGuardrails {
        let (rails, errors) = CompiledGuardrails::compile(&[doc]);
        assert!(errors.is_empty(), "{errors:?}");
        rails
    }
    #[test]
    fn redacts_email_in_openai_chat_parts() {
        let rails = compiled(doc("redact"));
        let mut body = json!({"messages":[{"role":"user","content":[{"type":"text","text":"Contact test@example.test now."},{"type":"image_url","image_url":{"url":"test@example.test"}}]}]});
        let result = apply(
            AiProvider::Openai,
            Direction::Input,
            &mut body,
            &rails.applicable("api/v1", &[], Direction::Input),
        );
        assert_eq!(
            body["messages"][0]["content"][0]["text"],
            "Contact [REDACTED:email] now."
        );
        assert_eq!(
            body["messages"][0]["content"][1]["image_url"]["url"],
            "test@example.test"
        );
        assert_eq!(result.redactions, vec![("email".into(), 1)]);
        assert_eq!(
            redact_text(
                "test@example.test",
                &rails.applicable("api/v1", &[], Direction::Input)
            ),
            "[REDACTED:email]"
        );
        let preview = test_text(&doc("redact"), "test@example.test").unwrap();
        assert_eq!(
            preview["matches"][0],
            json!({"detector":"email","start":0,"end":17})
        );
    }
    #[test]
    fn redacts_in_anthropic_system_blocks() {
        let rails = compiled(doc("redact"));
        let mut body = json!({"system":[{"type":"text","text":"test@example.test"}],"messages":[{"role":"user","content":"other@example.test"}]});
        let result = apply(
            AiProvider::Anthropic,
            Direction::Input,
            &mut body,
            &rails.applicable("api/v1", &[], Direction::Input),
        );
        assert_eq!(body["system"][0]["text"], "[REDACTED:email]");
        assert_eq!(result.redactions, vec![("email".into(), 2)]);
    }
    #[test]
    fn block_outcome_has_no_matched_text() {
        let rails = compiled(doc("block"));
        let mut body = json!({"messages":[{"role":"user","content":"test@example.test"}]});
        let result = apply(
            AiProvider::Openai,
            Direction::Input,
            &mut body,
            &rails.applicable("api/v1", &[], Direction::Input),
        );
        assert_eq!(result.blocked_by.as_deref(), Some("Protect email"));
        assert!(!format!("{result:?}").contains("test@example.test"));
    }
    #[test]
    fn credit_card_requires_luhn() {
        let mut rail = doc("redact");
        rail["detectors"] = json!([{"type":"builtin","id":"credit_card"}]);
        assert_eq!(
            test_text(&rail, "4111 1111 1111 1111").unwrap()["redacted"],
            "[REDACTED:credit_card]"
        );
        assert_eq!(
            test_text(&rail, "4111 1111 1111 1112").unwrap()["matches"],
            json!([])
        );
        assert_eq!(
            test_text(&rail, "0000 0000 0000 0000").unwrap()["matches"],
            json!([])
        );
    }
    #[test]
    fn dry_run_never_alters() {
        for action in ["redact", "block", "log_only"] {
            let mut rail = doc(action);
            rail["mode"] = json!("dry_run");
            let rails = compiled(rail);
            let mut body = json!({"messages":[{"role":"user","content":"test@example.test"}]});
            let original = body.clone();
            let applicable = rails.applicable("api/v1", &[], Direction::Input);
            let result = apply(AiProvider::Openai, Direction::Input, &mut body, &applicable);
            assert_eq!(body, original);
            assert!(result.blocked_by.is_none());
            assert!(result.redactions.is_empty());
            assert_eq!(result.dry_run_hits, vec![("email".into(), 1)]);
            assert_eq!(
                redact_text("test@example.test", &applicable),
                "test@example.test"
            );
        }
    }
    #[test]
    fn tool_blocks_untouched() {
        let rails = compiled(doc("redact"));
        for (provider, mut body) in [
            (
                AiProvider::Anthropic,
                json!({"messages":[{"role":"user","content":[{"type":"tool_result","content":"test@example.test"},{"type":"tool_use","input":{"text":"test@example.test"}},{"type":"image","source":{"data":"test@example.test"}}]}]}),
            ),
            (
                AiProvider::Openai,
                json!({"messages":[{"role":"tool","content":"test@example.test"}],"input":[{"type":"function_call_output","output":"test@example.test"}]}),
            ),
            (
                AiProvider::Gemini,
                json!({"contents":[{"parts":[{"functionResponse":{"response":{"text":"test@example.test"}}},{"inlineData":{"data":"test@example.test"}}]}]}),
            ),
        ] {
            let original = body.clone();
            apply(
                provider,
                Direction::Input,
                &mut body,
                &rails.applicable("api/v1", &[], Direction::Input),
            );
            assert_eq!(body, original);
        }
    }
    #[test]
    fn regex_size_limit_enforced() {
        let mut rail = doc("redact");
        for pattern in ["a".repeat(1025), "a{1000000}".into(), "[".into()] {
            rail["detectors"] = json!([{"type":"regex","pattern":pattern}]);
            assert!(validate_guardrail_doc(&rail).is_err());
        }
        rail["detectors"] = json!([{"type":"regex","pattern":"(?i)project\\s+bluebird"},{"type":"keywords","values":["ACME-CONFIDENTIAL"]}]);
        let preview = test_text(&rail, "Project bluebird ACME-CONFIDENTIAL").unwrap();
        assert_eq!(preview["matches"].as_array().unwrap().len(), 2);
        assert_eq!(preview["redacted"], "[REDACTED:regex] [REDACTED:keywords]");
    }
    #[test]
    fn validate_guardrail_doc_rejects_bad_direction() {
        let mut rail = doc("redact");
        rail["direction"] = json!("sideways");
        assert!(validate_guardrail_doc(&rail).is_err());
        let (compiled, errors) = CompiledGuardrails::compile(&[rail]);
        assert!(compiled.rails.is_empty());
        assert_eq!(errors.len(), 1);
    }
    #[test]
    fn output_redaction_and_scopes_follow_provider_text_shapes() {
        let mut rail = doc("redact");
        rail["direction"] = json!("output");
        rail["applies_to"] = json!({"apis":["api/v1"],"groups":["engineering"]});
        let rails = compiled(rail);
        assert!(
            rails
                .applicable("other/v1", &["engineering".into()], Direction::Output)
                .is_empty()
        );
        assert!(
            rails
                .applicable("api/v1", &[], Direction::Output)
                .is_empty()
        );
        assert!(
            rails
                .applicable("api/v1", &["engineering".into()], Direction::Input)
                .is_empty()
        );
        let applicable = rails.applicable("api/v1", &["engineering".into()], Direction::Output);
        for (provider, mut body) in [
            (
                AiProvider::Openai,
                json!({"output":[{"type":"message","content":[{"type":"output_text","text":"test@example.test"}]}]}),
            ),
            (
                AiProvider::Anthropic,
                json!({"content":[{"type":"text","text":"test@example.test"}]}),
            ),
            (
                AiProvider::Gemini,
                json!([{"candidates":[{"content":{"parts":[{"text":"test@example.test"}]}}]}]),
            ),
        ] {
            let result = apply(provider, Direction::Output, &mut body, &applicable);
            assert_eq!(result.redactions, vec![("email".into(), 1)]);
            assert!(!body.to_string().contains("test@example.test"));
        }
    }
    #[test]
    fn blocking_rule_sees_original_text_after_redact_rule() {
        let (rails, errors) = CompiledGuardrails::compile(&[doc("redact"), doc("block")]);
        assert!(errors.is_empty());
        let mut body = json!({"messages":[{"role":"user","content":"test@example.test"}]});
        let original = body.clone();
        let result = apply(
            AiProvider::Openai,
            Direction::Input,
            &mut body,
            &rails.applicable("api/v1", &[], Direction::Input),
        );
        assert_eq!(result.blocked_by.as_deref(), Some("Protect email"));
        assert_eq!(body, original);
    }
}
