//! Exact-match AI response cache (step 6).
//!
//! An entry is the full reply Doorman sent for a native AI request (after
//! output guardrails): status, content type, pass-through headers and body,
//! streamed or not, plus the provider-reported usage so a hit can record what
//! it saved. Entries live in Redis (encrypted) when Doorman runs with external
//! storage, so every instance shares them, and otherwise in a bounded
//! least-recently-used map in this process.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{ai::usage::AiUsage, storage::runtime::SharedStorage};

/// Largest reply stored (streams included).
pub const MAX_ENTRY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;
const REDIS_PREFIX: &str = "doorman:ai-cache:";
const REDIS_GENERATION_PREFIX: &str = "doorman:ai-cache-gen:";

/// What a request tells the cache to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMode {
    /// Caching is off for this API (or the operation is not cacheable).
    Off,
    /// The client opted out (`Cache-Control: no-store|no-cache`, `x-doorman-cache: bypass`).
    Bypass,
    /// Look up, and store on a miss.
    Use,
}

impl CacheMode {
    pub fn header(self, hit: bool) -> &'static str {
        match (self, hit) {
            (_, true) => "hit",
            (CacheMode::Use, false) => "miss",
            (CacheMode::Bypass, _) => "bypass",
            (CacheMode::Off, _) => "off",
        }
    }
}

/// Cache-Control `no-store` / `no-cache`, or `x-doorman-cache: bypass`.
pub fn client_opted_out(headers: &HeaderMap) -> bool {
    let has = |name: &str, needles: &[&str]| {
        headers.get_all(name).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                let value = value.to_ascii_lowercase();
                needles.iter().any(|needle| value.contains(needle))
            })
        })
    };
    has("cache-control", &["no-store", "no-cache"]) || has("x-doorman-cache", &["bypass"])
}

/// JSON with object keys sorted at every level and no whitespace.
pub fn canonical_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for key in keys {
                    out.insert(key.clone(), sorted(&map[key]));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(value).to_string()
}

/// Everything that can change the upstream answer (decision 4, tightened
/// after review). The key is `{api namespace}:{api generation}:{digest}`.
pub struct KeyParts<'a> {
    /// `api_namespace(api_id)`: hex, so it never contains glob characters.
    pub api_ns: &'a str,
    /// The API's purge generation (see [`generation`]).
    pub generation: u64,
    pub operation: &'a str,
    /// The upstream path after the model is set.
    pub path: &'a str,
    /// The upstream query, in the order sent.
    pub query: &'a [(String, String)],
    pub model: &'a str,
    pub stream: bool,
    /// `*` (shared) or `{username}#{user generation}`.
    pub owner: &'a str,
    /// The body as sent upstream (model set, output cap applied), without
    /// Doorman's injected user id.
    pub body: &'a Value,
    /// API identity, provider, AI config (minus `cache`), servers and
    /// credential targets, forwarded headers, and the output-guardrail policy.
    pub context: &'a Value,
}

pub fn key(parts: &KeyParts) -> String {
    let query: Vec<&(String, String)> = parts
        .query
        .iter()
        .filter(|(name, _)| name != "key")
        .collect();
    let material = json!({
        "operation": parts.operation,
        "path": parts.path,
        "query": query,
        "model": parts.model,
        "stream": parts.stream,
        "owner": parts.owner,
        "body": parts.body,
        "context": parts.context,
    });
    let digest = Sha256::digest(canonical_json(&material).as_bytes());
    format!(
        "{}:{}:{}",
        parts.api_ns,
        parts.generation,
        crate::ai::keys::hex(&digest)
    )
}

/// Request headers that never change the answer (tracing, client identity,
/// caching directives), left out of the key so SDK version bumps still hit.
/// Every other forwarded header is part of the key.
pub fn header_ignored_in_key(name: &str) -> bool {
    matches!(
        name,
        "x-request-id"
            | "traceparent"
            | "tracestate"
            | "baggage"
            | "sentry-trace"
            | "user-agent"
            | "accept"
            | "accept-language"
            | "cache-control"
            | "pragma"
            | "content-type"
            | "origin"
            | "referer"
    ) || name.starts_with("x-stainless-")
}

/// SHA-256 of a value's canonical JSON (hex).
pub fn fingerprint<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_value(value).unwrap_or(Value::Null);
    crate::ai::keys::hex(&Sha256::digest(canonical_json(&json).as_bytes()))
}

/// Stable namespace for one AI API (its immutable `api_id`), so replacing an
/// API under the same name/version never sees the old API's answers.
pub fn api_namespace(api_id: &str) -> String {
    crate::ai::keys::hex(&Sha256::digest(api_id.as_bytes()))[..32].to_owned()
}

/// An OpenAI/Anthropic/Gemini-style error envelope: a top-level `error` or
/// `"type": "error"` (any field order); for a JSON array, any element.
pub fn is_error_envelope(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("error").is_some_and(|error| !error.is_null())
                || map.get("type").and_then(Value::as_str) == Some("error")
        }
        Value::Array(items) => items.iter().any(is_error_envelope),
        _ => false,
    }
}

/// A stored reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedReply {
    pub status: u16,
    pub content_type: String,
    /// Pass-through response headers (rate-limit and request-id headers).
    pub headers: Vec<(String, String)>,
    #[serde(with = "body_base64")]
    pub body: Vec<u8>,
    pub stream: bool,
    /// Model that answered.
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    /// Usage was estimated from byte counts (the provider reported none).
    #[serde(default)]
    pub estimated: bool,
}

impl CachedReply {
    pub fn usage(&self) -> AiUsage {
        AiUsage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cache_read_tokens: self.cache_read_tokens,
            cache_write_tokens: self.cache_write_tokens,
            reasoning_tokens: self.reasoning_tokens,
            estimated: self.estimated,
            refusal: false,
        }
    }

    pub fn set_usage(&mut self, usage: &AiUsage) {
        self.input_tokens = usage.input_tokens;
        self.output_tokens = usage.output_tokens;
        self.cache_read_tokens = usage.cache_read_tokens;
        self.cache_write_tokens = usage.cache_write_tokens;
        self.reasoning_tokens = usage.reasoning_tokens;
        self.estimated = usage.estimated;
    }

    fn size(&self) -> usize {
        self.body.len()
            + self.content_type.len()
            + self.model.len()
            + self
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>()
            + 128
    }
}

mod body_base64 {
    use super::*;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

/// True when a successful reply may be stored (decision 6).
/// Usage quality does not matter (estimated usage is kept with the entry);
/// completeness does: streams are checked by the caller, and a non-stream
/// body must be JSON that is not an error envelope.
pub fn storable(reply: &CachedReply, usage: &AiUsage) -> bool {
    (200..300).contains(&reply.status)
        && reply.body.len() <= MAX_ENTRY_BYTES
        && !usage.refusal
        && (reply.stream
            || serde_json::from_slice::<Value>(&reply.body)
                .is_ok_and(|body| !is_error_envelope(&body)))
}

// ── Memory backend ──────────────────────────────────────────────────────────

struct MemoryEntry {
    reply: CachedReply,
    expires: Instant,
    last_used: u64,
    size: usize,
}

#[derive(Default)]
struct MemoryCache {
    entries: HashMap<String, MemoryEntry>,
    bytes: usize,
    tick: u64,
}

impl MemoryCache {
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes -= entry.size;
        }
    }

    fn get(&mut self, key: &str, now: Instant) -> Option<CachedReply> {
        let expired = self.entries.get(key)?.expires <= now;
        if expired {
            self.remove(key);
            return None;
        }
        self.tick += 1;
        let tick = self.tick;
        let entry = self.entries.get_mut(key)?;
        entry.last_used = tick;
        Some(entry.reply.clone())
    }

    fn put(
        &mut self,
        key: String,
        reply: CachedReply,
        ttl: Duration,
        max_bytes: usize,
        now: Instant,
    ) {
        let size = reply.size();
        if size > max_bytes {
            return;
        }
        self.remove(&key);
        if self.bytes + size > max_bytes {
            let expired: Vec<String> = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.expires <= now)
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                self.remove(&key);
            }
        }
        while self.bytes + size > max_bytes {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
        self.tick += 1;
        self.bytes += size;
        self.entries.insert(
            key,
            MemoryEntry {
                reply,
                expires: now + ttl,
                last_used: self.tick,
                size,
            },
        );
    }

    fn purge_prefix(&mut self, prefix: &str) -> u64 {
        let keys: Vec<String> = self
            .entries
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        for key in &keys {
            self.remove(key);
        }
        keys.len() as u64
    }
}

fn memory() -> &'static Mutex<MemoryCache> {
    static CACHE: OnceLock<Mutex<MemoryCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(MemoryCache::default()))
}

/// `AI_CACHE_MAX_BYTES`, default 256 MiB (memory backend only).
pub fn max_bytes() -> usize {
    std::env::var("AI_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_BYTES)
}

/// Memory keys carry the storage instance so separate gateways (tests) in one
/// process never share entries.
fn memory_key(storage: Option<&SharedStorage>, key: &str) -> String {
    format!("{}|{key}", storage.map_or(0, SharedStorage::instance_id))
}

fn redis_storage(storage: Option<&SharedStorage>) -> Option<&SharedStorage> {
    storage.filter(|storage| storage.has_redis())
}

// ── Public operations ───────────────────────────────────────────────────────

pub async fn get(storage: Option<&SharedStorage>, key: &str) -> Option<CachedReply> {
    if let Some(redis) = redis_storage(storage) {
        let raw = match redis.kv_get(&format!("{REDIS_PREFIX}{key}")).await {
            Ok(raw) => raw?,
            Err(error) => {
                tracing::warn!(%error, "AI cache read failed; treating as a miss");
                return None;
            }
        };
        // Only sealed entries are trusted; anything else is ignored.
        if !raw.starts_with("enc:") {
            return None;
        }
        let plain = crate::storage::field_encryption::decrypt_value(Some(&raw))?;
        return serde_json::from_str(&plain).ok();
    }
    memory()
        .lock()
        .ok()?
        .get(&memory_key(storage, key), Instant::now())
}

pub async fn put(storage: Option<&SharedStorage>, key: &str, reply: CachedReply, ttl_seconds: u64) {
    if reply.body.len() > MAX_ENTRY_BYTES {
        return;
    }
    if let Some(redis) = redis_storage(storage) {
        let Ok(plain) = serde_json::to_string(&reply) else {
            return;
        };
        // Answers are never written to Redis in plaintext (decision 10).
        let Some(sealed) = crate::storage::field_encryption::encrypt_value(Some(&plain))
            .filter(|sealed| sealed.starts_with("enc:"))
        else {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    "AI response cache uses Redis but no TOKEN_ENCRYPTION_KEY/MEM_ENCRYPTION_KEY is set; answers are not cached"
                );
            });
            return;
        };
        if let Err(error) = redis
            .kv_set_ex(&format!("{REDIS_PREFIX}{key}"), &sealed, ttl_seconds)
            .await
        {
            tracing::warn!(%error, "AI cache write failed");
        }
        return;
    }
    if let Ok(mut cache) = memory().lock() {
        cache.put(
            memory_key(storage, key),
            reply,
            Duration::from_secs(ttl_seconds),
            max_bytes(),
            Instant::now(),
        );
    }
}

fn generations() -> &'static Mutex<HashMap<String, u64>> {
    static GENERATIONS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    GENERATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The current generation of a namespace (`api:{ns}` or `user:{name}`).
/// Keys embed it, so bumping it makes every older entry unreachable at once,
/// including entries still being written when the bump happened.
pub async fn generation(storage: Option<&SharedStorage>, namespace: &str) -> Result<u64, String> {
    if let Some(redis) = redis_storage(storage) {
        return redis
            .kv_get(&format!("{REDIS_GENERATION_PREFIX}{namespace}"))
            .await
            .map(|raw| raw.and_then(|raw| raw.parse().ok()).unwrap_or(0))
            .map_err(|error| error.to_string());
    }
    Ok(generations()
        .lock()
        .map(|map| {
            map.get(&memory_key(storage, namespace))
                .copied()
                .unwrap_or(0)
        })
        .unwrap_or(0))
}

/// Starts a new generation for a namespace.
pub async fn bump(storage: Option<&SharedStorage>, namespace: &str) -> Result<u64, String> {
    if let Some(redis) = redis_storage(storage) {
        return redis
            .kv_incr(&format!("{REDIS_GENERATION_PREFIX}{namespace}"))
            .await
            .map_err(|error| error.to_string());
    }
    let mut map = generations()
        .lock()
        .map_err(|_| "AI cache generation lock poisoned".to_owned())?;
    let value = map.entry(memory_key(storage, namespace)).or_insert(0);
    *value += 1;
    Ok(*value)
}

/// Starts a new cache generation for a username (on user create and delete),
/// so `user`-scope answers never pass to another account with the same name.
pub async fn forget_user(storage: Option<&SharedStorage>, username: &str) {
    if let Err(error) = bump(storage, &format!("user:{username}")).await {
        tracing::error!(%error, "AI cache: could not reset the user's cache generation");
    }
}

/// Removes every entry of one API (`api_namespace`). The API's generation is
/// bumped first, so a reply still being written lands under the old
/// generation and is never served; then old entries are deleted. Returns how
/// many were deleted, or the backend error.
pub async fn purge(storage: Option<&SharedStorage>, api_ns: &str) -> Result<u64, String> {
    bump(storage, &format!("api:{api_ns}")).await?;
    if let Some(redis) = redis_storage(storage) {
        return redis
            .kv_delete_prefix(&format!("{REDIS_PREFIX}{api_ns}:"))
            .await
            .map_err(|error| error.to_string());
    }
    memory()
        .lock()
        .map(|mut cache| cache.purge_prefix(&memory_key(storage, &format!("{api_ns}:"))))
        .map_err(|_| "AI cache lock poisoned".to_owned())
}

/// Backend summary for AI Settings. `encrypted` is false when Redis is used
/// without field-encryption key material: nothing is cached then.
pub fn stats(storage: Option<&SharedStorage>) -> Value {
    if redis_storage(storage).is_some() {
        let encrypted = crate::storage::field_encryption::key_material().is_some();
        return json!({"backend": "redis", "entries": null, "bytes": null, "max_bytes": null, "encrypted": encrypted});
    }
    let prefix = memory_key(storage, "");
    let (entries, bytes) = memory()
        .lock()
        .map(|cache| {
            cache
                .entries
                .iter()
                .filter(|(key, _)| key.starts_with(&prefix))
                .fold((0u64, 0u64), |(count, bytes), (_, entry)| {
                    (count + 1, bytes + entry.size as u64)
                })
        })
        .unwrap_or((0, 0));
    json!({"backend": "memory", "entries": entries, "bytes": bytes, "max_bytes": max_bytes(), "encrypted": true})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(body: &str) -> CachedReply {
        CachedReply {
            status: 200,
            content_type: "application/json".into(),
            headers: vec![],
            body: body.as_bytes().to_vec(),
            stream: false,
            model: "m".into(),
            input_tokens: 3,
            output_tokens: 2,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            estimated: false,
        }
    }

    fn parts<'a>(body: &'a Value, owner: &'a str, stream: bool) -> KeyParts<'a> {
        KeyParts {
            api_ns: "ns",
            generation: 0,
            operation: "chat",
            path: "v1/chat/completions",
            query: &[],
            model: "gpt-x",
            stream,
            owner,
            body,
            context: &Value::Null,
        }
    }

    #[test]
    fn key_ignores_key_order_but_not_content_owner_or_stream() {
        let a = json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]});
        let b: Value = serde_json::from_str(
            r#"{"messages":[{"content":"hi","role":"user"}],"model":"gpt-x"}"#,
        )
        .unwrap();
        let c = json!({"model": "gpt-x", "messages": [{"role": "user", "content": "hi!"}]});
        let base = key(&parts(&a, "alice", false));
        assert!(base.starts_with("ns:0:"));
        assert_eq!(base, key(&parts(&b, "alice", false)));
        assert_ne!(base, key(&parts(&c, "alice", false)));
        assert_ne!(base, key(&parts(&a, "bob", false)));
        assert_ne!(base, key(&parts(&a, "alice", true)));
    }

    #[test]
    fn key_keeps_query_order_generation_and_context() {
        let body = json!({"model": "gpt-x"});
        let ab = [
            ("a".to_owned(), "1".to_owned()),
            ("b".to_owned(), "2".to_owned()),
        ];
        let ba = [
            ("b".to_owned(), "2".to_owned()),
            ("a".to_owned(), "1".to_owned()),
        ];
        let with_query = |query| KeyParts {
            query,
            ..parts(&body, "*", false)
        };
        assert_ne!(key(&with_query(&ab)), key(&with_query(&ba)));
        let next = KeyParts {
            generation: 1,
            ..parts(&body, "*", false)
        };
        assert!(key(&next).starts_with("ns:1:"));
        let context = json!({"headers": [["anthropic-beta", "x"]]});
        let with_context = KeyParts {
            context: &context,
            ..parts(&body, "*", false)
        };
        assert_ne!(key(&with_context), key(&parts(&body, "*", false)));
        assert_eq!(api_namespace("id-1").len(), 32);
        assert!(api_namespace("a*").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn error_envelopes_in_any_field_order() {
        assert!(is_error_envelope(
            &json!({"id": "x", "error": {"message": "m"}})
        ));
        assert!(is_error_envelope(&json!({"message": "m", "type": "error"})));
        assert!(is_error_envelope(
            &json!([{"candidates": []}, {"error": {"code": 500}}])
        ));
        assert!(!is_error_envelope(&json!({"error": null, "choices": []})));
        assert!(!is_error_envelope(&json!({"type": "message"})));
        let mut envelope = reply(r#"{"usage":{"prompt_tokens":1},"error":{"message":"x"}}"#);
        envelope.status = 200;
        assert!(!storable(&envelope, &envelope.usage()));
        assert!(!storable(&reply("not json"), &reply("x").usage()));
    }

    #[test]
    fn memory_generations_bump() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let start = generation(None, "user:gen-test").await.unwrap();
            forget_user(None, "gen-test").await;
            assert_eq!(generation(None, "user:gen-test").await.unwrap(), start + 1);
        });
    }

    #[test]
    fn memory_cache_expires_and_evicts_least_recently_used() {
        let mut cache = MemoryCache::default();
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        let size = reply("aaaa").size();
        cache.put("a".into(), reply("aaaa"), ttl, size * 2, now);
        cache.put("b".into(), reply("bbbb"), ttl, size * 2, now);
        assert!(cache.get("a", now).is_some()); // a is now more recent than b
        cache.put("c".into(), reply("cccc"), ttl, size * 2, now);
        assert!(
            cache.get("b", now).is_none(),
            "least recently used is evicted"
        );
        assert!(cache.get("a", now).is_some() && cache.get("c", now).is_some());
        assert!(cache.get("a", now + ttl).is_none(), "expired");
        assert_eq!(cache.purge_prefix("c"), 1);
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn opt_out_headers_and_storable_rules() {
        let mut headers = HeaderMap::new();
        assert!(!client_opted_out(&headers));
        headers.insert("cache-control", "max-age=0, No-Store".parse().unwrap());
        assert!(client_opted_out(&headers));
        let mut headers = HeaderMap::new();
        headers.insert("x-doorman-cache", "bypass".parse().unwrap());
        assert!(client_opted_out(&headers));
        let ok = reply("{}");
        let usage = ok.usage();
        assert!(storable(&ok, &usage));
        let mut error = reply("{}");
        error.status = 500;
        assert!(!storable(&error, &usage));
        assert!(!storable(
            &ok,
            &AiUsage {
                refusal: true,
                ..usage.clone()
            }
        ));
        // Estimated usage no longer blocks storage (complete replies are kept).
        assert!(storable(
            &ok,
            &AiUsage {
                estimated: true,
                ..usage
            }
        ));
    }

    #[test]
    fn reply_round_trips_through_json() {
        let original = reply("{\"a\":1}\u{0}binary");
        let text = serde_json::to_string(&original).unwrap();
        assert_eq!(
            serde_json::from_str::<CachedReply>(&text).unwrap(),
            original
        );
    }
}
