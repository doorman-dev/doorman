//! Normalised token usage and the stream usage parser contract (plan §5.10).

/// Normalised: input_tokens = UNCACHED input. OpenAI: prompt - cached. Anthropic: as-is.
/// Gemini: prompt - cachedContent; Gemini output = candidates + thoughts.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct AiUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
    pub estimated: bool,
    pub refusal: bool,
}

pub trait StreamUsageParser: Send {
    fn on_event(&mut self, event: &crate::ai::sse::SseEvent);
    /// Text deltas only, capped at 256 KiB.
    fn completion_text(&self) -> Option<&str>;
    /// None → caller estimates (bytes/4) and sets estimated=true.
    fn finish(self: Box<Self>) -> Option<AiUsage>;
}

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{Stream, stream::BoxStream};

use serde_json::{Value, json};

use crate::{
    ai::{
        adapter::AiProvider,
        pricing::{CostResult, PriceTable},
        sse::SseParser,
    },
    storage::runtime::SharedStorage,
};

/// Failed usage writes (exposed as `doorman_ai_usage_record_failures_total`).
pub static USAGE_RECORD_FAILURES: AtomicU64 = AtomicU64::new(0);

const PRICE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Price tables keyed by storage instance (one per gateway in production).
type CachedPrices = std::collections::HashMap<usize, (Instant, Arc<PriceTable>)>;

fn price_cache() -> &'static RwLock<CachedPrices> {
    static CACHE: std::sync::OnceLock<RwLock<CachedPrices>> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Drops the cached price tables; the next lookup reloads `ai_pricing`.
pub fn invalidate_price_table() {
    if let Ok(mut cache) = price_cache().write() {
        cache.clear();
    }
}

/// The `ai_pricing` table, cached for 60 s. Invalid rows are skipped (and
/// logged) so one bad row never unprices everything.
pub async fn price_table(storage: Option<&SharedStorage>) -> Arc<PriceTable> {
    let cache_key = storage.map_or(0, |storage| storage as *const SharedStorage as usize);
    if let Ok(cache) = price_cache().read()
        && let Some((loaded_at, table)) = cache.get(&cache_key)
        && loaded_at.elapsed() < PRICE_CACHE_TTL
    {
        return table.clone();
    }
    let docs = match storage {
        Some(storage) => storage
            .find_many("ai_pricing", &json!({}))
            .await
            .unwrap_or_else(|error| {
                tracing::error!(%error, "failed to load AI pricing");
                Vec::new()
            }),
        None => Vec::new(),
    };
    let valid: Vec<Value> = docs
        .into_iter()
        .filter(|doc| match crate::ai::pricing::validate_pricing_doc(doc) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "skipping invalid AI pricing row");
                false
            }
        })
        .collect();
    let table = Arc::new(
        PriceTable::from_docs(&valid)
            .unwrap_or_else(|_| PriceTable::empty())
            .with_builtin(),
    );
    if let Ok(mut cache) = price_cache().write() {
        cache.insert(cache_key, (Instant::now(), table.clone()));
    }
    table
}

/// Largest single SSE event the usage tap buffers (plan P2.1).
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Everything `record_usage` needs about one AI request.
#[derive(Clone)]
pub struct FinalizeCtx {
    pub storage: Option<Arc<SharedStorage>>,
    pub request_id: String,
    pub provider: AiProvider,
    /// "{name}/{ver}" as requested.
    pub api: String,
    /// The model actually sent upstream.
    pub model: String,
    pub username: Option<String>,
    pub operation: &'static str,
    pub metered: bool,
    pub stream: bool,
    pub status: u16,
    pub started: Instant,
    pub ttft_ms: Option<u64>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// Bandwidth counter key and TTL, when the API meters bandwidth.
    pub bandwidth: Option<(String, u64)>,
    pub redactions: u32,
    /// Upstream targets that failed before one answered (failover).
    pub fallbacks: u32,
    /// The user's groups at request time (snapshot for the group breakdown).
    pub groups: Vec<String>,
    /// The user's role and tier at request time (snapshots for the breakdown).
    pub role: Option<String>,
    pub tier: Option<String>,
    /// Activity log directory, when activity logging is enabled.
    pub log_dir: Option<PathBuf>,
    /// Budget counters to charge once usage is known.
    pub budget_charges: Vec<crate::ai::budgets::BudgetCharge>,
    /// Set when the effective log level is `full`.
    pub prompt_log: Option<PromptLog>,
}

/// Content captured for `ai_prompt_logs` (log level `full`, C8). Text is
/// redacted with the request's guardrails and encrypted when written.
#[derive(Clone)]
pub struct PromptLog {
    pub prompt: String,
    pub completion: Option<String>,
    pub rails: Arc<crate::ai::guardrails::CompiledGuardrails>,
    pub groups: Vec<String>,
    pub retention_days: u64,
    pub redactions: Vec<(String, u32)>,
}

impl PromptLog {
    fn redact(&self, api: &str, text: &str) -> String {
        use crate::ai::guardrails::{Direction, redact_text};
        let mut rails = self.rails.applicable(api, &self.groups, Direction::Input);
        for rail in self.rails.applicable(api, &self.groups, Direction::Output) {
            if !rails.iter().any(|existing| existing.id == rail.id) {
                rails.push(rail);
            }
        }
        redact_text(text, &rails)
    }
}

/// Writes one encrypted prompt log. Without field-encryption key material the
/// content is never stored in plaintext: the log is skipped with an error.
async fn write_prompt_log(storage: &SharedStorage, ctx: &FinalizeCtx, log: &PromptLog) {
    use crate::storage::field_encryption::{encrypt_value, key_material};
    if key_material().is_none() {
        USAGE_RECORD_FAILURES.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            "AI prompt logging is `full` but no TOKEN_ENCRYPTION_KEY/MEM_ENCRYPTION_KEY is set; prompt not stored"
        );
        return;
    }
    let now = time::OffsetDateTime::now_utc();
    let prompt = log.redact(&ctx.api, &log.prompt);
    let completion = log
        .completion
        .as_deref()
        .map(|completion| log.redact(&ctx.api, completion));
    let redactions: Vec<Value> = log
        .redactions
        .iter()
        .map(|(detector, count)| json!({"detector": detector, "count": count}))
        .collect();
    let document = json!({
        "log_id": uuid::Uuid::new_v4().to_string(),
        "request_id": ctx.request_id,
        "at": now.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "username": ctx.username,
        "api": ctx.api,
        "model": ctx.model,
        "prompt_enc": encrypt_value(Some(&prompt)),
        "completion_enc": encrypt_value(completion.as_deref()),
        "redactions": redactions,
        "expires_at": (now.unix_timestamp().max(0) as u64)
            .saturating_add(log.retention_days.saturating_mul(86_400)),
    });
    if let Err(error) = storage.insert_one("ai_prompt_logs", document).await {
        USAGE_RECORD_FAILURES.fetch_add(1, Ordering::Relaxed);
        tracing::error!(%error, "failed to write AI prompt log");
    }
}

/// Cost of `usage` at the current price table (unpriced → 0 nanos).
pub async fn cost_for(ctx: &FinalizeCtx, usage: &AiUsage) -> CostResult {
    price_table(ctx.storage.as_deref()).await.cost(
        ctx.provider.as_str(),
        &ctx.model,
        usage,
        time::OffsetDateTime::now_utc(),
    )
}

/// The `ai` block of an activity-log record (plan §5.9).
pub fn activity_block(ctx: &FinalizeCtx, usage: &AiUsage, cost: CostResult) -> Value {
    json!({
        "provider": ctx.provider.as_str(),
        "model": ctx.model,
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_read_tokens": usage.cache_read_tokens,
        "cache_write_tokens": usage.cache_write_tokens,
        "cost_nanos": cost.cost_nanos,
        "estimated": usage.estimated,
        "stream": ctx.stream,
        "redactions": ctx.redactions,
        "fallbacks": ctx.fallbacks,
    })
}

/// Token estimate used when the provider reported no usage: bytes / 4.
pub fn estimate_usage(request_bytes: u64, response_bytes: u64) -> AiUsage {
    AiUsage {
        input_tokens: request_bytes / 4,
        output_tokens: response_bytes / 4,
        estimated: true,
        ..AiUsage::default()
    }
}

/// Records one finished AI request: the durable daily rollup, the live
/// counters and, for streams, a separate `ai_usage` activity line. Failures
/// are logged and counted and never reach the client.
pub async fn record_usage(ctx: FinalizeCtx, usage: AiUsage, cost: Option<CostResult>) {
    if ctx.stream {
        if let (Some(storage), Some((key, ttl))) = (ctx.storage.as_ref(), ctx.bandwidth.as_ref()) {
            let bytes = ctx.request_bytes.saturating_add(ctx.response_bytes);
            if let Err(error) = storage.add_bandwidth(key, bytes, *ttl).await {
                tracing::error!(error = %error, "AI stream bandwidth accounting failed");
            }
        }
    }
    if !ctx.metered {
        return;
    }
    let success = (200..300).contains(&ctx.status);
    let cost = match cost {
        Some(cost) => cost,
        None if success => cost_for(&ctx, &usage).await,
        None => CostResult::default(),
    };
    let now = time::OffsetDateTime::now_utc();
    let day = now.date().to_string();
    let username = ctx.username.clone().unwrap_or_default();
    let id = format!("{day}|{}|{}|{username}", ctx.api, ctx.model);
    let latency_ms = ctx.started.elapsed().as_millis() as i64;
    let as_i64 = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    let inc = [
        ("requests", 1),
        ("errors", i64::from(!success)),
        ("input_tokens", as_i64(usage.input_tokens)),
        ("output_tokens", as_i64(usage.output_tokens)),
        ("cache_read_tokens", as_i64(usage.cache_read_tokens)),
        ("cache_write_tokens", as_i64(usage.cache_write_tokens)),
        ("cost_nanos", as_i64(cost.cost_nanos)),
        ("estimated_requests", i64::from(success && usage.estimated)),
        ("unpriced_requests", i64::from(success && cost.unpriced)),
        ("latency_ms_total", latency_ms),
        ("ttft_ms_total", as_i64(ctx.ttft_ms.unwrap_or(0))),
    ];
    let set_on_insert = json!({
        "day": day,
        "api": ctx.api,
        "provider": ctx.provider.as_str(),
        "model": ctx.model,
        "username": username,
        "groups": ctx.groups,
        "role": ctx.role,
        "tier": ctx.tier,
    });
    if let Some(storage) = ctx.storage.as_ref() {
        if success {
            if cost.unpriced
                && ctx
                    .budget_charges
                    .iter()
                    .any(|charge| charge.unit == crate::ai::budgets::BudgetUnit::Cost)
            {
                tracing::warn!(
                    provider = ctx.provider.as_str(),
                    model = %ctx.model,
                    "AI model has no price; USD budgets are not charged for this request. Add a price under AI Gateway pricing"
                );
            }
            crate::ai::budgets::charge(storage, &ctx.budget_charges, &usage, cost.cost_nanos).await;
        }
        if let Some(log) = ctx.prompt_log.as_ref() {
            write_prompt_log(storage, &ctx, log).await;
        }
        if let Err(error) = storage.ai_usage_increment(&id, &set_on_insert, &inc).await {
            USAGE_RECORD_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(%error, request_id = %ctx.request_id, "failed to record AI usage rollup");
        }
        let minute = (now.unix_timestamp().max(0) as u64) / 60 * 60;
        let live = [
            ("req", 1),
            ("in", usage.input_tokens),
            ("out", usage.output_tokens),
            ("cost", cost.cost_nanos),
        ];
        if let Err(error) = storage.ai_live_increment(minute, &live).await {
            USAGE_RECORD_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(%error, "failed to record AI live counters");
        }
    }
    if ctx.stream
        && let Some(log_dir) = ctx.log_dir.as_deref()
    {
        let mut record = activity_block(&ctx, &usage, cost);
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "time".to_owned(),
                json!(
                    now.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default()
                ),
            );
            object.insert("name".to_owned(), json!("doorman.gateway.rust"));
            object.insert("level".to_owned(), json!("INFO"));
            object.insert("message".to_owned(), json!("ai stream usage recorded"));
            object.insert("type".to_owned(), json!("ai_usage"));
            object.insert("request_id".to_owned(), json!(ctx.request_id));
            object.insert("user".to_owned(), json!(ctx.username));
            object.insert("api".to_owned(), json!(ctx.api));
        }
        if let Err(error) = crate::middleware::activity::append_json_record(log_dir, &record).await
        {
            USAGE_RECORD_FAILURES.fetch_add(1, Ordering::Relaxed);
            tracing::error!(%error, "failed to append AI usage log line");
        }
    }
}

fn spawn_record(ctx: FinalizeCtx, usage: AiUsage) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(record_usage(ctx, usage, None));
        }
        Err(_) => tracing::error!("AI usage dropped: no async runtime"),
    }
}

/// Forwards upstream SSE bytes unchanged while feeding a copy to the provider's
/// usage parser. Usage is recorded exactly once: at stream end, on idle
/// timeout, on upstream error, or when the client disconnects (drop).
pub struct UsageTap {
    inner: BoxStream<'static, Result<Bytes, reqwest::Error>>,
    sse: SseParser,
    parser: Option<Box<dyn StreamUsageParser>>,
    ctx: Option<FinalizeCtx>,
    idle: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
    done: bool,
}

impl UsageTap {
    pub fn new(
        inner: BoxStream<'static, Result<Bytes, reqwest::Error>>,
        parser: Box<dyn StreamUsageParser>,
        ctx: FinalizeCtx,
        idle: Duration,
    ) -> Self {
        Self {
            inner,
            sse: SseParser::new(MAX_SSE_EVENT_BYTES),
            parser: Some(parser),
            ctx: Some(ctx),
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
            done: false,
        }
    }

    fn finalize(&mut self, complete: bool) {
        let Some(mut ctx) = self.ctx.take() else {
            return;
        };
        if let (Some(log), Some(parser)) = (ctx.prompt_log.as_mut(), self.parser.as_ref()) {
            log.completion = parser.completion_text().map(str::to_owned);
        }
        let parsed = self.parser.take().and_then(|parser| parser.finish());
        let usage = match parsed {
            Some(mut usage) => {
                usage.estimated |= !complete || self.sse.overflowed();
                usage
            }
            None => estimate_usage(ctx.request_bytes, ctx.response_bytes),
        };
        spawn_record(ctx, usage);
    }
}

impl Stream for UsageTap {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let deadline = tokio::time::Instant::now() + this.idle;
                this.deadline.as_mut().reset(deadline);
                if let Some(ctx) = this.ctx.as_mut() {
                    ctx.response_bytes = ctx.response_bytes.saturating_add(chunk.len() as u64);
                    if ctx.ttft_ms.is_none() {
                        ctx.ttft_ms = Some(ctx.started.elapsed().as_millis() as u64);
                    }
                }
                if let Some(parser) = this.parser.as_mut() {
                    for event in this.sse.push(&chunk) {
                        parser.on_event(&event);
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.done = true;
                this.finalize(false);
                Poll::Ready(Some(Err(std::io::Error::other(error))))
            }
            Poll::Ready(None) => {
                this.done = true;
                this.finalize(true);
                Poll::Ready(None)
            }
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    tracing::warn!("AI stream idle timeout; ending stream");
                    this.done = true;
                    this.finalize(false);
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl Drop for UsageTap {
    fn drop(&mut self) {
        // Client disconnected before the stream ended.
        self.finalize(false);
    }
}
