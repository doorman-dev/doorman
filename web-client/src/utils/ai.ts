export type AiProvider = 'openai' | 'anthropic' | 'gemini' | 'azure_openai' | 'openai_compatible'
export type AiLogLevel = 'none' | 'metadata' | 'full'
export type AiOperation = 'chat' | 'responses' | 'messages' | 'count_tokens' | 'generate' | 'embed' | 'models'

export interface AiProviderPreset {
  id: AiProvider
  label: string
  default_server: string | null
  credential_header: string
  credential_format: 'bearer' | 'raw'
  sdk_base_url_suffix: string
  supports_user_id: boolean
  operations: AiOperation[]
}

export interface AiApiConfig {
  credential_group: string
  credential_overrides: { group: string; credential_group: string }[]
  allowed_models: string[]
  default_model: string | null
  model_aliases: Record<string, string>
  allowed_operations: AiOperation[] | null
  max_output_tokens: number | null
  stream_allowed: boolean
  inject_stream_usage: boolean
  forward_user_id: boolean
  require_subscription?: boolean
  log_level: AiLogLevel | null
  guardrail_ids: string[]
  first_byte_timeout_ms: number
  stream_idle_timeout_ms: number
  /** Backups used when the primary returns 502-504, times out or is unreachable. Never on 429. */
  fallback_targets?: AiTarget[]
  /** Spread traffic across the primary and backups on a different server. */
  load_balance?: boolean
}

export interface AiTarget {
  /** Empty = the provider's own key. */
  credential_group: string
  /** Null = the provider's own server. */
  server: string | null
  weight: number
}

export interface AiAccessKey {
  key_id: string
  name: string
  key_prefix: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  revoked: boolean
  api_scope: string[] | null
}

export interface AiCreatedAccessKey {
  key_id: string
  name: string
  key: string
  key_prefix: string
  expires_at: string | null
}

export type AiBudgetScope = 'user' | 'group' | 'tier' | 'api' | 'global'
export type AiBudgetLimitType = 'cost' | 'tokens' | 'requests'
export type AiBudgetPeriod = 'minute' | 'hour' | 'day' | 'week' | 'month'
export type AiBudgetAction = 'warn' | 'downgrade' | 'block'

export interface AiBudget {
  budget_id: string
  name: string
  scope: AiBudgetScope
  target: string
  period: AiBudgetPeriod
  limit_type: AiBudgetLimitType
  limit_value: number
  action: AiBudgetAction
  downgrade_model?: string | null
  warn_at_percent: number
  enabled: boolean
  /** Only requests to this provider count. */
  provider?: AiProvider | null
  /** Each member gets their own allowance (global, group, tier and api scopes). */
  per_user?: boolean
}

export interface BudgetStatus {
  budget_id: string
  name: string
  scope: AiBudgetScope
  target: string
  period: AiBudgetPeriod
  limit_type: AiBudgetLimitType
  limit_value: number
  used: number
  percent: number
  action: AiBudgetAction
  provider?: AiProvider | null
  per_user?: boolean
  period_key: string
  resets_at: string
}

export type AiBudgetListRow = AiBudget & { used: number; percent: number | null; resets_at: string }
export type AiBuiltinDetector = 'email' | 'us_ssn' | 'credit_card' | 'aws_access_key' | 'private_key_pem' | 'generic_api_key'
export type AiDetector =
  | { type: 'builtin'; id: AiBuiltinDetector }
  | { type: 'regex'; pattern: string }
  | { type: 'keywords'; values: string[] }

export interface AiGuardrail {
  guardrail_id: string
  name: string
  enabled: boolean
  applies_to: { apis: string[]; groups: string[] }
  direction: 'input' | 'output' | 'both'
  detectors: AiDetector[]
  action: 'redact' | 'block' | 'log_only'
  mode: 'enforce' | 'dry_run'
}

export interface AiPricingRow {
  pricing_id: string
  provider: AiProvider
  model_pattern: string
  input_usd_per_mtok: number
  output_usd_per_mtok: number
  cache_read_usd_per_mtok?: number | null
  cache_write_usd_per_mtok?: number | null
  effective_from: string
  note?: string | null
}

export interface AiUsageTotals {
  requests: number
  input_tokens: number
  output_tokens: number
  cost_nanos: number
  cost_usd: string
}

export interface AiTopModel extends AiUsageTotals {
  provider: AiProvider
  model: string
}

export interface AiOverview extends AiUsageTotals {
  start: string
  end: string
  errors: number
  cache_read_tokens: number
  cache_write_tokens: number
  active_users: number
  unpriced_requests: number
  estimated_requests: number
  top_models: AiTopModel[]
}

export type AiTimeseriesGroup = 'model' | 'api' | 'none'
export interface AiTimeseriesPoint extends AiUsageTotals {
  day: string
  key: string | null
}

export interface AiTimeseries {
  start: string
  end: string
  group_by: AiTimeseriesGroup
  points: AiTimeseriesPoint[]
}

export type AiBreakdownDimension = 'user' | 'group' | 'role' | 'tier' | 'provider' | 'model' | 'api'
export interface AiUsageRow extends AiUsageTotals {
  key: string
  groups?: string[]
  /** Employee rows: role and tier at the time of their latest usage. */
  role?: string
  tier?: string | null
  errors: number
  cache_read_tokens: number
  cache_write_tokens: number
  estimated_requests: number
  unpriced_requests: number
}

export interface AiBreakdown {
  dimension: AiBreakdownDimension
  start: string
  end: string
  rows: AiUsageRow[]
}

export interface AiMyUsage {
  username: string
  period: 'month'
  period_key: string
  usage: AiUsageTotals
  budgets: BudgetStatus[]
  apis?: AiMyApi[]
}

/** An AI API the signed-in user can call (from /platform/ai/usage/me). */
export interface AiMyApi {
  api_name: string
  api_version: string
  provider: AiProvider
  sdk_base_url_suffix: string
  default_model: string | null
  models: string[]
  model_patterns: string[]
}

export interface AiSettings {
  log_level: AiLogLevel
  retention_days: number
  notice_text: string | null
  egress_ips: string[]
}

export function defaultAiConfig(): AiApiConfig {
  return {
    credential_group: '', credential_overrides: [], allowed_models: [], default_model: null,
    model_aliases: {}, allowed_operations: null, max_output_tokens: null, stream_allowed: true,
    inject_stream_usage: true, forward_user_id: true, log_level: null, guardrail_ids: [],
    first_byte_timeout_ms: 60000, stream_idle_timeout_ms: 120000,
  }
}

export function aiValidationErrors(error: unknown): Record<string, string> {
  const fields: Record<string, string> = {}
  if (error instanceof Error) {
    for (const message of error.message.split('; ')) {
      const separator = message.indexOf(': ')
      if (separator > 0 && message.startsWith('api_')) fields[message.slice(0, separator)] = message.slice(separator + 2)
    }
  }
  return fields
}

export function aiSdkBaseUrl(gateway: string, name: string, version: string, suffix: string): string {
  const origin = gateway ? new URL(gateway).origin : ''
  return `${origin}/api/ai/${encodeURIComponent(name)}/${encodeURIComponent(version)}${suffix}`
}

const providerLabels: Record<AiProvider, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  gemini: 'Gemini API',
  azure_openai: 'Azure OpenAI',
  openai_compatible: 'OpenAI-compatible',
}

export function providerLabel(id: string): string {
  return providerLabels[id as AiProvider] ?? id
}

export function formatUsd(nanos: number | string): string {
  // Display to the cent. Exact amounts stay in the CSV export.
  const value = BigInt(typeof nanos === 'number' ? Math.round(nanos) : nanos)
  const absolute = value < 0n ? -value : value
  const cents = (absolute + 5_000_000n) / 10_000_000n
  if (cents === 0n && absolute > 0n) return value < 0n ? '-<$0.01' : '<$0.01'
  const dollars = new Intl.NumberFormat('en-US').format(cents / 100n)
  return `${value < 0n ? '-' : ''}$${dollars}.${(cents % 100n).toString().padStart(2, '0')}`
}

/** An allowance amount in its own unit: dollars, tokens or requests. */
/** An AI API as the API list returns it (the fields the budget screens use). */
export type AiApiSummary = { api_name: string; api_version: string; api_type: string; api_ai_provider?: AiProvider; api_ai_config?: AiApiConfig }

/**
 * Models these APIs allow that have no price ("OpenAI gpt-x"), optionally only
 * for one API ("name/version") or one provider. A USD limit counts them as $0.
 */
export function findUnpricedModels(apis: AiApiSummary[], pricing: AiPricingRow[], filter: { api?: string; provider?: string | null } = {}): string[] {
  return [...new Set(apis
    .filter(api => api.api_type === 'AI' && (!filter.api || `${api.api_name}/${api.api_version}` === filter.api) && (!filter.provider || api.api_ai_provider === filter.provider))
    .flatMap(api => (api.api_ai_config?.allowed_models || []).filter(model => !model.endsWith('*'))
      .filter(model => !pricing.some(row => row.provider === api.api_ai_provider && (row.model_pattern.endsWith('*') ? model.startsWith(row.model_pattern.slice(0, -1)) : row.model_pattern === model)))
      .map(model => `${providerLabel(api.api_ai_provider || '')} ${model}`)))].sort()
}

/** Dollars as typed (up to nine decimals) to nano-USD; null when not a valid positive amount. */
export const USD_PATTERN = '\\d+(\\.\\d{1,9})?'
export function usdToNanos(text: string): number | null {
  if (!/^\d+(?:\.\d{1,9})?$/.test(text.trim())) return null
  const [whole, fraction = ''] = text.trim().split('.')
  const nanos = BigInt(whole) * BigInt(1e9) + BigInt(fraction.padEnd(9, '0'))
  return nanos <= BigInt(0) || nanos > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(nanos)
}

/** Nano-USD to a plain dollar string for an input field ("12.5"). */
export const nanosToUsd = (nanos: number) => `${Math.trunc(nanos / 1e9)}.${String(nanos % 1e9).padStart(9, '0')}`.replace(/\.?0+$/, '')

export function formatBudgetAmount(limitType: string, value: number): string {
  if (limitType === 'cost') return formatUsd(value)
  return `${formatTokens(value)} ${limitType === 'requests' ? (value === 1 ? 'request' : 'requests') : 'tokens'}`
}

export function formatTokens(n: number): string {
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(n)
}

