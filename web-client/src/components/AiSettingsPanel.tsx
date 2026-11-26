'use client'

import { useEffect, useState } from 'react'
import { getJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { formatBytes, type AiCacheStats, type AiLogLevel, type AiSettings, type AiTelemetryStatus } from '@/utils/ai'

export default function AiSettingsPanel() {
  const [settings, setSettings] = useState<AiSettings | null>(null)
  const [logLevel, setLogLevel] = useState<AiLogLevel>('metadata')
  const [retention, setRetention] = useState('30')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [cacheStats, setCacheStats] = useState<AiCacheStats | null>(null)
  const [telemetry, setTelemetry] = useState<AiTelemetryStatus | 'unavailable' | null>(null)

  const apply = (value: AiSettings) => { setSettings(value); setLogLevel(value.log_level); setRetention(String(value.retention_days)); setNotice(value.notice_text || '') }
  useEffect(() => {
    getJson<AiSettings>(`${SERVER_URL}/platform/ai/settings`).then(apply).catch(reason => setError(reason instanceof Error ? reason.message : 'Unable to load AI settings'))
    getJson<AiCacheStats>(`${SERVER_URL}/platform/ai/cache`).then(setCacheStats).catch(() => {})
    getJson<AiTelemetryStatus>(`${SERVER_URL}/platform/ai/telemetry`).then(setTelemetry).catch(() => setTelemetry('unavailable'))
  }, [])

  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null); setSaved(false)
    const retention_days = Number(retention)
    if (!Number.isInteger(retention_days) || retention_days < 1 || retention_days > 3650) { setError('retention_days: enter a whole number from 1 to 3650'); return }
    if (logLevel === 'full' && !notice.trim()) { setError('notice_text: required when log level is Full'); return }
    setSaving(true)
    try { apply(await putJson<AiSettings>(`${SERVER_URL}/platform/ai/settings`, { log_level: logLevel, retention_days, notice_text: notice.trim() || null })); setSaved(true) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to save AI settings') }
    finally { setSaving(false) }
  }

  return <form className="card" onSubmit={save}>
    {!settings ? <div className="p-6 text-sm">{error ? <p role="alert" className="text-red-600">{error}</p> : 'Loading…'}</div> : <div className="p-6 space-y-4">
      <p className="text-sm text-gray-500">Applies to every AI provider. A provider can only log less than this, never more.</p>
      <label className="block text-sm max-w-xl">What to keep<select className="input w-full mt-1" value={logLevel} onChange={e => setLogLevel(e.target.value as AiLogLevel)}><option value="none">None: no AI request metadata or prompts</option><option value="metadata">Metadata: model, tokens and cost only</option><option value="full">Full: encrypted prompts and completions</option></select></label>
      {logLevel === 'full' && <p className="text-sm rounded-lg bg-warning-50 border border-warning-200 p-3 text-warning-800">Storing employee prompts may be regulated by employee-monitoring and privacy laws in your jurisdiction. All users see the notice below as a banner. Guardrail redactions are applied before storage, and prompts are encrypted at rest (requires <code>TOKEN_ENCRYPTION_KEY</code> or <code>MEM_ENCRYPTION_KEY</code>).</p>}
      <label className="block text-sm max-w-xl">Notice shown to employees{logLevel === 'full' && ' (required)'}<textarea className="input w-full mt-1" rows={3} maxLength={2000} required={logLevel === 'full'} value={notice} onChange={e => setNotice(e.target.value)} placeholder="AI prompts sent through Doorman are logged for security review." /></label>
      <label className="block text-sm">Keep logs for (days)<input className="input w-32 mt-1 block" type="number" min={1} max={3650} required value={retention} onChange={e => setRetention(e.target.value)} /></label>
      <div className="text-sm"><p>Outbound IP addresses</p>{settings.egress_ips.length ? <ul className="font-mono text-xs mt-1">{settings.egress_ips.map(ip => <li key={ip}>{ip}</li>)}</ul> : <p className="text-xs text-gray-500 mt-1">Not configured. Set <code>DOORMAN_EGRESS_IPS</code> to show the addresses providers should allowlist.</p>}</div>
      {cacheStats && <div className="text-sm"><p>Response cache</p><p className="text-xs text-gray-500 mt-1">{cacheStats.backend === 'redis'
        ? (cacheStats.encrypted === false
          ? 'Caching is unavailable: Redis is in use but no TOKEN_ENCRYPTION_KEY or MEM_ENCRYPTION_KEY is set, and answers are never stored unencrypted.'
          : 'Stored in Redis, encrypted, and shared by every gateway instance.')
        : `Stored in this gateway's memory: ${cacheStats.entries ?? 0} answer${cacheStats.entries === 1 ? '' : 's'}, ${formatBytes(cacheStats.bytes ?? 0)} of ${formatBytes(cacheStats.max_bytes ?? 0)} (set AI_CACHE_MAX_BYTES to change). Turn caching on per provider under Providers.`}</p></div>}
      <section aria-labelledby="ai-telemetry-heading" className="space-y-2 text-sm">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h2 id="ai-telemetry-heading" className="font-medium">Telemetry (OpenTelemetry)</h2>
          <p className="text-xs text-gray-500">
            {telemetry === null ? 'Loading…' : telemetry === 'unavailable' ? 'Status unavailable' : telemetry.enabled ? 'On' : 'Off'}
          </p>
        </div>
        {telemetry && telemetry !== 'unavailable' && (
          <>
            {telemetry.enabled && (
              <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-xs">
                <dt className="text-gray-500">Protocol</dt><dd>{telemetry.protocol === 'grpc' ? 'gRPC' : 'HTTP/protobuf'}</dd>
                <dt className="text-gray-500">Traces</dt><dd className="break-all font-mono">{telemetry.traces_endpoint ?? 'Off'}</dd>
                <dt className="text-gray-500">Metrics</dt><dd className="break-all font-mono">{telemetry.metrics_endpoint ?? 'Off'}</dd>
                <dt className="text-gray-500">User identity</dt>
                <dd>{telemetry.traces_endpoint && telemetry.include_user ? 'Included on AI traces' : 'Excluded'}</dd>
              </dl>
            )}
            {telemetry.last_error && (
              <p role="alert" className="break-words rounded-lg border border-warning-200 bg-warning-50 p-2 text-xs text-warning-800">
                <span className="font-medium">Last exporter error</span><br />{telemetry.last_error}
              </p>
            )}
          </>
        )}
        <p className="text-xs text-gray-500">
          Configure export through gateway environment variables.{' '}
          <a href="/docs/ai-gateway.md" target="_blank" rel="noreferrer" className="text-primary-700 underline">OpenTelemetry setup guide</a>
        </p>
      </section>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {saved && <p role="status" className="text-sm text-green-700">Saved.</p>}
      <button type="submit" className="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
    </div>}
  </form>
}
