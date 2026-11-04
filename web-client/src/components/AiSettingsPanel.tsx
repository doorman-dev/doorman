'use client'

import { useEffect, useState } from 'react'
import { getJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import type { AiLogLevel, AiSettings } from '@/utils/ai'

export default function AiSettingsPanel() {
  const [settings, setSettings] = useState<AiSettings | null>(null)
  const [logLevel, setLogLevel] = useState<AiLogLevel>('metadata')
  const [retention, setRetention] = useState('30')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const apply = (value: AiSettings) => { setSettings(value); setLogLevel(value.log_level); setRetention(String(value.retention_days)); setNotice(value.notice_text || '') }
  useEffect(() => {
    getJson<AiSettings>(`${SERVER_URL}/platform/ai/settings`).then(apply).catch(reason => setError(reason instanceof Error ? reason.message : 'Unable to load AI settings'))
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

  return <form className="card max-w-2xl" onSubmit={save}>
    <div className="card-header"><h3 className="card-title">AI gateway</h3><p className="text-sm text-gray-500 mt-1">Prompt logging and retention for all AI APIs. A per-API log level can only lower this setting.</p></div>
    {!settings ? <div className="p-6 text-sm">{error ? <p role="alert" className="text-red-600">{error}</p> : 'Loading AI settings…'}</div> : <div className="p-6 space-y-4">
      <label className="block text-sm">Prompt log level<select className="input w-full mt-1" value={logLevel} onChange={e => setLogLevel(e.target.value as AiLogLevel)}><option value="none">None: no AI request metadata or prompts</option><option value="metadata">Metadata: model, tokens and cost only</option><option value="full">Full: encrypted prompts and completions</option></select></label>
      {logLevel === 'full' && <p className="text-sm rounded-lg bg-warning-50 border border-warning-200 p-3 text-warning-800">Storing employee prompts may be regulated by employee-monitoring and privacy laws in your jurisdiction. All users see the notice below as a banner. Guardrail redactions are applied before storage, and prompts are encrypted at rest (requires <code>TOKEN_ENCRYPTION_KEY</code> or <code>MEM_ENCRYPTION_KEY</code>).</p>}
      <label className="block text-sm">Notice text{logLevel === 'full' && ' (required)'}<textarea className="input w-full mt-1" rows={3} maxLength={2000} required={logLevel === 'full'} value={notice} onChange={e => setNotice(e.target.value)} placeholder="AI prompts sent through Doorman are logged for security review." /></label>
      <label className="block text-sm">Retention (days)<input className="input w-full mt-1" type="number" min={1} max={3650} required value={retention} onChange={e => setRetention(e.target.value)} /></label>
      <div className="text-sm"><p>Egress IPs (read-only)</p>{settings.egress_ips.length ? <ul className="font-mono text-xs mt-1">{settings.egress_ips.map(ip => <li key={ip}>{ip}</li>)}</ul> : <p className="text-xs text-gray-500 mt-1">Not configured. Set <code>DOORMAN_EGRESS_IPS</code> to show the addresses providers should allowlist.</p>}</div>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {saved && <p role="status" className="text-sm text-green-700">AI settings saved.</p>}
      <button type="submit" className="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save AI settings'}</button>
    </div>}
  </form>
}
