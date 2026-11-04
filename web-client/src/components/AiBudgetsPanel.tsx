'use client'

import { useCallback, useEffect, useState } from 'react'
import SearchableSelect from '@/components/SearchableSelect'
import ConfirmModal from '@/components/ConfirmModal'
import { delJson, fetchAllPaginated, getJson, postJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import AiBudgetBar from '@/components/AiBudgetBar'
import { aiValidationErrors, formatTokens, formatUsd, providerLabel, type AiApiConfig, type AiBudget, type AiBudgetListRow, type AiBudgetScope, type AiProvider } from '@/utils/ai'

type Api = { api_name: string; api_version: string; api_type: string; api_ai_provider?: AiProvider; api_ai_config?: AiApiConfig }
const SCOPES: [AiBudgetScope, string][] = [['global', 'Everyone'], ['group', 'Group'], ['tier', 'Tier'], ['user', 'One user'], ['api', 'One AI API']]
const scopeLabel = (scope: string) => SCOPES.find(([id]) => id === scope)?.[1] || scope
type Draft = Omit<AiBudget, 'limit_value'> & { limit: string }
const fresh = (): Draft => ({ budget_id: '', name: '', scope: 'global', target: '', period: 'month', limit_type: 'cost', limit: '', action: 'warn', downgrade_model: null, warn_at_percent: 80, enabled: true, provider: null, per_user: false })
const dollars = (nanos: number) => `${Math.trunc(nanos / 1e9)}.${String(nanos % 1e9).padStart(9, '0')}`.replace(/\.?0+$/, '')

export default function AiBudgetsPanel() {
  const [rows, setRows] = useState<AiBudgetListRow[]>([])
  const [apis, setApis] = useState<Api[]>([])
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [removing, setRemoving] = useState<AiBudgetListRow | null>(null)
  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const result = await getJson<{ budgets: AiBudgetListRow[] }>(`${SERVER_URL}/platform/ai/budgets`)
      setRows(result.budgets)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load budgets') }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    let active = true
    fetchAllPaginated<Api>((page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data.apis || [])
      .then(result => { if (active) setApis(result.filter(api => api.api_type === 'AI')) })
      .catch(() => {})
    return () => { active = false }
  }, [])
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const scope = params.get('budget_scope')
    if (scope === 'user' || scope === 'group' || scope === 'api') {
      setDraft({ ...fresh(), scope, target: params.get('budget_target') || '' })
      setFields({})
    }
  }, [])
  const options = async (scope: AiBudgetScope): Promise<string[]> => {
    if (scope === 'api') return apis.map(api => `${api.api_name}/${api.api_version}`)
    if (scope === 'tier') {
      const result = await getJson<{ tiers?: { tier_id: string }[] } | { tier_id: string }[]>(`${SERVER_URL}/platform/tiers/?page=1&page_size=500`)
      return (Array.isArray(result) ? result : result.tiers || []).map(tier => tier.tier_id)
    }
    const kind = scope === 'user' ? 'user' : 'group'
    const result = await fetchAllPaginated<Record<string, string>>((page, size) => `${SERVER_URL}/platform/${kind}/all?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data[`${kind}s`] || [])
    return result.map(row => row[kind === 'user' ? 'username' : 'group_name']).filter(Boolean)
  }
  const models = [...new Set(apis.flatMap(api => [...(api.api_ai_config?.allowed_models || []).filter(model => !model.endsWith('*')), ...Object.values(api.api_ai_config?.model_aliases || {})]))].sort()
  const update = (value: Partial<Draft>) => setDraft(current => current ? { ...current, ...value } : current)
  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!draft) return
    setFields({}); setError(null)
    let limit: bigint
    if (draft.limit_type === 'cost') {
      if (!/^\d+(?:\.\d{1,9})?$/.test(draft.limit)) { setFields({ limit_value: 'Enter dollars with at most nine decimal places.' }); return }
      const [whole, fraction = ''] = draft.limit.split('.')
      limit = BigInt(whole) * BigInt(1e9) + BigInt(fraction.padEnd(9, '0'))
    } else {
      if (!/^\d+$/.test(draft.limit)) { setFields({ limit_value: 'Enter a positive whole token count.' }); return }
      limit = BigInt(draft.limit)
    }
    if (limit <= BigInt(0) || limit > BigInt(Number.MAX_SAFE_INTEGER)) { setFields({ limit_value: 'Enter a positive limit within the supported integer range.' }); return }
    const { limit: _limit, budget_id, ...values } = draft
    const body = { ...values, target: draft.scope === 'global' ? '' : draft.target, limit_value: Number(limit), downgrade_model: draft.action === 'downgrade' ? draft.downgrade_model : null, provider: draft.provider || null, per_user: draft.scope !== 'user' && !!draft.per_user }
    setWorking(true)
    try {
      if (budget_id) await putJson(`${SERVER_URL}/platform/ai/budgets/${encodeURIComponent(budget_id)}`, body)
      else await postJson(`${SERVER_URL}/platform/ai/budgets`, body)
      setDraft(null); await load()
    } catch (reason) { setFields(aiValidationErrors(reason)); setError(reason instanceof Error ? reason.message : 'Unable to save budget') }
    finally { setWorking(false) }
  }
  const remove = async () => {
    if (!removing) return
    setWorking(true)
    try { await delJson(`${SERVER_URL}/platform/ai/budgets/${encodeURIComponent(removing.budget_id)}`); setRemoving(null); await load() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to delete budget') }
    finally { setWorking(false) }
  }
  const issue = (field: string) => fields[field] && <p className="text-xs text-red-600 mt-1">{fields[field]}</p>
  return <div className="card p-6 space-y-4">
    <div className="flex justify-between gap-3"><div><h3 className="card-title">AI Budgets</h3><p className="text-sm text-gray-500 mt-1">Budgets are soft limits. Concurrent requests and streams can exceed a limit before usage is charged.</p></div><button type="button" className="btn btn-primary" onClick={() => { setDraft(fresh()); setFields({}); setError(null) }}>Create budget</button></div>
    {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
    {loading ? <p>Loading budgets…</p> : <><button type="button" className="btn btn-ghost" onClick={load}>Refresh usage</button>{rows.length ? <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>Name</th><th>Scope / target</th><th>Period</th><th>Limit</th><th>Action</th><th>Current usage</th><th /></tr></thead><tbody>{rows.map(row => <tr key={row.budget_id}><td>{row.name}{!row.enabled && <span className="block text-xs">Disabled</span>}</td><td>{scopeLabel(row.scope)}{row.target && <span className="block text-xs font-mono">{row.target}</span>}{row.per_user && row.scope !== 'user' && <span className="block text-xs text-gray-500">Each member</span>}{row.provider && <span className="block text-xs text-gray-500">{providerLabel(row.provider)} only</span>}</td><td>{row.period}</td><td>{row.limit_type === 'cost' ? formatUsd(row.limit_value) : `${formatTokens(row.limit_value)} tokens`}</td><td>{row.action}{row.downgrade_model && <span className="block text-xs">{row.downgrade_model}</span>}</td><td>{row.percent == null ? <p className="text-sm">{row.limit_type === 'cost' ? formatUsd(row.used) : `${formatTokens(row.used)} tokens`} total<span className="block text-xs text-gray-500">across members; limit is per member</span></p> : <><p>{row.percent}%</p><AiBudgetBar percent={row.percent} warnAt={row.warn_at_percent} label={`${row.name} usage`} className="max-w-[10rem]" /></>}<p className="text-xs text-gray-500">Resets {new Date(row.resets_at).toLocaleString()}</p></td><td><div className="flex gap-2"><button type="button" className="btn btn-ghost" onClick={() => { setDraft({ ...row, limit: row.limit_type === 'cost' ? dollars(row.limit_value) : String(row.limit_value) }); setFields({}); setError(null) }}>Edit</button><button type="button" className="btn btn-ghost" onClick={() => setRemoving(row)}>Delete</button></div></td></tr>)}</tbody></table></div> : <p className="text-sm text-gray-500">No AI budgets yet.</p>}</>}
    {draft && <div className="fixed inset-0 bg-black/50 z-50 flex justify-end"><form role="dialog" aria-modal="true" aria-label={draft.budget_id ? 'Edit AI budget' : 'Create AI budget'} onSubmit={save} className="bg-white dark:bg-gray-900 w-full max-w-xl h-full overflow-y-auto p-6 space-y-4"><h3 className="text-lg font-semibold">{draft.budget_id ? 'Edit' : 'Create'} AI budget</h3>
      <label className="block text-sm">Name<input className="input w-full mt-1" required value={draft.name} onChange={event => update({ name: event.target.value })} />{issue('name')}</label>
      <label className="block text-sm">Scope<select className="input w-full mt-1" value={draft.scope} onChange={event => update({ scope: event.target.value as AiBudgetScope, target: '', per_user: event.target.value === 'user' ? false : draft.per_user })}>{SCOPES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>{issue('scope')}</label>
      {draft.scope !== 'global' && <div className="text-sm"><p className="mb-1">Target</p><SearchableSelect key={draft.scope} value={draft.target} onChange={target => update({ target })} fetchOptions={() => options(draft.scope)} restrictToOptions placeholder={`Select ${draft.scope}`} />{issue('target')}</div>}
      {draft.scope !== 'user' && <fieldset className="text-sm space-y-1"><legend className="mb-1">How the limit is shared</legend>
        <label className="flex gap-2"><input type="radio" checked={!draft.per_user} onChange={() => update({ per_user: false })} />One shared pool{draft.scope === 'global' ? ' for the whole company' : ''}</label>
        <label className="flex gap-2"><input type="radio" checked={!!draft.per_user} onChange={() => update({ per_user: true })} />Each {draft.scope === 'api' ? 'user' : 'member'} gets this amount</label>
        {issue('per_user')}</fieldset>}
      <label className="block text-sm">Provider<select className="input w-full mt-1" value={draft.provider || ''} onChange={event => update({ provider: (event.target.value || null) as AiProvider | null })}><option value="">All providers</option>{(['openai', 'anthropic', 'gemini', 'azure_openai', 'openai_compatible'] as AiProvider[]).map(value => <option key={value} value={value}>{providerLabel(value)}</option>)}</select><span className="text-xs text-gray-500">Only requests to this provider count toward the limit.</span>{issue('provider')}</label>
      <label className="block text-sm">Period<select className="input w-full mt-1" value={draft.period} onChange={event => update({ period: event.target.value as AiBudget['period'] })}>{['day', 'week', 'month'].map(value => <option key={value}>{value}</option>)}</select>{issue('period')}</label>
      <label className="block text-sm">Limit type<select className="input w-full mt-1" value={draft.limit_type} onChange={event => update({ limit_type: event.target.value as AiBudget['limit_type'], limit: '' })}><option value="cost">USD ($)</option><option value="tokens">Tokens</option></select>{issue('limit_type')}</label>
      <label className="block text-sm">Limit {draft.limit_type === 'cost' ? '(USD)' : '(tokens)'}<input className="input w-full mt-1" inputMode="decimal" required value={draft.limit} onChange={event => update({ limit: event.target.value })} />{issue('limit_value')}</label>
      <label className="block text-sm">Action<select className="input w-full mt-1" value={draft.action} onChange={event => update({ action: event.target.value as AiBudget['action'] })}>{['warn', 'downgrade', 'block'].map(value => <option key={value}>{value}</option>)}</select>{issue('action')}</label>
      {draft.action === 'downgrade' && <div className="text-sm"><p className="mb-1">Downgrade model</p><SearchableSelect value={draft.downgrade_model || ''} onChange={downgrade_model => update({ downgrade_model })} fetchOptions={async () => models} placeholder="Allowed model ID" /><p className="text-xs text-gray-500 mt-1">Select an allowed model or enter a concrete ID allowed by a wildcard. The target API must also allow it.</p>{issue('downgrade_model')}</div>}
      <label className="block text-sm">Warn at %<input className="input w-full mt-1" type="number" min={1} max={99} required value={draft.warn_at_percent} onChange={event => update({ warn_at_percent: Number(event.target.value) })} />{issue('warn_at_percent')}</label>
      <label className="flex gap-2 text-sm"><input type="checkbox" checked={draft.enabled} onChange={event => update({ enabled: event.target.checked })} />Enabled{issue('enabled')}</label>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <div className="flex gap-2"><button type="submit" className="btn btn-primary" disabled={working}>Save budget</button><button type="button" className="btn btn-secondary" disabled={working} onClick={() => setDraft(null)}>Cancel</button></div>
    </form></div>}
    <ConfirmModal open={!!removing} title="Delete AI budget?" message={`Delete ${removing?.name || ''}? Its limit will no longer apply.`} onConfirm={remove} onCancel={() => { if (!working) setRemoving(null) }} loading={working} confirmLabel="Delete budget" />
  </div>
}
