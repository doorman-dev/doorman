'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useAiProviders } from '@/hooks/useAiProviders'
import { getJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { formatTokens, type AiBreakdown, type AiOverview, type AiPricingRow, type AiProvider } from '@/utils/ai'

const rateFields = ['input_usd_per_mtok', 'output_usd_per_mtok', 'cache_read_usd_per_mtok', 'cache_write_usd_per_mtok'] as const

export default function AiPricingPanel({ canManage }: { canManage: boolean }) {
  const { providers } = useAiProviders()
  const [rows, setRows] = useState<AiPricingRow[]>([])
  const [loading, setLoading] = useState(true)
  const [loaded, setLoaded] = useState(false)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [examples, setExamples] = useState(false)
  const [unpriced, setUnpriced] = useState(0)
  const [unpricedModels, setUnpricedModels] = useState<string[]>([])
  const [updatedAt, setUpdatedAt] = useState<string | null>(null)
  const [rowErrors, setRowErrors] = useState<Record<number, string>>({})
  useEffect(() => {
    let active = true
    Promise.all([
      getJson<{ pricing: AiPricingRow[]; updated_at: string | null }>(`${SERVER_URL}/platform/ai/pricing`),
      getJson<AiOverview>(`${SERVER_URL}/platform/analytics/ai/overview`),
      getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?dimension=model&limit=500`),
    ]).then(([pricing, overview, models]) => {
      if (!active) return
      setRows(pricing.pricing); setUpdatedAt(pricing.updated_at); setLoaded(true)
      setUnpriced(overview.unpriced_requests)
      setUnpricedModels(models.rows.filter(model => model.unpriced_requests > 0).map(model => model.key))
    }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Unable to load AI pricing') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])
  const update = (index: number, patch: Partial<AiPricingRow>) => setRows(previous => previous.map((row, i) => i === index ? { ...row, ...patch } : row))
  const loadExamples = () => {
    setRows([
      { model_pattern: 'claude-opus-5-5', input_usd_per_mtok: 4, output_usd_per_mtok: 20, cache_read_usd_per_mtok: 0.2 },
      { model_pattern: 'claude-sonnet-5-5', input_usd_per_mtok: 2, output_usd_per_mtok: 10, cache_read_usd_per_mtok: 0.2 },
      { model_pattern: 'claude-haiku-5-5', input_usd_per_mtok: 0.1, output_usd_per_mtok: 0.5, note: 'verify; >100K-token prompts priced higher' },
      { model_pattern: 'claude-fable-5-1', input_usd_per_mtok: 10, output_usd_per_mtok: 50 },
    ].map(row => ({ ...row, pricing_id: crypto.randomUUID(), provider: 'anthropic' as AiProvider, effective_from: '2026-10-06', note: row.note || 'verify', cache_write_usd_per_mtok: null })))
    setExamples(true); setSuccess(null); setError(null); setRowErrors({})
  }
  const save = async () => {
    setWorking(true); setError(null); setSuccess(null); setRowErrors({})
    try {
      const result = await putJson<{ pricing: AiPricingRow[]; updated_at: string }>(`${SERVER_URL}/platform/ai/pricing`, { pricing: rows })
      setRows(result.pricing); setUpdatedAt(result.updated_at); setSuccess('AI pricing saved')
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : 'Unable to save pricing'
      const errors: Record<number, string> = {}
      for (const part of message.split('; ')) { const match = /^pricing\[(\d+)\]: (.*)$/.exec(part); if (match) errors[Number(match[1])] = match[2] }
      setRowErrors(errors); setError(message)
    } finally { setWorking(false) }
  }
  return <div className="card p-6 space-y-4" id="ai-pricing-panel">
    <div className="flex flex-wrap gap-3 justify-between items-center"><div><h3 className="card-title">AI Pricing</h3><p className="text-sm text-gray-500">USD per million tokens. Exact models take priority over the longest trailing-* prefix.</p></div>{canManage && <button type="button" className="btn btn-secondary" disabled={working || loading || !loaded} onClick={loadExamples}>Load example pricing</button>}</div>
    {examples && <p role="status" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">Example Anthropic rates as of October 6, 2026. Verify every rate, model and cache policy against your own provider contract before saving. Empty cache-write pricing uses the input rate.</p>}
    {unpriced > 0 && <p className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">{formatTokens(unpriced)} unpriced requests in the last 30 days. Check pricing for {unpricedModels.join(', ') || 'models with traffic'}. Unpriced traffic is recorded at zero cost. <Link href="/ai/usage" className="underline">View AI usage</Link></p>}
    {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
    {success && <p role="status" className="text-sm text-green-700">{success}</p>}
    {loading ? <p className="text-sm">Loading pricing…</p> : <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>Provider</th><th>Model pattern</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>Effective from (UTC)</th><th>Note</th>{canManage && <th />}</tr></thead><tbody>{rows.map((row, index) => <tr key={row.pricing_id} className={rowErrors[index] ? 'bg-red-50' : unpricedModels.some(model => row.model_pattern.endsWith('*') ? model.startsWith(row.model_pattern.slice(0, -1)) : model === row.model_pattern) ? 'bg-amber-50' : ''}>
      <td><select aria-label={`Provider row ${index + 1}`} className="input min-w-36" value={row.provider} disabled={!canManage || working} onChange={e => update(index, { provider: e.target.value as AiProvider })}>{providers.map(provider => <option key={provider.id} value={provider.id}>{provider.label}</option>)}</select></td>
      <td><input aria-label={`Model pattern row ${index + 1}`} className="input min-w-48" value={row.model_pattern} disabled={!canManage || working} onChange={e => update(index, { model_pattern: e.target.value })} />{rowErrors[index] && <p className="text-xs text-red-600">{rowErrors[index]}</p>}</td>
      {rateFields.map((field, column) => <td key={field}><input aria-label={`${field} row ${index + 1}`} className="input min-w-28" type="number" min={0} step="0.000001" placeholder={field === 'cache_write_usd_per_mtok' ? 'Input rate' : column > 1 ? 'Not set' : '0'} value={row[field] ?? ''} disabled={!canManage || working} onChange={e => update(index, { [field]: e.target.value === '' && column > 1 ? null : Number(e.target.value) })} /></td>)}
      <td><input aria-label={`Effective date row ${index + 1}`} type="date" className="input" value={row.effective_from.slice(0, 10)} disabled={!canManage || working} onChange={e => update(index, { effective_from: e.target.value })} /></td>
      <td><input aria-label={`Note row ${index + 1}`} className="input min-w-48" value={row.note || ''} disabled={!canManage || working} onChange={e => update(index, { note: e.target.value || null })} /></td>
      {canManage && <td><button type="button" className="btn btn-ghost" disabled={working} onClick={() => setRows(previous => previous.filter((_, i) => i !== index))}>Remove</button></td>}
    </tr>)}</tbody></table>{!rows.length && <p className="text-sm text-gray-500 py-4">No prices configured. Unknown models are marked unpriced and recorded at zero cost.</p>}</div>}
    {canManage && <div className="flex gap-2"><button type="button" className="btn btn-secondary" disabled={working || loading || !loaded} onClick={() => setRows(previous => [...previous, { pricing_id: crypto.randomUUID(), provider: 'openai', model_pattern: '', input_usd_per_mtok: 0, output_usd_per_mtok: 0, effective_from: new Date().toISOString().slice(0, 10), cache_read_usd_per_mtok: null, cache_write_usd_per_mtok: null, note: null }])}>Add price</button><button type="button" className="btn btn-primary" disabled={working || loading || !loaded} onClick={save}>{working ? 'Saving…' : 'Save pricing'}</button></div>}
    {updatedAt && <p className="text-xs text-gray-500">Updated {new Date(updatedAt).toLocaleString()}</p>}
  </div>
}
