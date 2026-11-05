'use client'

import { useEffect, useMemo, useState } from 'react'
import { useAiProviders } from '@/hooks/useAiProviders'
import { getJson, postJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { formatTokens, providerLabel, type AiBreakdown, type AiOverview, type AiPricingRow, type AiProvider } from '@/utils/ai'

const rateFields = ['input_usd_per_mtok', 'output_usd_per_mtok', 'cache_read_usd_per_mtok', 'cache_write_usd_per_mtok'] as const
const SHOWN = 50

interface BuiltinPrices {
  enabled: boolean
  source: string
  license: string
  generated_at: string
  prices: Omit<AiPricingRow, 'pricing_id' | 'effective_from'>[]
}

interface RecalculateResult { repriced_requests: number; added_cost_usd: string; skipped_partly_priced_rows: number; still_unpriced_rows: number }

const rate = (value: number | null | undefined) => value === null || value === undefined ? '—' : `$${value}`

export default function AiPricingPanel({ canManage }: { canManage: boolean }) {
  const { providers } = useAiProviders()
  const [rows, setRows] = useState<AiPricingRow[]>([])
  const [builtin, setBuiltin] = useState<BuiltinPrices | null>(null)
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [unpriced, setUnpriced] = useState(0)
  const [unpricedModels, setUnpricedModels] = useState<string[]>([])
  const [rowErrors, setRowErrors] = useState<Record<number, string>>({})
  const [providerFilter, setProviderFilter] = useState('')
  const [search, setSearch] = useState('')

  const loadUnpriced = () => Promise.all([
    getJson<AiOverview>(`${SERVER_URL}/platform/analytics/ai/overview`),
    getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?dimension=model&limit=500`),
  ]).then(([overview, models]) => {
    setUnpriced(overview.unpriced_requests)
    setUnpricedModels(models.rows.filter(model => model.unpriced_requests > 0).map(model => model.key))
  }).catch(() => {})

  useEffect(() => {
    let active = true
    Promise.all([
      getJson<{ pricing: AiPricingRow[] }>(`${SERVER_URL}/platform/ai/pricing`),
      getJson<BuiltinPrices>(`${SERVER_URL}/platform/ai/pricing/builtin`).catch(() => null),
    ]).then(([pricing, list]) => { if (active) { setRows(pricing.pricing); setBuiltin(list) } })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load prices') })
      .finally(() => { if (active) setLoading(false) })
    loadUnpriced()
    return () => { active = false }
  }, [])

  const update = (index: number, patch: Partial<AiPricingRow>) => setRows(previous => previous.map((row, i) => i === index ? { ...row, ...patch } : row))
  const addRow = (seed?: Partial<AiPricingRow>) => setRows(previous => [...previous, { pricing_id: crypto.randomUUID(), provider: 'openai', model_pattern: '', input_usd_per_mtok: 0, output_usd_per_mtok: 0, effective_from: new Date().toISOString().slice(0, 10), cache_read_usd_per_mtok: null, cache_write_usd_per_mtok: null, note: null, ...seed }])

  const save = async () => {
    setWorking(true); setError(null); setSuccess(null); setRowErrors({})
    try {
      const result = await putJson<{ pricing: AiPricingRow[] }>(`${SERVER_URL}/platform/ai/pricing`, { pricing: rows })
      setRows(result.pricing); setSuccess('Prices saved. New requests use them.')
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : 'Could not save prices'
      const errors: Record<number, string> = {}
      for (const part of message.split('; ')) { const match = /^pricing\[(\d+)\]: (.*)$/.exec(part); if (match) errors[Number(match[1])] = match[2] }
      setRowErrors(errors); setError(message)
    } finally { setWorking(false) }
  }

  const recalculate = async () => {
    setWorking(true); setError(null); setSuccess(null)
    try {
      const result = await postJson<RecalculateResult>(`${SERVER_URL}/platform/ai/pricing/recalculate`, { days: 90 })
      const notes = [result.still_unpriced_rows ? `${result.still_unpriced_rows} model-days still have no price` : '', result.skipped_partly_priced_rows ? `${result.skipped_partly_priced_rows} partly priced model-days were left as they were` : ''].filter(Boolean)
      setSuccess(`Re-priced ${formatTokens(result.repriced_requests)} requests from the last 90 days, adding $${Number(result.added_cost_usd).toFixed(2)}.${notes.length ? ` ${notes.join('; ')}.` : ''}`)
      await loadUnpriced()
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not recalculate') }
    finally { setWorking(false) }
  }

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    return (builtin?.prices || []).filter(price => (!providerFilter || price.provider === providerFilter) && (!term || price.model_pattern.toLowerCase().includes(term)))
  }, [builtin, providerFilter, search])
  const builtinProviders = useMemo(() => [...new Set((builtin?.prices || []).map(price => price.provider))], [builtin])

  return <div className="space-y-6">
    {unpriced > 0 && <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 flex flex-wrap items-center justify-between gap-3">
      <span>{formatTokens(unpriced)} requests in the last 30 days had no price and were counted as $0{unpricedModels.length ? ` (${unpricedModels.join(', ')})` : ''}.</span>
      {canManage && <button type="button" className="btn btn-secondary" disabled={working} onClick={recalculate}>Recalculate past usage</button>}
    </div>}
    {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
    {success && <p role="status" className="text-sm text-green-700">{success}</p>}

    <section className="card p-6 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="card-title">Your prices</h2><p className="text-sm text-gray-500 mt-1">US dollars per million tokens. These override the built-in prices. An exact model name wins over a pattern ending in *.</p></div>
        {canManage && <div className="flex gap-2"><button type="button" className="btn btn-secondary" disabled={working || loading} onClick={() => addRow()}>Add price</button><button type="button" className="btn btn-primary" disabled={working || loading} onClick={save}>{working ? 'Saving…' : 'Save prices'}</button></div>}
      </div>
      {loading ? <p className="text-sm text-gray-500">Loading prices…</p> : rows.length ? <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>Provider</th><th>Model</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>From</th>{canManage && <th />}</tr></thead><tbody>{rows.map((row, index) => <tr key={row.pricing_id} className={rowErrors[index] ? 'bg-red-50' : ''}>
        <td><select aria-label={`Provider row ${index + 1}`} className="input min-w-32" value={row.provider} disabled={!canManage || working} onChange={e => update(index, { provider: e.target.value as AiProvider })}>{providers.map(provider => <option key={provider.id} value={provider.id}>{provider.label}</option>)}</select></td>
        <td><input aria-label={`Model row ${index + 1}`} className="input min-w-44" value={row.model_pattern} disabled={!canManage || working} onChange={e => update(index, { model_pattern: e.target.value })} />{rowErrors[index] && <p className="text-xs text-red-600">{rowErrors[index]}</p>}</td>
        {rateFields.map((field, column) => <td key={field}><input aria-label={`${field} row ${index + 1}`} className="input w-24" type="number" min={0} step="0.000001" placeholder={field === 'cache_write_usd_per_mtok' ? 'Input' : column > 1 ? '—' : '0'} value={row[field] ?? ''} disabled={!canManage || working} onChange={e => update(index, { [field]: e.target.value === '' && column > 1 ? null : Number(e.target.value) })} /></td>)}
        <td><input aria-label={`Effective date row ${index + 1}`} type="date" className="input" value={row.effective_from.slice(0, 10)} disabled={!canManage || working} onChange={e => update(index, { effective_from: e.target.value })} /></td>
        {canManage && <td><button type="button" className="btn btn-ghost" disabled={working} onClick={() => setRows(previous => previous.filter((_, i) => i !== index))}>Remove</button></td>}
      </tr>)}</tbody></table></div> : <p className="text-sm text-gray-500">None yet. The built-in prices below are used.</p>}
    </section>

    <section className="card p-6 space-y-4">
      <div>
        <h2 className="card-title">Built-in prices</h2>
        <p className="text-sm text-gray-500 mt-1">{builtin ? (builtin.enabled ? `${formatTokens(builtin.prices.length)} models from LiteLLM's public price list, updated ${builtin.generated_at}. Used when you haven't set a price.` : 'Turned off on this gateway (AI_BUILTIN_PRICES=false).') : 'Not available.'}</p>
      </div>
      {builtin?.enabled && <>
        <div className="flex flex-wrap gap-3">
          <label className="text-xs text-gray-500 flex flex-col gap-1" htmlFor="builtin-provider">Provider<select id="builtin-provider" className="input w-auto text-sm" value={providerFilter} onChange={event => setProviderFilter(event.target.value)}><option value="">All providers</option>{builtinProviders.map(provider => <option key={provider} value={provider}>{providerLabel(provider)}</option>)}</select></label>
          <label className="text-xs text-gray-500 flex flex-col gap-1" htmlFor="builtin-search">Model<input id="builtin-search" className="input w-64 text-sm" placeholder="Search models" value={search} onChange={event => setSearch(event.target.value)} /></label>
        </div>
        <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>Provider</th><th>Model</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th>{canManage && <th />}</tr></thead><tbody>{filtered.slice(0, SHOWN).map(price => <tr key={`${price.provider}/${price.model_pattern}`}>
          <td>{providerLabel(price.provider)}</td><td className="break-all">{price.model_pattern}</td>
          <td className="tabular-nums">{rate(price.input_usd_per_mtok)}</td><td className="tabular-nums">{rate(price.output_usd_per_mtok)}</td><td className="tabular-nums">{rate(price.cache_read_usd_per_mtok)}</td><td className="tabular-nums">{rate(price.cache_write_usd_per_mtok)}</td>
          {canManage && <td><button type="button" className="btn btn-ghost" onClick={() => { addRow({ provider: price.provider, model_pattern: price.model_pattern, input_usd_per_mtok: price.input_usd_per_mtok, output_usd_per_mtok: price.output_usd_per_mtok, cache_read_usd_per_mtok: price.cache_read_usd_per_mtok ?? null, cache_write_usd_per_mtok: price.cache_write_usd_per_mtok ?? null }); setSuccess(`Added ${price.model_pattern} to your prices. Edit it, then save.`) }}>Override</button></td>}
        </tr>)}</tbody></table></div>
        <p className="text-xs text-gray-500">{filtered.length > SHOWN ? `Showing ${SHOWN} of ${formatTokens(filtered.length)}. Search to narrow the list.` : `${formatTokens(filtered.length)} models.`} Source: {builtin.source}, {builtin.license}.</p>
      </>}
    </section>
  </div>
}
