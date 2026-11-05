'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import TimeSeriesChart from '@/components/analytics/TimeSeriesChart'
import DetailModal from '@/components/analytics/DetailModal'
import AiBudgetBar from '@/components/AiBudgetBar'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { formatTokens, formatUsd, providerLabel, type AiBreakdown, type AiBreakdownDimension, type AiOverview, type AiTimeseries, type AiUsageRow, type BudgetStatus } from '@/utils/ai'

const colors = ['#2563eb', '#059669', '#d97706', '#dc2626', '#7c3aed', '#db2777', '#0891b2', '#ea580c', '#4f46e5', '#0d9488', '#64748b']
type Filters = { model: string; group: string; role: string; tier: string; provider: string }
type FilterKey = keyof Filters
type UsageData = { overview: AiOverview; series: AiTimeseries; models: AiBreakdown; budgets: BudgetStatus[] }
const EMPTY: Filters = { model: '', group: '', role: '', tier: '', provider: '' }
const tokens = (row: AiUsageRow) => row.input_tokens + row.output_tokens + row.cache_read_tokens + row.cache_write_tokens
/** Breakdown tabs; `filter` is the filter a row click applies (drill-down). */
const VIEWS: { id: AiBreakdownDimension; label: string; column: string; filter?: FilterKey }[] = [
  { id: 'user', label: 'Employees', column: 'Employee' },
  { id: 'group', label: 'Groups', column: 'Group', filter: 'group' },
  { id: 'role', label: 'Roles', column: 'Role', filter: 'role' },
  { id: 'tier', label: 'Tiers', column: 'Tier', filter: 'tier' },
  { id: 'provider', label: 'Providers', column: 'Provider', filter: 'provider' },
  { id: 'model', label: 'Models', column: 'Model', filter: 'model' },
  { id: 'api', label: 'AI APIs', column: 'API' },
]
const FILTERS: { key: FilterKey; label: string; all: string }[] = [
  { key: 'provider', label: 'Provider', all: 'All providers' }, { key: 'model', label: 'Model', all: 'All models' },
  { key: 'group', label: 'Group', all: 'All groups' }, { key: 'role', label: 'Role', all: 'All roles' }, { key: 'tier', label: 'Tier', all: 'All tiers' },
]
const keyLabel = (dimension: string, key: string) => dimension === 'provider' ? providerLabel(key) : key

export default function AiUsageTab({ start, end, refreshToken, onRangeChange, onClearRange }: {
  start: string; end: string; refreshToken: number; onRangeChange: (start: string, end: string) => void; onClearRange: () => void
}) {
  const [data, setData] = useState<UsageData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [retry, setRetry] = useState(0)
  const [filters, setFilters] = useState<Filters>(EMPTY)
  const [choices, setChoices] = useState<Record<FilterKey, string[]>>({ model: [], group: [], role: [], tier: [], provider: [] })
  const [view, setView] = useState<AiBreakdownDimension>('user')
  const [breakdown, setBreakdown] = useState<AiBreakdown | null>(null)
  const [breakdownError, setBreakdownError] = useState<string | null>(null)
  const [selectedUser, setSelectedUser] = useState<AiUsageRow | null>(null)
  const [userDetail, setUserDetail] = useState<{ models: AiUsageRow[]; providers: AiUsageRow[] } | null>(null)
  const [userError, setUserError] = useState<string | null>(null)
  const query = useMemo(() => {
    const params = new URLSearchParams({ start, end })
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value)
    return params.toString()
  }, [start, end, filters])

  useEffect(() => {
    let active = true
    const range = new URLSearchParams({ start, end, limit: '500' })
    const keys: FilterKey[] = ['model', 'group', 'role', 'tier', 'provider']
    Promise.all(keys.map(dimension => getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?${range}&dimension=${dimension}`)))
      .then(results => { if (active) setChoices(Object.fromEntries(keys.map((key, index) => [key, results[index].rows.map(row => row.key)])) as Record<FilterKey, string[]>) }).catch(() => {})
    return () => { active = false }
  }, [start, end, refreshToken])
  useEffect(() => {
    let active = true
    setLoading(true); setError(null); setSelectedUser(null)
    Promise.all([
      getJson<AiOverview>(`${SERVER_URL}/platform/analytics/ai/overview?${query}`),
      getJson<AiTimeseries>(`${SERVER_URL}/platform/analytics/ai/timeseries?${query}&group_by=model`),
      getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?${query}&dimension=model&limit=500`),
      getJson<{ budgets: BudgetStatus[] }>(`${SERVER_URL}/platform/ai/budgets/status?scope=group`).catch(() => ({ budgets: [] })),
    ]).then(([overview, series, models, budgets]) => {
      if (active) setData({ overview, series, models, budgets: budgets.budgets })
    }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : 'Unable to load AI usage') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [query, refreshToken, retry])
  useEffect(() => {
    let active = true
    setBreakdown(null); setBreakdownError(null)
    getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?${query}&dimension=${view}&limit=200`)
      .then(result => { if (active) setBreakdown(result) })
      .catch((reason: unknown) => { if (active) setBreakdownError(reason instanceof Error ? reason.message : 'Unable to load breakdown') })
    return () => { active = false }
  }, [query, view, refreshToken, retry])
  useEffect(() => {
    if (!selectedUser) return
    let active = true
    setUserDetail(null); setUserError(null)
    const base = `${SERVER_URL}/platform/analytics/ai/breakdown?${query}&limit=500&username=${encodeURIComponent(selectedUser.key)}`
    Promise.all([getJson<AiBreakdown>(`${base}&dimension=model`), getJson<AiBreakdown>(`${base}&dimension=provider`)])
      .then(([models, providers]) => { if (active) setUserDetail({ models: models.rows, providers: providers.rows }) })
      .catch((reason: unknown) => { if (active) setUserError(reason instanceof Error ? reason.message : 'Unable to load employee breakdown') })
    return () => { active = false }
  }, [selectedUser, query])

  const chart = useMemo(() => {
    const models = data?.models.rows.slice(0, 10).map(row => row.key) || []
    const hasOther = !!data?.series.points.some(point => point.key !== null && !models.includes(point.key))
    const series = [...models, ...(hasOther ? ['Other models'] : [])].map((label, index) => ({ key: `model_${index}`, label, color: colors[index % colors.length] }))
    const days = new Map<string, { timestamp: number; count: number; [key: string]: number }>()
    for (const point of data?.series.points || []) {
      const index = models.indexOf(point.key || '')
      const key = `model_${index < 0 ? models.length : index}`
      const day = days.get(point.day) || { timestamp: Date.parse(`${point.day}T00:00:00Z`) / 1000, count: 0 }
      day[key] = (day[key] || 0) + point.cost_nanos
      days.set(point.day, day)
    }
    for (const day of days.values()) for (const item of series) day[item.key] ??= 0
    return { series, points: [...days.values()].sort((a, b) => a.timestamp - b.timestamp) }
  }, [data])

  const active = VIEWS.find(item => item.id === view) || VIEWS[0]
  const totalCost = data?.overview.cost_nanos || 0
  const share = (row: AiUsageRow) => totalCost > 0 ? `${((row.cost_nanos / totalCost) * 100).toFixed(1)}%` : '—'
  const applied = FILTERS.filter(item => filters[item.key])
  const groupBudget = (key: string) => data?.budgets.filter(item => item.scope === 'group' && item.target === key).sort((a, b) => b.percent - a.percent)[0]
  const detailTable = (rows: AiUsageRow[], column: string, dimension: string) => <table className="table w-full text-sm"><thead><tr><th>{column}</th><th>Requests</th><th>Tokens</th><th>Cost</th></tr></thead><tbody>{rows.map(row => <tr key={row.key}><td>{keyLabel(dimension, row.key)}</td><td>{formatTokens(row.requests)}</td><td>{formatTokens(tokens(row))}</td><td>{formatUsd(row.cost_nanos)}</td></tr>)}</tbody></table>

  return <div className="space-y-5">
    <div className="flex flex-wrap items-end gap-3" aria-label="Filter AI usage">
      {FILTERS.map(item => <label key={item.key} className="text-xs text-gray-500 flex flex-col gap-1">{item.label}<select id={`ai-filter-${item.key}`} className="input w-auto min-w-[9rem] text-sm" value={filters[item.key]} onChange={event => setFilters(current => ({ ...current, [item.key]: event.target.value }))}><option value="">{item.all}</option>{[...new Set([...choices[item.key], ...(filters[item.key] ? [filters[item.key]] : [])])].map(value => <option key={value} value={value}>{keyLabel(item.key, value)}</option>)}</select></label>)}
      <label className="text-xs text-gray-500 flex flex-col gap-1">From<input id="ai-filter-start" type="date" className="input w-auto text-sm" value={start} max={end} onChange={event => event.target.value && onRangeChange(event.target.value, end)} /></label>
      <label className="text-xs text-gray-500 flex flex-col gap-1">To<input id="ai-filter-end" type="date" className="input w-auto text-sm" value={end} min={start} onChange={event => event.target.value && onRangeChange(start, event.target.value)} /></label>
      {(applied.length > 0) && <button type="button" className="btn btn-ghost" onClick={() => { setFilters(EMPTY); onClearRange() }}>Clear filters</button>}
    </div>
    {loading && <p className="text-sm text-gray-500">Loading AI usage…</p>}
    {error && <div role="alert" className="space-y-2"><p className="text-sm text-red-600">{error}</p><button type="button" className="btn btn-secondary" onClick={() => setRetry(value => value + 1)}>Retry</button></div>}
    {!loading && !error && data && (data.overview.requests === 0 && !applied.length ? <div className="card text-center p-10"><p>No AI traffic in this period.</p><Link href="/ai/setup" className="btn btn-primary mt-3">Set up AI for employees</Link></div> : <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">{[
        ['Spend', formatUsd(data.overview.cost_nanos)], ['Requests', formatTokens(data.overview.requests)], ['Tokens', formatTokens(data.overview.input_tokens + data.overview.output_tokens)], ['Active employees', formatTokens(data.overview.active_users)],
      ].map(([label, value]) => <div key={label} className="card p-4"><p className="text-xs text-gray-500">{label}</p><p className="text-2xl font-semibold mt-1 tabular-nums">{value}</p></div>)}</div>
      {data.overview.unpriced_requests > 0 && <p className="text-sm rounded border border-amber-300 bg-amber-50 px-3 py-2 text-amber-900">{formatTokens(data.overview.unpriced_requests)} requests have no price and count as $0. <Link href="/ai/providers#prices" className="underline">Add model prices</Link></p>}
      {data.overview.estimated_requests > 0 && <p className="text-sm text-amber-800">{formatTokens(data.overview.estimated_requests)} requests use estimated token counts.</p>}
      <div className="card p-4"><TimeSeriesChart data={chart.points} title="Spend by model" series={chart.series} stacked valueFormatter={formatUsd} timestampFormatter={timestamp => new Date(timestamp * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })} /></div>

      <section className="card p-4 space-y-3">
        <div className="flex flex-wrap justify-between items-end gap-3"><h3 className="font-semibold text-gray-900">Breakdown</h3><div role="tablist" aria-label="Break down AI usage by" className="flex flex-wrap gap-1 border-b border-gray-200">{VIEWS.map(item => <button key={item.id} type="button" role="tab" aria-selected={view === item.id} onClick={() => setView(item.id)} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${view === item.id ? 'border-primary-600 text-primary-700 font-medium' : 'border-transparent text-gray-600 hover:text-gray-900'}`}>{item.label}</button>)}</div></div>
        {breakdownError ? <p role="alert" className="text-sm text-red-600">{breakdownError}</p> : !breakdown ? <p className="text-sm text-gray-500">Loading…</p> : !breakdown.rows.length ? <p className="text-sm text-gray-500">No usage for these filters.</p> : <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>{active.column}</th>{view === 'user' && <><th>Groups</th><th>Role</th><th>Tier</th></>}<th>Requests</th><th>Tokens</th><th>Cost</th><th>Share of spend</th>{view === 'group' && <th>Current budget</th>}</tr></thead><tbody>{breakdown.rows.map(row => {
          const budget = view === 'group' ? groupBudget(row.key) : undefined
          const label = keyLabel(view, row.key)
          return <tr key={row.key}>
            <td>{view === 'user' ? <button type="button" className="text-primary-700 underline" onClick={() => setSelectedUser(row)}>{row.key}</button> : active.filter ? <button type="button" className="text-primary-700 underline" title={`Show only ${label}`} onClick={() => { const key = active.filter as FilterKey; setFilters(current => ({ ...current, [key]: row.key })); setView('user') }}>{label}</button> : <span className="font-mono">{label}</span>}</td>
            {view === 'user' && <><td>{row.groups?.join(', ') || '—'}</td><td>{row.role || '—'}</td><td>{row.tier && row.tier !== '(none)' ? row.tier : '—'}</td></>}
            <td>{formatTokens(row.requests)}</td><td>{formatTokens(tokens(row))}</td><td>{formatUsd(row.cost_nanos)}</td><td>{share(row)}</td>
            {view === 'group' && <td>{budget ? <div className="min-w-36"><p>{budget.name}: {budget.percent}%</p><AiBudgetBar percent={budget.percent} label={`${budget.name} usage`} /><p className="text-xs text-gray-500">Current {budget.period}</p></div> : '—'}</td>}
          </tr>
        })}</tbody></table></div>}
        <p className="text-xs text-gray-500">{view === 'user' ? 'Select an employee for their usage by provider and model.' : active.filter ? `Select a ${active.column.toLowerCase()} to see its employees.` : ''} {view === 'group' ? 'Employees in several groups count toward each group, so group totals can add up to more than total spend.' : view === 'role' || view === 'tier' ? `Each request counts under the employee's ${view} when it was made.` : ''}</p>
      </section>
    </>)}
    <DetailModal isOpen={!!selectedUser} onClose={() => setSelectedUser(null)} title={`${selectedUser?.key || ''} AI usage`}>
      {selectedUser && <dl className="grid sm:grid-cols-3 gap-4 text-sm"><div><dt>Groups</dt><dd>{selectedUser.groups?.join(', ') || '—'}</dd></div><div><dt>Role</dt><dd>{selectedUser.role || '—'}</dd></div><div><dt>Tier</dt><dd>{selectedUser.tier && selectedUser.tier !== '(none)' ? selectedUser.tier : '—'}</dd></div><div><dt>Requests</dt><dd>{formatTokens(selectedUser.requests)}</dd></div><div><dt>Tokens</dt><dd>{formatTokens(tokens(selectedUser))}</dd></div><div><dt>Cost</dt><dd>{formatUsd(selectedUser.cost_nanos)}</dd></div></dl>}
      {userError ? <p role="alert" className="mt-4 text-sm text-red-600">{userError}</p> : !userDetail ? <p className="mt-4 text-sm">Loading…</p> : <div className="mt-5 space-y-5 overflow-x-auto"><div><h5 className="font-medium mb-1">By provider</h5>{detailTable(userDetail.providers, 'Provider', 'provider')}</div><div><h5 className="font-medium mb-1">By model</h5>{detailTable(userDetail.models, 'Model', 'model')}</div>{selectedUser && <Link className="btn btn-secondary" href={`/users/${encodeURIComponent(selectedUser.key)}`}>Open employee</Link>}</div>}
    </DetailModal>
  </div>
}
