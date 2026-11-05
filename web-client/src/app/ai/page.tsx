'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import AiPage from '@/components/AiPage'
import AiBudgetBar from '@/components/AiBudgetBar'
import { useAuth } from '@/contexts/AuthContext'
import { SERVER_URL } from '@/utils/config'
import { fetchAllPaginated, getJson } from '@/utils/api'
import { formatBudgetAmount, formatTokens, formatUsd, type AiOverview, type BudgetStatus } from '@/utils/ai'

const PERIODS: Record<string, string> = { minute: 'per minute', hour: 'per hour', day: 'today', week: 'this week', month: 'this month' }

export default function AiOverviewPage() {
  const { permissions } = useAuth()
  const [aiApis, setAiApis] = useState<number | null>(null)
  const [month, setMonth] = useState<AiOverview | null>(null)
  const [recent, setRecent] = useState<AiOverview | null>(null)
  const [budgets, setBudgets] = useState<BudgetStatus[]>([])
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        setError(null)
        const apis = await fetchAllPaginated<{ api_type: string }>(
          (page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`,
          data => Array.isArray(data) ? data : data.apis || data.response?.apis || []
        )
        const count = apis.filter(api => api.api_type === 'AI').length
        if (!active) return
        setAiApis(count)
        if (!count) return
        const end = new Date().toISOString().slice(0, 10)
        const [m, r] = await Promise.all([
          getJson<AiOverview>(`${SERVER_URL}/platform/analytics/ai/overview?start=${end.slice(0, 7)}-01&end=${end}`),
          getJson<AiOverview>(`${SERVER_URL}/platform/analytics/ai/overview`),
        ])
        if (active) { setMonth(m); setRecent(r) }
        const status = await getJson<{ budgets: BudgetStatus[] }>(`${SERVER_URL}/platform/ai/budgets/status`).catch(() => null)
        if (active && status) setBudgets([...status.budgets].sort((a, b) => (b.percent ?? 0) - (a.percent ?? 0)))
      } catch (reason) { if (active) setError(reason instanceof Error ? reason.message : 'AI usage is unavailable') }
    }
    load()
    return () => { active = false }
  }, [reload])

  const tiles: [string, string, string][] = month && recent ? [
    ['Spend this month', formatUsd(month.cost_nanos), '/ai/usage'],
    ['Requests this month', formatTokens(month.requests), '/ai/usage'],
    ['Active employees, 30 days', formatTokens(recent.active_users), '/ai/usage'],
    ['Providers', formatTokens(aiApis || 0), '/ai/providers'],
  ] : []

  return <AiPage title="AI Gateway" description="How your company is using AI this month." permission="view_analytics" actions={<button type="button" className="btn btn-secondary" onClick={() => setReload(value => value + 1)}>Refresh</button>}>
    {error && <div role="alert" className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">AI usage is unavailable: {error}</div>}
    {aiApis === 0 && <div className="card p-10 text-center space-y-3">
      <h2 className="text-lg font-semibold">No AI providers yet</h2>
      <p className="text-sm text-gray-600">Connect a provider, choose who can use it and set allowances.</p>
      {permissions?.manage_ai ? <Link href="/ai/setup" className="btn btn-primary">Add provider</Link> : <p className="text-sm text-gray-500">Ask an admin with the Manage AI permission to add one.</p>}
    </div>}
    {tiles.length > 0 && <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {tiles.map(([label, value, href]) => <Link key={label} href={href} className="card p-4 hover:border-primary-300"><span className="block text-xs text-gray-500">{label}</span><span className="block text-2xl font-semibold text-gray-900 tabular-nums mt-1">{value}</span></Link>)}
      </div>
      {recent && recent.unpriced_requests > 0 && <p className="text-sm rounded border border-amber-300 bg-amber-50 px-3 py-2 text-amber-900">{formatTokens(recent.unpriced_requests)} requests in the last 30 days have no price and count as $0. <Link href="/ai/providers#prices" className="font-medium">Add model prices →</Link></p>}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 items-start">
        <section className="card p-5 space-y-4">
          <div className="flex items-center justify-between"><h2 className="card-title">Allowances</h2>{permissions?.manage_ai && <Link href="/ai/allowances" className="text-sm font-medium text-primary-700">Manage →</Link>}</div>
          {budgets.length ? <ul className="space-y-4">{budgets.slice(0, 5).map(budget => <li key={budget.budget_id} className="space-y-1.5">
            <div className="flex justify-between gap-3 text-sm"><span className="truncate">{budget.name}</span><span className="text-gray-500 tabular-nums shrink-0">{formatBudgetAmount(budget.limit_type, budget.used)} of {formatBudgetAmount(budget.limit_type, budget.limit_value)} {PERIODS[budget.period] || ''}</span></div>
            <AiBudgetBar percent={budget.percent} label={`${budget.name} usage`} />
          </li>)}</ul> : <p className="text-sm text-gray-500">No allowances set. Everyone can use AI without a limit.</p>}
        </section>
        <section className="card p-5 space-y-3">
          <div className="flex items-center justify-between"><h2 className="card-title">Top models, 30 days</h2><Link href="/ai/usage" className="text-sm font-medium text-primary-700">Usage →</Link></div>
          {recent && recent.top_models.length ? <table className="w-full text-sm"><tbody>{recent.top_models.slice(0, 5).map(model => <tr key={`${model.provider}/${model.model}`} className="border-b border-gray-100 last:border-0"><td className="py-2">{model.model}</td><td className="py-2 text-right text-gray-500 tabular-nums">{formatTokens(model.requests)} requests</td><td className="py-2 text-right tabular-nums w-24">{formatUsd(model.cost_nanos)}</td></tr>)}</tbody></table> : <p className="text-sm text-gray-500">No AI traffic in the last 30 days.</p>}
        </section>
      </div>
    </>}
  </AiPage>
}
