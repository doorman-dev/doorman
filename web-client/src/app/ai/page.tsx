'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import AiPage from '@/components/AiPage'
import { useAuth } from '@/contexts/AuthContext'
import { SERVER_URL } from '@/utils/config'
import { fetchAllPaginated, getJson } from '@/utils/api'
import { formatTokens, formatUsd, type AiOverview, type BudgetStatus } from '@/utils/ai'

export default function AiOverviewPage() {
  const { permissions } = useAuth()
  const [aiApis, setAiApis] = useState<number | null>(null)
  const [month, setMonth] = useState<AiOverview | null>(null)
  const [recent, setRecent] = useState<AiOverview | null>(null)
  const [alerts, setAlerts] = useState<BudgetStatus[]>([])
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
        const budgets = await getJson<{ budgets: BudgetStatus[] }>(`${SERVER_URL}/platform/ai/budgets/status`).catch(() => null)
        if (active && budgets) setAlerts(budgets.budgets.filter(budget => (budget.percent ?? 0) >= 80).sort((a, b) => b.percent - a.percent))
      } catch (reason) { if (active) setError(reason instanceof Error ? reason.message : 'AI usage is unavailable') }
    }
    load()
    return () => { active = false }
  }, [reload])

  const card = 'rounded border border-gray-200 bg-white p-4'
  const tile = (label: string, value: string, href?: string) => {
    const body = <><div className="text-xs text-gray-500">{label}</div><div className="text-[26px] font-semibold text-gray-900">{value}</div></>
    return href ? <Link key={label} href={href} className={`${card} hover:border-primary-300`}>{body}</Link> : <div key={label} className={card}>{body}</div>
  }

  return <AiPage title="AI Gateway" description="How your company is using AI this month." permission="view_analytics" actions={<button type="button" className="btn btn-primary" onClick={() => setReload(value => value + 1)}>Refresh</button>}>
    {error && <div role="alert" className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">AI usage unavailable: {error}</div>}
    {aiApis === 0 && <div className={`${card} text-center py-10 space-y-3`}>
      <h2 className="text-lg font-semibold">No AI providers yet</h2>
      <p className="text-sm text-gray-600">Connect a provider, choose who can use it and set allowances. Takes about two minutes.</p>
      {permissions?.manage_ai ? <Link href="/ai/setup" className="btn btn-primary">Set up AI for employees</Link> : <p className="text-sm text-gray-500">Ask an admin with the Manage AI permission to run AI Setup.</p>}
    </div>}
    {month && recent && <>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {tile('Spend (month to date)', formatUsd(month.cost_nanos), '/ai/usage')}
        {tile('Requests (month to date)', formatTokens(month.requests), '/ai/usage')}
        {tile('Active employees (30 days)', formatTokens(recent.active_users), '/ai/usage')}
        {tile('Unpriced requests (30 days)', formatTokens(recent.unpriced_requests), '/ai/pricing')}
      </div>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className={card}>
          <div className="mb-2 flex items-center justify-between"><strong className="text-gray-900">Allowances near their limit</strong>{permissions?.manage_ai && <Link href="/ai/allowances" className="text-sm text-primary-700 underline">Manage</Link>}</div>
          {alerts.length ? <ul className="space-y-1 text-sm">{alerts.map(budget => <li key={budget.budget_id} className="flex justify-between border-b border-gray-100 py-1"><span>{budget.name}</span><span className={budget.percent >= 100 ? 'text-red-700 font-semibold' : 'text-amber-700'}>{budget.percent.toFixed(1)}% used</span></li>)}</ul> : <p className="text-sm text-gray-500 py-2">No allowance is above 80%.</p>}
        </div>
        <div className={card}>
          <div className="mb-2 flex items-center justify-between"><strong className="text-gray-900">Top models (30 days)</strong><Link href="/ai/usage" className="text-sm text-primary-700 underline">Usage</Link></div>
          {recent.top_models.length ? <table className="w-full text-sm"><tbody>{recent.top_models.slice(0, 5).map(model => <tr key={model.model} className="border-b border-gray-100"><td className="py-1">{model.model}</td><td className="py-1 text-right text-gray-500">{formatTokens(model.requests)} req</td><td className="py-1 text-right">{formatUsd(model.cost_nanos)}</td></tr>)}</tbody></table> : <p className="text-sm text-gray-500 py-2">No AI traffic in the last 30 days.</p>}
        </div>
      </div>
    </>}
  </AiPage>
}
