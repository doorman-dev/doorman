'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useAuth } from '@/contexts/AuthContext'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import AiBudgetBar from '@/components/AiBudgetBar'
import { formatTokens, formatUsd, providerLabel, type AiBreakdown, type AiMyUsage, type BudgetStatus } from '@/utils/ai'

export default function AiBudgetUsageCard({ scope, target }: { scope?: 'user' | 'group'; target?: string }) {
  const { permissions } = useAuth()
  const canView = !scope || !!permissions?.view_analytics
  const canManage = !!permissions?.manage_ai
  const [budgets, setBudgets] = useState<BudgetStatus[]>([])
  const [usage, setUsage] = useState<{ requests: number; cost_nanos: number; input_tokens: number; output_tokens: number } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const load = useCallback(async () => {
    if (!canView) return
    setLoading(true); setError(null); setUsage(null)
    try {
      if (!scope) {
        const result = await getJson<AiMyUsage>(`${SERVER_URL}/platform/ai/usage/me`)
        setUsage(result.usage); setBudgets(result.budgets)
      } else {
        const end = new Date().toISOString().slice(0, 10)
        const query = new URLSearchParams({ start: `${end.slice(0, 7)}-01`, end, dimension: scope, limit: '500' })
        query.set(scope === 'user' ? 'username' : 'group', target || '')
        const [breakdown, status] = await Promise.all([
          getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?${query}`),
          getJson<{ budgets: BudgetStatus[] }>(`${SERVER_URL}/platform/ai/budgets/status?${new URLSearchParams({ scope, target: target || '' })}`),
        ])
        const row = breakdown.rows.find(item => item.key === target)
        setUsage(row || { requests: 0, cost_nanos: 0, input_tokens: 0, output_tokens: 0 })
        setBudgets(status.budgets)
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load AI usage') }
    finally { setLoading(false) }
  }, [canView, scope, target])
  useEffect(() => { load() }, [load])
  if (!canView && !canManage) return null
  return <section className="card p-6 space-y-4">
    <div className="flex justify-between flex-wrap gap-3"><h3 className="card-title">{scope === 'group' ? 'AI budget and usage' : 'AI usage'}</h3>{scope && canManage && <Link className="btn btn-secondary" href={`/credits?${new URLSearchParams({ budget_scope: scope, budget_target: target || '' })}#ai-budgets`}>{scope === 'group' ? 'Add group budget' : 'Create user budget'}</Link>}</div>
    {canView && <>
      {loading ? <p className="text-sm">Loading AI usage…</p> : error ? <div role="alert"><p className="text-sm text-red-600">{error}</p><button type="button" className="btn btn-ghost" onClick={load}>Retry</button></div> : <>
        {usage && <p className="text-sm">This UTC month: {formatTokens(usage.requests)} requests · {formatTokens(usage.input_tokens + usage.output_tokens)} input/output tokens · {formatUsd(usage.cost_nanos)}</p>}
        {budgets.length ? <div className="space-y-4">{budgets.map(budget => <div key={budget.budget_id} className="space-y-1"><div className="flex justify-between gap-3 text-sm"><span>{budget.name}{budget.provider ? ` · ${providerLabel(budget.provider)}` : ''} · {budget.period} · {budget.action}</span><span>{budget.percent}%</span></div><AiBudgetBar percent={budget.percent} label={`${budget.name} usage`} /><p className="text-xs text-gray-500">{budget.limit_type === 'cost' ? formatUsd(budget.used) : formatTokens(budget.used)} / {budget.limit_type === 'cost' ? formatUsd(budget.limit_value) : `${formatTokens(budget.limit_value)} tokens`} · Resets {new Date(budget.resets_at).toLocaleString()}</p></div>)}</div> : <p className="text-sm text-gray-500">No applicable budgets.</p>}
        <button type="button" className="btn btn-ghost" onClick={load}>Refresh AI usage</button>
      </>}
      <p className="text-xs text-gray-500">Budget bars show their current UTC period. Concurrent requests can exceed soft limits.{scope === 'group' ? ' A member’s usage contributes to every group in their request snapshot.' : ''}</p>
    </>}
  </section>
}
