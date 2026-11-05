'use client'

import { useCallback, useEffect, useState } from 'react'
import AiPage from '@/components/AiPage'
import AiKeysPanel from '@/components/AiKeysPanel'
import AiBudgetBar from '@/components/AiBudgetBar'
import { SignalCopyButton } from '@/components/signal/Signal'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { aiSdkBaseUrl, formatBudgetAmount, formatTokens, formatUsd, providerLabel, type AiMyApi, type AiMyUsage, type BudgetStatus } from '@/utils/ai'
import { aiSnippets } from '@/utils/aiSnippets'

const amount = (budget: BudgetStatus, value: number) => formatBudgetAmount(budget.limit_type, value)
const periodLabel: Record<string, string> = { minute: 'per minute', hour: 'per hour', day: 'today', week: 'this week', month: 'this month' }

function Allowance({ budget }: { budget: BudgetStatus }) {
  const left = Math.max(0, budget.limit_value - budget.used)
  const over = budget.percent >= 100
  return <div className="space-y-1.5">
    <div className="flex justify-between gap-3 text-sm"><span className="font-medium">{budget.provider ? providerLabel(budget.provider) : 'All providers'}</span><span className="text-gray-600 tabular-nums">{amount(budget, budget.used)} of {amount(budget, budget.limit_value)} {periodLabel[budget.period] || ''}</span></div>
    <AiBudgetBar percent={budget.percent} label={`${budget.name} usage`} />
    <p className={`text-xs ${over ? 'text-red-700' : 'text-gray-500'}`}>{over ? (budget.action === 'block' ? 'Limit reached. Requests are blocked until ' : 'Over the limit. Resets ') : `${amount(budget, left)} left, resets `}{new Date(budget.resets_at).toLocaleDateString()}</p>
  </div>
}

function Connect({ apis }: { apis: AiMyApi[] }) {
  const [selected, setSelected] = useState(0)
  const api = apis[Math.min(selected, apis.length - 1)]
  const baseUrl = aiSdkBaseUrl(SERVER_URL, api.api_name, api.api_version, api.sdk_base_url_suffix)
  const model = api.default_model || api.models[0] || 'YOUR_ALLOWED_MODEL'
  const snippets = aiSnippets(api.provider, baseUrl, model)
  const [tab, setTab] = useState(snippets[0].id)
  const active = snippets.find(snippet => snippet.id === tab) || snippets[0]
  return <section className="card p-6 space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="card-title">Connect a tool</h2>
      {apis.length > 1 && <label className="text-sm flex items-center gap-2">Provider
        <select id="my-ai-provider" className="input w-auto" value={selected} onChange={event => { setSelected(Number(event.target.value)); setTab('') }}>
          {apis.map((item, index) => <option key={`${item.api_name}/${item.api_version}`} value={index}>{providerLabel(item.provider)} ({item.api_name})</option>)}
        </select>
      </label>}
    </div>
    <dl className="grid gap-3 text-sm sm:grid-cols-[8rem_minmax(0,1fr)]">
      <dt className="text-gray-500">Base URL</dt>
      <dd className="flex min-w-0 items-center gap-2"><code className="min-w-0 break-all">{baseUrl}</code><SignalCopyButton text={baseUrl} label="Copy" /></dd>
      <dt className="text-gray-500">Models</dt>
      <dd className="min-w-0 break-words">{(api.models.length ? api.models : api.model_patterns).join(', ')}</dd>
    </dl>
    <div>
      <div role="tablist" aria-label="Setup instructions" className="flex flex-wrap gap-1 border-b border-gray-200">{snippets.map(snippet => <button key={snippet.id} type="button" role="tab" aria-selected={snippet.id === active.id} onClick={() => setTab(snippet.id)} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${snippet.id === active.id ? 'border-primary-600 text-primary-700 font-medium' : 'border-transparent text-gray-600 hover:text-gray-900'}`}>{snippet.label}</button>)}</div>
      <div className="relative mt-3"><pre className="bg-gray-900 text-gray-100 text-xs p-4 pr-20 rounded overflow-x-auto"><code>{active.code}</code></pre><div className="absolute top-2 right-2"><SignalCopyButton text={active.code} label="Copy" /></div></div>
      <p className="text-xs text-gray-500 mt-2">Replace <code>dk_your_key_here</code> with your access key.</p>
    </div>
  </section>
}

export default function MyAiPage() {
  const [data, setData] = useState<AiMyUsage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const load = useCallback(() => {
    getJson<AiMyUsage>(`${SERVER_URL}/platform/ai/usage/me`).then(result => { setData(result); setError(null) }).catch(reason => setError(reason instanceof Error ? reason.message : 'Could not load your AI access'))
  }, [])
  useEffect(() => { load() }, [load])
  const apis = data?.apis || []
  return <AiPage title="My AI" description="Your allowance, your access key and how to connect your tools.">
    {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
    <section className="card p-6 space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="card-title">This month</h2>
        {data && <p className="text-sm text-gray-600 tabular-nums">{formatTokens(data.usage.requests)} requests · {formatUsd(data.usage.cost_nanos)}</p>}
      </div>
      {!data ? <p className="text-sm text-gray-500">Loading…</p> : data.budgets.length ? <div className={data.budgets.length > 1 ? 'grid gap-5 md:grid-cols-2' : 'space-y-5'}>{data.budgets.map(budget => <Allowance key={budget.budget_id} budget={budget} />)}</div> : <p className="text-sm text-gray-500">No limits are set for you.</p>}
    </section>
    <AiKeysPanel showUsage={false} />
    {data && (apis.length ? <Connect apis={apis} /> : <p className="card p-6 text-sm text-gray-600">You don&apos;t have access to any AI providers yet. Ask your administrator to add you.</p>)}
  </AiPage>
}
