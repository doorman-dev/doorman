'use client'

import { useCallback, useEffect, useState } from 'react'
import Layout from '@/components/Layout'
import AiKeysPanel from '@/components/AiKeysPanel'
import AiBudgetBar from '@/components/AiBudgetBar'
import { SignalCopyButton, SignalPageHeader } from '@/components/signal/Signal'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { aiSdkBaseUrl, formatTokens, formatUsd, providerLabel, type AiMyApi, type AiMyUsage, type BudgetStatus } from '@/utils/ai'
import { aiSnippets } from '@/utils/aiSnippets'

const amount = (budget: BudgetStatus, value: number) => budget.limit_type === 'cost' ? formatUsd(value) : `${formatTokens(value)} tokens`
const periodLabel: Record<string, string> = { day: 'today', week: 'this week', month: 'this month' }
const appliesTo = (budget: BudgetStatus) => {
  const where = budget.scope === 'global' ? 'Company-wide' : budget.scope === 'group' ? `Group ${budget.target}` : budget.scope === 'tier' ? `Tier ${budget.target}` : budget.scope === 'api' ? budget.target : 'Just for you'
  return budget.scope === 'user' ? where : `${where} · ${budget.per_user ? 'your own allowance' : 'shared pool'}`
}

function Allowance({ budget }: { budget: BudgetStatus }) {
  const left = Math.max(0, budget.limit_value - budget.used)
  return <div className="space-y-1">
    <div className="flex justify-between gap-3 text-sm"><span className="font-medium">{budget.provider ? providerLabel(budget.provider) : 'All AI providers'}<span className="font-normal text-gray-500"> · {appliesTo(budget)}</span></span><span>{amount(budget, budget.used)} of {amount(budget, budget.limit_value)} {periodLabel[budget.period] || ''}</span></div>
    <AiBudgetBar percent={budget.percent} label={`${budget.name} usage`} />
    <p className="text-xs text-gray-500">{budget.percent >= 100 ? (budget.action === 'block' ? 'Limit reached: requests are blocked until ' : budget.action === 'downgrade' ? 'Limit reached: requests use a smaller model until ' : 'Over the limit; your admin is notified. Resets ') : `${amount(budget, left)} left · resets `}{new Date(budget.resets_at).toLocaleDateString()}</p>
  </div>
}

function ApiCard({ api }: { api: AiMyApi }) {
  const baseUrl = aiSdkBaseUrl(SERVER_URL, api.api_name, api.api_version, api.sdk_base_url_suffix)
  const model = api.default_model || api.models[0] || 'YOUR_ALLOWED_MODEL'
  const snippets = aiSnippets(api.provider, baseUrl, model)
  const [tab, setTab] = useState(snippets[0].id)
  const active = snippets.find(snippet => snippet.id === tab) || snippets[0]
  return <section className="card p-6 space-y-4">
    <div className="flex flex-wrap justify-between gap-3"><div><h3 className="card-title">{providerLabel(api.provider)}</h3><p className="text-sm text-gray-500 font-mono">{api.api_name}/{api.api_version}</p></div></div>
    <div className="text-sm space-y-1"><p className="font-medium">Base URL</p><div className="flex items-center gap-2"><code className="break-all bg-gray-50 px-2 py-1 rounded">{baseUrl}</code><SignalCopyButton text={baseUrl} label="Copy" /></div></div>
    <div className="text-sm"><p className="font-medium">Models you can use</p><p className="font-mono text-xs mt-1">{api.model_patterns.join(', ')}</p>{api.models.length > 0 && <p className="text-xs text-gray-500 mt-1">For example: {api.models.slice(0, 6).join(', ')}</p>}</div>
    <div>
      <div role="tablist" aria-label={`${providerLabel(api.provider)} setup`} className="flex flex-wrap gap-1 border-b border-gray-200">{snippets.map(snippet => <button key={snippet.id} type="button" role="tab" aria-selected={snippet.id === active.id} onClick={() => setTab(snippet.id)} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${snippet.id === active.id ? 'border-primary-600 text-primary-700' : 'border-transparent text-gray-600'}`}>{snippet.label}</button>)}</div>
      <div className="relative mt-2"><pre className="bg-gray-900 text-gray-100 text-xs p-4 rounded overflow-x-auto"><code>{active.code}</code></pre><div className="absolute top-2 right-2"><SignalCopyButton text={active.code} label="Copy" /></div></div>
      <p className="text-xs text-gray-500 mt-1">Set <code>DOORMAN_AI_KEY</code> (or replace <code>dk_your_key_here</code>) with your access key from above. Never use a provider key directly.</p>
    </div>
  </section>
}

export default function MyAiPage() {
  const [data, setData] = useState<AiMyUsage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const load = useCallback(() => {
    getJson<AiMyUsage>(`${SERVER_URL}/platform/ai/usage/me`).then(result => { setData(result); setError(null) }).catch(reason => setError(reason instanceof Error ? reason.message : 'Unable to load your AI access'))
  }, [])
  useEffect(() => { load() }, [load])
  const apis = data?.apis || []
  return <Layout>
    <div className="space-y-6">
      <SignalPageHeader kicker="AI access" title="My AI" description="Your AI allowances, your access key, and how to connect your tools." actions={<button type="button" className="btn btn-secondary" onClick={load}>Refresh</button>} />
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <section className="card p-6 space-y-4">
        <h3 className="card-title">Get started in 3 steps</h3>
        <ol className="list-decimal ml-5 text-sm space-y-1">
          <li>Create an access key below and store it somewhere safe. It is shown once.</li>
          <li>Pick a provider below and copy its setup into your tool or code.</li>
          <li>Use AI as usual. Usage counts toward your allowance, shown here.</li>
        </ol>
      </section>
      <section className="card p-6 space-y-4">
        <h3 className="card-title">Allowances</h3>
        {!data ? <p className="text-sm">Loading…</p> : <>
          <p className="text-sm">This month: {formatTokens(data.usage.requests)} requests · {formatUsd(data.usage.cost_nanos)}</p>
          {data.budgets.length ? <div className="space-y-4">{data.budgets.map(budget => <Allowance key={budget.budget_id} budget={budget} />)}</div> : <p className="text-sm text-gray-500">No limits are set for you.</p>}
        </>}
      </section>
      <AiKeysPanel showUsage={false} />
      <div className="space-y-4">
        <h2 className="text-lg font-semibold">Connect your tools</h2>
        {data && !apis.length && <p className="card p-6 text-sm text-gray-600">You don&apos;t have access to any AI providers yet. Ask your administrator to add you.</p>}
        {apis.map(api => <ApiCard key={`${api.api_name}/${api.api_version}`} api={api} />)}
      </div>
    </div>
  </Layout>
}
