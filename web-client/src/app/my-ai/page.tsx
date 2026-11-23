'use client'

import { useCallback, useEffect, useState } from 'react'
import AiPage from '@/components/AiPage'
import AiKeysPanel from '@/components/AiKeysPanel'
import AiBudgetBar from '@/components/AiBudgetBar'
import AiTabs from '@/components/AiTabs'
import { SignalCopyButton } from '@/components/signal/Signal'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { aiSdkBaseUrl, aiUnifiedBaseUrl, formatBudgetAmount, formatTokens, formatUsd, providerLabel, type AiMyApi, type AiMyUsage, type BudgetStatus } from '@/utils/ai'
import { aiSnippets, aiUnifiedSnippets } from '@/utils/aiSnippets'

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
  const model = api.default_model || api.models.find(model => !model.endsWith('*')) || 'YOUR_ALLOWED_MODEL'
  const snippets = aiSnippets(api.provider, baseUrl, model, undefined, api.models)
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
      <div className="relative mt-3"><pre className="bg-gray-50 border border-gray-200 text-gray-800 text-xs p-4 pr-20 rounded-lg overflow-x-auto"><code>{active.code}</code></pre><div className="absolute top-2 right-2"><SignalCopyButton text={active.code} label="Copy" /></div></div>
      {(active.id === 'boto3' || active.id === 'aws-js') && <p className="text-xs text-gray-500 mt-2">The AWS SDKs need Doorman&apos;s HTTPS address. They refuse to send the key over plain HTTP.</p>}
      <p className="text-xs text-gray-500 mt-2">Replace <code>dk_your_key_here</code> or set <code>DOORMAN_AI_KEY</code> to your access key. Enter a concrete allowed model where the example uses a model placeholder.</p>
    </div>
  </section>
}

function AnyModel({ unified }: { unified: NonNullable<AiMyUsage['unified']> }) {
  const [selection, setSelection] = useState('')
  const [tab, setTab] = useState('python')
  const baseUrl = aiUnifiedBaseUrl(SERVER_URL, unified.base_url_suffix)
  const model = unified.models.find(name => name === selection) || unified.models[0] || 'YOUR_ALLOWED_MODEL'
  const snippets = aiUnifiedSnippets(baseUrl, model)
  const active = snippets.find(snippet => snippet.id === tab) || snippets[0]
  return <section className="card min-w-0 space-y-4 p-5 sm:p-6">
    <div className="space-y-1">
      <h2 className="card-title">Any model</h2>
      <p className="text-sm text-gray-500">Use a <code>dk_</code> key from Access keys and choose any model available to you.</p>
    </div>
    <dl className="grid gap-3 text-sm sm:grid-cols-[8rem_minmax(0,1fr)]">
      <dt className="text-gray-500">Base URL</dt>
      <dd className="flex min-w-0 flex-wrap items-center gap-2">
        <code className="min-w-0 break-all">{baseUrl}</code><SignalCopyButton text={baseUrl} label="Copy base URL" />
      </dd>
      <dt className="text-gray-500">Models</dt>
      <dd className="flex min-w-0 flex-wrap gap-2">
        {unified.models.map(name => <button key={name} type="button" aria-pressed={name === model} onClick={() => setSelection(name)}
          className={`ai-chip max-w-full break-all px-2.5 py-1.5 text-left focus-visible:outline focus-visible:outline-2 ${name === model ? 'ai-chip--ok' : 'ai-chip--off'}`}>
          {name}
        </button>)}
        {!unified.models.length && <span className="text-gray-500">Enter a concrete model allowed by your administrator.</span>}
      </dd>
    </dl>
    <div className="space-y-3">
      <AiTabs tabs={snippets} value={active.id} onChange={setTab} label="Unified endpoint examples" />
      <div className="relative min-w-0">
        <pre className="overflow-x-auto rounded-lg border border-gray-200 bg-gray-50 p-4 pt-12 text-xs text-gray-800 sm:pr-32 sm:pt-4"><code>{active.code}</code></pre>
        <div className="absolute right-2 top-2"><SignalCopyButton text={active.code} label="Copy example" /></div>
      </div>
      <p className="text-xs text-gray-500">Set <code>DOORMAN_AI_KEY</code> to your access key before running an example.</p>
    </div>
    <div className="space-y-1 border-t border-[var(--border)] pt-4">
      <h3 className="text-sm font-medium">OpenAI-compatible tools</h3>
      <p className="text-sm text-gray-500">In Open WebUI or LibreChat, add an OpenAI-compatible connection. In Continue, set <code>apiBase</code> for the OpenAI provider. In Cursor, use Override OpenAI Base URL and select your model. Use Chat Completions where the tool offers a choice.</p>
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
  return <AiPage title="My AI" description="Your allowance, your access key and how to connect your tools." className="pt-8 lg:pt-0">
    {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
    <section className="card p-6 space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="card-title">This month</h2>
        {data && <p className="text-sm text-gray-600 tabular-nums">{formatTokens(data.usage.requests)} requests · {formatUsd(data.usage.cost_nanos)}</p>}
      </div>
      {!data ? <p className="text-sm text-gray-500">Loading…</p> : data.budgets.length ? <div className={data.budgets.length > 1 ? 'grid gap-5 md:grid-cols-2' : 'space-y-5'}>{data.budgets.map(budget => <Allowance key={budget.budget_id} budget={budget} />)}</div> : <p className="text-sm text-gray-500">No limits are set for you.</p>}
    </section>
    <AiKeysPanel showUsage={false} />
    {data?.unified?.enabled && <AnyModel unified={data.unified} />}
    {data && (apis.length ? <Connect apis={apis} /> : <p className="card p-6 text-sm text-gray-600">You don&apos;t have access to any AI providers yet. Ask your administrator to add you.</p>)}
  </AiPage>
}
