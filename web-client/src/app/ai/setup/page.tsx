'use client'

import Link from 'next/link'
import { useEffect, useMemo, useState } from 'react'
import Layout from '@/components/Layout'
import { SignalCopyButton, SignalPageHeader } from '@/components/signal/Signal'
import { useAuth } from '@/contexts/AuthContext'
import { useAiProviders } from '@/hooks/useAiProviders'
import { fetchAllPaginated, getJson, postJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { providerLabel, type AiPricingRow, type AiProvider } from '@/utils/ai'

type Plan = 'pool' | 'each' | 'group' | 'tier' | 'none'
type ProviderDraft = { enabled: boolean; key: string; name: string; models: string; server: string }
type Price = { input: string; output: string }

const ORDER: AiProvider[] = ['openai', 'anthropic', 'gemini', 'azure_openai', 'openai_compatible']
const DEFAULTS: Record<AiProvider, { name: string; models: string }> = {
  openai: { name: 'openai', models: 'gpt-*' },
  anthropic: { name: 'claude', models: 'claude-*' },
  gemini: { name: 'gemini', models: 'gemini-*' },
  azure_openai: { name: 'azure-openai', models: '' },
  openai_compatible: { name: 'local-llm', models: '' },
}
const PLANS: [Plan, string, string][] = [
  ['each', 'Same allowance for every employee', 'e.g. everyone gets $50/month of OpenAI and $30/month of Claude.'],
  ['pool', 'One shared company pool', 'e.g. the whole company shares $2,000/month of OpenAI.'],
  ['group', 'Different allowance per group', 'e.g. Engineering gets $100 each, Sales $20 each.'],
  ['tier', 'Different allowance per tier', 'Uses your existing user tiers, e.g. Pro vs Standard.'],
  ['none', 'No limits (track usage only)', 'You can add budgets later in Credits → AI Budgets.'],
]
const STEPS = ['Providers', 'Who gets access', 'Allowances', 'Review']
const listOf = (text: string) => text.split(/[\n,]/).map(value => value.trim()).filter(Boolean)

export default function AiSetupPage() {
  const { permissions } = useAuth()
  const { providers: presets } = useAiProviders()
  const [step, setStep] = useState(0)
  const [drafts, setDrafts] = useState<Record<AiProvider, ProviderDraft>>(() => Object.fromEntries(ORDER.map(id => [id, { enabled: id === 'openai' || id === 'anthropic', key: '', name: DEFAULTS[id].name, models: DEFAULTS[id].models, server: '' }])) as Record<AiProvider, ProviderDraft>)
  const [everyone, setEveryone] = useState(true)
  const [groups, setGroups] = useState<string[]>([])
  const [allGroups, setAllGroups] = useState<string[]>([])
  const [allTiers, setAllTiers] = useState<{ tier_id: string; name?: string }[]>([])
  const [existingApis, setExistingApis] = useState<string[]>([])
  const [existingCreds, setExistingCreds] = useState<string[]>([])
  const [pricing, setPricing] = useState<AiPricingRow[]>([])
  const [plan, setPlan] = useState<Plan>('each')
  const [unit, setUnit] = useState<'cost' | 'tokens'>('cost')
  const [action, setAction] = useState<'block' | 'warn'>('block')
  const [amounts, setAmounts] = useState<Record<string, string>>({})
  const [targets, setTargets] = useState<string[]>([])
  const [prices, setPrices] = useState<Record<string, Price>>({})
  const [running, setRunning] = useState(false)
  const [log, setLog] = useState<{ text: string; ok: boolean }[]>([])
  const [done, setDone] = useState(false)

  useEffect(() => {
    fetchAllPaginated<{ group_name: string }>((page, size) => `${SERVER_URL}/platform/group/all?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data.groups || [])
      .then(rows => setAllGroups(rows.map(row => row.group_name).filter(name => name && name !== 'ALL'))).catch(() => {})
    getJson<{ tiers?: { tier_id: string; name?: string }[] } | { tier_id: string; name?: string }[]>(`${SERVER_URL}/platform/tiers/?page=1&page_size=500`)
      .then(result => setAllTiers(Array.isArray(result) ? result : result.tiers || [])).catch(() => {})
    fetchAllPaginated<{ api_name: string; api_version: string }>((page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data.apis || [])
      .then(rows => setExistingApis(rows.map(row => `${row.api_name}/${row.api_version}`))).catch(() => {})
    fetchAllPaginated<{ api_credit_group: string }>((page, size) => `${SERVER_URL}/platform/credit/defs?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data?.items || data?.response?.items || [])
      .then(rows => setExistingCreds(rows.map(row => row.api_credit_group))).catch(() => {})
    getJson<{ pricing: AiPricingRow[] }>(`${SERVER_URL}/platform/ai/pricing`).then(result => setPricing(result.pricing)).catch(() => {})
  }, [])

  const chosen = ORDER.filter(id => drafts[id].enabled)
  const preset = (id: AiProvider) => presets.find(item => item.id === id)
  const needsServer = (id: AiProvider) => !preset(id)?.default_server
  const unpriced = unit === 'cost' && plan !== 'none' ? chosen.filter(id => !pricing.some(row => row.provider === id)) : []
  const rows: string[] = plan === 'group' || plan === 'tier' ? targets : plan === 'none' ? [] : ['']
  const amountKey = (target: string, provider: AiProvider) => `${target}|${provider}`
  const update = (id: AiProvider, patch: Partial<ProviderDraft>) => setDrafts(current => ({ ...current, [id]: { ...current[id], ...patch } }))

  const providerErrors = useMemo(() => {
    const errors: Record<string, string> = {}
    for (const id of chosen) {
      const draft = drafts[id]
      if (!draft.key.trim()) errors[id] = 'Paste the provider API key.'
      else if (!/^[a-z0-9][a-z0-9-]*$/.test(draft.name)) errors[id] = 'Name: lowercase letters, digits and dashes.'
      else if (existingApis.includes(`${draft.name}/v1`)) errors[id] = `An API named ${draft.name}/v1 already exists. Choose another name.`
      else if (existingCreds.includes(`${draft.name}-key`)) errors[id] = `A credential named ${draft.name}-key already exists. Choose another name.`
      else if (!listOf(draft.models).length) errors[id] = 'List at least one model (use a trailing * for a family, e.g. gpt-*).'
      else if (needsServer(id) && !/^https?:\/\//.test(draft.server.trim())) errors[id] = 'Enter the provider endpoint URL.'
    }
    return errors
  }, [chosen, drafts, existingApis, existingCreds]) // eslint-disable-line react-hooks/exhaustive-deps

  const stepError = (): string | null => {
    if (step === 0) return !chosen.length ? 'Choose at least one provider.' : Object.keys(providerErrors).length ? 'Fix the highlighted providers.' : null
    if (step === 1) return !everyone && !groups.length ? 'Choose at least one group, or give everyone access.' : null
    if (step === 2) {
      if ((plan === 'group' || plan === 'tier') && !targets.length) return `Choose at least one ${plan}.`
      if (plan !== 'none' && !rows.some(target => chosen.some(id => Number(amounts[amountKey(target, id)]) > 0))) return 'Enter at least one allowance amount.'
      for (const target of rows) for (const id of chosen) {
        const value = amounts[amountKey(target, id)]
        if (value && !(Number(value) > 0)) return 'Allowance amounts must be positive numbers.'
      }
      for (const id of unpriced) { const price = prices[id]; if (!(Number(price?.input) >= 0 && Number(price?.output) >= 0 && price?.input && price?.output)) return `Enter ${providerLabel(id)} prices so dollar allowances can be charged.` }
    }
    return null
  }

  const budgetDocs = () => rows.flatMap(target => chosen.flatMap(id => {
    const value = Number(amounts[amountKey(target, id)])
    if (!(value > 0)) return []
    const scope = plan === 'pool' || plan === 'each' ? 'global' : plan
    const who = plan === 'pool' ? 'company pool' : plan === 'each' ? 'per employee' : `${target}, per member`
    return [{ name: `${providerLabel(id)} · ${who}`, scope, target: scope === 'global' ? '' : target, period: 'month', limit_type: unit, limit_value: unit === 'cost' ? Math.round(value * 1e9) : Math.round(value), action, warn_at_percent: 80, enabled: true, provider: id, per_user: plan !== 'pool' }]
  }))

  const run = async () => {
    setRunning(true); setLog([])
    const note = (text: string, ok = true) => setLog(current => [...current, { text, ok }])
    try {
      for (const id of chosen) {
        const draft = drafts[id]
        const credential = `${draft.name}-key`
        await postJson(`${SERVER_URL}/platform/credit`, { api_credit_group: credential, api_key: draft.key.trim(), api_key_header: preset(id)?.credential_header || 'authorization', credit_tiers: [] })
        note(`Stored the ${providerLabel(id)} key (encrypted) as ${credential}`)
        await postJson(`${SERVER_URL}/platform/api`, {
          api_name: draft.name, api_version: 'v1', api_type: 'AI', api_ai_provider: id,
          api_description: `${providerLabel(id)} for employees (created by AI setup)`,
          api_servers: [needsServer(id) ? draft.server.trim() : preset(id)?.default_server],
          api_allowed_groups: everyone ? ['ALL'] : groups, api_allowed_roles: [],
          api_ai_config: { credential_group: credential, allowed_models: listOf(draft.models), require_subscription: false },
        })
        note(`Created AI API ${draft.name}/v1 for ${everyone ? 'everyone' : groups.join(', ')}`)
      }
      if (unpriced.length) {
        const today = new Date().toISOString().slice(0, 10)
        const added = unpriced.flatMap(id => listOf(drafts[id].models).map(pattern => ({ provider: id, model_pattern: pattern, input_usd_per_mtok: Number(prices[id].input), output_usd_per_mtok: Number(prices[id].output), cache_read_usd_per_mtok: null, cache_write_usd_per_mtok: null, effective_from: today, note: 'AI setup' })))
        await putJson(`${SERVER_URL}/platform/ai/pricing`, { pricing: [...pricing, ...added] })
        note(`Added prices for ${unpriced.map(providerLabel).join(', ')}`)
      }
      for (const budget of budgetDocs()) {
        await postJson(`${SERVER_URL}/platform/ai/budgets`, budget)
        note(`Created allowance “${budget.name}”`)
      }
      setDone(true)
    } catch (reason) {
      note(reason instanceof Error ? reason.message : 'Setup step failed', false)
      note('Setup stopped. Everything above this line was created; fix the problem and finish in APIs or Credits.', false)
    } finally { setRunning(false) }
  }

  const missing = (['manage_apis', 'manage_credits', 'manage_ai'] as const).filter(permission => !permissions?.[permission])
  const shareText = `You now have AI access through Doorman. Open ${typeof window === 'undefined' ? '' : window.location.origin}/my-ai to create your personal key and copy the setup for your tools (Claude Code, Python, Node.js and more). Please don't use provider API keys directly.`
  const error = stepError()
  const amountLabel = unit === 'cost' ? 'USD per month' : 'tokens per month'

  return <Layout>
    <div className="space-y-6 max-w-4xl">
      <SignalPageHeader kicker="AI gateway" title="AI setup" description="Give employees access to AI providers with allowances, in four steps." />
      {missing.length > 0 && <p role="alert" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">Your role is missing {missing.join(', ')}. Setup will stop at the first step that needs it.</p>}
      <ol className="flex flex-wrap gap-2 text-sm">{STEPS.map((label, index) => <li key={label} className={`px-3 py-1 rounded-full border ${index === step ? 'border-primary-600 text-primary-700 font-medium' : index < step ? 'border-green-600 text-green-700' : 'border-gray-300 text-gray-500'}`}>{index + 1}. {label}</li>)}</ol>

      {done ? <section className="card p-6 space-y-4">
        <h3 className="card-title">You&apos;re set up</h3>
        <ul className="text-sm space-y-1">{log.map((line, index) => <li key={index}>✓ {line.text}</li>)}</ul>
        <div className="space-y-2"><p className="font-medium text-sm">Tell your employees</p><p className="text-sm bg-gray-50 p-3 rounded">{shareText}</p><SignalCopyButton text={shareText} label="Copy message" /></div>
        <div className="flex flex-wrap gap-2"><Link className="btn btn-primary" href="/my-ai">Open My AI</Link><Link className="btn btn-secondary" href="/ai/allowances">Adjust allowances</Link><Link className="btn btn-secondary" href="/ai/usage">Watch usage</Link></div>
        <p className="text-xs text-gray-500">Individual exceptions: add a “One user” budget in Credits → AI Budgets. Guardrails (PII redaction) are in Security → AI Guardrails.</p>
      </section> : <>
        {step === 0 && <section className="card p-6 space-y-4">
          <div><h3 className="card-title">Which AI providers will you offer?</h3><p className="text-sm text-gray-500">Paste each company API key once. It is encrypted and never shown to employees.</p></div>
          {ORDER.map(id => { const draft = drafts[id]; return <div key={id} className={`rounded border p-4 space-y-3 ${draft.enabled ? 'border-primary-300' : 'border-gray-200'}`}>
            <label className="flex items-center gap-2 font-medium"><input type="checkbox" checked={draft.enabled} onChange={event => update(id, { enabled: event.target.checked })} />{providerLabel(id)}</label>
            {draft.enabled && <div className="grid gap-3 md:grid-cols-2 text-sm">
              <label className="block md:col-span-2">API key<input className="input w-full mt-1" type="password" autoComplete="off" value={draft.key} onChange={event => update(id, { key: event.target.value })} placeholder={id === 'anthropic' ? 'sk-ant-…' : id === 'openai' ? 'sk-…' : 'Provider key'} /></label>
              {needsServer(id) && <label className="block md:col-span-2">Endpoint URL<input className="input w-full mt-1" value={draft.server} onChange={event => update(id, { server: event.target.value })} placeholder={id === 'azure_openai' ? 'https://YOUR-RESOURCE.openai.azure.com' : 'http://llm.internal:8000'} /></label>}
              <label className="block">Allowed models<input className="input w-full mt-1 font-mono" value={draft.models} onChange={event => update(id, { models: event.target.value })} placeholder={id === 'azure_openai' ? 'your-deployment-name' : 'model-*'} /><span className="text-xs text-gray-500">Comma-separated; a trailing * allows a family.</span></label>
              <label className="block">Name in URLs<input className="input w-full mt-1 font-mono" value={draft.name} onChange={event => update(id, { name: event.target.value.toLowerCase() })} /></label>
              {providerErrors[id] && <p className="text-xs text-red-600 md:col-span-2">{providerErrors[id]}</p>}
            </div>}
          </div> })}
        </section>}

        {step === 1 && <section className="card p-6 space-y-4">
          <h3 className="card-title">Who gets access?</h3>
          <label className="flex gap-2 text-sm"><input type="radio" checked={everyone} onChange={() => setEveryone(true)} />Everyone in the company</label>
          <label className="flex gap-2 text-sm"><input type="radio" checked={!everyone} onChange={() => setEveryone(false)} />Only these groups</label>
          {!everyone && (allGroups.length ? <div className="flex flex-wrap gap-2 ml-6">{allGroups.map(group => <label key={group} className="flex gap-1 items-center text-sm border rounded px-2 py-1"><input type="checkbox" checked={groups.includes(group)} onChange={event => setGroups(current => event.target.checked ? [...current, group] : current.filter(g => g !== group))} />{group}</label>)}</div> : <p className="ml-6 text-sm text-gray-500">No groups yet. <Link className="underline" href="/groups">Create groups</Link> first, or give everyone access.</p>)}
          <p className="text-xs text-gray-500">No per-person subscriptions are needed: anyone in these groups, including people who join later, can create a key on My AI.</p>
        </section>}

        {step === 2 && <section className="card p-6 space-y-5">
          <h3 className="card-title">How much can people use?</h3>
          <div className="space-y-2">{PLANS.map(([id, label, hint]) => <label key={id} className={`flex gap-3 rounded border p-3 text-sm cursor-pointer ${plan === id ? 'border-primary-500 bg-primary-50' : 'border-gray-200'}`}><input type="radio" checked={plan === id} onChange={() => { setPlan(id); setTargets([]) }} /><span><span className="font-medium">{label}</span><span className="block text-gray-500">{hint}</span></span></label>)}</div>
          {plan !== 'none' && <>
            <div className="flex flex-wrap gap-6 text-sm">
              <label>Measure in <select className="input ml-1" value={unit} onChange={event => setUnit(event.target.value as 'cost' | 'tokens')}><option value="cost">US dollars</option><option value="tokens">Tokens</option></select></label>
              <label>When someone hits the limit <select className="input ml-1" value={action} onChange={event => setAction(event.target.value as 'block' | 'warn')}><option value="block">Block until next month</option><option value="warn">Allow, but flag it</option></select></label>
            </div>
            {(plan === 'group' || plan === 'tier') && <div className="text-sm"><p className="mb-1">{plan === 'group' ? 'Groups' : 'Tiers'}</p>{(plan === 'group' ? allGroups : allTiers.map(tier => tier.tier_id)).length ? <div className="flex flex-wrap gap-2">{(plan === 'group' ? allGroups : allTiers.map(tier => tier.tier_id)).map(target => <label key={target} className="flex gap-1 items-center border rounded px-2 py-1"><input type="checkbox" checked={targets.includes(target)} onChange={event => setTargets(current => event.target.checked ? [...current, target] : current.filter(t => t !== target))} />{plan === 'tier' ? allTiers.find(tier => tier.tier_id === target)?.name || target : target}</label>)}</div> : <p className="text-gray-500">None yet. <Link className="underline" href={plan === 'group' ? '/groups' : '/tiers'}>Create {plan === 'group' ? 'groups' : 'tiers'}</Link> first.</p>}</div>}
            {rows.length > 0 && <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr>{(plan === 'group' || plan === 'tier') && <th>{plan === 'group' ? 'Group' : 'Tier'}</th>}{chosen.map(id => <th key={id}>{providerLabel(id)} <span className="font-normal text-gray-500">({amountLabel})</span></th>)}</tr></thead><tbody>{rows.map(target => <tr key={target}>{(plan === 'group' || plan === 'tier') && <td>{plan === 'tier' ? allTiers.find(tier => tier.tier_id === target)?.name || target : target}</td>}{chosen.map(id => <td key={id}><input className="input w-32" inputMode="decimal" aria-label={`${providerLabel(id)} ${target || 'allowance'}`} placeholder="No limit" value={amounts[amountKey(target, id)] || ''} onChange={event => setAmounts(current => ({ ...current, [amountKey(target, id)]: event.target.value }))} /></td>)}</tr>)}</tbody></table><p className="text-xs text-gray-500 mt-1">{plan === 'pool' ? 'One total for the whole company, per provider.' : 'Each person gets this amount, per provider. Leave blank for no limit.'} Allowances reset on the 1st of each month (UTC).</p></div>}
            {unpriced.length > 0 && <div className="rounded border border-amber-300 bg-amber-50 p-3 space-y-2 text-sm"><p className="text-amber-900">Dollar allowances need prices. Enter your contract rates (USD per 1M tokens) for providers with no pricing yet:</p>{unpriced.map(id => <div key={id} className="flex flex-wrap gap-3 items-center"><span className="w-32 font-medium">{providerLabel(id)}</span><label>Input<input className="input w-24 ml-1" inputMode="decimal" value={prices[id]?.input || ''} onChange={event => setPrices(current => ({ ...current, [id]: { ...current[id], input: event.target.value } }))} /></label><label>Output<input className="input w-24 ml-1" inputMode="decimal" value={prices[id]?.output || ''} onChange={event => setPrices(current => ({ ...current, [id]: { ...current[id], output: event.target.value } }))} /></label></div>)}<p className="text-xs text-amber-900">Applied to every allowed model pattern for that provider. Refine per model later in Credits → AI Pricing.</p></div>}
          </>}
        </section>}

        {step === 3 && <section className="card p-6 space-y-4">
          <h3 className="card-title">Review</h3>
          <ul className="text-sm list-disc ml-5 space-y-1">
            {chosen.map(id => <li key={id}><strong>{providerLabel(id)}</strong> at <code>/api/ai/{drafts[id].name}/v1</code>, models <code>{listOf(drafts[id].models).join(', ')}</code></li>)}
            <li>Access: {everyone ? 'everyone' : groups.join(', ')}; no per-person subscriptions</li>
            {budgetDocs().map(budget => <li key={budget.name}>{budget.name}: {unit === 'cost' ? `$${(budget.limit_value / 1e9).toFixed(2)}` : `${budget.limit_value.toLocaleString()} tokens`} / month, {action === 'block' ? 'blocks' : 'warns'} at the limit</li>)}
            {plan === 'none' && <li>No allowances; usage is tracked in Analytics → AI Usage</li>}
            {unpriced.map(id => <li key={id}>Prices for {providerLabel(id)}: ${prices[id].input} in / ${prices[id].output} out per 1M tokens</li>)}
          </ul>
          {log.length > 0 && <ul className="text-sm space-y-1">{log.map((line, index) => <li key={index} className={line.ok ? '' : 'text-red-600'}>{line.ok ? '✓' : '✗'} {line.text}</li>)}</ul>}
          <button type="button" className="btn btn-primary" disabled={running || log.length > 0} onClick={run}>{running ? 'Setting up…' : 'Create everything'}</button>
        </section>}

        {step < 3 && <div className="flex items-center gap-3">
          {step > 0 && <button type="button" className="btn btn-secondary" onClick={() => setStep(step - 1)}>Back</button>}
          <button type="button" className="btn btn-primary" disabled={!!error} onClick={() => setStep(step + 1)}>Continue</button>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>}
        {step === 3 && !running && log.length === 0 && <button type="button" className="btn btn-secondary" onClick={() => setStep(2)}>Back</button>}
      </>}
    </div>
  </Layout>
}
