'use client'

import { useEffect, useState } from 'react'
import InfoTooltip from '@/components/InfoTooltip'
import { SignalCopyButton } from '@/components/signal/Signal'
import { useAiProviders } from '@/hooks/useAiProviders'
import { getJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { aiSdkBaseUrl, aiValidationErrors, defaultAiConfig, formatTokens, formatUsd, type AiApiConfig, type AiBreakdown, type AiLogLevel, type AiProvider, type AiUsageRow } from '@/utils/ai'

export function AiModelFields({ value, onChange, disabled = false, errors = {} }: {
  value: AiApiConfig; onChange: (value: AiApiConfig) => void; disabled?: boolean; errors?: Record<string, string>
}) {
  const [model, setModel] = useState('')
  const [alias, setAlias] = useState('')
  const [target, setTarget] = useState('')
  const update = (patch: Partial<AiApiConfig>) => onChange({ ...value, ...patch })
  const addModels = () => {
    const models = model.split(/[\s,]+/).filter(Boolean)
    update({ allowed_models: [...new Set([...value.allowed_models, ...models])] })
    setModel('')
  }
  return <div className="space-y-4">
    <div>
      <label htmlFor="ai-models" className="block text-sm font-medium mb-1">Allowed models *</label>
      <div className="flex gap-2"><input id="ai-models" className="input flex-1" placeholder="Model IDs or trailing-* prefixes" value={model} onChange={e => setModel(e.target.value)} disabled={disabled} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addModels() } }} /><button type="button" className="btn btn-secondary" disabled={disabled || !model.trim()} onClick={addModels}>Add</button></div>
      <div className="flex flex-wrap gap-2 mt-2">{value.allowed_models.map(id => <span key={id} className="badge badge-secondary">{id}<button type="button" className="ml-2" aria-label={`Remove model ${id}`} disabled={disabled} onClick={() => update({ allowed_models: value.allowed_models.filter(item => item !== id) })}>×</button></span>)}</div>
      {errors['api_ai_config.allowed_models'] && <p className="text-sm text-red-600" role="alert">{errors['api_ai_config.allowed_models']}</p>}
    </div>
    <div>
      <p className="text-sm font-medium mb-1">Model aliases</p>
      {Object.entries(value.model_aliases).map(([name, id]) => <div key={name} className="flex gap-2 items-center mb-2"><code className="w-1/3 break-all">{name}</code><input aria-label={`Target for ${name}`} className="input flex-1" value={id} disabled={disabled} onChange={e => update({ model_aliases: { ...value.model_aliases, [name]: e.target.value } })} /><button type="button" className="btn btn-ghost" aria-label={`Remove alias ${name}`} disabled={disabled} onClick={() => { const aliases = { ...value.model_aliases }; delete aliases[name]; update({ model_aliases: aliases }) }}>Remove</button></div>)}
      <div className="flex gap-2"><input aria-label="New alias" placeholder="Alias, e.g. fast" className="input w-1/3" value={alias} onChange={e => setAlias(e.target.value)} disabled={disabled} /><input aria-label="Alias model" placeholder="Allowed model ID" className="input flex-1" value={target} onChange={e => setTarget(e.target.value)} disabled={disabled} /><button type="button" className="btn btn-secondary" disabled={disabled || !alias.trim() || !target.trim()} onClick={() => { update({ model_aliases: { ...value.model_aliases, [alias.trim()]: target.trim() } }); setAlias(''); setTarget('') }}>Add alias</button></div>
      {errors['api_ai_config.model_aliases'] && <p className="text-sm text-red-600" role="alert">{errors['api_ai_config.model_aliases']}</p>}
    </div>
    <div className="grid sm:grid-cols-2 gap-4">
      <label className="text-sm">Default model<input className="input mt-1" value={value.default_model || ''} disabled={disabled} onChange={e => update({ default_model: e.target.value || null })} />{errors['api_ai_config.default_model'] && <span className="text-red-600">{errors['api_ai_config.default_model']}</span>}</label>
      <label className="text-sm">Maximum output tokens<input type="number" min={1} className="input mt-1" placeholder="Provider default" value={value.max_output_tokens ?? ''} disabled={disabled} onChange={e => update({ max_output_tokens: e.target.value ? Number(e.target.value) : null })} />{errors['api_ai_config.max_output_tokens'] && <span className="text-red-600">{errors['api_ai_config.max_output_tokens']}</span>}</label>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={value.stream_allowed} disabled={disabled} onChange={e => update({ stream_allowed: e.target.checked })} />Allow streaming</label>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={value.forward_user_id} disabled={disabled} onChange={e => update({ forward_user_id: e.target.checked })} />Forward user attribution<InfoTooltip text="Send a stable pseudonymous user ID where supported, so your provider can attribute usage and abuse. Client-supplied values are preserved. Gemini has no user-ID field." /></label>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={value.inject_stream_usage} disabled={disabled} onChange={e => update({ inject_stream_usage: e.target.checked })} />Request OpenAI stream usage</label>
      <label className="text-sm">Prompt log override (can only reduce the global level)<select className="input mt-1" value={value.log_level || ''} disabled={disabled} onChange={e => update({ log_level: (e.target.value || null) as AiLogLevel | null })}><option value="">Global setting</option><option value="none">None</option><option value="metadata">Metadata</option><option value="full">Full (requires employee notice)</option></select></label>
    </div>
  </div>
}

export default function AiModelsPanel({ apiName, apiVersion, provider, config, onSaved }: {
  apiName: string; apiVersion: string; provider: AiProvider; config: AiApiConfig; onSaved: (config: AiApiConfig) => void
}) {
  const { providers } = useAiProviders()
  const [draft, setDraft] = useState<AiApiConfig>({ ...defaultAiConfig(), ...config })
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [modelsAvailable, setModelsAvailable] = useState<boolean | null>(null)
  const [stats, setStats] = useState<AiUsageRow | null>(null)
  const [language, setLanguage] = useState('Python')
  useEffect(() => { setDraft({ ...defaultAiConfig(), ...config }) }, [config])
  useEffect(() => {
    let active = true
    setModelsAvailable(null)
    getJson(`${SERVER_URL}/platform/ai/apis/${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}/models`)
      .then(() => { if (active) setModelsAvailable(true) })
      .catch((reason: unknown) => {
        if (active) setModelsAvailable(!(reason instanceof Error && 'status' in reason && reason.status === 404))
      })
    return () => { active = false }
  }, [apiName, apiVersion])
  useEffect(() => {
    let active = true
    getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?dimension=api`).then(data => {
      if (active) setStats(data.rows.find(row => row.key === `${apiName}/${apiVersion}`) || null)
    }).catch(() => {})
    return () => { active = false }
  }, [apiName, apiVersion])
  const suffix = providers.find(item => item.id === provider)?.sdk_base_url_suffix ?? (provider === 'openai' || provider === 'openai_compatible' ? '/v1' : '')
  const baseUrl = aiSdkBaseUrl(SERVER_URL, apiName, apiVersion, suffix)
  const model = provider === 'anthropic' ? 'claude-opus-5-5' : draft.default_model || draft.allowed_models[0] || 'YOUR_ALLOWED_MODEL'
  const q = JSON.stringify
  const snippets: Record<string, string> = provider === 'anthropic' ? {
    Python: `import os, anthropic\nclient = anthropic.Anthropic(base_url=${q(baseUrl)}, api_key=os.environ["DOORMAN_AI_KEY"])\nreply = client.messages.create(model=${q(model)}, max_tokens=1024, messages=[{"role":"user","content":"Hello"}])`,
    TypeScript: `import Anthropic from '@anthropic-ai/sdk'\nconst client = new Anthropic({ baseURL: ${q(baseUrl)}, apiKey: process.env.DOORMAN_AI_KEY })\nconst reply = await client.messages.create({ model: ${q(model)}, max_tokens: 1024, messages: [{ role: 'user', content: 'Hello' }] })`,
    curl: `curl ${q(`${baseUrl}/v1/messages`)} -H 'Content-Type: application/json' -H "x-api-key: $DOORMAN_AI_KEY" -H 'anthropic-version: 2023-06-01' -d '${JSON.stringify({ model, max_tokens: 1024, messages: [{ role: 'user', content: 'Hello' }] })}'`,
  } : provider === 'gemini' ? {
    Python: `import os\nfrom google import genai\nfrom google.genai import types\nclient = genai.Client(api_key=os.environ["DOORMAN_AI_KEY"], http_options=types.HttpOptions(base_url=${q(baseUrl)}))\nreply = client.models.generate_content(model=${q(model)}, contents="Hello")`,
    TypeScript: `import { GoogleGenAI } from '@google/genai'\nconst client = new GoogleGenAI({ apiKey: process.env.DOORMAN_AI_KEY, httpOptions: { baseUrl: ${q(baseUrl)} } })\nconst reply = await client.models.generateContent({ model: ${q(model)}, contents: 'Hello' })`,
    curl: `curl ${q(`${baseUrl}/v1beta/models/${encodeURIComponent(model)}:generateContent`)} -H "x-goog-api-key: $DOORMAN_AI_KEY" -H 'Content-Type: application/json' -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'`,
  } : provider === 'azure_openai' ? {
    Python: `import os\nfrom openai import AzureOpenAI\nclient = AzureOpenAI(azure_endpoint=${q(baseUrl)}, api_key=os.environ["DOORMAN_AI_KEY"], api_version="2024-10-21")\nreply = client.chat.completions.create(model=${q(model)}, messages=[{"role":"user","content":"Hello"}])`,
    TypeScript: `import { AzureOpenAI } from 'openai'\nconst client = new AzureOpenAI({ endpoint: ${q(baseUrl)}, apiKey: process.env.DOORMAN_AI_KEY, apiVersion: '2024-10-21' })\nconst reply = await client.chat.completions.create({ model: ${q(model)}, messages: [{ role: 'user', content: 'Hello' }] })`,
    curl: `curl ${q(`${baseUrl}/openai/deployments/${encodeURIComponent(model)}/chat/completions?api-version=2024-10-21`)} -H "api-key: $DOORMAN_AI_KEY" -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"Hello"}]}'`,
  } : {
    Python: `import os\nfrom openai import OpenAI\nclient = OpenAI(base_url=${q(baseUrl)}, api_key=os.environ["DOORMAN_AI_KEY"])\nreply = client.chat.completions.create(model=${q(model)}, messages=[{"role":"user","content":"Hello"}])`,
    TypeScript: `import OpenAI from 'openai'\nconst client = new OpenAI({ baseURL: ${q(baseUrl)}, apiKey: process.env.DOORMAN_AI_KEY })\nconst reply = await client.chat.completions.create({ model: ${q(model)}, messages: [{ role: 'user', content: 'Hello' }] })`,
    curl: `curl ${q(`${baseUrl}/chat/completions`)} -H "Authorization: Bearer $DOORMAN_AI_KEY" -H 'Content-Type: application/json' -d '${JSON.stringify({ model, messages: [{ role: 'user', content: 'Hello' }] })}'`,
  }
  const save = async () => {
    setWorking(true); setError(null); setSuccess(null); setErrors({})
    try {
      await putJson(`${SERVER_URL}/platform/api/${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}`, { api_ai_config: draft })
      onSaved(draft); setSuccess('AI model settings saved')
    } catch (reason) { setErrors(aiValidationErrors(reason)); setError(reason instanceof Error ? reason.message : 'Unable to save AI settings') }
    finally { setWorking(false) }
  }
  const fetchModels = async () => {
    setWorking(true); setError(null)
    try {
      const data = await getJson<{ models: (string | { id?: string; name?: string })[] }>(`${SERVER_URL}/platform/ai/apis/${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}/models`)
      const models = data.models.map(item => typeof item === 'string' ? item : item.id || item.name || '').filter(Boolean)
      setDraft(value => ({ ...value, allowed_models: [...new Set([...value.allowed_models, ...models])] }))
    } catch (reason) {
      if (reason instanceof Error && 'status' in reason && reason.status === 404) setModelsAvailable(false)
      else setError(reason instanceof Error ? reason.message : 'Unable to fetch models')
    } finally { setWorking(false) }
  }
  return <div className="card">
    <div className="card-header"><h3 className="card-title">AI models and SDK access</h3></div>
    <div className="p-6 space-y-5">
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {success && <p role="status" className="text-sm text-green-700">{success}</p>}
      <AiModelFields value={draft} onChange={setDraft} disabled={working} errors={errors} />
      <div className="flex gap-2"><button type="button" className="btn btn-primary" disabled={working || !draft.allowed_models.length} onClick={save}>Save AI settings</button>{modelsAvailable && <button type="button" className="btn btn-secondary" disabled={working} onClick={fetchModels}>Fetch from provider</button>}</div>
      {stats && <p className="text-sm">Last 30 days: {formatTokens(stats.requests)} requests · {formatTokens(stats.input_tokens + stats.output_tokens + stats.cache_read_tokens + stats.cache_write_tokens)} tokens · {formatUsd(stats.cost_nanos)}</p>}
      <div className="border rounded p-4 space-y-3"><h4 className="font-medium">Connect your SDK</h4><div className="flex items-center gap-2"><code className="text-xs break-all">{baseUrl}</code><SignalCopyButton text={baseUrl} label="Copy SDK base URL" /></div><div role="tablist" aria-label="SDK language" className="flex gap-2">{Object.keys(snippets).map(name => <button type="button" role="tab" aria-selected={name === language} key={name} onClick={() => setLanguage(name)} className={`btn ${name === language ? 'btn-primary' : 'btn-secondary'}`}>{name}</button>)}</div><pre className="overflow-x-auto text-xs p-3 bg-gray-50 dark:bg-black/20 rounded">{snippets[language]}</pre><SignalCopyButton text={snippets[language]} label="Copy SDK example" /></div>
    </div>
  </div>
}
