'use client'

import { useState } from 'react'
import { delJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { AI_CACHE_TTL_PRESETS, defaultCacheConfig, type AiApiConfig, type AiCacheConfig } from '@/utils/ai'

const MIN_TTL = 60
const MAX_TTL = 604800

/** Edits an AI API's response caching (api_ai_config.cache) and clears its stored answers. */
export default function AiCacheEditor({ apiName, apiVersion, config, canClear, onClose, onSaved }: {
  apiName: string; apiVersion: string; config: Partial<AiApiConfig>; canClear: boolean; onClose: () => void; onSaved: (config: Partial<AiApiConfig>) => void
}) {
  const initial = { ...defaultCacheConfig(), ...(config.cache || {}) }
  const [cache, setCache] = useState<AiCacheConfig>(initial)
  const isPreset = AI_CACHE_TTL_PRESETS.some(preset => preset.seconds === initial.ttl_seconds)
  const [custom, setCustom] = useState(!isPreset)
  const [seconds, setSeconds] = useState(String(initial.ttl_seconds))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const [cleared, setCleared] = useState<string | null>(null)

  // Custom lifetimes are whole seconds, saved exactly as typed (never rounded).
  const ttlSeconds = custom ? Number(seconds) : cache.ttl_seconds
  const ttlValid = Number.isInteger(ttlSeconds) && ttlSeconds >= MIN_TTL && ttlSeconds <= MAX_TTL
  const api = `${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}`

  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!ttlValid) { setError('Keep answers for 60 to 604800 seconds (1 minute to 7 days), in whole seconds.'); return }
    setSaving(true); setError(null)
    const next = { ...config, cache: { ...cache, ttl_seconds: ttlSeconds } }
    try {
      await putJson(`${SERVER_URL}/platform/api/${api}`, { api_ai_config: next })
      onSaved(next)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not save caching') }
    finally { setSaving(false) }
  }

  const clear = async () => {
    setConfirmClear(false); setError(null); setCleared(null)
    try {
      const result = await delJson<{ purged?: number; response?: { purged?: number } }>(`${SERVER_URL}/platform/ai/cache/${api}`)
      const purged = result?.purged ?? result?.response?.purged ?? 0
      setCleared(`Cleared ${purged} stored answer${purged === 1 ? '' : 's'}.`)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not clear the cache') }
  }

  return <div className="fixed inset-0 z-[60] bg-black/50 flex justify-end" onClick={event => { if (event.target === event.currentTarget && !saving) onClose() }}>
    <form role="dialog" aria-modal="true" aria-label="Response caching" onSubmit={save} className="h-full w-full max-w-xl overflow-y-auto bg-white p-6 space-y-5">
      <div>
        <h2 className="text-lg font-semibold">Response caching for {apiName}</h2>
        <p className="text-sm text-gray-600 mt-1">When someone sends exactly the same request again, Doorman replays the stored answer instead of calling the provider. It costs nothing, comes back right away, and Usage shows what it saved. Errors and refused answers are never stored.</p>
      </div>
      <label className="flex items-start gap-2 text-sm" htmlFor="cache-enabled">
        <input id="cache-enabled" type="checkbox" className="mt-1" checked={cache.enabled} onChange={event => setCache(current => ({ ...current, enabled: event.target.checked }))} />
        <span>Cache answers<span className="block text-xs text-gray-500">Best for repeated questions, such as a help bot or a shared prompt. Each person can skip the cache by sending <code>Cache-Control: no-store</code>.</span></span>
      </label>
      <fieldset className="space-y-2" disabled={!cache.enabled}>
        <legend className="text-sm font-medium">Keep answers for</legend>
        <div className="flex flex-wrap gap-2">
          {AI_CACHE_TTL_PRESETS.map(preset => <button key={preset.seconds} type="button" aria-pressed={!custom && cache.ttl_seconds === preset.seconds}
            className={`btn ${!custom && cache.ttl_seconds === preset.seconds ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => { setCustom(false); setCache(current => ({ ...current, ttl_seconds: preset.seconds })) }}>{preset.label}</button>)}
          <button type="button" aria-pressed={custom} className={`btn ${custom ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setCustom(true)}>Custom</button>
        </div>
        {custom && <label className="block text-sm" htmlFor="cache-seconds">Seconds
          <input id="cache-seconds" className="input w-36 mt-1 ml-2" type="number" inputMode="numeric" min={MIN_TTL} max={MAX_TTL} step={1} value={seconds} onChange={event => setSeconds(event.target.value)} />
          <span className="block text-xs text-gray-500">60 (1 minute) to 604800 (7 days). For example 3600 is one hour.</span>
        </label>}
      </fieldset>
      <fieldset className="space-y-2" disabled={!cache.enabled}>
        <legend className="text-sm font-medium">Who gets a stored answer</legend>
        <label className="flex items-start gap-2 text-sm" htmlFor="cache-scope-user">
          <input id="cache-scope-user" type="radio" name="cache-scope" className="mt-1" checked={cache.scope === 'user'} onChange={() => setCache(current => ({ ...current, scope: 'user' }))} />
          <span>Only the same person<span className="block text-xs text-gray-500">Answers are never shown to anyone else.</span></span>
        </label>
        <label className="flex items-start gap-2 text-sm" htmlFor="cache-scope-shared">
          <input id="cache-scope-shared" type="radio" name="cache-scope" className="mt-1" checked={cache.scope === 'shared'} onChange={() => setCache(current => ({ ...current, scope: 'shared' }))} />
          <span>Everyone who can use this provider<span className="block text-xs text-gray-500">More requests are saved. Someone sending the same prompt as a colleague gets the colleague&apos;s answer, so only choose this when prompts don&apos;t contain personal information.</span></span>
        </label>
      </fieldset>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <div className="flex flex-wrap gap-2"><button type="submit" className="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save caching'}</button><button type="button" className="btn btn-secondary" disabled={saving} onClick={onClose}>Cancel</button></div>
      {canClear && <div className="border-t border-gray-100 pt-4 space-y-2">
        <h3 className="text-sm font-medium">Stored answers</h3>
        <p className="text-xs text-gray-500">Clear them after changing a system prompt or when answers are out of date.</p>
        {!confirmClear && <button type="button" className="btn btn-secondary" onClick={() => { setConfirmClear(true); setCleared(null) }}>Clear cache</button>}
        {confirmClear && <div className="flex flex-wrap items-center gap-2 text-sm"><span>Clear every stored answer for {apiName}?</span><button type="button" className="btn btn-primary" onClick={clear}>Clear</button><button type="button" className="btn btn-secondary" onClick={() => setConfirmClear(false)}>Keep</button></div>}
        {cleared && <p role="status" className="text-sm text-gray-700">{cleared}</p>}
      </div>}
    </form>
  </div>
}
