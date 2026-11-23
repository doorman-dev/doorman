'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { SignalCopyButton } from '@/components/signal/Signal'
import { fetchAllPaginated, getJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import {
  AI_UNIFIED_MODEL_LENGTH, AI_UNIFIED_ROUTE_LIMIT, AI_UNIFIED_TARGET_LIMIT,
  aiUnifiedBaseUrl, providerLabel,
  type AiApiConfig, type AiSettings, type AiUnifiedResolution,
  type AiUnifiedRoute, type AiUnifiedSettings, type AiUnifiedTarget,
} from '@/utils/ai'

type UnifiedApi = {
  api_name: string
  api_version: string
  api_ai_provider?: string
  api_ai_config?: Partial<AiApiConfig>
}
type TargetDraft = AiUnifiedTarget & { id: number }
type RouteDraft = Omit<AiUnifiedRoute, 'targets'> & { id: number; targets: TargetDraft[] }

const settingsUrl = `${SERVER_URL}/platform/ai/settings`
const apiLabel = (api: UnifiedApi) => `${api.api_name}/${api.api_version}`
const errorMessage = (error: unknown, fallback: string) => error instanceof Error ? error.message : fallback

function ModelPicker({ api, target, onChange }: {
  api?: UnifiedApi
  target: TargetDraft
  onChange: (model: string) => void
}) {
  const allowed = api?.api_ai_config?.allowed_models || []
  const models = [...new Set([
    ...allowed.filter(model => !model.endsWith('*')),
    ...Object.keys(api?.api_ai_config?.model_aliases || {}),
  ])].sort()
  const hasPattern = allowed.some(model => model.endsWith('*'))
  const listId = `unified-models-${target.id}`
  return <label className="block min-w-0 text-sm">
    Model
    {hasPattern ? <>
      <input className="input mt-1 w-full min-w-0" list={listId} maxLength={AI_UNIFIED_MODEL_LENGTH}
        required value={target.model} onChange={event => onChange(event.target.value)} placeholder="Enter an allowed model" />
      <datalist id={listId}>{models.map(model => <option key={model} value={model} />)}</datalist>
      <span className="mt-1 block break-words text-xs text-gray-500">{allowed.filter(model => model.endsWith('*')).join(', ')}</span>
    </> : <select className="input mt-1 w-full min-w-0" required disabled={!api}
      value={target.model} onChange={event => onChange(event.target.value)}>
      <option value="">{api ? 'Choose a model' : 'Choose an AI API first'}</option>
      {target.model && !models.includes(target.model) && <option value={target.model}>{target.model} (unavailable)</option>}
      {models.map(model => <option key={model} value={model}>{model}</option>)}
    </select>}
  </label>
}

function ResolutionTable({ resolution }: { resolution: AiUnifiedResolution }) {
  if (!resolution.models.length) {
    return <p className="text-sm text-gray-500">No models are available for {resolution.username}.</p>
  }
  return <div className="overflow-x-auto">
    <table className="table w-full text-sm" aria-label={`Models available to ${resolution.username}`}>
      <thead><tr><th scope="col">Model</th><th scope="col">AI API</th><th scope="col">Provider</th><th scope="col">Via</th></tr></thead>
      <tbody>
        {resolution.models.flatMap(row => row.targets.map((target, index) =>
          <tr key={`${row.model}-${index}`}>
            <td data-label="Model"><code className="break-all">{row.model}</code></td>
            <td className="min-w-32" data-label="AI API">
              <span className="break-all">{target.api}</span>
              {target.model !== row.model && <code className="block break-all text-xs text-gray-500">{target.model}</code>}
            </td>
            <td data-label="Provider">{providerLabel(target.provider)}</td>
            <td data-label="Via">{row.via === 'route' && row.targets.length > 1 ? `Route · target ${index + 1}` : row.via === 'route' ? 'Route' : 'Auto'}</td>
          </tr>,
        ))}
      </tbody>
    </table>
  </div>
}

export default function AiUnifiedPanel({ apis, providersError, canManage, canListUsers }: {
  apis: UnifiedApi[] | null
  providersError: string | null
  canManage: boolean
  canListUsers: boolean
}) {
  const nextId = useRef(0)
  const [enabled, setEnabled] = useState(true)
  const [routes, setRoutes] = useState<RouteDraft[] | null>(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [settingsError, setSettingsError] = useState<string | null>(null)
  const [usernames, setUsernames] = useState<string[]>([])
  const [employee, setEmployee] = useState('')
  const [preview, setPreview] = useState({ username: '' })
  const [resolution, setResolution] = useState<AiUnifiedResolution | null>(null)
  const [resolveError, setResolveError] = useState<string | null>(null)
  const baseUrl = aiUnifiedBaseUrl(SERVER_URL)
  const availableApis = apis || []

  const apply = useCallback((settings: AiUnifiedSettings) => {
    setEnabled(settings.enabled)
    setRoutes(settings.routes.map(route => ({
      ...route, id: nextId.current++,
      targets: route.targets.map(target => ({ ...target, id: nextId.current++ })),
    })))
  }, [])

  useEffect(() => {
    let active = true
    getJson<AiSettings>(settingsUrl)
      .then(result => { if (active) apply(result.unified || { enabled: true, routes: [] }) })
      .catch(error => { if (active) setSettingsError(errorMessage(error, 'Could not load endpoint settings')) })
    return () => { active = false }
  }, [apply])

  useEffect(() => {
    if (!canListUsers) return
    let active = true
    fetchAllPaginated<{ username: string }>(
      (page, size) => `${SERVER_URL}/platform/user/all?page=${page}&page_size=${size}`,
      data => data?.users || data?.response?.users || [],
      undefined, undefined, 'cache:users:all'
    ).then(users => {
      if (active) setUsernames(users.map(user => user.username).filter(Boolean).sort())
    }).catch(() => {}) // The username field also accepts a typed username.
    return () => { active = false }
  }, [canListUsers])

  useEffect(() => {
    let active = true
    const params = preview.username ? `?username=${encodeURIComponent(preview.username)}` : ''
    setResolution(null)
    setResolveError(null)
    getJson<AiUnifiedResolution>(`${SERVER_URL}/platform/ai/unified/resolve${params}`)
      .then(result => { if (active) setResolution(result) })
      .catch(error => { if (active) setResolveError(errorMessage(error, 'Could not load model resolution')) })
    return () => { active = false }
  }, [preview])

  const changeRoutes = (change: (draft: RouteDraft[]) => RouteDraft[]) => {
    setSaved(false)
    setRoutes(current => current && change(current))
  }
  const editRoute = (id: number, change: (route: RouteDraft) => RouteDraft) => {
    changeRoutes(current => current.map(route => route.id === id ? change(route) : route))
  }
  const addTarget = (route: RouteDraft) => {
    const target = { id: nextId.current++, api: '', model: '' }
    editRoute(route.id, draft => ({ ...draft, targets: [...draft.targets, target] }))
  }
  const editTarget = (route: RouteDraft, id: number, fields: Partial<AiUnifiedTarget>) => {
    editRoute(route.id, draft => ({ ...draft, targets: draft.targets.map(target => target.id === id ? { ...target, ...fields } : target) }))
  }
  const moveTarget = (route: RouteDraft, index: number, direction: -1 | 1) => {
    editRoute(route.id, draft => {
      const targets = [...draft.targets]
      const [target] = targets.splice(index, 1)
      targets.splice(index + direction, 0, target)
      return { ...draft, targets }
    })
  }

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!canManage || !routes || saving) return
    setSettingsError(null)
    setSaved(false)
    const settings: AiUnifiedSettings = {
      enabled,
      routes: routes.map(route => ({
        model: route.model.trim(),
        targets: route.targets.map(target => ({ api: target.api, model: target.model.trim() })),
      })),
    }
    if (settings.routes.some(route => !route.model || route.targets.some(target => !target.api || !target.model))) {
      setSettingsError('Each route needs a name and each target needs an AI API and a model.')
      return
    }
    if (new Set(settings.routes.map(route => route.model)).size !== settings.routes.length) {
      setSettingsError('Each route needs a unique name.')
      return
    }
    setSaving(true)
    try {
      const result = await putJson<AiSettings>(settingsUrl, { unified: settings })
      apply(result.unified || settings)
      setSaved(true)
      setPreview(current => ({ username: current.username }))
    } catch (error) {
      setSettingsError(errorMessage(error, 'Could not save endpoint settings'))
    } finally {
      setSaving(false)
    }
  }

  return <>
    <form className="card space-y-5 p-5 sm:p-6" onSubmit={save}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-1">
          <h2 className="card-title">Unified endpoint</h2>
          <p className="text-sm text-gray-500">Employees can use their access key with one OpenAI-compatible base URL.</p>
        </div>
        {routes && <button className="btn btn-secondary" type="button" role="switch"
          aria-label="Enable unified endpoint" aria-checked={enabled} disabled={!canManage || saving}
          onClick={() => { setEnabled(!enabled); setSaved(false) }}>
          <span aria-hidden="true" className={`relative inline-block h-5 w-9 rounded-full border border-[var(--border-strong)] ${enabled ? 'bg-emerald-500/25' : 'bg-[var(--surface-3)]'}`}>
            <span className={`absolute left-0.5 top-0.5 size-3.5 rounded-full transition-transform ${enabled ? 'translate-x-4 bg-emerald-400' : 'bg-gray-400'}`} />
          </span>
          {enabled ? 'On' : 'Off'}
        </button>}
      </div>
      <div className="space-y-1">
        <p className="text-sm text-gray-500">Base URL</p>
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <code className="min-w-0 break-all rounded-md border border-[var(--border)] bg-[var(--bg-raised)] px-2.5 py-1.5 text-sm">{baseUrl}</code>
          <SignalCopyButton text={baseUrl} label="Copy base URL" />
        </div>
      </div>
      {routes ? <fieldset className="min-w-0 space-y-4 border-t border-[var(--border)] pt-5" disabled={!canManage || saving}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h3 className="card-title">Routes</h3>
            <p className="text-sm text-gray-500">Name a route and order the targets Doorman should try.</p>
          </div>
          {canManage && <button type="button" className="btn btn-secondary" disabled={routes.length >= AI_UNIFIED_ROUTE_LIMIT || !availableApis.length}
            onClick={() => {
              const route = { id: nextId.current++, model: '', targets: [{ id: nextId.current++, api: '', model: '' }] }
              changeRoutes(current => [...current, route])
            }}>Add route</button>}
        </div>
        {providersError && <p role="alert" className="text-sm text-red-600">{providersError}</p>}
        {!apis && !providersError && <p className="text-sm text-gray-500">Loading providers…</p>}
        {apis && !routes.length && <p className="text-sm text-gray-500">{apis.length ? 'No named routes. Models are resolved automatically.' : 'Add an AI provider to create a route.'}</p>}
        {routes.map(route => <div key={route.id} className="space-y-4 rounded-lg border border-[var(--border)] bg-[var(--bg-raised)] p-4">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <label className="block min-w-0 w-full text-sm sm:max-w-sm">Route name
              <input className="input mt-1 w-full" required maxLength={AI_UNIFIED_MODEL_LENGTH}
                value={route.model} placeholder="fast"
                onChange={event => {
                  const model = event.target.value
                  editRoute(route.id, draft => ({ ...draft, model }))
                }} />
            </label>
            {canManage && <button type="button" className="btn btn-ghost" onClick={() => changeRoutes(current => current.filter(item => item.id !== route.id))}>Remove route</button>}
          </div>
          <ol aria-label={route.model ? `Targets for ${route.model}` : 'Route targets'} className="space-y-3">
            {route.targets.map((target, index) => {
              const api = availableApis.find(entry => apiLabel(entry) === target.api)
              return <li key={target.id} className="grid min-w-0 gap-3 border-t border-[var(--border)] pt-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
                <label className="block min-w-0 text-sm">AI API
                  <select className="input mt-1 w-full min-w-0" required value={target.api}
                    onChange={event => editTarget(route, target.id, { api: event.target.value, model: '' })}>
                    <option value="">Choose an AI API</option>
                    {target.api && !api && <option value={target.api}>{target.api} (unavailable)</option>}
                    {availableApis.map(entry => <option key={apiLabel(entry)} value={apiLabel(entry)}>
                      {apiLabel(entry)}{entry.api_ai_provider ? ` · ${providerLabel(entry.api_ai_provider)}` : ''}
                    </option>)}
                  </select>
                </label>
                <ModelPicker api={api} target={target} onChange={model => editTarget(route, target.id, { model })} />
                {canManage && <div className="flex flex-wrap items-end gap-1">
                  <button type="button" className="btn btn-secondary" aria-label={`Move target ${index + 1} up`}
                    disabled={index === 0} onClick={() => moveTarget(route, index, -1)}>↑</button>
                  <button type="button" className="btn btn-secondary" aria-label={`Move target ${index + 1} down`}
                    disabled={index === route.targets.length - 1} onClick={() => moveTarget(route, index, 1)}>↓</button>
                  <button type="button" className="btn btn-ghost" aria-label={`Remove target ${index + 1}`}
                    disabled={route.targets.length === 1}
                    onClick={() => editRoute(route.id, draft => ({ ...draft, targets: draft.targets.filter(item => item.id !== target.id) }))}>Remove</button>
                </div>}
              </li>
            })}
          </ol>
          {canManage && <button type="button" className="btn btn-secondary" disabled={route.targets.length >= AI_UNIFIED_TARGET_LIMIT || !availableApis.length}
            onClick={() => addTarget(route)}>Add target</button>}
        </div>)}
        {canManage && <button type="submit" className="btn btn-primary">{saving ? 'Saving…' : 'Save changes'}</button>}
      </fieldset> : !settingsError && <p className="text-sm text-gray-500">Loading endpoint settings…</p>}
      {settingsError && <p role="alert" className="text-sm text-red-600">{settingsError}</p>}
      {saved && <p role="status" className="text-sm text-emerald-500">Changes saved.</p>}
    </form>

    <section className="card min-w-0 space-y-4 p-5 sm:p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h2 className="card-title">Who serves what</h2>
          <p className="text-sm text-gray-500">{resolution ? `Showing model resolution for ${resolution.username}.` : 'Preview which APIs can serve an employee’s models.'}</p>
        </div>
        <form className="flex flex-wrap items-end gap-2" onSubmit={event => { event.preventDefault(); setPreview({ username: employee.trim() }) }}>
          <label className="block min-w-0 text-sm">Username
            <input className="input mt-1 w-full" list="unified-usernames" placeholder="Your account"
              autoComplete="off" value={employee} onChange={event => setEmployee(event.target.value)} />
          </label>
          <datalist id="unified-usernames">{usernames.map(username => <option key={username} value={username} />)}</datalist>
          <button type="submit" className="btn btn-secondary">Preview</button>
        </form>
      </div>
      {resolveError ? <p role="alert" className="text-sm text-red-600">{resolveError}</p>
        : resolution ? <ResolutionTable resolution={resolution} />
        : <p className="text-sm text-gray-500">Loading model resolution…</p>}
    </section>
  </>
}
