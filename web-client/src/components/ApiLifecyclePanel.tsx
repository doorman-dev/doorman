'use client'

import React, { useCallback, useEffect, useState } from 'react'
import ConfirmModal from '@/components/ConfirmModal'
import { getCookie } from '@/utils/http'
import { useToast } from '@/contexts/ToastContext'
import { SERVER_URL } from '@/utils/config'
import { fetchAllPaginated } from '@/utils/api'

export type LifecycleStatus = 'draft' | 'active' | 'deprecated' | 'retired'

interface LifecycleHistoryEntry {
  from: LifecycleStatus
  status: LifecycleStatus
  at: string
  actor: string
  note?: string
}

interface LifecycleVersion {
  api_version: string
  api_lifecycle_status: LifecycleStatus
  api_deprecated_at?: string | null
  api_retirement_date?: string | null
  api_successor_version?: string | null
  api_lifecycle_history: LifecycleHistoryEntry[]
}

interface VersionsResponse {
  resolution: 'found' | 'retired' | 'not_found'
  resolved_version?: string | null
  versions: LifecycleVersion[]
}

export const LIFECYCLE_BADGE: Record<LifecycleStatus, string> = {
  draft: 'badge-gray',
  active: 'badge-success',
  deprecated: 'badge-warning',
  retired: 'badge-error',
}

const ACTIONS: Record<LifecycleStatus, { to: LifecycleStatus; label: string }[]> = {
  draft: [{ to: 'active', label: 'Publish' }],
  active: [{ to: 'deprecated', label: 'Deprecate' }],
  deprecated: [
    { to: 'active', label: 'Cancel deprecation' },
    { to: 'retired', label: 'Retire' },
  ],
  retired: [{ to: 'deprecated', label: 'Restore to deprecated' }],
}

const majorLine = (version: string) => {
  const match = /^v(\d+)(?:\.\d+){0,2}$/.exec(version)
  return match ? `v${match[1]}` : null
}

const formatDate = (value?: string | null) =>
  value ? new Date(value).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—'

async function lifecycleFetch(path: string, init: RequestInit = {}) {
  const csrf = getCookie('csrf_token')
  const headers: Record<string, string> = { Accept: 'application/json', ...(init.headers as Record<string, string>) }
  if (csrf) headers['X-CSRF-Token'] = csrf
  const resp = await fetch(`${SERVER_URL}${path}`, { credentials: 'include', ...init, headers })
  const data = await resp.json().catch(() => ({}))
  const payload = data && typeof data === 'object' && 'response' in data ? data.response : data
  if (!resp.ok) throw new Error(payload?.error_message || payload?.message || resp.statusText)
  return payload
}

export default function ApiLifecyclePanel({ apiName, apiVersion }: { apiName: string; apiVersion: string }) {
  const toast = useToast()
  const [versions, setVersions] = useState<LifecycleVersion[]>([])
  const [resolvedVersion, setResolvedVersion] = useState<string | null>(null)
  const [successorVersions, setSuccessorVersions] = useState<LifecycleVersion[]>([])
  const [record, setRecord] = useState<LifecycleVersion | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [retirementDate, setRetirementDate] = useState('')
  const [successor, setSuccessor] = useState('')
  const [note, setNote] = useState('')
  const [wholeLine, setWholeLine] = useState(false)
  const [confirmRetire, setConfirmRetire] = useState(false)
  const line = majorLine(apiVersion)
  const isMajorLine = line === apiVersion
  const base = `/platform/api/${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}`

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [data, apis] = await Promise.all([
        lifecycleFetch(`/platform/api/${encodeURIComponent(apiName)}/${encodeURIComponent(line || apiVersion)}/versions`) as Promise<VersionsResponse>,
        fetchAllPaginated<LifecycleVersion & { api_name: string }>(
          (page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`,
          data => Array.isArray(data) ? data : (data.apis || data.response?.apis || []),
          undefined,
          Number.POSITIVE_INFINITY
        ),
      ])
      const found = data.versions.find(v => v.api_version === apiVersion)
      if (!found) throw new Error('The selected API release is no longer available')
      setVersions(data.versions)
      setResolvedVersion(data.resolved_version || null)
      setSuccessorVersions(apis.filter(api => api.api_name === apiName && api.api_version !== apiVersion &&
        (!api.api_lifecycle_status || api.api_lifecycle_status === 'active' || api.api_lifecycle_status === 'deprecated')))
      setRecord(found)
      setRetirementDate(found?.api_retirement_date?.slice(0, 10) || '')
      setSuccessor(found?.api_successor_version || '')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load lifecycle')
    } finally {
      setLoading(false)
    }
  }, [apiName, apiVersion, line])

  useEffect(() => { load() }, [load])

  const transition = async (to: LifecycleStatus) => {
    setWorking(true)
    try {
      const target = wholeLine && line ? `/platform/api/${encodeURIComponent(apiName)}/${line}` : base
      const body: Record<string, string> = { status: to }
      if (to === 'deprecated' && retirementDate) body.retirement_date = retirementDate
      if (to === 'deprecated' || successor !== (record?.api_successor_version || '')) {
        body.successor_version = successor.trim()
      }
      if (note.trim()) body.note = note.trim()
      const result = await lifecycleFetch(`${target}/lifecycle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const updated: string[] = result?.updated_versions || []
      toast.success(`Moved ${updated.join(', ') || apiVersion} to ${to}`)
      setNote('')
      await load()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Lifecycle change failed')
    } finally {
      setWorking(false)
      setConfirmRetire(false)
    }
  }

  const status = record?.api_lifecycle_status || 'active'
  const savedSuccessor = record?.api_successor_version
  const savedSuccessorIsLine = successorVersions.some(version => majorLine(version.api_version) === savedSuccessor)
  const pastRetirement =
    status === 'deprecated' && !!record?.api_retirement_date && new Date(record.api_retirement_date) < new Date()
  const today = new Date().toISOString().slice(0, 10)

  return (
    <div className="card">
      <div className="card-header flex items-center justify-between">
        <h3 className="card-title">Version Lifecycle</h3>
        {!loading && !error && <span className={`badge ${LIFECYCLE_BADGE[status]}`}>{status}</span>}
      </div>
      <div className="p-6 space-y-4">
        {loading ? (
          <p className="text-sm text-gray-500 dark:text-white/60">Loading lifecycle…</p>
        ) : error ? (
          <div role="alert" className="space-y-2">
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            <button type="button" className="btn btn-secondary" onClick={load}>Retry</button>
          </div>
        ) : (
          <>
            <p className="text-sm text-gray-600 dark:text-white/70">
              Consumers call <code>/{line || apiVersion}/</code>. Each response includes an <code>X-API-Lifecycle-Status</code> header,
              and deprecated versions also send a <code>Sunset</code> header with the retirement date.
            </p>
            <div>
              <h4 className="font-medium mb-2">{line ? `${line} releases` : 'Versions'}</h4>
              <ul className="space-y-2" aria-label="Releases in this version line">
                {versions.map(version => (
                  <li key={version.api_version} className="flex flex-wrap items-center gap-2 text-sm">
                    <code>{version.api_version}</code>
                    <span className={`badge ${LIFECYCLE_BADGE[version.api_lifecycle_status || 'active']}`}>
                      {version.api_lifecycle_status || 'active'}
                    </span>
                    {version.api_version === apiVersion && <span className="text-gray-500">Selected release</span>}
                    {version.api_version === resolvedVersion && <span className="badge badge-primary">Resolved version</span>}
                  </li>
                ))}
              </ul>
            </div>
            <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
              <div>
                <dt className="text-gray-500 dark:text-white/60">Deprecated on</dt>
                <dd className="text-gray-900 dark:text-white">{formatDate(record?.api_deprecated_at)}</dd>
              </div>
              <div>
                <dt className="text-gray-500 dark:text-white/60">Retirement date</dt>
                <dd className="text-gray-900 dark:text-white">
                  {formatDate(record?.api_retirement_date)}
                  {pastRetirement && <span className="badge badge-error ml-2">Past retirement date</span>}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500 dark:text-white/60">Successor</dt>
                <dd className="text-gray-900 dark:text-white">{record?.api_successor_version || '—'}</dd>
              </div>
            </dl>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {(status === 'active' || status === 'retired') && (
                <label className="block text-sm">
                  <span className="text-gray-600 dark:text-white/60">Retirement date (required to deprecate or restore)</span>
                  <input id="lifecycle-retirement-date" type="date" className="input mt-1 w-full" min={status === 'active' ? today : undefined}
                    value={retirementDate} onChange={e => setRetirementDate(e.target.value)} />
                </label>
              )}
              {(status === 'active' || status === 'deprecated' || status === 'retired') && (
                <label className="block text-sm">
                  <span className="text-gray-600 dark:text-white/60">Successor version</span>
                  <select id="lifecycle-successor" className="input mt-1 w-full"
                    value={successor} onChange={e => setSuccessor(e.target.value)}>
                    <option value="">No successor</option>
                    {savedSuccessor && !successorVersions.some(version => version.api_version === savedSuccessor) && (
                      <option value={savedSuccessor} disabled={!savedSuccessorIsLine}>
                        {savedSuccessor} ({savedSuccessorIsLine ? 'major line' : 'unavailable'})
                      </option>
                    )}
                    {successorVersions.map(version => (
                      <option key={version.api_version} value={version.api_version}>
                        {version.api_version} ({version.api_lifecycle_status || 'active'})
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label className="block text-sm sm:col-span-2">
                <span className="text-gray-600 dark:text-white/60">Note (optional, kept in history)</span>
                <input id="lifecycle-note" className="input mt-1 w-full" maxLength={255}
                  value={note} onChange={e => setNote(e.target.value)} />
              </label>
            </div>

            {isMajorLine && (
              <p className="text-sm text-gray-700 dark:text-white/80">
                Lifecycle changes to {apiVersion} apply to eligible releases in this major line.
              </p>
            )}
            {line && !isMajorLine && (
              <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-white/80">
                <input id="lifecycle-whole-line" type="checkbox" checked={wholeLine} onChange={e => setWholeLine(e.target.checked)} />
                Apply to every eligible {line}.x release
              </label>
            )}

            <div className="flex flex-wrap gap-2">
              {ACTIONS[status].map(action => (
                <button key={action.to} type="button" disabled={working}
                  className={action.to === 'retired' ? 'btn btn-error' : 'btn btn-secondary'}
                  onClick={() => (action.to === 'retired' ? setConfirmRetire(true) : transition(action.to))}>
                  {action.label}
                </button>
              ))}
            </div>

            {!!record?.api_lifecycle_history?.length && (
              <div className="overflow-x-auto">
                <table className="table w-full text-sm">
                  <thead>
                    <tr><th>When</th><th>Change</th><th>By</th><th>Note</th></tr>
                  </thead>
                  <tbody>
                    {[...record.api_lifecycle_history].reverse().map((entry, index) => (
                      <tr key={`${entry.at}-${index}`}>
                        <td>{new Date(entry.at).toLocaleString()}</td>
                        <td>{entry.from} → {entry.status}</td>
                        <td>{entry.actor}</td>
                        <td>{entry.note || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
      <ConfirmModal
        open={confirmRetire}
        title={`Retire ${(wholeLine || isMajorLine) && line ? `${line}.x` : apiVersion}?`}
        message="Requests to a retired version get 410 Gone. You can restore it to deprecated later."
        confirmLabel="Retire"
        loading={working}
        onConfirm={() => transition('retired')}
        onCancel={() => setConfirmRetire(false)}
      />
    </div>
  )
}
