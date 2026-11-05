'use client'

import { useEffect, useState } from 'react'
import { fetchAllPaginated, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import type { AiApiConfig, AiTarget } from '@/utils/ai'

const blank = (): AiTarget => ({ credential_group: '', server: null, weight: 1 })

/** Summary line for a provider card. */
export function backupsSummary(config: Partial<AiApiConfig>): string {
  const targets = config.fallback_targets || []
  if (!targets.length) return 'None'
  return `${targets.length} backup${targets.length === 1 ? '' : 's'}${config.load_balance ? ', load balanced' : ''}`
}

/** Edits an AI API's failover backups (api_ai_config.fallback_targets). */
export default function AiBackupsEditor({ apiName, apiVersion, config, onClose, onSaved }: {
  apiName: string; apiVersion: string; config: Partial<AiApiConfig>; onClose: () => void; onSaved: (config: Partial<AiApiConfig>) => void
}) {
  const [rows, setRows] = useState<AiTarget[]>(() => (config.fallback_targets || []).map(target => ({ ...target })))
  const [balance, setBalance] = useState(!!config.load_balance)
  const [groups, setGroups] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchAllPaginated<{ api_credit_group: string }>(
      (page, size) => `${SERVER_URL}/platform/credit/defs?page=${page}&page_size=${size}`,
      data => Array.isArray(data) ? data : data.items || data.response?.items || []
    ).then(items => setGroups(items.map(item => item.api_credit_group).sort())).catch(() => {})
  }, [])

  const update = (index: number, patch: Partial<AiTarget>) => setRows(current => current.map((row, i) => i === index ? { ...row, ...patch } : row))
  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    setSaving(true); setError(null)
    const fallback_targets = rows.map(row => ({ credential_group: row.credential_group.trim(), server: row.server?.trim() || null, weight: Math.max(1, Number(row.weight) || 1) }))
    const next = { ...config, fallback_targets, load_balance: balance && fallback_targets.some(row => row.server) }
    try {
      await putJson(`${SERVER_URL}/platform/api/${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}`, { api_ai_config: next })
      onSaved(next)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not save backups') }
    finally { setSaving(false) }
  }

  return <div className="fixed inset-0 z-[60] bg-black/50 flex justify-end" onClick={event => { if (event.target === event.currentTarget && !saving) onClose() }}>
    <form role="dialog" aria-modal="true" aria-label="Backups" onSubmit={save} className="h-full w-full max-w-xl overflow-y-auto bg-white p-6 space-y-5">
      <div>
        <h2 className="text-lg font-semibold">Backups for {apiName}</h2>
        <p className="text-sm text-gray-600 mt-1">If the provider is down (502, 503 or 504), times out or can&apos;t be reached, Doorman tries these in order. A rate limit (429) is always passed back to the caller and never moved to another key.</p>
      </div>
      {!rows.length && <p className="text-sm text-gray-500">No backups yet.</p>}
      <ol className="space-y-4">{rows.map((row, index) => <li key={index} className="border-t border-gray-100 pt-4 first:border-t-0 first:pt-0 space-y-3">
        <div className="flex items-center justify-between"><span className="text-sm font-medium">Backup {index + 1}</span><button type="button" className="btn btn-ghost" onClick={() => setRows(current => current.filter((_, i) => i !== index))}>Remove</button></div>
        <label className="block text-sm" htmlFor={`backup-key-${index}`}>Key
          <select id={`backup-key-${index}`} className="input w-full mt-1" value={row.credential_group} onChange={event => update(index, { credential_group: event.target.value })}>
            <option value="">Same key as the provider</option>
            {[...new Set([...groups, ...(row.credential_group ? [row.credential_group] : [])])].map(group => <option key={group} value={group}>{group}</option>)}
          </select>
        </label>
        <label className="block text-sm" htmlFor={`backup-server-${index}`}>Server
          <input id={`backup-server-${index}`} className="input w-full mt-1" placeholder="Same server as the provider" value={row.server || ''} onChange={event => update(index, { server: event.target.value || null })} />
          <span className="text-xs text-gray-500">For another region or Azure deployment, for example https://eastus2.example.openai.azure.com</span>
        </label>
        {balance && row.server && <label className="block text-sm" htmlFor={`backup-weight-${index}`}><span className="block">Share of traffic</span>
          <input id={`backup-weight-${index}`} className="input w-28 mt-1" type="number" min={1} max={1000} value={row.weight} onChange={event => update(index, { weight: Number(event.target.value) })} />
          <span className="text-xs text-gray-500 ml-2">The provider itself counts as 1.</span>
        </label>}
      </li>)}</ol>
      <button type="button" className="btn btn-secondary" disabled={rows.length >= 10} onClick={() => setRows(current => [...current, blank()])}>Add backup</button>
      <label className="flex items-start gap-2 text-sm" htmlFor="backup-balance">
        <input id="backup-balance" type="checkbox" className="mt-1" checked={balance} onChange={event => setBalance(event.target.checked)} />
        <span>Spread traffic across servers<span className="block text-xs text-gray-500">Only backups on a different server share traffic. Backups that only use another key stay standby.</span></span>
      </label>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <div className="flex gap-2"><button type="submit" className="btn btn-primary" disabled={saving}>{saving ? 'Saving…' : 'Save backups'}</button><button type="button" className="btn btn-secondary" disabled={saving} onClick={onClose}>Cancel</button></div>
    </form>
  </div>
}
