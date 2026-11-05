'use client'

import AiBudgetBar from '@/components/AiBudgetBar'
import { useCallback, useEffect, useState } from 'react'
import ConfirmModal from '@/components/ConfirmModal'
import { SignalCopyButton } from '@/components/signal/Signal'
import { delJson, getJson, postJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { formatBudgetAmount, formatTokens, formatUsd, type AiAccessKey, type AiCreatedAccessKey, type AiMyUsage } from '@/utils/ai'

const date = (value: string | null) => value ? new Date(value).toLocaleString() : '—'

export default function AiKeysPanel({ username, showUsage = true }: { username?: string; showUsage?: boolean }) {
  const [keys, setKeys] = useState<AiAccessKey[]>([])
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [expires, setExpires] = useState('')
  const [scope, setScope] = useState('')
  const [issued, setIssued] = useState<AiCreatedAccessKey | null>(null)
  const [revoking, setRevoking] = useState<AiAccessKey | null>(null)
  const [usage, setUsage] = useState<AiMyUsage | null>(null)
  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const data = await getJson<{ keys: AiAccessKey[] }>(`${SERVER_URL}/platform/ai/keys${username ? `/user/${encodeURIComponent(username)}` : ''}`)
      setKeys(data.keys)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load AI access keys') }
    finally { setLoading(false) }
  }, [username])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (username) return
    let active = true
    getJson<AiMyUsage>(`${SERVER_URL}/platform/ai/usage/me?period=month`).then(data => { if (active) setUsage(data) }).catch(() => {})
    return () => { active = false }
  }, [username])
  const create = async () => {
    if (!name.trim()) return
    setWorking(true); setError(null)
    try {
      const apiScope = scope.split(/[\s,]+/).filter(Boolean)
      const key = await postJson<AiCreatedAccessKey>(`${SERVER_URL}/platform/ai/keys`, {
        name: name.trim(), ...(expires ? { expires_in_days: Number(expires) } : {}), ...(apiScope.length ? { api_scope: apiScope } : {}),
      })
      setIssued(key); setCreateOpen(false); setName(''); setExpires(''); setScope('')
      await load()
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to create AI key') }
    finally { setWorking(false) }
  }
  const revoke = async () => {
    if (!revoking) return
    setWorking(true); setError(null)
    try { await delJson(`${SERVER_URL}/platform/ai/keys/${encodeURIComponent(revoking.key_id)}`); setRevoking(null); await load() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to revoke AI key') }
    finally { setWorking(false) }
  }
  return <div className="card p-6 space-y-4">
    <div className="flex items-center justify-between gap-3"><h3 className="card-title">{username ? 'AI access keys' : 'Access keys'}</h3>{!username && <button type="button" className="btn btn-primary" onClick={() => { setError(null); setCreateOpen(true) }} disabled={working}>Create key</button>}</div>
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-white/70">Use this key in place of a provider key. It is shown once, when you create it.</p>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {loading ? <p className="text-sm">Loading keys…</p> : keys.length ? <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>Name / prefix</th><th>Created</th><th>Last used</th><th>Expires</th><th>Scope</th><th>Status</th><th /></tr></thead><tbody>{keys.map(key => <tr key={key.key_id}><td>{key.name}<code className="block text-xs">{key.key_prefix}…</code></td><td>{date(key.created_at)}</td><td>{date(key.last_used_at)}</td><td>{date(key.expires_at)}</td><td>{key.api_scope?.join(', ') || 'All permitted APIs'}</td><td>{key.revoked ? 'Revoked' : key.expires_at && new Date(key.expires_at) <= new Date() ? 'Expired' : 'Active'}</td><td>{!key.revoked && <button type="button" className="btn btn-ghost" disabled={working} onClick={() => setRevoking(key)}>Revoke</button>}</td></tr>)}</tbody></table></div> : <p className="text-sm text-gray-500">No AI access keys.</p>}
      {showUsage && usage && <div className="border-t pt-4 space-y-3"><h4 className="font-medium">AI usage this month</h4><p className="text-sm">{formatTokens(usage.usage.requests)} requests · {formatTokens(usage.usage.input_tokens + usage.usage.output_tokens)} tokens · {formatUsd(usage.usage.cost_nanos)}</p>{usage.budgets.map(budget => <div key={budget.budget_id} className="space-y-1"><p className="text-sm">{budget.name}: {budget.percent.toFixed(1)}% · {formatBudgetAmount(budget.limit_type, budget.used)} / {formatBudgetAmount(budget.limit_type, budget.limit_value)}</p><AiBudgetBar percent={budget.percent} label={budget.name} /><p className="text-xs text-gray-500">Resets {date(budget.resets_at)}</p></div>)}</div>}
    </div>
    {createOpen && <div className="fixed inset-0 z-[60] bg-black/50 flex items-center justify-center p-4"><form role="dialog" aria-modal="true" aria-label="Create AI access key" className="card w-full max-w-lg p-6 space-y-4" onSubmit={e => { e.preventDefault(); create() }}><h3 className="font-semibold">Create AI access key</h3><label className="block text-sm">Name<input className="input mt-1" value={name} onChange={e => setName(e.target.value)} required maxLength={100} /></label><label className="block text-sm">Expires in days (optional)<input className="input mt-1" type="number" min={1} max={365} value={expires} onChange={e => setExpires(e.target.value)} /></label><label className="block text-sm">API scope (optional)<input className="input mt-1" placeholder="corp-openai/v1, corp-claude/v1" value={scope} onChange={e => setScope(e.target.value)} /></label><p className="text-xs text-gray-500">Leave scope empty to allow every API your user can access. Up to 20 active keys.</p>{error && <p role="alert" className="text-sm text-red-600">{error}</p>}<div className="flex gap-2"><button type="submit" className="btn btn-primary" disabled={working || !name.trim()}>Create</button><button type="button" className="btn btn-secondary" disabled={working} onClick={() => setCreateOpen(false)}>Cancel</button></div></form></div>}
    {issued && <div className="fixed inset-0 z-[60] bg-black/50 flex items-center justify-center p-4"><div role="dialog" aria-modal="true" aria-label="Store your AI access key" className="card w-full max-w-lg p-6 space-y-4"><h3 className="font-semibold">Store your key now</h3><p className="text-sm">This key is shown once. Copy it to your secret store before closing.</p><code className="block break-all p-3 border rounded">{issued.key}</code><SignalCopyButton text={issued.key} label="Copy AI access key" /><button type="button" className="btn btn-primary block" onClick={() => setIssued(null)}>I&apos;ve stored it</button></div></div>}
    <ConfirmModal open={!!revoking} title="Revoke AI access key?" message={`Revoke ${revoking?.name || ''} (${revoking?.key_prefix || ''}…)? Applications using it will lose access.`} confirmLabel="Revoke key" loading={working} onConfirm={revoke} onCancel={() => { if (!working) setRevoking(null) }} />
  </div>
}
