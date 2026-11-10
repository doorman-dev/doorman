'use client'

import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { delJson, getJson, postJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import Link from 'next/link'
import UnpricedModelsNotice from '@/components/UnpricedModelsNotice'
import { formatBudgetAmount, nanosToUsd, USD_PATTERN, usdToNanos, type AiBudgetAction, type AiBudgetListRow, type AiBudgetPeriod } from '@/utils/ai'

const NAME = 'Personal AI spend limit'
const PERIODS: [AiBudgetPeriod, string][] = [['day', 'Per day'], ['week', 'Per week'], ['month', 'Per month']]
const ACTIONS: [AiBudgetAction, string][] = [['block', 'Block requests'], ['warn', 'Warn only']]

const forUser = (row: AiBudgetListRow, username: string) => row.scope === 'user' && row.target === username
/**
 * The cap this card manages: the one-person dollar allowance it created (by
 * name). Allowances made under AI → Allowances are listed, never edited here,
 * so a downgrade action, short period or provider filter is never overwritten.
 */
const isCardCap = (row: AiBudgetListRow, username: string) =>
  forUser(row, username) && row.name === NAME && row.limit_type === 'cost' && !row.provider && PERIODS.some(([id]) => id === row.period) && ACTIONS.some(([id]) => id === row.action)

export default function AiSpendLimitCard({ username }: { username: string }) {
  const { permissions } = useAuth()
  const canManage = !!permissions?.manage_ai
  const [existing, setExisting] = useState<AiBudgetListRow | null>(null)
  const [others, setOthers] = useState<AiBudgetListRow[]>([])
  const [amount, setAmount] = useState('')
  const [period, setPeriod] = useState<AiBudgetPeriod>('month')
  const [action, setAction] = useState<AiBudgetAction>('block')
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [message, setMessage] = useState<{ error: boolean; text: string } | null>(null)

  const load = useCallback(async () => {
    if (!canManage) return
    setLoading(true)
    try {
      const result = await getJson<{ budgets: AiBudgetListRow[] }>(`${SERVER_URL}/platform/ai/budgets`)
      const row = result.budgets.find(item => isCardCap(item, username)) || null
      setExisting(row)
      setOthers(result.budgets.filter(item => forUser(item, username) && item !== row))
      setAmount(row ? nanosToUsd(row.limit_value) : '')
      setPeriod(row ? row.period : 'month')
      setAction(row ? row.action : 'block')
    } catch (reason) {
      setMessage({ error: true, text: reason instanceof Error ? reason.message : 'Could not load the spend limit' })
    } finally { setLoading(false) }
  }, [canManage, username])
  useEffect(() => { load() }, [load])

  if (!canManage) return null

  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    setMessage(null)
    const limit = usdToNanos(amount)
    if (limit === null) { setMessage({ error: true, text: 'Enter a positive dollar amount, e.g. 25 or 12.50.' }); return }
    const body = { name: NAME, scope: 'user', target: username, period, limit_type: 'cost', limit_value: limit, action, downgrade_model: null, warn_at_percent: existing?.warn_at_percent ?? 80, enabled: true, provider: null, per_user: false }
    setWorking(true)
    try {
      if (existing) await putJson(`${SERVER_URL}/platform/ai/budgets/${encodeURIComponent(existing.budget_id)}`, body)
      else await postJson(`${SERVER_URL}/platform/ai/budgets`, body)
      setMessage({ error: false, text: 'Spend limit saved.' })
      await load()
    } catch (reason) {
      setMessage({ error: true, text: reason instanceof Error ? reason.message : 'Could not save the spend limit' })
    } finally { setWorking(false) }
  }

  const remove = async () => {
    if (!existing) return
    setMessage(null); setWorking(true)
    try {
      await delJson(`${SERVER_URL}/platform/ai/budgets/${encodeURIComponent(existing.budget_id)}`)
      setMessage({ error: false, text: 'Spend limit removed.' })
      await load()
    } catch (reason) {
      setMessage({ error: true, text: reason instanceof Error ? reason.message : 'Could not remove the spend limit' })
    } finally { setWorking(false) }
  }

  return <section className="card p-6 space-y-4">
    <div>
      <h3 className="card-title">AI spend limit</h3>
      <p className="text-sm text-gray-500">The most this person can spend on AI, across every model and key. Group, tier and company allowances still apply; the tightest one wins.</p>
    </div>
    {loading ? <p className="text-sm">Loading…</p> : <form onSubmit={save} className="grid gap-3 sm:grid-cols-[1fr_1fr_1fr_auto] sm:items-end">
      <label className="block text-sm">Limit (USD)
        <input className="input w-full mt-1" inputMode="decimal" pattern={USD_PATTERN} title="A dollar amount, e.g. 25 or 12.50" placeholder="No personal limit" value={amount} onChange={event => setAmount(event.target.value)} required />
      </label>
      <label className="block text-sm">Period
        <select className="input w-full mt-1" value={period} onChange={event => setPeriod(event.target.value as AiBudgetPeriod)}>{PERIODS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select>
      </label>
      <label className="block text-sm">At the limit
        <select className="input w-full mt-1" value={action} onChange={event => setAction(event.target.value as AiBudgetAction)}>{ACTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select>
      </label>
      <div className="flex gap-2">
        <button type="submit" className="btn btn-primary" disabled={working}>{existing ? 'Update' : 'Set limit'}</button>
        {existing && <button type="button" className="btn btn-ghost" disabled={working} onClick={remove}>Remove</button>}
      </div>
    </form>}
    {others.length > 0 && <div className="text-sm space-y-1">
      <p className="text-gray-500">Other allowances for this person (edit them under <Link href="/ai/allowances" className="font-medium">AI → Allowances</Link>):</p>
      <ul className="list-disc pl-5">{others.map(row => <li key={row.budget_id}>{row.name}: {formatBudgetAmount(row.limit_type, row.limit_value)} per {row.period}, {row.action}{row.provider ? `, ${row.provider} only` : ''}{row.enabled ? '' : ' (disabled)'}</li>)}</ul>
    </div>}
    <UnpricedModelsNotice />
    {message && <p role={message.error ? 'alert' : 'status'} className={`text-sm ${message.error ? 'text-red-600' : 'text-gray-500'}`}>{message.text}</p>}
  </section>
}
