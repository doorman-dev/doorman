'use client'

import { useState } from 'react'
import AiPage from '@/components/AiPage'
import AiUsageTab from '@/components/analytics/AiUsageTab'
import AiChargebackCard from '@/components/analytics/AiChargebackCard'

const RANGES = [['7d', 'Last 7 days', 7], ['30d', 'Last 30 days', 30], ['90d', 'Last 90 days', 90]] as const
const daysAgo = (days: number) => new Date(Date.now() - days * 86400000).toISOString().slice(0, 10)

export default function AiUsagePage() {
  const [range, setRange] = useState<string>('30d')
  const [custom, setCustom] = useState<{ start: string; end: string } | null>(null)
  const [refreshToken, setRefreshToken] = useState(0)
  const days = RANGES.find(([id]) => id === range)?.[2] ?? 30
  const start = custom?.start || daysAgo(days)
  const end = custom?.end || new Date().toISOString().slice(0, 10)
  const pick = (id: string) => { setRange(id); setCustom(null) }

  return <AiPage title="Usage" description="AI spend and tokens by employee, group, role, tier, provider and model." permission="view_analytics"
    actions={<div className="flex flex-wrap gap-2">{RANGES.map(([id, label]) => <button key={id} type="button" aria-pressed={!custom && range === id} className={`btn ${!custom && range === id ? 'btn-primary' : 'btn-secondary'}`} onClick={() => pick(id)}>{label}</button>)}<button type="button" className="btn btn-secondary" onClick={() => setRefreshToken(value => value + 1)}>Refresh</button></div>}>
    <div className="card p-6"><AiUsageTab start={start} end={end} refreshToken={refreshToken} onRangeChange={(s, e) => setCustom({ start: s.slice(0, 10), end: e.slice(0, 10) })} onClearRange={() => pick('30d')} /></div>
    <div id="chargeback"><AiChargebackCard /></div>
  </AiPage>
}
