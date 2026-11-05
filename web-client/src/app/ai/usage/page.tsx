'use client'

import { useState } from 'react'
import AiPage from '@/components/AiPage'
import AiTabs, { useHashTab } from '@/components/AiTabs'
import AiUsageTab from '@/components/analytics/AiUsageTab'
import AiChargebackCard from '@/components/analytics/AiChargebackCard'
import LogsView from '@/components/LogsView'
import { useAuth } from '@/contexts/AuthContext'

const RANGES = [['7d', '7 days', 7], ['30d', '30 days', 30], ['90d', '90 days', 90]] as const
const daysAgo = (days: number) => new Date(Date.now() - days * 86400000).toISOString().slice(0, 10)

export default function AiUsagePage() {
  const { permissions, logsEnabled } = useAuth()
  const tabs = [{ id: 'spend', label: 'Spend' }, ...(permissions?.view_logs && logsEnabled ? [{ id: 'requests', label: 'Requests' }] : []), { id: 'export', label: 'Export' }]
  const [tab, setTab] = useHashTab(tabs)
  const [range, setRange] = useState<string>('30d')
  const [custom, setCustom] = useState<{ start: string; end: string } | null>(null)
  const days = RANGES.find(([id]) => id === range)?.[2] ?? 30
  const start = custom?.start || daysAgo(days)
  const end = custom?.end || new Date().toISOString().slice(0, 10)
  const pick = (id: string) => { setRange(id); setCustom(null) }

  return <AiPage title="Usage" description="Who is using AI, which models, and what it costs." permission="view_analytics"
    actions={tab === 'spend' ? <div className="flex gap-1" role="group" aria-label="Period">{RANGES.map(([id, label]) => <button key={id} type="button" aria-pressed={!custom && range === id} className={`btn ${!custom && range === id ? 'btn-primary' : 'btn-secondary'}`} onClick={() => pick(id)}>{label}</button>)}</div> : undefined}>
    <AiTabs tabs={tabs} value={tab} onChange={setTab} label="Usage sections" />
    {tab === 'spend' && <AiUsageTab start={start} end={end} refreshToken={0} onRangeChange={(s, e) => setCustom({ start: s.slice(0, 10), end: e.slice(0, 10) })} onClearRange={() => pick('30d')} />}
    {tab === 'requests' && <LogsView mode="ai" />}
    {tab === 'export' && <AiChargebackCard />}
  </AiPage>
}
