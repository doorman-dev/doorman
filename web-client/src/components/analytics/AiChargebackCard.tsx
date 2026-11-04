'use client'

import { useState } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { fetchWithCsrf } from '@/utils/http'
import { SERVER_URL } from '@/utils/config'

export default function AiChargebackCard() {
  const { permissions } = useAuth()
  const [month, setMonth] = useState(new Date().toISOString().slice(0, 7))
  const [dimension, setDimension] = useState('group')
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const download = async () => {
    setWorking(true); setError(null)
    try {
      const response = await fetchWithCsrf(`${SERVER_URL}/platform/analytics/ai/export.csv?${new URLSearchParams({ month, dimension })}`)
      if (!response.ok) {
        const raw = await response.json().catch(() => ({}))
        const payload = raw.response || raw
        throw new Error(payload.error_message || response.statusText)
      }
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url; link.download = `ai-chargeback-${dimension}-${month}.csv`
      document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to download chargeback CSV') }
    finally { setWorking(false) }
  }
  return <div className="card p-6 space-y-4"><h3 className="card-title">AI chargeback</h3><p className="text-sm text-gray-600">Export monthly usage and cost metadata. Users in multiple groups contribute to each group; group totals can double-count. Prompt and completion content is excluded.</p><div className="flex flex-wrap gap-4 items-end"><label className="text-sm">Month (UTC)<input type="month" className="input mt-1" value={month} onChange={e => setMonth(e.target.value)} /></label><label className="text-sm">Dimension<select className="input mt-1" value={dimension} onChange={e => setDimension(e.target.value)}><option value="group">Group</option><option value="user">User</option></select></label><button type="button" className="btn btn-primary" onClick={download} disabled={working || !month || !permissions?.export_logs}>{working ? 'Downloading…' : 'Download CSV'}</button></div>{!permissions?.export_logs && <p className="text-sm text-gray-500">Export Logs permission is required to download chargeback CSV.</p>}{error && <p role="alert" className="text-sm text-red-600">{error}</p>}</div>
}
