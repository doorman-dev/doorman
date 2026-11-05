'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import AiPage from '@/components/AiPage'
import AiTabs, { useHashTab } from '@/components/AiTabs'
import AiPricingPanel from '@/components/AiPricingPanel'
import AiBackupsEditor, { backupsSummary } from '@/components/AiBackupsEditor'
import { useAuth } from '@/contexts/AuthContext'
import { fetchAllPaginated, getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { formatTokens, formatUsd, providerLabel, type AiApiConfig, type AiBreakdown, type AiUsageRow } from '@/utils/ai'

interface AiApi {
  api_id?: string
  api_name: string
  api_version: string
  api_type: string
  api_ai_provider?: string
  api_ai_config?: Partial<AiApiConfig>
  api_allowed_groups?: string[]
  api_servers?: string[]
}

const TABS = [{ id: 'providers', label: 'Providers' }, { id: 'prices', label: 'Model prices' }]

function ProviderCard({ api, usage, canEdit, onBackups }: { api: AiApi; usage?: AiUsageRow; canEdit: boolean; onBackups: () => void }) {
  const config = api.api_ai_config || {}
  const hasKey = !!config.credential_group && config.credential_group !== 'none'
  const models = config.allowed_models?.length ? config.allowed_models : ['Any model']
  const aliases = Object.entries(config.model_aliases || {})
  const groups = (api.api_allowed_groups || []).filter(group => group !== 'admin')
  const who = config.require_subscription === false ? (groups.includes('ALL') || !groups.length ? 'Everyone' : groups.join(', ')) : 'Subscribed users'
  return <article className="card p-5 flex flex-col gap-4 min-w-0">
    <div className="flex items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="text-base font-semibold text-gray-900">{providerLabel(api.api_ai_provider || '')}</h2>
        <p className="text-xs text-gray-500 break-all">{api.api_name}/{api.api_version}</p>
      </div>
      <span className={`ai-chip ${hasKey ? 'ai-chip--ok' : config.credential_group === 'none' ? 'ai-chip--off' : 'ai-chip--warn'}`}>{hasKey ? 'Key set' : config.credential_group === 'none' ? 'No key needed' : 'No key'}</span>
    </div>
    <dl className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
      <dt className="text-gray-500">Models</dt><dd className="min-w-0 break-words">{models.join(', ')}</dd>
      {aliases.length > 0 && <><dt className="text-gray-500">Aliases</dt><dd className="min-w-0 break-words">{aliases.map(([alias, model]) => `${alias} → ${model}`).join(', ')}</dd></>}
      <dt className="text-gray-500">Who can use it</dt><dd>{who}</dd>
      <dt className="text-gray-500">Backups</dt><dd>{backupsSummary(config)}</dd>
      <dt className="text-gray-500">Last 30 days</dt><dd className="tabular-nums">{usage ? `${formatTokens(usage.requests)} requests · ${formatUsd(usage.cost_nanos)}` : 'No traffic'}</dd>
    </dl>
    {canEdit && api.api_id && <div className="mt-auto flex gap-2 border-t border-gray-100 pt-3"><Link href={`/apis/${encodeURIComponent(api.api_id)}`} className="btn btn-secondary">Edit</Link><button type="button" className="btn btn-secondary" onClick={onBackups}>Backups</button></div>}
  </article>
}

export default function AiProvidersPage() {
  const { permissions } = useAuth()
  const [tab, setTab] = useHashTab(TABS)
  const [apis, setApis] = useState<AiApi[] | null>(null)
  const [usage, setUsage] = useState<Map<string, AiUsageRow>>(new Map())
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState<AiApi | null>(null)

  useEffect(() => {
    let active = true
    fetchAllPaginated<AiApi>(
      (page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`,
      data => Array.isArray(data) ? data : data.apis || data.response?.apis || []
    ).then(all => { if (active) setApis(all.filter(api => api.api_type === 'AI').sort((a, b) => a.api_name.localeCompare(b.api_name))) })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Could not load providers') })
    getJson<AiBreakdown>(`${SERVER_URL}/platform/analytics/ai/breakdown?dimension=api&limit=200`)
      .then(result => { if (active) setUsage(new Map(result.rows.map(row => [row.key, row]))) })
      .catch(() => {})
    return () => { active = false }
  }, [])

  const canManage = !!permissions?.manage_ai
  return <AiPage title="Providers" description="The AI providers your company offers, their models and who can use them." permission="manage_apis"
    actions={tab === 'providers' && canManage ? <Link href="/ai/setup" className="btn btn-primary">Add provider</Link> : undefined}>
    <AiTabs tabs={TABS} value={tab} onChange={setTab} label="Providers sections" />
    {tab === 'providers' && <>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {!apis && !error && <p className="text-sm text-gray-500">Loading providers…</p>}
      {apis && !apis.length && <div className="card p-10 text-center space-y-3"><h2 className="text-lg font-semibold">No AI providers yet</h2><p className="text-sm text-gray-600">Add a provider key, pick who can use it and set allowances.</p>{canManage && <Link href="/ai/setup" className="btn btn-primary">Add provider</Link>}</div>}
      {apis && apis.length > 0 && <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{apis.map(api => <ProviderCard key={`${api.api_name}/${api.api_version}`} api={api} usage={usage.get(`${api.api_name}/${api.api_version}`) || usage.get(api.api_name)} canEdit={!!permissions?.manage_apis} onBackups={() => setEditing(api)} />)}</div>}
      {apis && apis.length > 0 && <p className="text-xs text-gray-500">Need full control? <Link href="/apis/add?type=AI" className="underline">Add a provider manually</Link>.</p>}
    </>}
    {tab === 'prices' && <AiPricingPanel canManage={canManage} />}
    {editing && <AiBackupsEditor apiName={editing.api_name} apiVersion={editing.api_version} config={editing.api_ai_config || {}} onClose={() => setEditing(null)}
      onSaved={config => { setApis(current => current && current.map(api => api === editing ? { ...api, api_ai_config: config } : api)); setEditing(null) }} />}
  </AiPage>
}
