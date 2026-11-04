'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import InfoTooltip from '@/components/InfoTooltip'
import FormHelp from '@/components/FormHelp'
import { SERVER_URL } from '@/utils/config'
import { getJson, putJson, delJson, fetchAllPaginated } from '@/utils/api'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import ConfirmModal from '@/components/ConfirmModal'
import { useAiProviders } from '@/hooks/useAiProviders'

export default function EditCreditDefPage() {
  const { providers } = useAiProviders()
  const [preset, setPreset] = useState('')
  const [usedBy, setUsedBy] = useState<{ api_id: string; api_name: string; api_version: string }[] | null>(null)
  const params = useParams<{ group: string }>()
  const router = useRouter()
  const group = decodeURIComponent(params.group)
  const [api_credit_group] = useState(group)
  const [api_key_header, setHeader] = useState('x-api-key')
  const [api_key, setKey] = useState('')
  type Tier = { tier_name: string; credits: number; input_limit: number; output_limit: number; reset_frequency: string }
  const [tiers, setTiers] = useState<Tier[]>([])
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [showDelete, setShowDelete] = useState(false)
  const [confirmText, setConfirmText] = useState('')

  useEffect(() => {
    let active = true
    fetchAllPaginated<{ api_id: string; api_name: string; api_version: string; api_type: string; api_ai_config?: { credential_group: string; credential_overrides?: { credential_group: string }[] } }>(
      (page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`,
      data => Array.isArray(data) ? data : data.apis || data.response?.apis || []
    ).then(apis => {
      if (active) setUsedBy(apis.filter(api => api.api_type === 'AI' && (api.api_ai_config?.credential_group === group || api.api_ai_config?.credential_overrides?.some(override => override.credential_group === group))))
    }).catch(() => {})
    return () => { active = false }
  }, [group])

  useEffect(() => { load() }, [])
  const load = async () => {
    try {
      setError(null)
      const res = await getJson<any>(`${SERVER_URL}/platform/credit/defs/${encodeURIComponent(group)}`)
      const data = res?.response || res
      setHeader(data.api_key_header || 'x-api-key')
      setTiers((data.credit_tiers || []) as Tier[])
    } catch (e:any) {
      setError(e?.message || 'Failed to load token definition')
    }
  }

  const update = async () => {
    setWorking(true); setError(null); setSuccess(null)
    try {
      const payload: any = { api_credit_group, api_key_header, credit_tiers: tiers }
      if (api_key) payload.api_key = api_key
      await putJson(`${SERVER_URL}/platform/credit/${encodeURIComponent(api_credit_group)}`, payload)
      setSuccess('Credit definition updated')
      setKey('')
    } catch (e:any) {
      setError(e?.message || 'Failed to update token definition')
    } finally {
      setWorking(false)
    }
  }

  const onDelete = async () => {
    if (confirmText !== api_credit_group) return
    setWorking(true)
    try {
      await delJson(`${SERVER_URL}/platform/credit/${encodeURIComponent(api_credit_group)}`)
      router.push('/credit-defs')
    } catch (e:any) {
      setError(e?.message || 'Failed to delete token definition')
    } finally {
      setWorking(false)
    }
  }

  return (
    <ProtectedRoute requiredPermission="manage_credits">
      <Layout>
        <div className="space-y-6">
          <div className="page-header">
            <div>
              <h1 className="page-title">Edit Credit Definition</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">{api_credit_group}</p>
            </div>
            <Link href="/credits" className="btn btn-secondary">Back to Credits</Link>
          </div>

          <div className="card">
            <div className="p-6 space-y-4">
              <FormHelp docHref="/docs/using-fields.html#credits">Edit key header, optional key, and tiers. Changes apply immediately.</FormHelp>
              {error && <div className="text-sm text-error-600">{error}</div>}
              {success && <div className="text-sm text-success-600">{success}</div>}
              <label className="block text-sm font-medium">Provider preset
                <select className="input mt-1" value={preset} onChange={e => {
                  setPreset(e.target.value)
                  const selected = providers.find(provider => provider.id === e.target.value)
                  if (selected) setHeader(selected.credential_header)
                }}><option value="">None / custom</option>{providers.map(provider => <option key={provider.id} value={provider.id}>{provider.label}</option>)}</select>
              </label>
              <p className="rounded border p-3 text-sm">Use your organization&apos;s own API key from the provider console. Consumer subscriptions (ChatGPT Plus, Claude Pro) are not supported. Provider credentials may have no credit tiers.</p>
              <p className="text-sm">Used by AI APIs: {usedBy === null ? 'Unavailable' : usedBy.length ? usedBy.map(api => <Link className="underline mr-3" key={api.api_id} href={`/apis/${encodeURIComponent(api.api_id)}`}>{api.api_name}/{api.api_version}</Link>) : 'None'}</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium">API Credit Group <InfoTooltip text="Immutable group name referenced by APIs for credits and key injection" /></label>
                  <input className="input" value={api_credit_group} readOnly />
                </div>
                <div>
                  <label className="block text-sm font-medium">API Key Header <InfoTooltip text="Header name injected when proxying (e.g., x-api-key)" /></label>
                  <input className="input" value={api_key_header} onChange={e => setHeader(e.target.value)} />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium">API Key (leave blank to keep existing) <InfoTooltip text="Optional default key for this group; leave empty to keep current. Per-user keys apply when Auth Required is enabled." /></label>
                  <input type="password" autoComplete="off" className="input" value={api_key} onChange={e => setKey(e.target.value)} placeholder="Provider API key" />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium">Credit Tiers</label>
                  <div className="overflow-x-auto border rounded">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Tier Name</th>
                          <th>Credits</th>
                          <th>Input Limit</th>
                          <th>Output Limit</th>
                          <th>Reset Freq</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {tiers.map((t, idx) => (
                          <tr key={idx}>
                            <td><input className="input" value={t.tier_name} onChange={e => setTiers(prev => prev.map((x,i)=> i===idx?{...x, tier_name: e.target.value}:x))} /></td>
                            <td><input className="input" type="number" value={t.credits} onChange={e => setTiers(prev => prev.map((x,i)=> i===idx?{...x, credits: Number(e.target.value||0)}:x))} /></td>
                            <td><input className="input" type="number" value={t.input_limit} onChange={e => setTiers(prev => prev.map((x,i)=> i===idx?{...x, input_limit: Number(e.target.value||0)}:x))} /></td>
                            <td><input className="input" type="number" value={t.output_limit} onChange={e => setTiers(prev => prev.map((x,i)=> i===idx?{...x, output_limit: Number(e.target.value||0)}:x))} /></td>
                            <td><input className="input" value={t.reset_frequency} onChange={e => setTiers(prev => prev.map((x,i)=> i===idx?{...x, reset_frequency: e.target.value}:x))} placeholder="monthly" /></td>
                            <td>
                              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setTiers(prev => prev.filter((_,i)=>i!==idx))}>Remove</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="mt-2">
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => setTiers(prev => [...prev, { tier_name: '', credits: 0, input_limit: 0, output_limit: 0, reset_frequency: 'monthly' }])}>Add Tier</button>
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={update} disabled={working} className="btn btn-primary">{working ? 'Saving...' : 'Save Changes'}</button>
                <button onClick={() => setShowDelete(true)} className="btn btn-error">Delete</button>
                <Link href="/credits" className="btn btn-ghost">Cancel</Link>
              </div>
            </div>
          </div>

          <ConfirmModal
            open={showDelete}
            title="Delete Credit Definition"
            message={<div>
              Type <span className="font-mono">{api_credit_group}</span> to confirm deletion.
              <div className="mt-3"><input className="input w-full" value={confirmText} onChange={e => setConfirmText(e.target.value)} /></div>
            </div>}
            confirmLabel={working ? 'Deleting...' : 'Delete'}
            cancelLabel="Cancel"
            onCancel={() => setShowDelete(false)}
            onConfirm={onDelete}
          />
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
