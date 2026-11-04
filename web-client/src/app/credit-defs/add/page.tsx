'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import Layout from '@/components/Layout'
import InfoTooltip from '@/components/InfoTooltip'
import FormHelp from '@/components/FormHelp'
import { SERVER_URL } from '@/utils/config'
import { postJson } from '@/utils/api'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { useAiProviders } from '@/hooks/useAiProviders'

export default function AddCreditDefPage() {
  const { providers } = useAiProviders()
  const [preset, setPreset] = useState('')
  const [api_credit_group, setGroup] = useState('')
  const [api_key_header, setHeader] = useState('x-api-key')
  const [api_key, setKey] = useState('')
  type Tier = { tier_name: string; credits: number; input_limit: number; output_limit: number; reset_frequency: string }
  const [tiers, setTiers] = useState<Tier[]>([
    { tier_name: 'basic', credits: 100, input_limit: 150, output_limit: 150, reset_frequency: 'monthly' }
  ])
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get('preset')
    const selected = providers.find(provider => provider.id === requested)
    if (selected) {
      setPreset(selected.id); setHeader(selected.credential_header)
      setGroup(previous => previous || `${selected.id.replaceAll('_', '-')}-prod`)
      setTiers([])
    }
  }, [providers])

  const create = async () => {
    setWorking(true); setError(null); setSuccess(null)
    try {
      if (!api_credit_group.trim()) throw new Error('Group is required')
      await postJson(`${SERVER_URL}/platform/credit`, { api_credit_group: api_credit_group.trim(), api_key, api_key_header, credit_tiers: tiers })
      setSuccess('Credit definition created')
    } catch (e: any) {
      setError(e?.message || 'Failed to create credit definition')
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
              <h1 className="page-title">Add Credit Definition</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">Create a credit group and tiers</p>
            </div>
            <Link href="/credits" className="btn btn-secondary">Back to Credits</Link>
          </div>

          <div className="card">
            <div className="p-6 space-y-4">
              <FormHelp docHref="/docs/using-fields.html#credits">Define a credit group, key header, optional key, and tiers.</FormHelp>
              {error && <div className="text-sm text-error-600">{error}</div>}
              {success && <div className="text-sm text-success-600">{success}</div>}
              <label className="block text-sm font-medium">Provider preset
                <select className="input mt-1" value={preset} onChange={e => {
                  setPreset(e.target.value)
                  const selected = providers.find(provider => provider.id === e.target.value)
                  if (selected) { setHeader(selected.credential_header); setGroup(previous => previous || `${selected.id.replaceAll('_', '-')}-prod`); setTiers([]) }
                }}><option value="">None</option>{providers.map(provider => <option key={provider.id} value={provider.id}>{provider.label}</option>)}</select>
              </label>
              {preset && <p className="rounded border p-3 text-sm">Use your organization&apos;s own API key from the provider console. Consumer subscriptions (ChatGPT Plus, Claude Pro) are not supported. Credit tiers are optional for provider credentials.</p>}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium">API Credit Group <InfoTooltip text="Reference name used by APIs to deduct credits and inject the key header." /></label>
                  <input className="input" value={api_credit_group} onChange={e => setGroup(e.target.value)} placeholder="ai-basic" />
                </div>
                <div>
                  <label className="block text-sm font-medium">API Key Header <InfoTooltip text="Header name injected when proxying requests (e.g., x-api-key)." /></label>
                  <input className="input" value={api_key_header} onChange={e => setHeader(e.target.value)} placeholder="x-api-key" />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium">API Key <InfoTooltip text="Default key injected for this group; per-user keys may override when Auth Required is enabled." /></label>
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
                <button onClick={create} disabled={working} className="btn btn-primary">{working ? 'Saving...' : 'Create'}</button>
                <Link href="/credits" className="btn btn-ghost">Cancel</Link>
              </div>
            </div>
          </div>
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
