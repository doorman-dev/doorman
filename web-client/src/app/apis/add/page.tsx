'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import Layout from '@/components/Layout'
import InfoTooltip from '@/components/InfoTooltip'
import FormHelp from '@/components/FormHelp'
import { SERVER_URL } from '@/utils/config'
import { postJson, fetchAllPaginated } from '@/utils/api'
import ConfirmModal from '@/components/ConfirmModal'
import { getJson } from '@/utils/api'
import SearchableSelect from '@/components/SearchableSelect'

const STEPS = [
  { id: 'basics', title: 'Basics', hint: 'Name and protocol' },
  { id: 'upstream', title: 'Upstream', hint: 'Servers and routing' },
  { id: 'access', title: 'Access', hint: 'Who can call it' },
  { id: 'policies', title: 'Policies', hint: 'IP rules, headers, credits' },
  { id: 'review', title: 'Review', hint: 'Confirm and create' },
]

function Field({ label, htmlFor, hint, tip, required, children }: { label: string; htmlFor?: string; hint?: React.ReactNode; tip?: string; required?: boolean; children: React.ReactNode }) {
  return <div>
    <label htmlFor={htmlFor} className="block text-sm font-medium text-gray-800 mb-1">{label}{required && <span className="text-red-600"> *</span>}{tip && <InfoTooltip text={tip} />}</label>
    {children}
    {hint && <p className="text-xs text-gray-500 mt-1">{hint}</p>}
  </div>
}

function Toggle({ id, name, checked, onChange, disabled, title, description, tip }: { id: string; name: string; checked: boolean; onChange: (e: React.ChangeEvent<HTMLInputElement>) => void; disabled?: boolean; title: string; description?: React.ReactNode; tip?: string }) {
  return <div className="flex items-start gap-3 py-2">
    <input id={id} name={name} type="checkbox" className="mt-1 h-4 w-4 rounded border-gray-300" checked={checked} onChange={onChange} disabled={disabled} />
    <label htmlFor={id} className="flex-1 cursor-pointer">
      <span className="block text-sm font-medium text-gray-800">{title}{tip && <InfoTooltip text={tip} />}</span>
      {description && <span className="block text-xs font-normal text-gray-500">{description}</span>}
    </label>
  </div>
}

function Chip({ text, onRemove }: { text: string; onRemove: () => void }) {
  return <span className="inline-flex items-center gap-2 rounded border border-gray-300 bg-gray-50 px-2 py-1 text-sm">{text}<button type="button" onClick={onRemove} className="text-gray-500 hover:text-gray-800" aria-label={`Remove ${text}`}>×</button></span>
}

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return <section className="space-y-4"><div className="border-b border-gray-200 pb-2"><h3 className="text-sm font-semibold text-gray-900">{title}</h3>{description && <p className="text-xs text-gray-500">{description}</p>}</div>{children}</section>
}

const AddApiPage = () => {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [formData, setFormData] = useState({
    api_name: '',
    api_version: '',
    api_type: 'REST',
    api_description: '',
    api_hostname: '',
    api_allowed_retry_count: 0,
    api_servers: [] as string[],
    api_allowed_roles: [] as string[],
    api_allowed_groups: ['ALL'] as string[],
    api_allowed_headers: [] as string[],
    api_authorization_field_swap: '',
    api_credits_enabled: false,
    api_credit_group: '',
    api_anonymous_allowed: false,
    api_anonymous_credit_group: '',
    active: true,
    api_auth_required: true,
    api_ip_mode: 'allow_all' as 'allow_all' | 'whitelist',
    api_trust_x_forwarded_for: false,
    validation_enabled: false
  })
  const [publicConfirmOpen, setPublicConfirmOpen] = useState(false)
  const [pendingPublicValue, setPendingPublicValue] = useState<boolean | null>(null)
  const [pubCredsConfirmOpen, setPubCredsConfirmOpen] = useState(false)
  const [pendingPubCredsField, setPendingPubCredsField] = useState<null | { field: 'api_public' | 'api_credits_enabled'; value: boolean }>(null)
  const [newServer, setNewServer] = useState('')
  const [newRole, setNewRole] = useState('')
  const [newGroup, setNewGroup] = useState('')
  const [newHeader, setNewHeader] = useState('')
  const [ipWhitelistText, setIpWhitelistText] = useState('')
  const [ipBlacklistText, setIpBlacklistText] = useState('')
  const [clientIp, setClientIp] = useState('')
  const [clientIpXff, setClientIpXff] = useState('')
  const [protoFile, setProtoFile] = useState<File | null>(null)
  const [uploadProto, setUploadProto] = useState(false)
  const [step, setStep] = useState(0)

  React.useEffect(() => {
    (async () => {
      try {
        const data = await getJson<any>(`${SERVER_URL}/platform/security/settings`)
        setClientIp(String(data.client_ip || ''))
        setClientIpXff(String(data.client_ip_xff || ''))
      } catch {}
    })()
  }, [])

  const fetchRoles = async (): Promise<string[]> => {
    const items = await fetchAllPaginated<any>(
      (p, s) => `${SERVER_URL}/platform/role/all?page=${p}&page_size=${s}`,
      (data) => (Array.isArray(data) ? data : (data.roles || data.response?.roles || [])),
      undefined,
      undefined,
      'cache:roles:all'
    )
    return items.map((r: any) => r.role_name || r.name || r).filter(Boolean)
  }

  const fetchGroups = async (): Promise<string[]> => {
    const items = await fetchAllPaginated<any>(
      (p, s) => `${SERVER_URL}/platform/group/all?page=${p}&page_size=${s}`,
      (data) => (Array.isArray(data) ? data : (data.groups || data.response?.groups || [])),
      undefined,
      undefined,
      'cache:groups:all'
    )
    return items.map((g: any) => g.group_name || g.name || g).filter(Boolean)
  }

  const addMyIpToWhitelist = () => {
    const effectiveIp = (((formData as any).api_trust_x_forwarded_for && clientIpXff) ? clientIpXff : clientIp)
    if (!effectiveIp) return
    const list = ipWhitelistText.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean)
    if (list.includes(effectiveIp)) return
    setIpWhitelistText(prev => (prev && prev.trim().length > 0) ? `${prev.trim()}\n${effectiveIp}` : effectiveIp)
  }

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const payload: any = { ...formData }
      payload.api_ip_whitelist = ipWhitelistText.split(/\r?\n|,/).map((s:string) => s.trim()).filter(Boolean)
      payload.api_ip_blacklist = ipBlacklistText.split(/\r?\n|,/).map((s:string) => s.trim()).filter(Boolean)
      if (!payload.api_authorization_field_swap) delete payload.api_authorization_field_swap
      if (!payload.api_hostname) delete payload.api_hostname
      if (!payload.api_credit_group) delete payload.api_credit_group
      if (!payload.api_anonymous_credit_group) delete payload.api_anonymous_credit_group
      if (payload.api_auth_required) {
        payload.api_anonymous_allowed = false
        delete payload.api_anonymous_credit_group
      }
      if (!Array.isArray(payload.api_allowed_headers) || payload.api_allowed_headers.length === 0) delete payload.api_allowed_headers
      if (!Array.isArray(payload.api_allowed_roles) || payload.api_allowed_roles.length === 0) delete payload.api_allowed_roles
      if (!Array.isArray(payload.api_allowed_groups) || payload.api_allowed_groups.length === 0) {
        payload.api_allowed_groups = ['ALL']
      }
      const created = await postJson<any>(`${SERVER_URL}/platform/api`, payload)
      const createdApi = created?.api || created?.response?.api || created
      
      // Upload proto file if provided
      if (uploadProto && protoFile) {
        try {
          const formData = new FormData()
          formData.append('file', protoFile)
          const csrf = document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1]
          await fetch(`${SERVER_URL}/platform/proto/${encodeURIComponent(payload.api_name)}/${encodeURIComponent(payload.api_version)}`, {
            method: 'POST',
            credentials: 'include',
            headers: csrf ? { 'X-CSRF-Token': csrf } : {},
            body: formData
          })
        } catch (protoErr) {
          console.error('Proto upload failed:', protoErr)
          // Don't fail the whole operation if proto upload fails
        }
      }
      
      const newId = createdApi?.api_id
      if (newId) {
        try { sessionStorage.setItem('selectedApi', JSON.stringify(createdApi)) } catch {}
        router.push(`/apis/${encodeURIComponent(String(newId))}/endpoints?add=1`)
      } else {
        router.push('/apis')
      }
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Unable to create the API. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target
    if (name === 'api_public' && type === 'checkbox') {
      const checked = (e.target as HTMLInputElement).checked
      if (checked) {
        setPendingPublicValue(true)
        setPublicConfirmOpen(true)
        return
      }
    }
    if (name === 'api_public' && (e.target as HTMLInputElement).checked && (formData as any).api_credits_enabled) {
      setPendingPubCredsField({ field: 'api_public', value: true })
      setPubCredsConfirmOpen(true)
      return
    }
    if (name === 'api_credits_enabled' && (e.target as HTMLInputElement).checked && ((formData as any).api_public || pendingPublicValue)) {
      setPendingPubCredsField({ field: 'api_credits_enabled', value: true })
      setPubCredsConfirmOpen(true)
      return
    }
    if (name === 'api_auth_required' && type === 'checkbox' && (e.target as HTMLInputElement).checked) {
      setFormData(prev => ({
        ...prev,
        api_auth_required: true,
        api_anonymous_allowed: false,
        api_anonymous_credit_group: ''
      }))
      return
    }
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? (e.target as HTMLInputElement).checked : (name === 'api_allowed_retry_count' ? Number(value || 0) : value)
    }))
  }

  const addServer = () => {
    const value = newServer.trim()
    if (!value) return
    if (formData.api_servers.includes(value)) return
    setFormData(prev => ({ ...prev, api_servers: [...prev.api_servers, value] }))
    setNewServer('')
  }

  const removeServer = (index: number) => {
    setFormData(prev => ({ ...prev, api_servers: prev.api_servers.filter((_, i) => i !== index) }))
  }

  const addRole = () => {
    const v = newRole.trim()
    if (!v) return
    if (formData.api_allowed_roles.includes(v)) return
    setFormData(prev => ({ ...prev, api_allowed_roles: [...prev.api_allowed_roles, v] }))
    setNewRole('')
  }

  const removeRole = (index: number) => {
    setFormData(prev => ({ ...prev, api_allowed_roles: prev.api_allowed_roles.filter((_, i) => i !== index) }))
  }

  const addGroup = () => {
    const v = newGroup.trim()
    if (!v) return
    if (formData.api_allowed_groups.includes(v)) return
    setFormData(prev => ({ ...prev, api_allowed_groups: [...prev.api_allowed_groups, v] }))
    setNewGroup('')
  }

  const removeGroup = (index: number) => {
    setFormData(prev => ({ ...prev, api_allowed_groups: prev.api_allowed_groups.filter((_, i) => i !== index) }))
  }

  const addHeader = () => {
    const v = newHeader.trim()
    if (!v) return
    if (formData.api_allowed_headers.includes(v)) return
    setFormData(prev => ({ ...prev, api_allowed_headers: [...prev.api_allowed_headers, v] }))
    setNewHeader('')
  }

  const removeHeader = (index: number) => {
    setFormData(prev => ({ ...prev, api_allowed_headers: prev.api_allowed_headers.filter((_, i) => i !== index) }))
  }

  const parseList = (t: string) => t.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean)
  const ipWarning = (() => {
    const effectiveIp = (((formData as any).api_trust_x_forwarded_for && clientIpXff) ? clientIpXff : clientIp)
    const wl = parseList(ipWhitelistText)
    const bl = parseList(ipBlacklistText)
    const isIPv6 = (s: string) => s.includes(':')
    const toIPv4 = (s: string) => { const parts = s.split('.'); if (parts.length !== 4) return null as any; return parts.reduce((a, p) => (a << 8n) + (BigInt(parseInt(p, 10) & 255)), 0n) }
    const expandIPv6 = (ip: string) => { if (ip.indexOf('::') !== -1) { const [h, t] = ip.split('::'); const hp = h ? h.split(':') : []; const tp = t ? t.split(':') : []; const missing = 8 - (hp.length + tp.length); return [...hp, ...Array(Math.max(0, missing)).fill('0'), ...tp].map(x => x || '0') } return ip.split(':') }
    const toIPv6 = (s: string) => { const parts = expandIPv6(s); if (parts.length !== 8) return null as any; try { return parts.reduce((acc, h) => (acc << 16n) + BigInt(parseInt(h || '0', 16)), 0n) } catch { return null as any } }
    const matches = (ip: string, patterns: string[]) => {
      if (!ip) return false
      const v6 = isIPv6(ip)
      const ipVal = v6 ? toIPv6(ip) : toIPv4(ip)
      return patterns.some(raw => {
        const p = raw.trim(); if (!p) return false
        if (p.includes('/')) {
          const [net, maskStr] = p.split('/'); const m = parseInt(maskStr, 10)
          const n6 = isIPv6(net); if (n6 !== v6) return false
          const netVal = n6 ? toIPv6(net) : toIPv4(net); if (netVal === null || ipVal === null || isNaN(m as any)) return false
          const bits = n6 ? 128 : 32
          const shift = BigInt(bits - Math.min(Math.max(m, 0), bits))
          const mask = ((1n << BigInt(bits)) - 1n) ^ ((1n << shift) - 1n)
          return ((ipVal & mask) === (netVal & mask))
        }
        return p.toLowerCase() === ip.toLowerCase()
      })
    }
    const warnWL = formData.api_ip_mode === 'whitelist' && wl.length > 0 && !matches(effectiveIp, wl)
    const warnBL = matches(effectiveIp, bl)
    if (!(warnWL || warnBL)) return null
    return { text: warnBL ? 'Your current IP is in the blocked list. You may lose access after saving.' : 'Your current IP is not in the allowed list. You may lose access after saving.', ip: effectiveIp || 'unknown', xff: !!formData.api_trust_x_forwarded_for }
  })()

  const fd = formData as any
  const nameOk = formData.api_name.trim().length > 0 && formData.api_version.trim().length > 0
  const stepError = step === 0 && !nameOk ? 'Enter an API name and version to continue.' : null
  const isLast = step === STEPS.length - 1
  const goNext = () => { if (stepError) { setError(stepError); return } setError(null); setStep(s => Math.min(s + 1, STEPS.length - 1)) }
  const goBack = () => { setError(null); setStep(s => Math.max(s - 1, 0)) }
  const jump = (i: number) => { if (i > 0 && !nameOk) { setError('Enter an API name and version to continue.'); setStep(0); return } setError(null); setStep(i) }

  const yesNo = (v: boolean) => (v ? 'Yes' : 'No')
  const reviewRows: [string, React.ReactNode][] = [
    ['Name / version', `${formData.api_name || '—'} / ${formData.api_version || '—'}`],
    ['Protocol', formData.api_type],
    ['Enabled on creation', yesNo(!!formData.active)],
    ['Upstream servers', formData.api_servers.length ? formData.api_servers.join(', ') : 'None (add later)'],
    ['Custom hostname', formData.api_hostname || '—'],
    ['Retry attempts', String(formData.api_allowed_retry_count)],
    ['Authentication required', yesNo(!!formData.api_auth_required)],
    ['Public access', yesNo(!!fd.api_public)],
    ['Allowed groups', formData.api_allowed_groups.join(', ') || 'ALL'],
    ['Allowed roles', formData.api_allowed_roles.join(', ') || 'Any'],
    ['IP policy', formData.api_ip_mode === 'whitelist' ? `Allow list only (${parseList(ipWhitelistText).length} entries)` : 'Allow all'],
    ['Blocked IPs', String(parseList(ipBlacklistText).length)],
    ['Credits', formData.api_credits_enabled ? `On (${formData.api_credit_group || 'no group'})` : 'Off'],
    ['gRPC proto file', uploadProto && protoFile ? protoFile.name : '—'],
  ]

  return (
    <Layout>
      <div className="space-y-5 max-w-4xl">
        <div className="page-header">
          <div>
            <h1 className="page-title">Add API</h1>
            <p className="text-gray-600 mt-1">Step {step + 1} of {STEPS.length}: {STEPS[step].hint}</p>
          </div>
          <Link href="/apis" className="btn btn-secondary">Cancel</Link>
        </div>

        <ol className="flex items-center gap-2" aria-label="Progress">
          {STEPS.map((s, i) => (
            <li key={s.id} className="flex flex-1 items-center gap-2">
              <button type="button" onClick={() => jump(i)} aria-current={i === step ? 'step' : undefined}
                className={`flex w-full items-center gap-2 rounded border px-3 py-2 text-left text-sm ${i === step ? 'border-primary-600 bg-primary-50 text-gray-900' : i < step ? 'border-gray-300 bg-white text-gray-700' : 'border-gray-200 bg-white text-gray-500'}`}>
                <span className={`flex h-5 w-5 flex-none items-center justify-center rounded-full text-xs font-semibold ${i === step ? 'bg-primary-600 text-white' : i < step ? 'bg-gray-700 text-white' : 'bg-gray-200 text-gray-600'}`}>{i < step ? '✓' : i + 1}</span>
                <span className="font-medium">{s.title}</span>
              </button>
            </li>
          ))}
        </ol>

        {error && <div className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{error}</div>}

        <form onSubmit={(e) => { e.preventDefault(); if (isLast) handleSubmit(); else goNext() }} className="card space-y-6 !p-6">
          {step === 0 && (
            <Section title="Basics" description="These identify the API and form the base path clients call, e.g. /name/version.">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Field label="API name" htmlFor="api_name" required hint="Unique identifier, e.g. user-service">
                  <input id="api_name" name="api_name" type="text" className="input" placeholder="user-service" value={formData.api_name} onChange={handleChange} disabled={loading} autoFocus />
                </Field>
                <Field label="Version" htmlFor="api_version" required hint="e.g. v1, v2">
                  <input id="api_version" name="api_version" type="text" className="input" placeholder="v1" value={formData.api_version} onChange={handleChange} disabled={loading} />
                </Field>
              </div>
              <Field label="Protocol" htmlFor="api_type" hint="The protocol this API speaks to its upstream servers.">
                <select id="api_type" name="api_type" className="input md:w-1/2" value={formData.api_type} onChange={handleChange} disabled={loading}>
                  <option value="REST">REST</option><option value="GraphQL">GraphQL</option><option value="gRPC">gRPC</option><option value="SOAP">SOAP</option>
                </select>
              </Field>
              <Field label="Description" htmlFor="api_description" hint="Optional. Shown in the API list.">
                <textarea id="api_description" name="api_description" rows={3} className="input resize-none" placeholder="What does this API do?" value={formData.api_description} onChange={handleChange} disabled={loading} />
              </Field>
              <Toggle id="active" name="active" checked={!!formData.active} onChange={handleChange} disabled={loading} title="Enable this API" description="Disabled APIs reject all requests until switched on." />
            </Section>
          )}

          {step === 1 && (<>
            <Section title="Upstream servers" description="Base URLs that requests are proxied to. You can override these per endpoint later.">
              <Field label="Server URL" hint="Include scheme and port, e.g. http://localhost:8080. Press Enter to add." tip="Base URLs for upstreams. Include scheme and port.">
                <div className="flex gap-2">
                  <input type="text" className="input flex-1" placeholder="http://localhost:8080" value={newServer} onChange={(e) => setNewServer(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addServer() } }} disabled={loading} />
                  <button type="button" onClick={addServer} className="btn btn-secondary" disabled={loading}>Add server</button>
                </div>
              </Field>
              <div className="flex flex-wrap gap-2">
                {formData.api_servers.map((srv, idx) => <Chip key={idx} text={srv} onRemove={() => removeServer(idx)} />)}
                {formData.api_servers.length === 0 && <p className="text-xs text-gray-500">No servers added yet.</p>}
              </div>
            </Section>
            <Section title="Routing and requests">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Field label="Custom hostname (optional)" htmlFor="api_hostname" tip="Requests with this Host header are routed to this API, preserving the original path and query." hint="Leave blank to use the standard path-based URL.">
                  <input id="api_hostname" name="api_hostname" type="text" className="input" placeholder="api.example.com" value={formData.api_hostname} onChange={handleChange} disabled={loading} />
                </Field>
                <Field label="Retry attempts" htmlFor="api_allowed_retry_count" hint="Retries on upstream failure. 0 disables retries.">
                  <input id="api_allowed_retry_count" type="number" name="api_allowed_retry_count" className="input" min={0} value={formData.api_allowed_retry_count} onChange={handleChange} disabled={loading} />
                </Field>
              </div>
              <Field label="Forward Authorization as header (optional)" htmlFor="api_authorization_field_swap" tip="Copies the inbound Authorization header into a different header name expected by the upstream, e.g. X-Api-Key." hint="Header name the upstream expects instead of Authorization.">
                <input id="api_authorization_field_swap" type="text" name="api_authorization_field_swap" className="input md:w-1/2" placeholder="X-Api-Key" value={formData.api_authorization_field_swap} onChange={handleChange} disabled={loading} />
              </Field>
            </Section>
            {formData.api_type === 'gRPC' && (
              <Section title="gRPC proto file (optional)" description="Uploaded and compiled automatically after the API is created.">
                <Toggle id="upload_proto" name="upload_proto" checked={uploadProto} onChange={(e) => { setUploadProto(e.target.checked); if (!e.target.checked) setProtoFile(null) }} title="Upload a .proto file" />
                {uploadProto && (
                  <div className="flex items-center gap-3">
                    <label className="btn btn-secondary cursor-pointer">Choose file
                      <input type="file" accept=".proto,text/plain" style={{ display: 'none' }} onChange={(e) => {
                        const file = e.target.files?.[0]
                        if (file) {
                          if (!file.name.endsWith('.proto')) { alert('Please select a .proto file'); e.target.value = ''; return }
                          setProtoFile(file)
                        }
                      }} />
                    </label>
                    {protoFile && <span className="text-sm">{protoFile.name} <button type="button" className="ml-2 text-red-700" onClick={() => setProtoFile(null)}>Remove</button></span>}
                  </div>
                )}
              </Section>
            )}
          </>)}

          {step === 2 && (<>
            <Section title="Authentication" description="Controls whether callers must sign in.">
              <Toggle id="api_auth_required" name="api_auth_required" checked={!!formData.api_auth_required} onChange={handleChange} disabled={loading} title="Require authentication" description="Callers must present a valid platform token and pass subscription and group checks." />
              <Toggle id="api_anonymous_allowed" name="api_anonymous_allowed" checked={!!formData.api_anonymous_allowed} onChange={handleChange} disabled={loading || !!formData.api_auth_required} title="Allow anonymous access" description={formData.api_auth_required ? 'Turn off “Require authentication” to enable.' : 'Unauthenticated callers are tracked as anonymous users by IP.'} />
              {fd.api_public && fd.api_credits_enabled && <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">Public + credits: anyone can call this API and the group API key is injected. Per-user deductions are skipped.</div>}
              <Toggle id="api_public" name="api_public" checked={!!fd.api_public} onChange={handleChange} disabled={loading || fd.api_credits_enabled === true} title="Public access" description={fd.api_credits_enabled ? 'Turn off credits to change this.' : 'Anyone with the URL can call this API. Authentication, subscription and group checks are skipped. Use with care.'} />
            </Section>
            <Section title="Who can call it" description="Enforced only when authentication is required.">
              <Field label="Allowed groups" tip="Users must belong to at least one listed group. ALL allows any group." hint="Add ALL to allow every group.">
                <SearchableSelect value={newGroup} onChange={setNewGroup} onAdd={addGroup} onKeyPress={(e) => e.key === 'Enter' && addGroup()} placeholder="Select a group" fetchOptions={fetchGroups} disabled={loading} addButtonText="Add" restrictToOptions />
                <div className="mt-2 flex flex-wrap gap-2">{formData.api_allowed_groups.map((g, i) => <Chip key={i} text={g} onRemove={() => removeGroup(i)} />)}</div>
              </Field>
              <Field label="Allowed roles" tip="Users must have at least one listed platform role." hint="Leave empty to allow any role.">
                <SearchableSelect value={newRole} onChange={setNewRole} onAdd={addRole} onKeyPress={(e) => e.key === 'Enter' && addRole()} placeholder="Select a role" fetchOptions={fetchRoles} disabled={loading} addButtonText="Add" restrictToOptions />
                <div className="mt-2 flex flex-wrap gap-2">{formData.api_allowed_roles.map((r, i) => <Chip key={i} text={r} onRemove={() => removeRole(i)} />)}</div>
              </Field>
            </Section>
          </>)}

          {step === 3 && (<>
            <Section title="IP access control" description="Optional network restrictions for this API.">
              {ipWarning && <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">{ipWarning.text}<div className="text-xs mt-1">Your IP: {ipWarning.ip}{ipWarning.xff ? ' (from X-Forwarded-For)' : ''}</div></div>}
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Field label="Access policy" htmlFor="api_ip_mode" hint="With “Allow list only”, only listed IPs can call this API. The blocked list is always checked first.">
                  <select id="api_ip_mode" name="api_ip_mode" className="input" value={formData.api_ip_mode} onChange={(e) => setFormData(p => ({ ...p, api_ip_mode: e.target.value as any }))}>
                    <option value="allow_all">Allow all</option><option value="whitelist">Allow list only</option>
                  </select>
                </Field>
                <Toggle id="api_trust_x_forwarded_for" name="api_trust_x_forwarded_for" checked={!!formData.api_trust_x_forwarded_for} onChange={(e) => setFormData(p => ({ ...p, api_trust_x_forwarded_for: e.target.checked }))} title="Trust X-Forwarded-For" description="Use when Doorman is behind a proxy. The proxy must be in the platform's trusted proxies." />
              </div>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Field label="Allowed IPs / CIDRs" hint="One per line or comma-separated. Used only with “Allow list only”.">
                  <textarea className="input min-h-[110px]" value={ipWhitelistText} onChange={(e) => setIpWhitelistText(e.target.value)} placeholder={'10.0.0.0/8\n192.168.1.100'} />
                  <button type="button" className="btn btn-ghost btn-xs mt-1" onClick={addMyIpToWhitelist}>Add my IP</button>
                </Field>
                <Field label="Blocked IPs / CIDRs" hint="Always checked first; matches are denied.">
                  <textarea className="input min-h-[110px]" value={ipBlacklistText} onChange={(e) => setIpBlacklistText(e.target.value)} placeholder={'203.0.113.0/24\n203.0.113.50'} />
                </Field>
              </div>
            </Section>
            <Section title="Forwarded response headers" description="Upstream response headers Doorman may pass back to the client.">
              <Field label="Header name" tip={formData.api_type === 'SOAP' ? 'Use lowercase names, e.g. x-rate-limit, retry-after. For SOAP, common request headers (Content-Type, SOAPAction, Accept, User-Agent) are allowed automatically.' : 'Use lowercase names, e.g. x-rate-limit, retry-after.'}>
                <div className="flex gap-2">
                  <input type="text" className="input flex-1" placeholder="x-rate-limit" value={newHeader} onChange={(e) => setNewHeader(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addHeader() } }} disabled={loading} />
                  <button type="button" onClick={addHeader} className="btn btn-secondary" disabled={loading}>Add header</button>
                </div>
                <div className="mt-2 flex flex-wrap gap-2">{formData.api_allowed_headers.map((h, i) => <Chip key={i} text={h} onRemove={() => removeHeader(i)} />)}</div>
              </Field>
            </Section>
            <Section title="Credits" description="Charge credits for each request.">
              <Toggle id="api_credits_enabled" name="api_credits_enabled" checked={!!formData.api_credits_enabled} onChange={handleChange} disabled={loading || fd.api_public === true} title="Charge credits per request" description={fd.api_public ? 'Turn off public access to enable.' : 'Each request deducts credits before it is proxied.'} />
              {formData.api_credits_enabled && (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <Field label="Credit group" htmlFor="api_credit_group" tip="Determines which API key header is injected, e.g. ai-basic.">
                    <input id="api_credit_group" type="text" name="api_credit_group" className="input" placeholder="ai-group-1" value={formData.api_credit_group} onChange={handleChange} disabled={loading} />
                  </Field>
                  {formData.api_anonymous_allowed && (
                    <Field label="Anonymous credit group (optional)" htmlFor="api_anonymous_credit_group" hint="Defaults to the credit group.">
                      <input id="api_anonymous_credit_group" type="text" name="api_anonymous_credit_group" className="input" placeholder={formData.api_credit_group || 'anon-group'} value={formData.api_anonymous_credit_group} onChange={handleChange} disabled={loading} />
                    </Field>
                  )}
                </div>
              )}
            </Section>
          </>)}

          {step === 4 && (
            <Section title="Review" description="Check the details below. After you create the API you can add its endpoints right away.">
              <dl className="divide-y divide-gray-100 rounded border border-gray-200">
                {reviewRows.map(([k, v]) => <div key={k} className="grid grid-cols-3 gap-4 px-4 py-2 text-sm"><dt className="text-gray-500">{k}</dt><dd className="col-span-2 break-words text-gray-900">{v}</dd></div>)}
              </dl>
              {formData.api_servers.length === 0 && <p className="text-sm text-amber-800">No upstream servers are set. Requests will fail until you add one.</p>}
            </Section>
          )}

          <div className="flex items-center justify-between border-t border-gray-200 pt-4">
            <button type="button" className="btn btn-secondary" onClick={goBack} disabled={step === 0 || loading}>Back</button>
            {isLast ? (
              <button type="submit" disabled={loading || !nameOk} className="btn btn-primary">{loading ? 'Creating…' : 'Create API and add endpoints'}</button>
            ) : (
              <button type="submit" className="btn btn-primary" disabled={loading}>Continue</button>
            )}
          </div>
        </form>
      </div>
      <ConfirmModal
        open={publicConfirmOpen}
        title="Make API Public?"
        message={<div>
          <p className="mb-2">This API will be public. Anyone with the URL can call it.</p>
          <p className="text-amber-600">Authentication, subscriptions, and group checks will be skipped.</p>
        </div>}
        confirmLabel="Make Public"
        onConfirm={() => {
          setPublicConfirmOpen(false)
          if (pendingPublicValue) {
            setFormData(prev => ({ ...prev, api_public: true as any }))
          }
          setPendingPublicValue(null)
        }}
        onCancel={() => {
          setPublicConfirmOpen(false)
          setPendingPublicValue(null)
        }}
      />

      <ConfirmModal
        open={pubCredsConfirmOpen}
        title="Public API with Credits?"
        message={<div>
          <p className="mb-2">Enabling Credits on a Public API injects the group API key for anyone calling this API.</p>
          <p className="text-amber-600">User-level deductions/keys are skipped for public/no-auth calls.</p>
        </div>}
        confirmLabel="Proceed"
        onConfirm={() => {
          setPubCredsConfirmOpen(false)
          if (pendingPubCredsField) {
            setFormData(prev => ({ ...prev, [pendingPubCredsField.field]: pendingPubCredsField.value as any }))
          }
          setPendingPubCredsField(null)
        }}
        onCancel={() => {
          setPubCredsConfirmOpen(false)
          setPendingPubCredsField(null)
        }}
      />
    </Layout>
  )
}

export default AddApiPage
