'use client'

import { useCallback, useEffect, useState } from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { useAuth } from '@/contexts/AuthContext'
import { getJson, postJson, putJson, delJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { SignalPageHeader, SignalPanel, SignalTable } from '@/components/signal/Signal'

type ProfileKind = 'client_ca' | 'upstream'
type Profile = { id: string; kind: ProfileKind; source: 'file' | 'admin'; revision?: number; read_only: boolean }
type Listener = { source: 'file' | 'admin'; revision: number | null; has_override: boolean }
type ProfileForm = {
  id: string
  kind: ProfileKind
  ca_pem: string
  cert_pem: string
  key_pem: string
  server_name: string
}
type BindingForm = {
  target: 'api' | 'endpoint'
  setting: 'client_policy' | 'upstream_profile'
  api_name: string
  api_version: string
  endpoint_method: string
  endpoint_uri: string
  mode: 'inherit' | 'off' | 'optional' | 'required'
  ca_profile_id: string
  dns_sans: string
  uri_sans: string
  upstream_profile_id: string
}

const emptyProfile: ProfileForm = {
  id: '', kind: 'client_ca', ca_pem: '', cert_pem: '', key_pem: '', server_name: ''
}
const emptyBinding: BindingForm = {
  target: 'api', setting: 'client_policy', api_name: '', api_version: '', endpoint_method: 'GET',
  endpoint_uri: '', mode: 'inherit', ca_profile_id: '', dns_sans: '', uri_sans: '', upstream_profile_id: ''
}

const TABS = [
  { id: 'profiles', label: 'Profiles' },
  { id: 'bindings', label: 'API & endpoint bindings' },
  { id: 'listener', label: 'Listener certificate' },
] as const
type TabId = typeof TABS[number]['id']

const fieldClass = 'input w-full'
const buttonClass = 'btn btn-primary'

export default function TlsPage() {
  const { authResolved, permissions } = useAuth()
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [listener, setListener] = useState<Listener | null>(null)
  const [profile, setProfile] = useState<ProfileForm>(emptyProfile)
  const [binding, setBinding] = useState<BindingForm>(emptyBinding)
  const [replacing, setReplacing] = useState(false)
  const [listenerCert, setListenerCert] = useState('')
  const [listenerKey, setListenerKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [tab, setTab] = useState<TabId>('profiles')
  useEffect(() => {
    const h = window.location.hash.replace('#', '')
    if (TABS.some(t => t.id === h)) setTab(h as TabId)
  }, [])
  const selectTab = (id: TabId) => { setTab(id); setError(''); setNotice(''); try { window.history.replaceState(null, '', `#${id}`) } catch {} }

  const refresh = useCallback(async () => {
    const [profileData, listenerData] = await Promise.all([
      getJson<{ profiles: Profile[] }>(`${SERVER_URL}/platform/tls/profiles`),
      getJson<Listener>(`${SERVER_URL}/platform/tls/listener`)
    ])
    setProfiles(profileData.profiles || [])
    setListener(listenerData)
  }, [])

  useEffect(() => {
    if (!authResolved || !permissions?.manage_security) return
    refresh().catch(err => setError(String(err?.message || err))).finally(() => setLoading(false))
  }, [authResolved, permissions?.manage_security, refresh])

  const run = async (action: () => Promise<unknown>, message: string): Promise<boolean> => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await action()
      await refresh()
      setNotice(message)
      return true
    } catch (err: any) {
      setError(String(err?.message || err))
      return false
    } finally {
      setBusy(false)
    }
  }

  const saveProfile = async (event: React.FormEvent) => {
    event.preventDefault()
    const id = profile.id.trim()
    if (!id || (profile.kind === 'client_ca' && !profile.ca_pem.trim()) ||
        (!!profile.cert_pem !== !!profile.key_pem)) {
      setError('Provide an ID, a CA bundle for client CA profiles, and both client certificate and key when using upstream mTLS.')
      return
    }
    const body = {
      id, kind: profile.kind,
      ...(profile.ca_pem ? { ca_pem: profile.ca_pem } : {}),
      ...(profile.kind === 'upstream' && profile.cert_pem ? { cert_pem: profile.cert_pem, key_pem: profile.key_pem } : {}),
      ...(profile.kind === 'upstream' && profile.server_name.trim() ? { server_name: profile.server_name.trim() } : {})
    }
    const saved = await run(
      () => replacing
        ? putJson(`${SERVER_URL}/platform/tls/profiles/${encodeURIComponent(id)}`, body)
        : postJson(`${SERVER_URL}/platform/tls/profiles`, body),
      replacing ? 'TLS profile replaced.' : 'TLS profile created.'
    )
    if (saved) {
      setProfile(emptyProfile)
      setReplacing(false)
    }
  }

  const removeProfile = async (id: string) => {
    if (!window.confirm(`Delete TLS profile ${id}?`)) return
    await run(() => delJson(`${SERVER_URL}/platform/tls/profiles/${encodeURIComponent(id)}`), 'TLS profile deleted.')
  }

  const saveListener = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!listenerCert.trim() || !listenerKey.trim()) {
      setError('Provide both the listener certificate and private key.')
      return
    }
    const saved = await run(
      () => putJson(`${SERVER_URL}/platform/tls/listener`, { cert_pem: listenerCert, key_pem: listenerKey }),
      'Listener certificate activated.'
    )
    if (saved) {
      setListenerCert('')
      setListenerKey('')
    }
  }

  const resetListener = async () => {
    if (!window.confirm('Remove the stored listener certificate and use the mounted certificate?')) return
    await run(() => delJson(`${SERVER_URL}/platform/tls/listener`), 'Mounted listener certificate activated.')
  }

  const saveBinding = async (event: React.FormEvent) => {
    event.preventDefault()
    const name = binding.api_name.trim()
    const version = binding.api_version.trim()
    const uri = binding.endpoint_uri.trim().replace(/^\/+/, '')
    if (!name || !version || (binding.target === 'endpoint' && !uri)) {
      setError('Enter the API name and version, and an endpoint URI when targeting an endpoint.')
      return
    }
    const prefix = binding.target === 'api' ? 'api' : 'endpoint'
    const path = binding.target === 'api'
      ? `/platform/api/${encodeURIComponent(name)}/${encodeURIComponent(version)}`
      : `/platform/endpoint/${encodeURIComponent(binding.endpoint_method)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/${uri.split('/').map(encodeURIComponent).join('/')}`
    let value: unknown
    if (binding.setting === 'upstream_profile') {
      value = binding.upstream_profile_id || null
    } else if (binding.mode === 'inherit') {
      value = null
    } else if (binding.mode === 'off') {
      value = { mode: 'off' }
    } else {
      const dns = binding.dns_sans.split(/[,\n]/).map(item => item.trim()).filter(Boolean)
      const uris = binding.uri_sans.split(/[,\n]/).map(item => item.trim()).filter(Boolean)
      if (!binding.ca_profile_id || (dns.length === 0 && uris.length === 0)) {
        setError('Select a client CA and enter at least one permitted DNS or URI SAN.')
        return
      }
      value = { mode: binding.mode, ca_profile_id: binding.ca_profile_id, allowed_dns_sans: dns, allowed_uri_sans: uris }
    }
    const field = binding.setting === 'client_policy' ? `${prefix}_client_tls_policy` : `${prefix}_upstream_tls_profile`
    await run(() => putJson(path, { [field]: value }), 'TLS binding saved.')
  }

  return (
    <ProtectedRoute requiredPermission="manage_security">
      <Layout>
        <div className="space-y-6">
          <SignalPageHeader kicker="Security" title="TLS certificates and profiles" description="Manage client trust, upstream TLS identities, and the native listener certificate. Private keys are encrypted at rest and never shown again after saving." />
          {error && <div role="alert" className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
          {notice && <div role="status" className="rounded border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">{notice}</div>}

          <div role="tablist" aria-label="TLS sections" className="flex gap-1 border-b border-gray-200">
            {TABS.map(t => (
              <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} onClick={() => selectTab(t.id)}
                className={`-mb-px border-b-2 px-4 py-2 text-sm font-medium ${tab === t.id ? 'border-primary-600 text-primary-700' : 'border-transparent text-gray-600 hover:text-gray-900'}`}>
                {t.label}{t.id === 'profiles' ? ` (${profiles.length})` : ''}
              </button>
            ))}
          </div>


          {tab === 'profiles' && (<>
          <SignalPanel tone="white" title="Profiles" kicker={`${profiles.length} configured`}>
            {loading ? <p className="text-sm text-gray-500">Loading profiles…</p> : profiles.length === 0 ? <p className="py-4 text-center text-sm text-gray-500">No TLS profiles configured. Add one below.</p> : (
              <SignalTable>
                <thead><tr><th>ID</th><th>Type</th><th>Source</th><th>Revision</th><th className="w-40">Actions</th></tr></thead>
                <tbody>
                  {profiles.map(item => (
                    <tr key={`${item.source}:${item.id}`}>
                      <td><strong>{item.id}</strong></td>
                      <td><span className="badge badge-secondary">{item.kind === 'client_ca' ? 'Client CA' : 'Upstream'}</span></td>
                      <td>{item.source}{item.read_only ? ' (read-only)' : ''}</td>
                      <td>{item.revision ?? '—'}</td>
                      <td>{!item.read_only && <div className="flex gap-2">
                        <button type="button" disabled={busy} className="btn btn-secondary btn-xs" onClick={() => { setProfile({ ...emptyProfile, id: item.id, kind: item.kind }); setReplacing(true); window.scrollTo({ top: document.body.scrollHeight / 3, behavior: 'smooth' }) }}>Replace</button>
                        <button type="button" disabled={busy} className="btn btn-error btn-xs" onClick={() => removeProfile(item.id)}>Delete</button>
                      </div>}</td>
                    </tr>
                  ))}
                </tbody>
              </SignalTable>
            )}
          </SignalPanel>

          <SignalPanel tone="white" title={replacing ? `Replace ${profile.id}` : 'Add profile'} kicker="Create or replace a profile">
          <form onSubmit={saveProfile} className="space-y-4">
              {replacing && <p className="text-sm text-gray-600">Enter the complete certificate material again. Existing private material cannot be displayed.</p>}
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">Profile ID<input required disabled={replacing} className={`mt-1 ${fieldClass}`} value={profile.id} onChange={event => setProfile({ ...profile, id: event.target.value })} /></label>
                <label className="block">Type<select disabled={replacing} className={`mt-1 ${fieldClass}`} value={profile.kind} onChange={event => setProfile({ ...profile, kind: event.target.value as ProfileKind })}><option value="client_ca">Client CA for inbound mTLS</option><option value="upstream">Upstream TLS profile</option></select></label>
              </div>
              <label className="block">CA bundle PEM<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={profile.ca_pem} onChange={event => setProfile({ ...profile, ca_pem: event.target.value })} /></label>
              {profile.kind === 'upstream' && <>
                <label className="block">Client certificate PEM (optional)<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={profile.cert_pem} onChange={event => setProfile({ ...profile, cert_pem: event.target.value })} /></label>
                <label className="block">Client private key PEM (required with certificate)<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={profile.key_pem} onChange={event => setProfile({ ...profile, key_pem: event.target.value })} /></label>
                <label className="block">Server name override (gRPC only, optional)<input className={`mt-1 ${fieldClass}`} value={profile.server_name} onChange={event => setProfile({ ...profile, server_name: event.target.value })} /></label>
              </>}
              <div className="flex gap-3"><button disabled={busy} className={buttonClass}>{replacing ? 'Replace profile' : 'Create profile'}</button>{replacing && <button type="button" className="btn btn-secondary" onClick={() => { setProfile(emptyProfile); setReplacing(false) }}>Cancel</button>}</div>
            </form>
          </SignalPanel>
          </>)}


          {tab === 'bindings' && (<>
          <SignalPanel tone="white" title={'API and endpoint TLS bindings'} kicker="Apply a profile to an API or endpoint">
          <p className="mb-4 text-sm text-gray-600">Set the client certificate policy, or choose an upstream TLS profile, on an existing API or endpoint. API or endpoint management permission is also required.</p>
          <form onSubmit={saveBinding} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">Target<select className={`mt-1 ${fieldClass}`} value={binding.target} onChange={event => setBinding({ ...binding, target: event.target.value as BindingForm['target'] })}><option value="api">API</option><option value="endpoint">Endpoint</option></select></label>
                <label className="block">Setting<select className={`mt-1 ${fieldClass}`} value={binding.setting} onChange={event => setBinding({ ...binding, setting: event.target.value as BindingForm['setting'] })}><option value="client_policy">Inbound client certificate policy</option><option value="upstream_profile">Outbound TLS profile</option></select></label>
                <label className="block">API name<input required className={`mt-1 ${fieldClass}`} value={binding.api_name} onChange={event => setBinding({ ...binding, api_name: event.target.value })} /></label>
                <label className="block">API version<input required className={`mt-1 ${fieldClass}`} value={binding.api_version} onChange={event => setBinding({ ...binding, api_version: event.target.value })} /></label>
                {binding.target === 'endpoint' && <>
                  <label className="block">Endpoint method<input required className={`mt-1 ${fieldClass}`} value={binding.endpoint_method} onChange={event => setBinding({ ...binding, endpoint_method: event.target.value.toUpperCase() })} /></label>
                  <label className="block">Endpoint URI<input required placeholder="/items" className={`mt-1 ${fieldClass}`} value={binding.endpoint_uri} onChange={event => setBinding({ ...binding, endpoint_uri: event.target.value })} /></label>
                </>}
              </div>
              {binding.setting === 'client_policy' ? <>
                <label className="block">Policy<select className={`mt-1 ${fieldClass}`} value={binding.mode} onChange={event => setBinding({ ...binding, mode: event.target.value as BindingForm['mode'] })}><option value="inherit">Clear override</option><option value="off">Off</option><option value="optional">Optional</option><option value="required">Required</option></select></label>
                {(binding.mode === 'optional' || binding.mode === 'required') && <>
                  <label className="block">Client CA profile<select required className={`mt-1 ${fieldClass}`} value={binding.ca_profile_id} onChange={event => setBinding({ ...binding, ca_profile_id: event.target.value })}><option value="">Select a CA profile</option>{profiles.filter(item => item.kind === 'client_ca').map(item => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label>
                  <label className="block">Allowed DNS SANs (comma or newline separated)<textarea className={`mt-1 h-20 ${fieldClass}`} value={binding.dns_sans} onChange={event => setBinding({ ...binding, dns_sans: event.target.value })} /></label>
                  <label className="block">Allowed URI SANs (comma or newline separated)<textarea className={`mt-1 h-20 ${fieldClass}`} value={binding.uri_sans} onChange={event => setBinding({ ...binding, uri_sans: event.target.value })} /></label>
                </>}
              </> : <label className="block">Upstream TLS profile<select className={`mt-1 ${fieldClass}`} value={binding.upstream_profile_id} onChange={event => setBinding({ ...binding, upstream_profile_id: event.target.value })}><option value="">Clear binding</option>{profiles.filter(item => item.kind === 'upstream').map(item => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label>}
              <div><button disabled={busy} className={buttonClass}>Save binding</button></div>
            </form>
          </SignalPanel>
          </>)}

          {tab === 'listener' && (<>
          <SignalPanel tone="white" title={'Native listener certificate'} kicker="Server identity">
          <p className="mb-4 text-sm text-gray-600">Active source: {listener?.source || 'unknown'}{listener?.revision ? ` · revision ${listener.revision}` : ''}. Requires native TLS mode.</p>
          <form onSubmit={saveListener} className="space-y-4">
              <label className="block">Certificate chain PEM<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={listenerCert} onChange={event => setListenerCert(event.target.value)} /></label>
              <label className="block">Private key PEM<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={listenerKey} onChange={event => setListenerKey(event.target.value)} /></label>
              <button disabled={busy} className={buttonClass}>Activate certificate</button>
              {listener?.has_override && <button type="button" disabled={busy} className="btn btn-secondary ml-3" onClick={resetListener}>Use mounted certificate</button>}
            </form>
          </SignalPanel>
          </>)}
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
