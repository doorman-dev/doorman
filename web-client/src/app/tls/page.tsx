'use client'

import { useCallback, useEffect, useState } from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { useAuth } from '@/contexts/AuthContext'
import { getJson, postJson, putJson, delJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'

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

const fieldClass = 'w-full rounded border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 dark:border-gray-600 dark:bg-gray-800 dark:text-white'
const buttonClass = 'rounded bg-primary-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50'

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
        <div className="mx-auto max-w-5xl space-y-6 p-6 text-gray-900 dark:text-white">
          <div>
            <h1 className="text-2xl font-semibold">TLS certificates and profiles</h1>
            <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">Manage client trust, upstream TLS identities, and the native listener certificate.</p>
          </div>
          {error && <p role="alert" className="rounded bg-red-100 p-3 text-sm text-red-800">{error}</p>}
          {notice && <p role="status" className="rounded bg-green-100 p-3 text-sm text-green-800">{notice}</p>}

          <section className="rounded border border-gray-200 p-5 dark:border-gray-700">
            <h2 className="text-lg font-semibold">Profiles</h2>
            {loading ? <p className="mt-3 text-sm">Loading profiles…</p> : (
              <div className="mt-3 space-y-2">
                {profiles.length === 0 && <p className="text-sm text-gray-600 dark:text-gray-300">No TLS profiles configured.</p>}
                {profiles.map(item => (
                  <div key={`${item.source}:${item.id}`} className="flex flex-wrap items-center justify-between gap-3 rounded border border-gray-200 p-3 dark:border-gray-700">
                    <div>
                      <strong>{item.id}</strong>
                      <span className="ml-2 text-sm text-gray-600 dark:text-gray-300">{item.kind === 'client_ca' ? 'Client CA' : 'Upstream'} · {item.source}{item.revision ? ` · revision ${item.revision}` : ''}</span>
                    </div>
                    {!item.read_only && <div className="flex gap-2">
                      <button type="button" disabled={busy} className="text-sm text-primary-600" onClick={() => { setProfile({ ...emptyProfile, id: item.id, kind: item.kind }); setReplacing(true) }}>Replace</button>
                      <button type="button" disabled={busy} className="text-sm text-red-600" onClick={() => removeProfile(item.id)}>Delete</button>
                    </div>}
                  </div>
                ))}
              </div>
            )}
          </section>

          <form onSubmit={saveProfile} className="space-y-4 rounded border border-gray-200 p-5 dark:border-gray-700">
            <h2 className="text-lg font-semibold">{replacing ? `Replace ${profile.id}` : 'Add profile'}</h2>
            {replacing && <p className="text-sm text-gray-600 dark:text-gray-300">Enter the complete certificate material again. Existing private material cannot be displayed.</p>}
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="text-sm">Profile ID<input required disabled={replacing} className={`mt-1 ${fieldClass}`} value={profile.id} onChange={event => setProfile({ ...profile, id: event.target.value })} /></label>
              <label className="text-sm">Type<select disabled={replacing} className={`mt-1 ${fieldClass}`} value={profile.kind} onChange={event => setProfile({ ...profile, kind: event.target.value as ProfileKind })}><option value="client_ca">Client CA for inbound mTLS</option><option value="upstream">Upstream TLS profile</option></select></label>
            </div>
            <label className="block text-sm">CA bundle PEM<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={profile.ca_pem} onChange={event => setProfile({ ...profile, ca_pem: event.target.value })} /></label>
            {profile.kind === 'upstream' && <>
              <label className="block text-sm">Client certificate PEM (optional)<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={profile.cert_pem} onChange={event => setProfile({ ...profile, cert_pem: event.target.value })} /></label>
              <label className="block text-sm">Client private key PEM (required with certificate)<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={profile.key_pem} onChange={event => setProfile({ ...profile, key_pem: event.target.value })} /></label>
              <label className="block text-sm">Server name override (gRPC only, optional)<input className={`mt-1 ${fieldClass}`} value={profile.server_name} onChange={event => setProfile({ ...profile, server_name: event.target.value })} /></label>
            </>}
            <div className="flex gap-3"><button disabled={busy} className={buttonClass}>{replacing ? 'Replace profile' : 'Create profile'}</button>{replacing && <button type="button" onClick={() => { setProfile(emptyProfile); setReplacing(false) }}>Cancel</button>}</div>
          </form>

          <form onSubmit={saveBinding} className="space-y-4 rounded border border-gray-200 p-5 dark:border-gray-700">
            <div><h2 className="text-lg font-semibold">API and endpoint TLS bindings</h2><p className="text-sm text-gray-600 dark:text-gray-300">Set client certificate policy or choose an upstream TLS profile on an existing API or endpoint. API or endpoint management permission is also required.</p></div>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="text-sm">Target<select className={`mt-1 ${fieldClass}`} value={binding.target} onChange={event => setBinding({ ...binding, target: event.target.value as BindingForm['target'] })}><option value="api">API</option><option value="endpoint">Endpoint</option></select></label>
              <label className="text-sm">Setting<select className={`mt-1 ${fieldClass}`} value={binding.setting} onChange={event => setBinding({ ...binding, setting: event.target.value as BindingForm['setting'] })}><option value="client_policy">Inbound client certificate policy</option><option value="upstream_profile">Outbound TLS profile</option></select></label>
              <label className="text-sm">API name<input required className={`mt-1 ${fieldClass}`} value={binding.api_name} onChange={event => setBinding({ ...binding, api_name: event.target.value })} /></label>
              <label className="text-sm">API version<input required className={`mt-1 ${fieldClass}`} value={binding.api_version} onChange={event => setBinding({ ...binding, api_version: event.target.value })} /></label>
              {binding.target === 'endpoint' && <>
                <label className="text-sm">Endpoint method<input required className={`mt-1 ${fieldClass}`} value={binding.endpoint_method} onChange={event => setBinding({ ...binding, endpoint_method: event.target.value.toUpperCase() })} /></label>
                <label className="text-sm">Endpoint URI<input required placeholder="/items" className={`mt-1 ${fieldClass}`} value={binding.endpoint_uri} onChange={event => setBinding({ ...binding, endpoint_uri: event.target.value })} /></label>
              </>}
            </div>
            {binding.setting === 'client_policy' ? <>
              <label className="block text-sm">Policy<select className={`mt-1 ${fieldClass}`} value={binding.mode} onChange={event => setBinding({ ...binding, mode: event.target.value as BindingForm['mode'] })}><option value="inherit">Clear override</option><option value="off">Off</option><option value="optional">Optional</option><option value="required">Required</option></select></label>
              {(binding.mode === 'optional' || binding.mode === 'required') && <>
                <label className="block text-sm">Client CA profile<select required className={`mt-1 ${fieldClass}`} value={binding.ca_profile_id} onChange={event => setBinding({ ...binding, ca_profile_id: event.target.value })}><option value="">Select a CA profile</option>{profiles.filter(item => item.kind === 'client_ca').map(item => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label>
                <label className="block text-sm">Allowed DNS SANs (comma or newline separated)<textarea className={`mt-1 h-20 ${fieldClass}`} value={binding.dns_sans} onChange={event => setBinding({ ...binding, dns_sans: event.target.value })} /></label>
                <label className="block text-sm">Allowed URI SANs (comma or newline separated)<textarea className={`mt-1 h-20 ${fieldClass}`} value={binding.uri_sans} onChange={event => setBinding({ ...binding, uri_sans: event.target.value })} /></label>
              </>}
            </> : <label className="block text-sm">Upstream TLS profile<select className={`mt-1 ${fieldClass}`} value={binding.upstream_profile_id} onChange={event => setBinding({ ...binding, upstream_profile_id: event.target.value })}><option value="">Clear binding</option>{profiles.filter(item => item.kind === 'upstream').map(item => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label>}
            <button disabled={busy} className={buttonClass}>Save binding</button>
          </form>

          <form onSubmit={saveListener} className="space-y-4 rounded border border-gray-200 p-5 dark:border-gray-700">
            <div><h2 className="text-lg font-semibold">Native listener certificate</h2><p className="text-sm text-gray-600 dark:text-gray-300">Active source: {listener?.source || 'unknown'}{listener?.revision ? ` · revision ${listener.revision}` : ''}. Requires native TLS mode.</p></div>
            <label className="block text-sm">Certificate chain PEM<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={listenerCert} onChange={event => setListenerCert(event.target.value)} /></label>
            <label className="block text-sm">Private key PEM<textarea className={`mt-1 h-32 font-mono ${fieldClass}`} value={listenerKey} onChange={event => setListenerKey(event.target.value)} /></label>
            <button disabled={busy} className={buttonClass}>Activate certificate</button>
            {listener?.has_override && <button type="button" disabled={busy} className="ml-3 text-sm text-primary-600" onClick={resetListener}>Use mounted certificate</button>}
          </form>
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
