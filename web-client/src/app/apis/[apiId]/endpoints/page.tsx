'use client'

import React, { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import { SERVER_URL } from '@/utils/config'
import { getJson, postJson } from '@/utils/api'
import ConfirmModal from '@/components/ConfirmModal'
import {
  SignalBreadcrumbs,
  SignalCopyButton,
  SignalEmptyState,
  SignalMethodFilter,
  SignalPageHeader,
  SignalPanel,
  SignalSearchInput,
  SignalTable
} from '@/components/signal/Signal'

interface EndpointItem {
  api_name: string
  api_version: string
  endpoint_method: string
  endpoint_uri: string
  client_uri?: string
  endpoint_description?: string
  endpoint_id?: string
  endpoint_servers?: string[]
}

export default function ApiEndpointsPage() {
  const params = useParams()
  const router = useRouter()
  const apiId = params.apiId as string
  const [apiName, setApiName] = useState('')
  const [apiVersion, setApiVersion] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([])
  const [allEndpoints, setAllEndpoints] = useState<EndpointItem[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [sortBy, setSortBy] = useState<'method' | 'uri' | 'servers'>('method')
  const [working, setWorking] = useState<Record<string, boolean>>({})
  const [epNewServer, setEpNewServer] = useState<Record<string, string>>({})
  const [editingDescription, setEditingDescription] = useState<string | null>(null)
  const [editedDescriptionValue, setEditedDescriptionValue] = useState('')
  const [editingClientUri, setEditingClientUri] = useState<string | null>(null)
  const [editedClientUriValue, setEditedClientUriValue] = useState('')

  type EpValidation = {
    loading: boolean
    exists: boolean
    enabled: boolean
    schemaText: string
    saving: boolean
    error: string | null
  }
  const [validationByEndpoint, setValidationByEndpoint] = useState<Record<string, EpValidation>>({})

  const ensureValidationLoaded = async (ep: EndpointItem) => {
    const eid = ep.endpoint_id
    if (!eid) return
    if (validationByEndpoint[eid]?.loading === false && validationByEndpoint[eid] !== undefined) return
    setValidationByEndpoint(prev => ({
      ...prev,
      [eid]: { loading: true, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: null }
    }))
    try {
      const { fetchWithCsrf } = await import('@/utils/http')
      const resp = await fetchWithCsrf(`${SERVER_URL}/platform/endpoint/validation/${encodeURIComponent(eid)}`, {
        headers: { 'Accept': 'application/json' }
      })
      if (resp.ok) {
        const data = await resp.json().catch(() => ({}))
        const payload = data.response || data
        const enabled = !!payload.validation_enabled
        const schema = payload.validation_schema || {}
        setValidationByEndpoint(prev => ({
          ...prev,
          [eid]: {
            loading: false,
            exists: true,
            enabled,
            schemaText: JSON.stringify(schema, null, 2),
            saving: false,
            error: null
          }
        }))
      } else if (resp.status === 404) {
        setValidationByEndpoint(prev => ({
          ...prev,
          [eid]: { loading: false, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: null }
        }))
      } else {
        setValidationByEndpoint(prev => ({
          ...prev,
          [eid]: { loading: false, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: 'Failed to load validation' }
        }))
      }
    } catch (e) {
      setValidationByEndpoint(prev => ({
        ...prev,
        [eid]: { loading: false, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: 'Failed to load validation' }
      }))
    }
  }

  const saveValidation = async (ep: EndpointItem) => {
    const eid = ep.endpoint_id
    if (!eid) return
    const cur = validationByEndpoint[eid]
    if (!cur) return
    setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...cur, saving: true, error: null } }))
    try {
      let schema: any = {}
      try { schema = JSON.parse(cur.schemaText || '{}') } catch { throw new Error('Schema must be valid JSON') }
      const body = JSON.stringify({ validation_enabled: !!cur.enabled, validation_schema: schema })
      const url = `${SERVER_URL}/platform/endpoint/validation/${encodeURIComponent(eid)}`
      const resp = await fetch(url, {
        method: 'PUT',
        credentials: 'include',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.error_message || 'Failed to save validation')
      }
      setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...prev[eid], saving: false, exists: true } }))
      setSuccess('Validation saved')
      setTimeout(() => setSuccess(null), 2000)
    } catch (e: any) {
      setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...prev[eid], saving: false, error: e?.message || 'Failed to save validation' } }))
    }
  }

  const createValidation = async (ep: EndpointItem) => {
    const eid = ep.endpoint_id
    if (!eid) return
    const cur = validationByEndpoint[eid]
    if (!cur) return
    setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...cur, saving: true, error: null } }))
    try {
      let schema: any = {}
      try { schema = JSON.parse(cur.schemaText || '{}') } catch { throw new Error('Schema must be valid JSON') }
      const body = JSON.stringify({ endpoint_id: eid, validation_enabled: !!cur.enabled, validation_schema: schema })
      const { fetchWithCsrf } = await import('@/utils/http')
      const resp = await fetchWithCsrf(`${SERVER_URL}/platform/endpoint/validation`, {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.error_message || 'Failed to create validation')
      }
      setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...prev[eid], saving: false, exists: true } }))
      setSuccess('Validation created')
      setTimeout(() => setSuccess(null), 2000)
    } catch (e: any) {
      setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...prev[eid], saving: false, error: e?.message || 'Failed to create validation' } }))
    }
  }

  const deleteValidation = async (ep: EndpointItem) => {
    const eid = ep.endpoint_id
    if (!eid) return
    const cur = validationByEndpoint[eid]
    if (!cur) return
    setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...cur, saving: true, error: null } }))
    try {
      const { fetchWithCsrf } = await import('@/utils/http')
      const resp = await fetchWithCsrf(`${SERVER_URL}/platform/endpoint/validation/${encodeURIComponent(eid)}`, {
        method: 'DELETE',
        headers: { 'Accept': 'application/json' }
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.error_message || 'Failed to delete validation')
      }
      setValidationByEndpoint(prev => ({ ...prev, [eid]: { loading: false, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: null } }))
      setSuccess('Validation deleted')
      setTimeout(() => setSuccess(null), 2000)
    } catch (e: any) {
      setValidationByEndpoint(prev => ({ ...prev, [eid]: { ...prev[eid], saving: false, error: e?.message || 'Failed to delete validation' } }))
    }
  }

  useEffect(() => {
    const initApi = async () => {
      try {
        const apiData = sessionStorage.getItem('selectedApi')
        if (apiData) {
          const parsed = JSON.parse(apiData)
          if (parsed.api_name && parsed.api_version) {
            setApiName(parsed.api_name)
            setApiVersion(parsed.api_version)
            return
          }
        }
      } catch { }

      try {
        const data = await getJson<any>(`${SERVER_URL}/platform/api/all`)
        const list = Array.isArray(data) ? data : (data.apis || data.response?.apis || [])
        const found = (list || []).find((a: any) => String(a.api_id) === String(apiId))
        if (found) {
          setApiName(found.api_name || '')
          setApiVersion(found.api_version || '')
        }
      } catch (err) {
        console.error('Failed to load api details:', err)
      }
    }
    initApi()
  }, [apiId])

  const loadEndpoints = async () => {
    setLoading(true)
    setError(null)
    const attempt = async () => {
      if (!apiName || !apiVersion) return
      const { fetchJson } = await import('@/utils/http')
      const data = await fetchJson(`${SERVER_URL}/platform/endpoint/${encodeURIComponent(apiName)}/${encodeURIComponent(apiVersion)}`)
      let list: any[] = []
      if (data) {
        list = Array.isArray(data) ? data : (data.endpoints || data.response?.endpoints || [])
      }
      setEndpoints(list)
      setAllEndpoints(list)
    }
    try {
      await attempt()
    } catch (e: any) {
      try {
        await new Promise(r => setTimeout(r, 200))
        await attempt()
      } catch (err: any) {
        setError(err?.message || 'Failed to load endpoints')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (apiName && apiVersion) {
      loadEndpoints()
    } else {
      // Don't set loading false immediately, wait for API lookup
    }
  }, [apiName, apiVersion])

  const keyFor = (ep: EndpointItem) => `${ep.endpoint_method}:${ep.endpoint_uri}`
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set())
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [deleteConfirmation, setDeleteConfirmation] = useState('')
  const [endpointToDelete, setEndpointToDelete] = useState<EndpointItem | null>(null)
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState({ method: 'GET', uri: '', clientUri: '', description: '' })
  const [draftBusy, setDraftBusy] = useState(false)
  const [draftError, setDraftError] = useState<string | null>(null)
  const draftUriRef = React.useRef<HTMLInputElement>(null)

  useEffect(() => {
    try { if (new URLSearchParams(window.location.search).get('add') === '1') setAdding(true) } catch {}
  }, [])
  useEffect(() => { if (adding) draftUriRef.current?.focus() }, [adding])

  const submitDraft = async (keepOpen: boolean) => {
    const uri = draft.uri.trim()
    if (!uri) { setDraftError('Enter a URI for the endpoint.'); draftUriRef.current?.focus(); return }
    setDraftBusy(true); setDraftError(null)
    try {
      const body: any = {
        api_name: apiName,
        api_version: apiVersion,
        endpoint_method: draft.method,
        endpoint_uri: uri.startsWith('/') ? uri : '/' + uri,
        endpoint_description: draft.description.trim() || `${draft.method} ${uri}`
      }
      if (draft.clientUri.trim()) body.client_uri = draft.clientUri.trim()
      await postJson(`${SERVER_URL}/platform/endpoint`, body)
      setSuccess(`Added ${draft.method} ${body.endpoint_uri}`)
      setTimeout(() => setSuccess(null), 2000)
      setDraft(d => ({ ...d, uri: '', clientUri: '', description: '' }))
      await loadEndpoints()
      if (keepOpen) draftUriRef.current?.focus(); else setAdding(false)
    } catch (e: any) {
      setDraftError(e?.message || 'Failed to add endpoint')
    } finally {
      setDraftBusy(false)
    }
  }
  const draftKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') { e.preventDefault(); submitDraft(true) }
    if (e.key === 'Escape') { setAdding(false); setDraftError(null) }
  }

  const methodCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: allEndpoints.length }
    for (const ep of allEndpoints) {
      const m = ep.endpoint_method.toUpperCase()
      counts[m] = (counts[m] || 0) + 1
    }
    return counts
  }, [allEndpoints])

  const filtered = useMemo(() => {
    let list = allEndpoints
    if (methodFilter !== 'ALL') {
      list = list.filter(ep => ep.endpoint_method.toUpperCase() === methodFilter)
    }
    const t = searchTerm.trim().toLowerCase()
    if (t) {
      list = list.filter(ep =>
        ep.endpoint_method.toLowerCase().includes(t) ||
        ep.endpoint_uri.toLowerCase().includes(t) ||
        (ep.client_uri || '').toLowerCase().includes(t) ||
        (ep.endpoint_description || '').toLowerCase().includes(t)
      )
    }
    const sorted = [...list].sort((a, b) => {
      if (sortBy === 'method') return a.endpoint_method.localeCompare(b.endpoint_method)
      if (sortBy === 'uri') return a.endpoint_uri.localeCompare(b.endpoint_uri)
      const ac = (a.endpoint_servers || []).length
      const bc = (b.endpoint_servers || []).length
      return ac - bc
    })
    return sorted
  }, [allEndpoints, searchTerm, sortBy, methodFilter])

  const deleteEndpoint = async (ep: EndpointItem) => {
    const k = keyFor(ep)
    setWorking(prev => ({ ...prev, [k]: true }))
    setError(null)
    try {
      const { delJson } = await import('@/utils/api')
      await delJson(`${SERVER_URL}/platform/endpoint/${encodeURIComponent(ep.endpoint_method)}/${encodeURIComponent(ep.api_name)}/${encodeURIComponent(ep.api_version)}/${encodeURIComponent(ep.endpoint_uri.replace(/^\//, ''))}`)

      // Close modal and clear state first
      setShowDeleteModal(false)
      setDeleteConfirmation('')
      setEndpointToDelete(null)

      // Optimistically remove from state immediately
      setAllEndpoints(prev => prev.filter(item => keyFor(item) !== k))
      setEndpoints(prev => prev.filter(item => keyFor(item) !== k))

      // Then reload from server to ensure consistency
      await loadEndpoints()
      setSuccess('Endpoint deleted')
      setTimeout(() => setSuccess(null), 2000)
    } catch (e: any) {
      setError(e?.message || 'Failed to delete endpoint')
    } finally {
      setWorking(prev => ({ ...prev, [k]: false }))
    }
  }

  const handleDeleteClick = (ep: EndpointItem, e?: React.MouseEvent) => {
    if (e) e.stopPropagation()
    setEndpointToDelete(ep)
    setDeleteConfirmation('')
    setShowDeleteModal(true)
  }

  const saveEndpointServers = async (ep: EndpointItem, servers: string[]) => {
    const k = keyFor(ep)
    setWorking(prev => ({ ...prev, [k]: true }))
    setError(null)
    try {
      const { putJson } = await import('@/utils/api')
      await putJson(`${SERVER_URL}/platform/endpoint/${encodeURIComponent(ep.endpoint_method)}/${encodeURIComponent(ep.api_name)}/${encodeURIComponent(ep.api_version)}/${encodeURIComponent(ep.endpoint_uri.replace(/^\//, ''))}`, { endpoint_servers: servers })
      await loadEndpoints()
      setSuccess('Endpoint servers updated')
      setTimeout(() => setSuccess(null), 2000)
    } catch (e: any) {
      setError(e?.message || 'Failed to update endpoint')
    } finally {
      setWorking(prev => ({ ...prev, [k]: false }))
    }
  }

  const addEndpointServer = async (ep: EndpointItem) => {
    const k = keyFor(ep)
    const value = (epNewServer[k] || '').trim()
    if (!value) return
    const next = [...(ep.endpoint_servers || [])]
    if (!next.includes(value)) next.push(value)
    await saveEndpointServers(ep, next)
    setEpNewServer(prev => ({ ...prev, [k]: '' }))
  }

  const removeEndpointServer = async (ep: EndpointItem, index: number) => {
    const next = (ep.endpoint_servers || []).filter((_, i) => i !== index)
    await saveEndpointServers(ep, next)
  }

  const startEditDescription = (ep: EndpointItem) => {
    const k = keyFor(ep)
    setEditingDescription(k)
    setEditedDescriptionValue(ep.endpoint_description || '')
  }

  const cancelEditDescription = () => {
    setEditingDescription(null)
    setEditedDescriptionValue('')
  }

  const saveDescription = async (ep: EndpointItem) => {
    const k = keyFor(ep)
    setWorking(prev => ({ ...prev, [k]: true }))
    setError(null)
    try {
      const { putJson } = await import('@/utils/api')
      await putJson(`${SERVER_URL}/platform/endpoint/${encodeURIComponent(ep.endpoint_method)}/${encodeURIComponent(ep.api_name)}/${encodeURIComponent(ep.api_version)}/${encodeURIComponent(ep.endpoint_uri.replace(/^\//, ''))}`, { endpoint_description: editedDescriptionValue })
      await loadEndpoints()
      setSuccess('Endpoint description updated')
      setTimeout(() => setSuccess(null), 2000)
      setEditingDescription(null)
      setEditedDescriptionValue('')
    } catch (e: any) {
      setError(e?.message || 'Failed to update endpoint description')
    } finally {
      setWorking(prev => ({ ...prev, [k]: false }))
    }
  }

  const startEditClientUri = (ep: EndpointItem) => {
    const k = keyFor(ep)
    setEditingClientUri(k)
    setEditedClientUriValue(ep.client_uri || '')
  }

  const cancelEditClientUri = () => {
    setEditingClientUri(null)
    setEditedClientUriValue('')
  }

  const saveClientUri = async (ep: EndpointItem) => {
    const k = keyFor(ep)
    // Basic validation
    if (editedClientUriValue && !editedClientUriValue.startsWith('/')) {
      setError('Client URI must start with /')
      return
    }
    setWorking(prev => ({ ...prev, [k]: true }))
    setError(null)
    try {
      const { putJson } = await import('@/utils/api')
      await putJson(`${SERVER_URL}/platform/endpoint/${encodeURIComponent(ep.endpoint_method)}/${encodeURIComponent(ep.api_name)}/${encodeURIComponent(ep.api_version)}/${encodeURIComponent(ep.endpoint_uri.replace(/^\//, ''))}`, { client_uri: editedClientUriValue || null })
      await loadEndpoints()
      setSuccess('Client URI updated')
      setTimeout(() => setSuccess(null), 2000)
      setEditingClientUri(null)
      setEditedClientUriValue('')
    } catch (e: any) {
      setError(e?.message || 'Failed to update client URI')
    } finally {
      setWorking(prev => ({ ...prev, [k]: false }))
    }
  }

  return (
    <Layout>
      <div className="space-y-6">
        <SignalBreadcrumbs
          items={[
            { label: 'APIs', href: '/apis' },
            { label: `${apiName || 'API'} (${apiVersion || 'v1'})`, href: `/apis/${encodeURIComponent(apiId)}` },
            { label: 'Endpoints' }
          ]}
        />

        <SignalPageHeader
          kicker="Route Policy"
          title={<>Endpoints for {apiName}/{apiVersion}</>}
          description="Create, edit, and delete endpoints. Precedence: Routing (client-key) → Endpoint servers → API servers."
          actions={
            <div className="flex gap-2">
              <button type="button" className="signal-button signal-button--primary" onClick={() => setAdding(true)} disabled={adding}>
                Add Endpoint
              </button>
              <Link href={`/apis/${encodeURIComponent(apiId)}`} className="signal-button btn-secondary">
                Back to API
              </Link>
            </div>
          }
        />

        {success && (
          <div className="rounded-lg bg-success-50 border border-success-200 p-4 dark:bg-success-900/20 dark:border-success-800">
            <div className="flex"><p className="text-sm text-success-700 dark:text-success-300">{success}</p></div>
          </div>
        )}
        {error && (
          <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
            <div className="flex"><p className="text-sm text-error-700 dark:text-error-300">{error}</p></div>
          </div>
        )}

        <SignalPanel tone="white" title="Search and Filters" kicker="Route discovery">
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row gap-4">
              <SignalSearchInput
                value={searchTerm}
                onChange={setSearchTerm}
                placeholder="Search endpoints by method, URI, or description..."
                className="flex-1"
              />

              <div className="flex gap-2">
                <button onClick={() => setSortBy('method')} className={`signal-button text-xs ${sortBy === 'method' ? 'signal-button--primary' : 'btn-secondary'}`}>
                  Method {sortBy === 'method' && '▲'}
                </button>
                <button onClick={() => setSortBy('uri')} className={`signal-button text-xs ${sortBy === 'uri' ? 'signal-button--primary' : 'btn-secondary'}`}>
                  URI {sortBy === 'uri' && '▲'}
                </button>
                <button onClick={() => setSortBy('servers')} className={`signal-button text-xs ${sortBy === 'servers' ? 'signal-button--primary' : 'btn-secondary'}`}>
                  Servers {sortBy === 'servers' && '▲'}
                </button>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t-2 border-signal-ink">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold uppercase text-signal-mist">Filter Method:</span>
                <SignalMethodFilter selected={methodFilter} onChange={setMethodFilter} counts={methodCounts} />
              </div>
              <div className="font-mono text-xs text-signal-mist uppercase font-bold">
                Showing {filtered.length} of {allEndpoints.length} endpoints
              </div>
            </div>
          </div>
        </SignalPanel>

        <SignalPanel tone="white" title="Configured Endpoints" kicker={`Active Registry (${filtered.length})`}>
          <SignalTable>
            <thead>
              <tr>
                <th className="w-8"></th>
                <th>Method</th>
                <th>URI (Backend)</th>
                <th>Client URI</th>
                <th>Description</th>
                <th>Routing</th>
                <th>Servers</th>
                <th className="w-28">Actions</th>
              </tr>
            </thead>
            <tbody>
              {adding && (<>
                <tr className="signal-draft-row">
                  <td></td>
                  <td>
                    <select className="input" aria-label="Method" value={draft.method} onChange={e => setDraft(d => ({ ...d, method: e.target.value }))} disabled={draftBusy}>
                      {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
                    </select>
                  </td>
                  <td><input ref={draftUriRef} className="input" aria-label="Backend URI" placeholder="/backend/path/{id}" value={draft.uri} onChange={e => setDraft(d => ({ ...d, uri: e.target.value }))} onKeyDown={draftKey} disabled={draftBusy} /></td>
                  <td><input className="input" aria-label="Client URI" placeholder="Same as backend" value={draft.clientUri} onChange={e => setDraft(d => ({ ...d, clientUri: e.target.value }))} onKeyDown={draftKey} disabled={draftBusy} /></td>
                  <td><input className="input" aria-label="Description" placeholder="Description (optional)" value={draft.description} onChange={e => setDraft(d => ({ ...d, description: e.target.value }))} onKeyDown={draftKey} disabled={draftBusy} /></td>
                  <td className="text-xs text-gray-500">Default</td>
                  <td className="text-xs text-gray-500">API servers</td>
                  <td>
                    <div className="flex gap-1">
                      <button type="button" className="btn btn-primary btn-xs" onClick={() => submitDraft(true)} disabled={draftBusy} title="Add and start another (Enter)">{draftBusy ? '…' : 'Add'}</button>
                      <button type="button" className="btn btn-ghost btn-xs" onClick={() => { setAdding(false); setDraftError(null) }} disabled={draftBusy} aria-label="Cancel">✕</button>
                    </div>
                  </td>
                </tr>
                <tr className="signal-draft-hint"><td></td><td colSpan={7} className="text-xs text-gray-500">{draftError ? <span className="text-red-700">{draftError}</span> : 'Press Enter to add and keep going; Esc or ✕ to close. Use {param} for path variables. Upstream servers can be overridden per endpoint after adding.'}</td></tr>
              </>)}
              {loading ? (
                <tr><td colSpan={8} className="text-center py-8 font-mono text-sm text-signal-mist">Loading endpoints...</td></tr>
              ) : filtered.length === 0 && adding ? null : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-0">
                    <SignalEmptyState
                      title="No Endpoints Found"
                      action={
                        <button type="button" className="signal-button signal-button--primary" onClick={() => setAdding(true)}>Add Endpoint</button>
                      }
                    >
                      {searchTerm || methodFilter !== 'ALL' ? 'Try adjusting your search terms or method filter.' : 'Get started by creating your first endpoint for this API.'}
                    </SignalEmptyState>
                  </td>
                </tr>
              ) : (
                  filtered.map((ep) => {
                    const k = keyFor(ep)
                    const saving = !!working[k]
                    const hasOverride = (ep.endpoint_servers || []).length > 0
                    const [expanded, setExpanded] = [undefined as any, undefined as any]
                    return (
                      <React.Fragment key={k}>
                        <tr className="cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-surfaceHover" onClick={() => setExpandedKeys(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n })}>
                          <td>
                            <button className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" onClick={(e) => { e.stopPropagation(); setExpandedKeys(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n }) }}>
                              <svg className={`h-4 w-4 transform transition-transform ${expandedKeys.has(k) ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                              </svg>
                            </button>
                          </td>
                          <td>
                            <span className={`badge ${ep.endpoint_method === 'GET' ? 'badge-success' : ep.endpoint_method === 'POST' ? 'badge-primary' : ep.endpoint_method === 'DELETE' ? 'badge-error' : 'badge-warning'}`}>{ep.endpoint_method}</span>
                          </td>
                          <td className="font-mono text-sm" title="Backend URI">{ep.endpoint_uri}</td>
                          <td className="text-sm">
                            {editingClientUri === k ? (
                              <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                                <input
                                  type="text"
                                  className="input input-sm min-w-[150px] font-mono text-xs"
                                  value={editedClientUriValue}
                                  onChange={(e) => setEditedClientUriValue(e.target.value)}
                                  placeholder="/public/path"
                                  onKeyPress={(e) => {
                                    if (e.key === 'Enter') saveClientUri(ep)
                                    else if (e.key === 'Escape') cancelEditClientUri()
                                  }}
                                  autoFocus
                                  disabled={saving}
                                />
                                <button onClick={() => saveClientUri(ep)} disabled={saving} className="btn btn-success btn-xs" title="Save">✓</button>
                                <button onClick={cancelEditClientUri} disabled={saving} className="btn btn-ghost btn-xs" title="Cancel">✕</button>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2 group min-h-[20px]">
                                <span className={`font-mono text-sm ${ep.client_uri ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400'}`}>
                                  {ep.client_uri || '-'}
                                </span>
                                <button
                                  onClick={(e) => { e.stopPropagation(); startEditClientUri(ep) }}
                                  className="opacity-0 group-hover:opacity-100 transition-opacity text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                  title="Edit Client URI"
                                >
                                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                  </svg>
                                </button>
                              </div>
                            )}
                          </td>
                          <td className="text-sm text-gray-600 dark:text-gray-400 max-w-xs">
                            {editingDescription === k ? (
                              <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                <input
                                  type="text"
                                  className="input input-sm flex-1 min-w-[200px]"
                                  value={editedDescriptionValue}
                                  onChange={(e) => setEditedDescriptionValue(e.target.value)}
                                  onKeyPress={(e) => {
                                    if (e.key === 'Enter') {
                                      saveDescription(ep)
                                    } else if (e.key === 'Escape') {
                                      cancelEditDescription()
                                    }
                                  }}
                                  autoFocus
                                  disabled={saving}
                                />
                                <button
                                  onClick={() => saveDescription(ep)}
                                  disabled={saving}
                                  className="btn btn-success btn-sm"
                                  title="Save"
                                >
                                  {saving ? (
                                    <div className="spinner h-3 w-3"></div>
                                  ) : (
                                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                  )}
                                </button>
                                <button
                                  onClick={cancelEditDescription}
                                  disabled={saving}
                                  className="btn btn-ghost btn-sm"
                                  title="Cancel"
                                >
                                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                  </svg>
                                </button>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2 group">
                                <span className="truncate">{ep.endpoint_description || '-'}</span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    startEditDescription(ep)
                                  }}
                                  className="opacity-0 group-hover:opacity-100 transition-opacity text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                                  title="Edit description"
                                >
                                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                  </svg>
                                </button>
                              </div>
                            )}
                          </td>
                          <td>
                            <span className={`badge ${hasOverride ? 'badge-primary' : 'badge-gray'}`} title="Routing precedence: client-key → endpoint → API">
                              {hasOverride ? 'Endpoint override' : 'API default'}
                            </span>
                          </td>
                          <td>
                            <span className="badge badge-secondary">{(ep.endpoint_servers || []).length}</span>
                          </td>
                          <td>
                            <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                              <SignalCopyButton
                                text={`curl -X ${ep.endpoint_method} "${typeof window !== 'undefined' ? window.location.origin : ''}${ep.client_uri || ep.endpoint_uri}"`}
                                label="cURL"
                              />
                            </div>
                          </td>
                        </tr>
                        {expandedKeys.has(k) && (
                          <tr>
                            <td colSpan={8} className="p-0">
                              <div className="bg-gray-50 dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
                                <div className="p-4 space-y-3">
                                  <div className="flex items-center gap-3">
                                    <div className="flex items-center gap-2">
                                      <input
                                        type="checkbox"
                                        checked={hasOverride}
                                        disabled={true}
                                        className="cursor-not-allowed"
                                        title="This setting is managed on the Edit API page"
                                      />
                                      <span className="text-sm text-gray-700 dark:text-gray-300">Use endpoint servers</span>
                                    </div>
                                    <div className="flex-1" />
                                    <button onClick={(e) => handleDeleteClick(ep, e)} className="btn btn-error btn-sm">Delete Endpoint</button>
                                  </div>
                                  <div className={`${hasOverride ? '' : 'opacity-60'}`}>
                                    <div className="text-sm font-medium mb-1">Endpoint Servers (override API servers)</div>
                                    <div className="space-y-2">
                                      {(ep.endpoint_servers || []).map((srv, idx) => (
                                        <div key={idx} className="flex items-center justify-between bg-white dark:bg-gray-900 px-3 py-2 rounded border">
                                          <span className="text-sm font-mono">{srv}</span>
                                          <button disabled={saving || !hasOverride} onClick={() => removeEndpointServer(ep, idx)} className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
                                            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                            </svg>
                                          </button>
                                        </div>
                                      ))}
                                      {(ep.endpoint_servers || []).length === 0 && (
                                        <p className="text-xs text-gray-500">No endpoint-specific servers. Using API servers.</p>
                                      )}
                                    </div>
                                    <div className="mt-2 flex gap-2">
                                      <input className="input flex-1" value={epNewServer[k] || ''} onChange={e => setEpNewServer(prev => ({ ...prev, [k]: e.target.value }))} placeholder="Add server URL" onKeyPress={(e) => e.key === 'Enter' && hasOverride && addEndpointServer(ep)} disabled={!hasOverride} />
                                      <button disabled={saving || !hasOverride} onClick={() => addEndpointServer(ep)} className="btn btn-secondary">{saving ? <div className="flex items-center"><div className="spinner mr-2"></div>Saving...</div> : 'Add'}</button>
                                    </div>
                                  </div>
                                  {ep.endpoint_id && (
                                    <div className="mt-4 p-3 rounded border bg-white dark:bg-gray-900">
                                      <div className="flex items-center justify-between mb-2">
                                        <div className="flex items-center gap-2">
                                          <input
                                            type="checkbox"
                                            checked={!!validationByEndpoint[ep.endpoint_id]?.enabled}
                                            onChange={(e) => {
                                              const v = validationByEndpoint[ep.endpoint_id!] || { loading: false, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: null }
                                              setValidationByEndpoint(prev => ({ ...prev, [ep.endpoint_id!]: { ...v, enabled: e.target.checked } }))
                                            }}
                                            onClick={(e) => e.stopPropagation()}
                                            onFocus={() => ensureValidationLoaded(ep)}
                                          />
                                          <span className="text-sm font-medium">Validation Enabled</span>
                                        </div>
                                        <div className="text-xs text-gray-500">
                                          {validationByEndpoint[ep.endpoint_id]?.exists ? 'Configured' : 'Not configured'}
                                        </div>
                                      </div>
                                      <div>
                                        <label className="block text-xs text-gray-500 mb-1">Validation Schema (JSON)</label>
                                        <textarea
                                          className="input font-mono text-xs h-32"
                                          value={validationByEndpoint[ep.endpoint_id!]?.schemaText || '{\n}\n'}
                                          onChange={(e) => {
                                            const v = validationByEndpoint[ep.endpoint_id!] || { loading: false, exists: false, enabled: false, schemaText: '{\n}\n', saving: false, error: null }
                                            setValidationByEndpoint(prev => ({ ...prev, [ep.endpoint_id!]: { ...v, schemaText: e.target.value } }))
                                          }}
                                          onFocus={() => ensureValidationLoaded(ep)}
                                        />
                                      </div>
                                      {validationByEndpoint[ep.endpoint_id!]?.error && (
                                        <div className="mt-2 text-xs text-error-600">{validationByEndpoint[ep.endpoint_id!]?.error}</div>
                                      )}
                                      <div className="mt-2 flex gap-2">
                                        {validationByEndpoint[ep.endpoint_id!]?.exists ? (
                                          <button
                                            className="btn btn-secondary btn-sm"
                                            disabled={validationByEndpoint[ep.endpoint_id!]?.saving}
                                            onClick={(e) => { e.stopPropagation(); saveValidation(ep) }}
                                          >
                                            {validationByEndpoint[ep.endpoint_id!]?.saving ? 'Saving...' : 'Save'}
                                          </button>
                                        ) : (
                                          <button
                                            className="btn btn-secondary btn-sm"
                                            disabled={validationByEndpoint[ep.endpoint_id!]?.saving}
                                            onClick={(e) => { e.stopPropagation(); createValidation(ep) }}
                                          >
                                            {validationByEndpoint[ep.endpoint_id!]?.saving ? 'Saving...' : 'Create'}
                                          </button>
                                        )}
                                        {validationByEndpoint[ep.endpoint_id!]?.exists && (
                                          <button
                                            className="btn btn-error btn-sm"
                                            disabled={validationByEndpoint[ep.endpoint_id!]?.saving}
                                            onClick={(e) => { e.stopPropagation(); deleteValidation(ep) }}
                                          >
                                            Delete
                                          </button>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    )
                  })
                )}
              </tbody>
            </SignalTable>
          </SignalPanel>
        </div>

      <ConfirmModal
        open={!!showDeleteModal && !!endpointToDelete}
        title="Delete Endpoint"
        message={<>
          This action cannot be undone. This will permanently delete endpoint
          <span className="font-mono"> {endpointToDelete?.endpoint_method} {endpointToDelete?.endpoint_uri}</span>.
        </>}
        confirmLabel="Delete Endpoint"
        cancelLabel="Cancel"
        onCancel={() => setShowDeleteModal(false)}
        onConfirm={() => endpointToDelete && deleteEndpoint(endpointToDelete)}
      />
    </Layout>
  )
}
