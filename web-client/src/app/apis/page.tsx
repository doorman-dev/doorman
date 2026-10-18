'use client'

import React, { useState, useEffect } from 'react'
import InfoTooltip from '@/components/InfoTooltip'
import { useRouter } from 'next/navigation'
import { SERVER_URL } from '@/utils/config'
import { fetchAllPaginated } from '@/utils/api'
import { LIFECYCLE_BADGE, type LifecycleStatus } from '@/components/ApiLifecyclePanel'
import Layout from '@/components/Layout'
import Pagination from '@/components/Pagination'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { SignalCopyButton, SignalEmptyState, SignalPageHeader, SignalPanel, SignalPrimaryLink, SignalSearchInput, SignalTable } from '@/components/signal/Signal'

interface API {
  api_version: React.ReactNode
  api_lifecycle_status?: string
  api_type: React.ReactNode
  api_description: React.ReactNode
  api_servers?: string[]
  api_id: React.ReactNode
  api_name: React.ReactNode
  id: string
  name: string
  version: string
  description: string
  status: string
  endpoints: number
  lastUpdated: string
}

const APIsPage = () => {
  const router = useRouter()
  const [apis, setApis] = useState<API[]>([])
  const [allApis, setAllApis] = useState<API[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [sortBy, setSortBy] = useState('api_name')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [selected, setSelected] = useState<API | null>(null)

  useEffect(() => {
    const fetchApis = async () => {
      try {
        setLoading(true)
        setError(null)
        const fetched = await fetchAllPaginated<API>(
          (page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`,
          data => Array.isArray(data) ? data : (data.apis || data.response?.apis || []),
          undefined,
          Number.POSITIVE_INFINITY
        )
        const seen = new Set<string>()
        const unique = fetched.filter(api => {
          const id = String(api.api_id || `${api.api_name}/${api.api_version}`)
          if (seen.has(id)) return false
          seen.add(id)
          return true
        })
        setAllApis(unique)
        setApis(unique)
      } catch {
        setError('Failed to load APIs. Please try again later.')
      } finally {
        setLoading(false)
      }
    }
    fetchApis()
  }, [])

  const changePageSize = (size: number) => {
    setPageSize(size)
    setPage(1)
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    const query = searchTerm.trim().toLowerCase()
    setApis(allApis.filter(api =>
      [api.api_name, api.api_version, api.api_type, api.api_description, ...(api.api_servers || [])]
        .some(value => String(value || '').toLowerCase().includes(query))
    ))
    setPage(1)
  }

  const handleSort = (sortField: string) => {
    setSortBy(sortField)
    setPage(1)
  }

  const groups = new Map<string, { name: string; line: string; releases: API[] }>()
  const sortedApis = [...apis].sort((a, b) => {
    const field = sortBy as 'api_name' | 'api_version' | 'api_type'
    return String(a[field]).localeCompare(String(b[field]), undefined, { numeric: true }) ||
      String(a.api_name).localeCompare(String(b.api_name)) ||
      String(a.api_version).localeCompare(String(b.api_version), undefined, { numeric: true })
  })
  for (const api of sortedApis) {
    const name = String(api.api_name)
    const version = String(api.api_version)
    const line = /^v(\d+)(?:\.\d+){0,2}$/.exec(version)?.[1]
    const label = line ? `v${line}` : version
    const key = JSON.stringify([name, label])
    const group = groups.get(key) || { name, line: label, releases: [] }
    group.releases.push(api)
    groups.set(key, group)
  }
  const visibleGroups = [...groups.entries()].slice((page - 1) * pageSize, page * pageSize)
  const hasNext = page * pageSize < groups.size

  const handleApiClick = (api: API) => {
    sessionStorage.setItem('selectedApi', JSON.stringify(api))
    router.push(`/apis/${api.api_id}`)
  }

  const handleViewEndpoints = (e: React.MouseEvent, api: API) => {
    e.stopPropagation()
    sessionStorage.setItem('selectedApi', JSON.stringify(api))
    router.push(`/apis/${api.api_id}/endpoints`)
  }

  return (
    <ProtectedRoute requiredPermission="manage_apis">
      <Layout>
      <div className="space-y-6">
        <SignalPageHeader kicker="Traffic policy" title={<>API<br className="sm:hidden" /> Gateway.</>} description="Configure, search, and monitor every gateway API without changing its live routing contract." actions={<div className="flex gap-2"><SignalPrimaryLink href="/apis/import-swagger" className="!bg-gray-200 !text-gray-900 border-2 border-gray-900">Import Swagger</SignalPrimaryLink><SignalPrimaryLink href="/apis/add">Add API</SignalPrimaryLink></div>} />

        <SignalPanel tone="white" title="Search and ordering" kicker={`Route registry (Showing ${apis.length} of ${allApis.length})`}>
          <div className="flex flex-col sm:flex-row gap-4">
            <form onSubmit={handleSearch} className="flex-1">
              <SignalSearchInput
                value={searchTerm}
                onChange={(val) => {
                  setSearchTerm(val)
                  if (!val) { setApis(allApis); setPage(1) }
                }}
                onClear={() => { setApis(allApis); setPage(1) }}
                placeholder="Search APIs by name, version, type, or description..."
              />
            </form>

            <div className="flex gap-2">
              <button
                onClick={() => handleSort('api_name')}
                className={`btn ${sortBy === 'api_name' ? 'btn-primary' : 'btn-secondary'}`}
              >
                Name {sortBy === 'api_name' && '▲'}
              </button>
              <button
                onClick={() => handleSort('api_version')}
                className={`btn ${sortBy === 'api_version' ? 'btn-primary' : 'btn-secondary'}`}
              >
                Version {sortBy === 'api_version' && '▲'}
              </button>
              <button
                onClick={() => handleSort('api_type')}
                className={`btn ${sortBy === 'api_type' ? 'btn-primary' : 'btn-secondary'}`}
              >
                Type {sortBy === 'api_type' && '▲'}
              </button>
            </div>
          </div>
        </SignalPanel>

        {error && (
          <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
            <div className="flex">
              <svg className="h-5 w-5 text-error-400 dark:text-error-500 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="ml-3">
                <p className="text-sm text-error-700 dark:text-error-300">{error}</p>
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="card">
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="spinner mx-auto mb-4"></div>
                <p className="text-gray-600 dark:text-gray-400">Loading APIs...</p>
              </div>
            </div>
          </div>
        ) : (
          /* APIs Table */
          <div className="signal-split"><div className="signal-split-main">
          <SignalPanel tone="white" title="Configured APIs" kicker="Gateway registry">
              <SignalTable>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Version</th>
                    <th>Servers</th>
                    <th>Description</th>
                    <th>Type</th>
                    <th className="w-56">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleGroups.map(([key, group]) => (
                    <React.Fragment key={key}>
                      <tr>
                        <th colSpan={6} scope="rowgroup" className="!text-left">
                          {group.name} <span aria-hidden="true">›</span> {group.line}
                          <span className="ml-2 font-normal">({group.releases.length} releases)</span>
                        </th>
                      </tr>
                      {group.releases.map((api, index) => (
                        <tr
                          key={String(api.api_id) || `${api.api_name}-${api.api_version}-${index}`}
                          onClick={() => setSelected(selected && selected.api_id === api.api_id ? null : api)}
                          aria-selected={selected?.api_id === api.api_id}
                          className={`group cursor-pointer transition-colors ${selected?.api_id === api.api_id ? 'signal-row-selected' : ''}`}
                        >
                          <td data-label="API">
                            <div className="flex items-center">
                              <div className="h-8 w-8 rounded-lg bg-primary-100 dark:bg-primary-900/20 flex items-center justify-center mr-3">
                                <svg className="h-4 w-4 text-primary-600 dark:text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
                              </div>
                              <div className="flex items-center gap-2">
                                <p className="font-medium text-gray-900 dark:text-white">{api.api_name}</p>
                                <SignalCopyButton text={String(api.api_name)} label="Copy" className="opacity-0 group-hover:opacity-100 transition-opacity" />
                                {(((api as any).api_ip_mode || 'allow_all') === 'whitelist') && (
                                  <span className="badge badge-secondary">IP Whitelist</span>
                                )}
                                {Array.isArray((api as any).api_ip_blacklist) && (api as any).api_ip_blacklist.length > 0 && (
                                  <span className="badge badge-error">Blacklist</span>
                                )}
                                {((api as any).api_public ?? false) && (
                                  <span className="badge badge-warning flex items-center gap-1" title="This API is public">
                                    Public
                                    <InfoTooltip text="Anyone can call this API; auth, subscription, and group checks are skipped." />
                                  </span>
                                )}
                                {!((api as any).api_public ?? false) && ((api as any).api_auth_required === false) && (
                                  <span className="badge badge-secondary flex items-center gap-1" title="No authentication required">
                                    No Auth
                                    <InfoTooltip text="Unauthenticated access is allowed. Subscription and group checks do not apply without auth." />
                                  </span>
                                )}
                              </div>
                            </div>
                          </td>
                          <td data-label="Version">
                            <span className="badge badge-primary">{api.api_version}</span>
                            <span className={`badge ${LIFECYCLE_BADGE[(api.api_lifecycle_status || 'active') as LifecycleStatus] || 'badge-gray'} ml-1`}>
                              {api.api_lifecycle_status || 'active'}
                            </span>
                          </td>
                          <td data-label="Upstreams">
                            {Array.isArray((api as any).api_servers) && (api as any).api_servers.length > 0 ? (
                              <div className="text-sm text-gray-700 dark:text-gray-300 max-w-xs truncate">
                                {(api as any).api_servers.slice(0, 3).join(', ')}
                                {(api as any).api_servers.length > 3 && ' …'}
                              </div>
                            ) : (
                              <span className="text-gray-500 dark:text-gray-400 text-sm">None</span>
                            )}
                          </td>
                          <td data-label="Description">
                            <p className="text-sm text-gray-600 dark:text-gray-400 max-w-xs truncate">
                              {api.api_description}
                            </p>
                          </td>
                          <td data-label="Protocol">
                            <span className={`badge ${(api.api_type as string)?.toLowerCase() === 'rest' ? 'badge-success' :
                              (api.api_type as string)?.toLowerCase() === 'graphql' ? 'badge-warning' :
                                (api.api_type as string)?.toLowerCase() === 'grpc' ? 'badge-error' :
                                  'badge-gray'
                              }`}>
                              {api.api_type}
                            </span>
                          </td>
                          <td data-label="Actions" className="whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <button
                                className="btn btn-secondary btn-sm"
                                onClick={(e) => handleViewEndpoints(e, api)}
                                title="View endpoints for this API"
                              >
                                <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                                </svg>
                                View Endpoints
                              </button>
                              <button
                                className="btn btn-ghost btn-sm"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleApiClick(api)
                                }}
                                title="Open API details"
                              >
                                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                </svg>
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </React.Fragment>
                  ))}
                </tbody>
              </SignalTable>

            <Pagination
              page={page}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={changePageSize}
              hasNext={hasNext}
            />

            {apis.length === 0 && !loading && (
              <SignalEmptyState title="No APIs found" action={<SignalPrimaryLink href="/apis/add">Add API</SignalPrimaryLink>}>{searchTerm ? 'Try adjusting your search terms.' : 'Get started by creating your first API.'}</SignalEmptyState>
            )}
          </SignalPanel>
          </div>
          {selected && (
            <aside className="signal-detail-pane" aria-label="API details">
              <div className="flex items-start justify-between gap-2">
                <div><h3>{selected.api_name}</h3><p className="signal-detail-sub">v{selected.api_version} · {selected.api_type}</p></div>
                <button className="signal-detail-close" onClick={() => setSelected(null)} aria-label="Close details">×</button>
              </div>
              <dl>
                <div><dt>API ID</dt><dd>{selected.api_id}</dd></div>
                <div><dt>Type</dt><dd>{selected.api_type}</dd></div>
                <div><dt>Version</dt><dd>{selected.api_version}</dd></div>
                <div><dt>Servers</dt><dd>{selected.api_servers && selected.api_servers.length ? selected.api_servers.join(', ') : '—'}</dd></div>
                <div><dt>Description</dt><dd>{selected.api_description || '—'}</dd></div>
              </dl>
              <div className="flex flex-col gap-2 mt-4">
                <button className="btn btn-primary" onClick={() => handleApiClick(selected)}>Open API</button>
                <button className="btn" onClick={(e) => handleViewEndpoints(e, selected)}>View endpoints</button>
              </div>
            </aside>
          )}
          </div>
        )}
      </div>
    </Layout>
  </ProtectedRoute>
  )
}

export default APIsPage
