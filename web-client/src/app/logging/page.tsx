'use client'

import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import Pagination from '@/components/Pagination'
import { getCookie } from '@/utils/http'
import { SERVER_URL } from '@/utils/config'
import { format } from 'date-fns'
import { ChangeEvent } from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { useAuth } from '@/contexts/AuthContext'
import { SignalCopyButton, SignalPageHeader } from '@/components/signal/Signal'

interface Log {
  timestamp: string
  request_id?: string
  level: string
  message: string
  source: string
  user?: string
  endpoint?: string
  method?: string
  ip_address?: string
  response_time?: string
  status_code?: string
  api?: string
  protocol?: string
}

interface FilterState {
  startDate: string
  endDate: string
  startTime: string
  endTime: string
  user: string
  api?: string
  endpoint: string
  request_id: string
  method: string
  ipAddress: string
  minResponseTime: string
  maxResponseTime: string
  level: string
}

interface GroupedLogs {
  request_id: string
  logs: Log[]
  first_timestamp: string
  last_timestamp: string
  user?: string
  method?: string
  endpoint?: string
  response_time?: string
  has_error: boolean
  expanded_logs?: Log[]
}


const logString = (value: unknown): string | undefined => {
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  return undefined
}

const normalizeLog = (entry: unknown, index: number): Log => {
  let value = entry
  if (typeof entry === 'string') {
    try { value = JSON.parse(entry) } catch {
      return {
        timestamp: new Date(0).toISOString(),
        level: 'INFO',
        message: entry,
        source: 'gateway',
        request_id: 'unstructured-' + index
      }
    }
  }
  const record = value && typeof value === 'object' ? value as Record<string, unknown> : {}
  return {
    timestamp: logString(record.timestamp) || logString(record.time) || new Date(0).toISOString(),
    request_id: logString(record.request_id),
    level: logString(record.level) || 'INFO',
    message: logString(record.message) || JSON.stringify(record),
    source: logString(record.source) || logString(record.name) || 'gateway',
    user: logString(record.user),
    endpoint: logString(record.endpoint),
    method: logString(record.method),
    ip_address: logString(record.ip_address),
    response_time: logString(record.response_time),
    status_code: logString(record.status_code),
    api: logString(record.api),
    protocol: logString(record.protocol)
  }
}

const logsFromResponse = (data: any): Log[] => {
  const entries = data?.response?.logs || data?.logs || []
  return Array.isArray(entries) ? entries.map(normalizeLog) : []
}

type OverrideKey = string

export default function LogsPage() {
  const { permissions, authResolved, logsEnabled } = useAuth()
  const router = useRouter()
  const canExport = !!permissions?.export_logs
  const [logs, setLogs] = useState<Log[]>([])
  const [groupedLogs, setGroupedLogs] = useState<GroupedLogs[]>([])
  const [logsPage, setLogsPage] = useState(1)
  const [logsPageSize, setLogsPageSize] = useState(10)
  const [logsHasNext, setLogsHasNext] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showMoreFilters, setShowMoreFilters] = useState(false)
  const [exporting, setExporting] = useState(false)
  // Removed log files listing per requirements
  const [expandedRequests, setExpandedRequests] = useState<Set<string>>(new Set())
  const [loadingExpanded, setLoadingExpanded] = useState<Set<string>>(new Set())
  const [currentRequestId, setCurrentRequestId] = useState<string | null>(null)
  const [hasSearched, setHasSearched] = useState(false)
  const [searchTrigger, setSearchTrigger] = useState(0)
  const [useLocalTime, setUseLocalTime] = useState(true)
  const [hidePlatformLogs, setHidePlatformLogs] = useState(false)
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number | null>(null)
  const [securityAuditActive, setSecurityAuditActive] = useState(false)

  useEffect(() => {
    if (authResolved && !logsEnabled) router.replace('/dashboard')
  }, [authResolved, logsEnabled, router])
  const [filters, setFilters] = useState<FilterState>(() => {
    const now = new Date()
    const today = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0')

    return {
      startDate: today,
      endDate: today,
      // Default to full-day range: 12:00 AM to 11:59 PM
      startTime: '00:00',
      endTime: '23:59',
      user: '',
      api: '',
      endpoint: '',
      request_id: '',
      method: '',
      ipAddress: '',
      minResponseTime: '',
      maxResponseTime: '',
      level: ''
    }
  })

  const [overrideMap, setOverrideMap] = useState<Record<OverrideKey, boolean>>({})

  const ensureEndpointOverridesLoaded = async (apiPath: string) => {
    try {
      const parts = apiPath.replace(/^\//, '').split('/')
      if (parts.length < 2) return
      const api_name = parts[0]
      const api_version = parts[1]
      const keyPrefix = `${api_name}|${api_version}|`
      if (Object.keys(overrideMap).some(k => k.includes(keyPrefix))) return
      const { fetchJson } = await import('@/utils/http')
      const responseData: any = await fetchJson(`${SERVER_URL}/platform/endpoint/${encodeURIComponent(api_name)}/${encodeURIComponent(api_version)}`)
      const data = responseData
      const eps: any[] = Array.isArray(data) ? data : (data.endpoints || data.response?.endpoints || [])
      const next: Record<OverrideKey, boolean> = {}
      eps.forEach(ep => {
        const k: OverrideKey = `${ep.endpoint_method}|${ep.api_name}|${ep.api_version}|${ep.endpoint_uri}`
        next[k] = Array.isArray(ep.endpoint_servers) && ep.endpoint_servers.length > 0
      })
      setOverrideMap(prev => ({ ...prev, ...next }))
    } catch { }
  }

  const toQueryParams = (f: FilterState) => {
    const qp = new URLSearchParams()

    // Helper to add standard fields
    const addStandardFields = () => {
      const map: Record<string, string> = {
        request_id: 'request_id',
        ipAddress: 'ip_address',
        minResponseTime: 'min_response_time',
        maxResponseTime: 'max_response_time',
        user: 'user',
        api: 'api',
        endpoint: 'endpoint',
        method: 'method',
        level: 'level'
      }
      Object.entries(f).forEach(([k, v]) => {
        if (!v || ['startDate', 'endDate', 'startTime', 'endTime'].includes(k)) return
        const key = (map as any)[k] || k
        qp.append(key, v)
      })
    }

    addStandardFields()

    if (hidePlatformLogs) {
      qp.append('exclude_type', 'platform')
    }

    // Handle Date/Time
    if (useLocalTime) {
      if (f.startDate) {
        // Construct local date time
        // If time is missing, default to 00:00 for start, 23:59 for end (though state has defaults)
        const d = new Date(`${f.startDate}T${f.startTime || '00:00'}`)
        if (!isNaN(d.getTime())) {
          qp.append('start_date', `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`)
          qp.append('start_time', `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`)
        }
      }

      if (f.endDate) {
        const d = new Date(`${f.endDate}T${f.endTime || '23:59'}`)
        if (!isNaN(d.getTime())) {
          qp.append('end_date', `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`)
          qp.append('end_time', `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`)
        }
      }
    } else {
      if (f.startDate) qp.append('start_date', f.startDate)
      if (f.startTime) qp.append('start_time', f.startTime)
      if (f.endDate) qp.append('end_date', f.endDate)
      if (f.endTime) qp.append('end_time', f.endTime)
    }

    return qp
  }

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const queryParams = toQueryParams(filters)
      queryParams.append('limit', String(logsPageSize))
      queryParams.append('offset', String((logsPage - 1) * logsPageSize))

      const { fetchJson } = await import('@/utils/http')
      const csrf = getCookie('csrf_token')
      const response = await fetch(`${SERVER_URL}/platform/logging/logs?${queryParams}`, { credentials: 'include', headers: { 'Accept': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } })

      if (!response.ok) {
        throw new Error('Failed to fetch logs')
      }

      const responseRequestId = response.headers.get('request_id')
      if (responseRequestId) {
        setCurrentRequestId(responseRequestId)
      }

      const data = await response.json()
      const logList = logsFromResponse(data)
      const hasMore = (data.response?.has_more ?? data.has_more) ?? (Array.isArray(logList) && logList.length === logsPageSize)
      setLogs(logList)
      setLogsHasNext(!!hasMore)

      // Group from the initial page of logs only; fetch per-request details lazily on expand
      const grouped = groupLogsByRequestId(logList)
      setGroupedLogs(grouped)
    } catch (error) {
      setError('Failed to fetch logs. Please try again later.')
      setLogs([])
      setGroupedLogs([])
    } finally {
      setLoading(false)
    }
  }, [filters, logsPage, logsPageSize, hidePlatformLogs, useLocalTime])

  useEffect(() => {
    if (!autoRefreshInterval) return
    const intervalId = setInterval(() => {
      fetchLogs()
    }, autoRefreshInterval * 1000)
    return () => clearInterval(intervalId)
  }, [autoRefreshInterval, fetchLogs])

  const fetchLogsForRequestId = useCallback(async (requestId: string) => {
    try {
      setLoadingExpanded(prev => new Set(prev).add(requestId))

      const queryParams = new URLSearchParams()
      queryParams.append('request_id', requestId)
      queryParams.append('limit', '1000')

      const { fetchJson } = await import('@/utils/http')
      const data: any = await fetchJson(`${SERVER_URL}/platform/logging/logs?${queryParams}`)
      const allLogsForRequest = logsFromResponse(data)

      setGroupedLogs(prev => prev.map(group => {
        if (group.request_id === requestId) {
          const sortedExpandedLogs = allLogsForRequest.sort((a: Log, b: Log) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
          const firstLog = sortedExpandedLogs[0]
          const lastLog = sortedExpandedLogs[sortedExpandedLogs.length - 1]

          const responseTimeLog = sortedExpandedLogs.find((log: Log) => log.response_time)
          const userLog = sortedExpandedLogs.find((log: Log) => log.user)
          const endpointLog = sortedExpandedLogs.find((log: Log) => log.endpoint && log.method)
          const hasError = sortedExpandedLogs.some((log: Log) => log.level.toLowerCase() === 'error')

          const DEBUG = process.env.NODE_ENV !== 'production'
          if (DEBUG) console.log(`Expanding request ${requestId}:`, {
            totalLogs: allLogsForRequest.length,
            userLog: userLog?.user,
            endpointLog: endpointLog?.endpoint,
            methodLog: endpointLog?.method,
            responseTimeLog: responseTimeLog?.response_time,
            hasError
          })

          return {
            ...group,
            expanded_logs: allLogsForRequest,
            first_timestamp: firstLog?.timestamp || group.first_timestamp,
            last_timestamp: lastLog?.timestamp || group.last_timestamp,
            user: userLog?.user || group.user,
            method: endpointLog?.method || group.method,
            endpoint: endpointLog?.endpoint || group.endpoint,
            response_time: responseTimeLog?.response_time || group.response_time,
            has_error: hasError
          }
        }
        return group
      }))
    } catch (error) {
      console.error('Failed to fetch logs for request ID:', error)
      setError('Failed to fetch detailed logs for this request.')
    } finally {
      setLoadingExpanded(prev => {
        const newSet = new Set(prev)
        newSet.delete(requestId)
        return newSet
      })
    }
  }, [])

  const groupLogsByRequestId = (logList: Log[]): GroupedLogs[] => {
    const groups: { [key: string]: Log[] } = {}

    let noIdCounter = 0

    logList.forEach(log => {
      let requestId = log.request_id

      // If no valid request_id, generate a unique one to prevent grouping
      if (!requestId || requestId === 'no-request-id') {
        noIdCounter++
        requestId = `no-id-${noIdCounter}-${Math.random().toString(36).substr(2, 9)}`
      }

      if (!groups[requestId]) {
        groups[requestId] = []
      }
      groups[requestId].push(log)
    })

    return Object.entries(groups)
      .filter(([requestId, logs]) => {
        // Since we are creating unique IDs for non-grouped logs, this filter logic remains safe
        if (currentRequestId && requestId === currentRequestId) {
          return false
        }
        return true
      })
      .map(([requestId, logs]) => {
        const sortedLogs = logs.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
        const firstLog = sortedLogs[0]
        const lastLog = sortedLogs[sortedLogs.length - 1]

        const responseTimeLog = sortedLogs.find(log => log.response_time)
        const userLog = sortedLogs.find(log => log.user)
        const endpointLog = sortedLogs.find(log => log.endpoint && log.method)
        const apiHintLog = sortedLogs.find(log => log.api)?.api
        if (apiHintLog) {
          ensureEndpointOverridesLoaded(apiHintLog as string)
        }
        const hasError = sortedLogs.some(log => log.level.toLowerCase() === 'error')

        return {
          request_id: requestId,
          logs: sortedLogs,
          first_timestamp: firstLog.timestamp,
          last_timestamp: lastLog.timestamp,
          user: userLog?.user,
          method: endpointLog?.method,
          endpoint: endpointLog?.endpoint,
          response_time: responseTimeLog?.response_time,
          has_error: hasError
        }
      }).sort((a, b) => new Date(b.first_timestamp).getTime() - new Date(a.first_timestamp).getTime())
  }

  useEffect(() => {
    if (hasSearched) {
      fetchLogs()
    }
  }, [fetchLogs, hasSearched, searchTrigger])

  const handleFilterChange = (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target
    setFilters(prev => ({ ...prev, [name]: value }))
  }

  const clearFilters = () => {
    const now = new Date()
    const today = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0')

    setSecurityAuditActive(false)
    // Reset to full-day by default
    setFilters({
      startDate: today,
      endDate: today,
      startTime: '00:00',
      endTime: '23:59',
      user: '',
      endpoint: '',
      request_id: '',
      method: '',
      ipAddress: '',
      minResponseTime: '',
      maxResponseTime: '',
      level: ''
    })
    setHasSearched(false)
    setLogs([])
    setGroupedLogs([])
    setError(null)
  }

  const toggleSecurityAudit = () => {
    const next = !securityAuditActive
    setSecurityAuditActive(next)
    if (next) {
      setFilters(prev => ({ ...prev, level: 'ERROR' }))
    } else {
      setFilters(prev => ({ ...prev, level: '' }))
    }
    setLogsPage(1)
    setHasSearched(true)
    setSearchTrigger(prev => prev + 1)
  }

  const displayedGroups = useMemo(() => {
    if (!securityAuditActive) return groupedLogs
    return groupedLogs.filter(group => {
      if (group.has_error) return true
      return (group.expanded_logs || group.logs || []).some(log => {
        const lvl = (log.level || '').toUpperCase()
        if (lvl === 'ERROR' || lvl === 'WARN') return true
        const status = String(log.status_code || '')
        if (['401', '403', '429'].includes(status)) return true
        const msg = (log.message || '').toLowerCase()
        return /401|403|429|unauthorized|forbidden|blocked|blacklist|rate limit|csrf|denied/.test(msg)
      })
    })
  }, [groupedLogs, securityAuditActive])

  const handleSearch = () => {
    setLogsPage(1)
    setHasSearched(true)
    setSearchTrigger(prev => prev + 1)
  }

  const toggleRequestExpansion = async (requestId: string) => {
    const newExpanded = new Set(expandedRequests)
    if (newExpanded.has(requestId)) {
      newExpanded.delete(requestId)
      setExpandedRequests(newExpanded)
    } else {
      newExpanded.add(requestId)
      setExpandedRequests(newExpanded)

      const group = groupedLogs.find(g => g.request_id === requestId)
      if (!group?.expanded_logs) {
        await fetchLogsForRequestId(requestId)
      }
    }
  }

  const exportLogs = async (format: 'json' | 'csv') => {
    try {
      setExporting(true)
      const queryParams = toQueryParams(filters)
      queryParams.append('format', format)
      const csrf = getCookie('csrf_token')
      const response = await fetch(`${SERVER_URL}/platform/logging/logs/download?${queryParams}`, {
        credentials: 'include',
        headers: { ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }
      })
      if (!response.ok) throw new Error('Failed to download logs')
      const blob = await response.blob()
      const disposition = response.headers.get('Content-Disposition') || ''
      const match = /filename="?([^";]+)"?/i.exec(disposition)
      const filename = match?.[1] || `logs-${new Date().toISOString().split('T')[0]}.${format}`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      setError('Failed to download logs. Please try again later.')
    } finally {
      setExporting(false)
    }
  }

  const downloadLatest = async (format: 'json' | 'csv') => {
    try {
      setExporting(true)
      const params = new URLSearchParams()
      params.append('format', format)
      const csrf = getCookie('csrf_token')
      const response = await fetch(`${SERVER_URL}/platform/logging/logs/download?${params.toString()}`, {
        credentials: 'include',
        headers: { ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }
      })
      if (!response.ok) throw new Error('Failed to download latest logs')
      const blob = await response.blob()
      const disposition = response.headers.get('Content-Disposition') || ''
      const match = /filename="?([^";]+)"?/i.exec(disposition)
      const filename = match?.[1] || `logs-latest.${format === 'json' ? 'json' : 'csv'}`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (e) {
      setError('Failed to download latest logs.')
    } finally {
      setExporting(false)
    }
  }

  const getLevelBgColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error': return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
      case 'warn': return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
      case 'info': return 'bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200'
      case 'debug': return 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
      default: return 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200'
    }
  }

  if (authResolved && !logsEnabled) return null

  return (
    <ProtectedRoute requiredPermission="view_logs">
      <Layout>
        <div className="signal-logs-workspace space-y-6">
          <SignalPageHeader
            kicker="Request operations"
            title={<>Request<br className="sm:hidden" /> Logs.</>}
            description="View and analyze system logs and API requests."
            actions={
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={toggleSecurityAudit}
                  className={`signal-button text-xs ${
                    securityAuditActive
                      ? '!bg-signal-terra font-bold !text-white border-2 border-signal-ink shadow-[2px_2px_0px_0px_rgba(25,32,28,1)]'
                      : 'btn-secondary'
                  }`}
                  title="Filter logs for security events (401, 403, 429, errors, blocks)"
                >
                  {securityAuditActive ? '🛡️ SECURITY AUDIT ACTIVE' : '🛡️ SECURITY AUDIT'}
                </button>
                <button
                  type="button"
                  onClick={() => setAutoRefreshInterval(prev => prev ? null : 5)}
                  className={`signal-button text-xs ${autoRefreshInterval ? 'bg-signal-lime font-bold text-signal-ink border-2 border-signal-ink shadow-[2px_2px_0px_0px_rgba(25,32,28,1)]' : 'btn-secondary'}`}
                  title="Toggle 5-second automatic log polling"
                >
                  {autoRefreshInterval ? '● LIVE POLLING (5s)' : '▶ AUTO-REFRESH OFF'}
                </button>
                <button
                  type="button"
                  onClick={() => fetchLogs()}
                  disabled={loading}
                  className="signal-button btn-secondary text-xs"
                  title="Fetch latest logs now"
                >
                  {loading ? 'REFRESHING...' : 'REFRESH NOW'}
                </button>
              </div>
            }
          />

          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Filters</h3>
            </div>
            <div className="p-6">
              <div className="mb-4 flex flex-col md:flex-row md:items-center md:justify-start gap-3">
                {canExport && (
                  <div className="flex flex-wrap gap-2">
                    <button onClick={() => exportLogs('json')} disabled={exporting} className="btn btn-secondary">Download JSON</button>
                    <button onClick={() => exportLogs('csv')} disabled={exporting} className="btn btn-secondary">Download CSV</button>
                    <button onClick={() => downloadLatest('json')} disabled={exporting} className="btn btn-outline">Latest JSON</button>
                    <button onClick={() => downloadLatest('csv')} disabled={exporting} className="btn btn-outline">Latest CSV</button>
                  </div>
                )}

                <div className="flex items-center ml-auto gap-4">
                  <label className="flex items-center space-x-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={hidePlatformLogs}
                      onChange={(e) => {
                        setHidePlatformLogs(e.target.checked)
                        if (hasSearched) {
                          setSearchTrigger(prev => prev + 1)
                        }
                      }}
                      className="checkbox"
                    />
                    <span>Hide Platform Logs</span>
                  </label>
                  <label className="flex items-center space-x-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={useLocalTime}
                      onChange={(e) => setUseLocalTime(e.target.checked)}
                      className="checkbox"
                    />
                    <span>Use Local Time</span>
                  </label>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Start Date
                  </label>
                  <input
                    type="date"
                    name="startDate"
                    value={filters.startDate}
                    onChange={handleFilterChange}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    End Date
                  </label>
                  <input
                    type="date"
                    name="endDate"
                    value={filters.endDate}
                    onChange={handleFilterChange}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Start Time
                  </label>
                  <input
                    type="time"
                    name="startTime"
                    value={filters.startTime}
                    onChange={handleFilterChange}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    End Time
                  </label>
                  <input
                    type="time"
                    name="endTime"
                    value={filters.endTime}
                    onChange={handleFilterChange}
                    className="input"
                  />
                </div>
              </div>

              {showMoreFilters && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      User
                    </label>
                    <input
                      type="text"
                      name="user"
                      value={filters.user}
                      onChange={handleFilterChange}
                      placeholder="Filter by user"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      API
                    </label>
                    <input
                      type="text"
                      name="api"
                      value={filters.api || ''}
                      onChange={handleFilterChange}
                      placeholder="Filter by API (e.g., rest:orders)"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Endpoint
                    </label>
                    <input
                      type="text"
                      name="endpoint"
                      value={filters.endpoint}
                      onChange={handleFilterChange}
                      placeholder="Filter by endpoint"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Request ID
                    </label>
                    <input
                      type="text"
                      name="request_id"
                      value={filters.request_id}
                      onChange={handleFilterChange}
                      placeholder="Filter by request ID"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Method
                    </label>
                    <select
                      name="method"
                      value={filters.method}
                      onChange={handleFilterChange}
                      className="input"
                    >
                      <option value="">All Methods</option>
                      <option value="GET">GET</option>
                      <option value="POST">POST</option>
                      <option value="PUT">PUT</option>
                      <option value="DELETE">DELETE</option>
                      <option value="PATCH">PATCH</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      IP Address
                    </label>
                    <input
                      type="text"
                      name="ipAddress"
                      value={filters.ipAddress}
                      onChange={handleFilterChange}
                      placeholder="Filter by IP"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Min Response Time (ms)
                    </label>
                    <input
                      type="number"
                      name="minResponseTime"
                      value={filters.minResponseTime}
                      onChange={handleFilterChange}
                      placeholder="Min time"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Max Response Time (ms)
                    </label>
                    <input
                      type="number"
                      name="maxResponseTime"
                      value={filters.maxResponseTime}
                      onChange={handleFilterChange}
                      placeholder="Max time"
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Log Level
                    </label>
                    <select
                      name="level"
                      value={filters.level}
                      onChange={handleFilterChange}
                      className="input"
                    >
                      <option value="">All Levels</option>
                      <option value="ERROR">Error</option>
                      <option value="WARN">Warning</option>
                      <option value="INFO">Info</option>
                      <option value="DEBUG">Debug</option>
                    </select>
                  </div>
                </div>
              )}

              <div className="flex gap-2 mt-6">
                <button onClick={handleSearch} className="btn btn-primary">
                  Search Logs
                </button>
                <button
                  onClick={() => setShowMoreFilters(!showMoreFilters)}
                  className="btn btn-outline"
                >
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.207A1 1 0 013 6.5V4z" />
                  </svg>
                  {showMoreFilters ? 'Hide Advanced Filters' : 'Show Advanced Filters'}
                </button>
                <button onClick={clearFilters} className="btn btn-secondary">
                  Clear Filters
                </button>
              </div>
            </div>
          </div>

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
                  <p className="text-gray-600 dark:text-gray-400">Loading logs...</p>
                </div>
              </div>
            </div>
          ) : (
            /* Grouped Logs Table */
            <div className="card">
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th></th>
                      <th>Request ID</th>
                      <th>Start Time</th>
                      <th># of logs</th>
                      <th>User</th>
                      <th>Endpoint</th>
                      <th>Routing</th>
                      <th>Method</th>
                      <th>Response Time</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedGroups.map((group) => (
                      <React.Fragment key={group.request_id}>
                        <tr
                          onClick={() => toggleRequestExpansion(group.request_id)}
                          className="cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-surfaceHover transition-colors"
                        >
                          <td>
                            <button className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                              <svg
                                className={`h-4 w-4 transform transition-transform ${expandedRequests.has(group.request_id) ? 'rotate-90' : ''}`}
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                              </svg>
                            </button>
                          </td>
                          <td>
                            <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                              <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                                {group.request_id}
                              </span>
                              <SignalCopyButton text={group.request_id} label="Copy" />
                            </div>
                          </td>
                          <td>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {format(new Date(group.first_timestamp), 'MMM dd, yyyy HH:mm:ss')}
                            </p>
                          </td>
                          <td>
                            <p className="text-sm text-gray-600 dark:text-gray-400">
                              {(group.expanded_logs || group.logs).length} log{(group.expanded_logs || group.logs).length !== 1 ? 's' : ''}
                            </p>
                          </td>
                          <td>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {group.user || '-'}
                            </p>
                          </td>
                          <td>
                            <p className="text-sm text-gray-600 dark:text-gray-400 max-w-xs truncate">
                              {group.endpoint || '-'}
                            </p>
                          </td>
                          <td>
                            {(() => {
                              if (!group.endpoint || !group.method) return '-'
                              const m = (group.endpoint || '').match(/^\/?([^/]+\/v\d+)(?:\/(.*))?$/)
                              if (!m) return '-'
                              const apiPath = m[1]
                              const epUri = '/' + (m[2] || '')
                              const parts = apiPath.split('/')
                              if (parts.length < 2) return '-'
                              const api_name = parts[0]
                              const api_version = parts[1]
                              const k: OverrideKey = `${group.method}|${api_name}|${api_version}|${epUri}`
                              const hasOverride = !!overrideMap[k]
                              return (
                                <span className={`badge ${hasOverride ? 'badge-primary' : 'badge-gray'}`} title="Routing precedence: client-key → endpoint → API">
                                  {hasOverride ? 'Endpoint override' : 'API default'}
                                </span>
                              )
                            })()}
                          </td>
                          <td>
                            <span className={`badge ${group.method === 'GET' ? 'badge-success' : group.method === 'POST' ? 'badge-primary' : 'badge-warning'}`}>
                              {group.method || '-'}
                            </span>
                          </td>
                          <td>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {group.response_time ? `${parseFloat(group.response_time).toFixed(2)}ms` : '-'}
                            </p>
                          </td>
                          <td>
                            <span className={`badge ${group.has_error ? 'badge-error' : 'badge-success'}`}>
                              {group.has_error ? 'Error' : 'Success'}
                            </span>
                          </td>
                        </tr>

                        {expandedRequests.has(group.request_id) && (
                          <tr>
                            <td colSpan={10} className="p-0">
                              <div className="bg-gray-50 dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
                                <div className="p-4">
                                  <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
                                    All Logs for Request: {group.request_id}
                                  </h4>

                                  {loadingExpanded.has(group.request_id) ? (
                                    <div className="flex items-center justify-center py-8">
                                      <div className="spinner mr-3"></div>
                                      <p className="text-sm text-gray-600 dark:text-gray-400">Loading all logs for this request...</p>
                                    </div>
                                  ) : (
                                    <div className="space-y-2">
                                      {((group.expanded_logs || group.logs) || []).map((log, index) => (
                                        <div key={index} className="flex items-start space-x-4 p-2 bg-white dark:bg-gray-900 rounded border">
                                          <div className="flex-shrink-0">
                                            <span className={`badge ${getLevelBgColor(log.level)}`}>
                                              {log.level}
                                            </span>
                                          </div>
                                          <div className="flex-1 min-w-0">
                                            <div className="flex items-center space-x-2 text-xs text-gray-500 dark:text-gray-400 mb-1">
                                              <span>{format(new Date(log.timestamp), 'HH:mm:ss.SSS')}</span>
                                              <span>•</span>
                                              <span>{log.source}</span>
                                            </div>
                                            <p className="text-sm text-gray-900 dark:text-white">
                                              {log.message}
                                            </p>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination
                page={logsPage}
                pageSize={logsPageSize}
                onPageChange={setLogsPage}
                onPageSizeChange={(s) => { setLogsPageSize(s); setLogsPage(1) }}
                hasNext={logsHasNext}
              />

              {!hasSearched ? (
                <div className="text-center py-12">
                  <div className="h-16 w-16 mx-auto mb-4 rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                    <svg className="h-8 w-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Ready to search logs</h3>
                  <p className="text-gray-600 dark:text-gray-400">
                    Use the filters above to search for specific logs and click "Search Logs" to get started.
                  </p>
                </div>
              ) : displayedGroups.length === 0 && !loading && (
                <div className="text-center py-12">
                  <div className="h-16 w-16 mx-auto mb-4 rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                    <svg className="h-8 w-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                    {securityAuditActive ? 'No security events found' : 'No logs found'}
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400">
                    {securityAuditActive
                      ? 'No 401, 403, 429, or error events recorded within the selected timeframe.'
                      : 'Try adjusting your filters or check back later for new logs.'}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
