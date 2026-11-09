'use client'

import React, { useState, useEffect, useRef } from 'react'
import type { ReadonlyURLSearchParams } from 'next/navigation'
import { useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { SERVER_URL } from '@/utils/config'
import { getJson } from '@/utils/api'
import TimeSeriesChart from '@/components/analytics/TimeSeriesChart'
import LatencyChart from '@/components/analytics/LatencyChart'
import ErrorRateChart from '@/components/analytics/ErrorRateChart'
import APIDistributionChart from '@/components/analytics/APIDistributionChart'
import TopAPIsTable from '@/components/analytics/TopAPIsTable'
import TopUsersTable from '@/components/analytics/TopUsersTable'
import DetailModal from '@/components/analytics/DetailModal'
import PerformanceTab from '@/components/analytics/PerformanceTab'
import FilterPanel from '@/components/analytics/FilterPanel'

// Types
interface AnalyticsOverview {
  time_range: {
    start_ts: number
    end_ts: number
    duration_seconds: number
  }
  summary: {
    total_requests: number
    total_errors: number
    error_rate: number
    avg_response_ms: number
    unique_users: number
    total_bandwidth: number
    bandwidth_in: number
    bandwidth_out: number
  }
  percentiles: {
    p50: number
    p75: number
    p90: number
    p95: number
    p99: number
    min: number
    max: number
  }
  top_apis: Array<{ api: string; count: number }>
  top_users: Array<{ user: string; count: number }>
  top_endpoints?: Array<{
    endpoint_uri: string
    method: string
    count: number
    avg_ms: number
    p95_ms: number
    error_rate: number
  }>
  status_distribution: { [key: string]: number }
}

interface TimeSeriesData {
  series: Array<{
    timestamp: number
    count: number
    error_count: number
    error_rate: number
    avg_ms: number
    percentiles: {
      p50: number
      p75: number
      p90: number
      p95: number
      p99: number
    }
  }>
}

type TimeRange = '1h' | '24h' | '7d' | '30d' | 'custom'
type ActiveTab = 'overview' | 'apis' | 'users' | 'performance'

const analyticsTabs = [
                      { id: 'overview', label: 'Overview', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
                      { id: 'apis', label: 'APIs', icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10' },
                      { id: 'users', label: 'Users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z' },
                      { id: 'performance', label: 'Performance', icon: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6' },
]

interface AnalyticsPageContentProps {
  searchParams: ReadonlyURLSearchParams
}

export default function AnalyticsPageContent({ searchParams }: AnalyticsPageContentProps) {
  const router = useRouter()
  
  // State
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null)
  const [timeSeries, setTimeSeries] = useState<TimeSeriesData | null>(null)
  const [timeRange, setTimeRange] = useState<TimeRange>('24h')
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview')
  const [customStartDate, setCustomStartDate] = useState('')
  const [customEndDate, setCustomEndDate] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null)
  

  // Modal state
  const [selectedAPI, setSelectedAPI] = useState<string | null>(null)
  const [selectedUser, setSelectedUser] = useState<string | null>(null)
  const [apiModalOpen, setAPIModalOpen] = useState(false)
  const [userModalOpen, setUserModalOpen] = useState(false)
  
  // Filter state
  const [selectedAPIs, setSelectedAPIs] = useState<string[]>([])
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])
  const [selectedStatusCodes, setSelectedStatusCodes] = useState<string[]>([])
  const [selectedMethods, setSelectedMethods] = useState<string[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [filterStartDate, setFilterStartDate] = useState('')
  const [filterEndDate, setFilterEndDate] = useState('')

  // Load filters from URL on mount
  useEffect(() => {
    const requestedTab = searchParams.get('tab')
    if (requestedTab === 'ai' || requestedTab === 'reports') { router.replace(requestedTab === 'reports' ? '/ai/usage#chargeback' : '/ai/usage'); return }
    if (analyticsTabs.some(tab => tab.id === requestedTab)) setActiveTab(requestedTab as ActiveTab)
    const apis = searchParams.get('apis')
    const users = searchParams.get('users')
    const statusCodes = searchParams.get('status')
    const methods = searchParams.get('methods')
    const search = searchParams.get('search')
    const startDate = searchParams.get('start')
    const endDate = searchParams.get('end')
    
    if (apis) setSelectedAPIs(apis.split(','))
    if (users) setSelectedUsers(users.split(','))
    if (statusCodes) setSelectedStatusCodes(statusCodes.split(','))
    if (methods) setSelectedMethods(methods.split(','))
    if (search) setSearchQuery(search)
    if (startDate) setFilterStartDate(startDate)
    if (endDate) setFilterEndDate(endDate)
  }, [searchParams, router])
  
  // Fetch analytics data
  const fetchAnalytics = async () => {
    try {
      setLoading(true)
      setError(null)

      // Fetch overview
      const overviewUrl = `${SERVER_URL}/platform/analytics/overview?range=${timeRange}`
      const overviewData = await getJson<any>(overviewUrl)
      // getJson already unwraps envelopes; use directly
      setOverview(overviewData)

      // Fetch time-series data
      const timeSeriesUrl = `${SERVER_URL}/platform/analytics/timeseries?range=${timeRange}`
      const timeSeriesData = await getJson<any>(timeSeriesUrl)
      setTimeSeries(timeSeriesData)
    } catch (err) {
      console.error('Failed to fetch analytics:', err)
      setError(err instanceof Error ? err.message : 'Failed to fetch analytics data')
      setOverview(null)
      setTimeSeries(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAnalytics()
  }, [timeRange])

  // Auto-refresh effect
  useEffect(() => {
    if (autoRefresh) {
      refreshIntervalRef.current = setInterval(() => {
        fetchAnalytics()
      }, 30000) // Refresh every 30 seconds
    } else {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current)
        refreshIntervalRef.current = null
      }
    }

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current)
      }
    }
  }, [autoRefresh])

  const handleCustomDateApply = () => {
    // TODO: Implement custom date range
    console.log('Custom date range:', customStartDate, customEndDate)
  }

  // Modal handlers
  const handleAPIClick = (api: string) => {
    setSelectedAPI(api)
    setAPIModalOpen(true)
  }

  const handleUserClick = (username: string) => {
    setSelectedUser(username)
    setUserModalOpen(true)
  }

  // Filter handlers
  const updateURLParams = () => {
    const params = new URLSearchParams()
    
    if (selectedAPIs.length > 0) params.set('apis', selectedAPIs.join(','))
    if (selectedUsers.length > 0) params.set('users', selectedUsers.join(','))
    if (selectedStatusCodes.length > 0) params.set('status', selectedStatusCodes.join(','))
    if (selectedMethods.length > 0) params.set('methods', selectedMethods.join(','))
    if (searchQuery) params.set('search', searchQuery)
    if (filterStartDate) params.set('start', filterStartDate)
    if (filterEndDate) params.set('end', filterEndDate)
    
    const queryString = params.toString()
    router.push(queryString ? `/analytics?${queryString}` : '/analytics')
  }

  const handleApplyFilters = () => {
    updateURLParams()
    fetchAnalytics()
  }

  const handleClearFilters = () => {
    setSelectedAPIs([])
    setSelectedUsers([])
    setSelectedStatusCodes([])
    setSelectedMethods([])
    setSearchQuery('')
    setFilterStartDate('')
    setFilterEndDate('')
    router.push('/analytics')
    fetchAnalytics()
  }

  const handleSaveView = () => {
    // Placeholder for save view functionality
    alert('Save View feature will be available in a future update')
  }

  // Format helpers
  const formatNumber = (num: number | undefined | null): string => {
    if (num === undefined || num === null) return '0'
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  const formatBytes = (bytes: number | undefined | null): string => {
    if (bytes === undefined || bytes === null) return '0 B'
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${bytes} B`
  }

  const formatMs = (ms: number | undefined | null): string => {
    if (ms === undefined || ms === null) return '0.0ms'
    return `${ms.toFixed(1)}ms`
  }

  const formatPercent = (rate: number | undefined | null): string => {
    if (rate === undefined || rate === null) return '0.00%'
    return `${(rate * 100).toFixed(2)}%`
  }

  return (
    <ProtectedRoute requiredPermission="view_analytics">
      <Layout>
        <div className="space-y-6">
          {/* Page Header */}
          <div className="page-header">
            <div>
              <h1 className="page-title">Analytics</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                Comprehensive insights into API usage, performance, and trends
              </p>
            </div>
          </div>

          <div className="card overflow-x-auto"><nav className="flex border-b border-gray-200" aria-label="Analytics sections">{analyticsTabs.map(tab => <button key={tab.id} type="button" aria-pressed={activeTab === tab.id} onClick={() => {
            setActiveTab(tab.id as ActiveTab)
            const params = new URLSearchParams(searchParams.toString()); params.set('tab', tab.id)
            router.replace(`/analytics?${params}`, { scroll: false })
          }} className={`inline-flex items-center px-5 py-3 border-b-2 text-sm font-medium whitespace-nowrap ${activeTab === tab.id ? 'border-primary-500 text-primary-700' : 'border-transparent text-gray-500'}`}><svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} /></svg>{tab.label}</button>)}</nav></div>

          {/* Time Range Selector */}
          {<div className="card">
            <div className="p-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Time Range:
                </span>
                
                {/* Preset Ranges */}
                <div className="flex gap-2">
                  {(['1h', '24h', '7d', '30d'] as TimeRange[]).map((range) => (
                    <button
                      key={range}
                      onClick={() => setTimeRange(range)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        timeRange === range
                          ? 'bg-gray-950 text-white'
                          : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                      }`}
                    >
                      {range === '1h' && 'Last Hour'}
                      {range === '24h' && 'Last 24 Hours'}
                      {range === '7d' && 'Last 7 Days'}
                      {range === '30d' && 'Last 30 Days'}
                    </button>
                  ))}
                  
                  <button
                    onClick={() => setTimeRange('custom')}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      timeRange === 'custom'
                        ? 'bg-gray-950 text-white'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                    }`}
                  >
                    Custom
                  </button>
                </div>

                {/* Custom Date Range */}
                {timeRange === 'custom' && (
                  <div className="flex items-center gap-2 ml-4">
                    <input
                      type="datetime-local"
                      value={customStartDate}
                      onChange={(e) => setCustomStartDate(e.target.value)}
                      className="input text-sm"
                    />
                    <span className="text-gray-500">to</span>
                    <input
                      type="datetime-local"
                      value={customEndDate}
                      onChange={(e) => setCustomEndDate(e.target.value)}
                      className="input text-sm"
                    />
                    <button
                      onClick={handleCustomDateApply}
                      className="btn btn-primary btn-sm"
                    >
                      Apply
                    </button>
                  </div>
                )}

                {/* Auto-Refresh Toggle */}
                <div className="ml-auto flex items-center gap-3">
                  <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <input
                      type="checkbox"
                      checked={autoRefresh}
                      onChange={(e) => setAutoRefresh(e.target.checked)}
                      className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                    />
                    <span>Auto-refresh (30s)</span>
                  </label>
                  
                  {/* Refresh Button */}
                  <button
                    onClick={() => fetchAnalytics()}
                    disabled={loading}
                    className="btn btn-outline btn-sm"
                  >
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Refresh
                  </button>
                </div>
              </div>
            </div>
          </div>}

          {/* Filter Panel */}
          {<FilterPanel
            availableAPIs={overview?.top_apis.map(a => a.api) || []}
            availableUsers={overview?.top_users.map(u => u.user) || []}
            selectedAPIs={selectedAPIs}
            selectedUsers={selectedUsers}
            selectedStatusCodes={selectedStatusCodes}
            selectedMethods={selectedMethods}
            searchQuery={searchQuery}
            startDate={filterStartDate}
            endDate={filterEndDate}
            onAPIsChange={setSelectedAPIs}
            onUsersChange={setSelectedUsers}
            onStatusCodesChange={setSelectedStatusCodes}
            onMethodsChange={setSelectedMethods}
            onSearchChange={setSearchQuery}
            onStartDateChange={setFilterStartDate}
            onEndDateChange={setFilterEndDate}
            onApplyFilters={handleApplyFilters}
            onClearFilters={handleClearFilters}
            onSaveView={handleSaveView}
          />}


          {/* Error State */}
          {error && (
            <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
              <div className="flex">
                <svg className="h-5 w-5 text-error-400 dark:text-error-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="ml-3">
                  <p className="text-sm text-error-700 dark:text-error-300">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Loading State */}
          {loading && !overview && (
            <div className="card">
              <div className="flex items-center justify-center py-12">
                <div className="text-center">
                  <div className="spinner mx-auto mb-4"></div>
                  <p className="text-gray-600 dark:text-gray-400">Loading analytics...</p>
                </div>
              </div>
            </div>
          )}

          {/* No Data State */}
          {!loading && !overview && !error && (
            <div className="card">
              <div className="flex items-center justify-center py-12">
                <div className="text-center">
                  <div className="h-16 w-16 mx-auto mb-4 rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                    <svg className="h-8 w-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No Analytics Data Available</h3>
                  <p className="text-gray-600 dark:text-gray-400 mb-4 max-w-md mx-auto">
                    No API requests have been recorded yet in the selected time range. Analytics data will appear here once requests are made through the gateway.
                  </p>
                  <button
                    onClick={() => fetchAnalytics()}
                    className="btn btn-primary"
                  >
                    <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Refresh
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Summary Cards */}
          {!loading && overview && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {/* Total Requests Card */}
                <div className="card">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                          Total Requests
                        </p>
                        <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                          {formatNumber(overview.summary.total_requests)}
                        </p>
                      </div>
                      <div className="p-3 bg-primary-100 dark:bg-primary-900/20 rounded-lg">
                        <svg className="h-8 w-8 text-primary-600 dark:text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                        </svg>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Average Latency Card */}
                <div className="card">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                          Avg Latency
                        </p>
                        <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                          {formatMs(overview.summary.avg_response_ms)}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                          p95: {formatMs(overview.percentiles.p95)}
                        </p>
                      </div>
                      <div className="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                        <svg className="h-8 w-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Error Rate Card */}
                <div className="card">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                          Error Rate
                        </p>
                        <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                          {formatPercent(overview.summary.error_rate)}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                          {formatNumber(overview.summary.total_errors)} errors
                        </p>
                      </div>
                      <div className={`p-3 rounded-lg ${
                        overview.summary.error_rate > 0.05
                          ? 'bg-error-100 dark:bg-error-900/20'
                          : 'bg-success-100 dark:bg-success-900/20'
                      }`}>
                        <svg className={`h-8 w-8 ${
                          overview.summary.error_rate > 0.05
                            ? 'text-error-600 dark:text-error-400'
                            : 'text-success-600 dark:text-success-400'
                        }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Active Users Card */}
                <div className="card">
                  <div className="p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                          Active Users
                        </p>
                        <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                          {formatNumber(overview.summary.unique_users)}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                          Unique users
                        </p>
                      </div>
                      <div className="p-3 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                        <svg className="h-8 w-8 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                        </svg>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="card">
                {/* Tab Content */}
                <div className="p-6">
                  {/* Overview Tab */}
                  {activeTab === 'overview' && (
                    <div className="space-y-6">
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {/* Percentiles */}
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                            Latency Percentiles
                          </h3>
                          <div className="space-y-3">
                            {[
                              { label: 'p50 (Median)', value: overview.percentiles.p50, color: 'bg-green-500' },
                              { label: 'p75', value: overview.percentiles.p75, color: 'bg-blue-500' },
                              { label: 'p90', value: overview.percentiles.p90, color: 'bg-yellow-500' },
                              { label: 'p95', value: overview.percentiles.p95, color: 'bg-orange-500' },
                              { label: 'p99', value: overview.percentiles.p99, color: 'bg-red-500' }
                            ].map((percentile) => (
                              <div key={percentile.label} className="flex items-center justify-between">
                                <span className="text-sm text-gray-600 dark:text-gray-400">{percentile.label}</span>
                                <div className="flex items-center gap-3">
                                  <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                                    <div
                                      className={`${percentile.color} h-2 rounded-full`}
                                      style={{ width: `${Math.min((percentile.value / overview.percentiles.p99) * 100, 100)}%` }}
                                    />
                                  </div>
                                  <span className="text-sm font-medium text-gray-900 dark:text-white w-16 text-right">
                                    {formatMs(percentile.value)}
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Bandwidth */}
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                            Bandwidth Usage
                          </h3>
                          <div className="space-y-4">
                            <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                              <div className="flex items-center">
                                <svg className="h-5 w-5 text-blue-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16l-4-4m0 0l4-4m-4 4h18" />
                                </svg>
                                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Inbound</span>
                              </div>
                              <span className="text-sm font-bold text-gray-900 dark:text-white">
                                {formatBytes(overview.summary.bandwidth_in)}
                              </span>
                            </div>
                            <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                              <div className="flex items-center">
                                <svg className="h-5 w-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
                                </svg>
                                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Outbound</span>
                              </div>
                              <span className="text-sm font-bold text-gray-900 dark:text-white">
                                {formatBytes(overview.summary.bandwidth_out)}
                              </span>
                            </div>
                            <div className="flex items-center justify-between p-4 bg-primary-50 dark:bg-primary-900/20 rounded-lg">
                              <div className="flex items-center">
                                <svg className="h-5 w-5 text-primary-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                                </svg>
                                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Total</span>
                              </div>
                              <span className="text-sm font-bold text-gray-900 dark:text-white">
                                {formatBytes(overview.summary.total_bandwidth)}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Charts */}
                      {timeSeries && timeSeries.series && timeSeries.series.length > 0 ? (
                        <div className="space-y-6">
                          {/* Request Volume Chart */}
                          <div className="card p-6">
                            <TimeSeriesChart
                              data={timeSeries.series}
                              title="Request Volume Over Time"
                              dataKey="count"
                              color="#3b82f6"
                              height={300}
                            />
                          </div>

                          {/* Error Rate Chart */}
                          <div className="card p-6">
                            <ErrorRateChart
                              data={timeSeries.series}
                              title="Error Rate Over Time"
                              threshold={0.05}
                              height={300}
                            />
                          </div>

                          {/* API Distribution */}
                          <div className="card p-6">
                            <APIDistributionChart
                              data={overview.top_apis}
                              title="API Usage Distribution"
                              height={350}
                            />
                          </div>
                        </div>
                      ) : (
                        <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-8 text-center">
                          <svg className="h-16 w-16 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                          </svg>
                          <p className="text-gray-500 dark:text-gray-400">
                            No time-series data available
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {/* APIs Tab */}
                  {activeTab === 'apis' && (
                    <TopAPIsTable
                      data={overview.top_apis}
                      onAPIClick={handleAPIClick}
                    />
                  )}

                  {/* Users Tab */}
                  {activeTab === 'users' && (
                    <TopUsersTable
                      data={overview.top_users}
                      onUserClick={handleUserClick}
                    />
                  )}

                  {/* Performance Tab */}
                  {activeTab === 'performance' && (
                    <PerformanceTab
                      overview={{
                        percentiles: overview.percentiles,
                        avg_response_ms: overview.summary.avg_response_ms
                      }}
                      timeSeries={timeSeries}
                      endpoints={overview.top_endpoints || []}
                    />
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* API Detail Modal */}
        <DetailModal
          isOpen={apiModalOpen}
          onClose={() => setAPIModalOpen(false)}
          title={`API Details: ${selectedAPI || ''}`}
        >
          {selectedAPI && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">API Name</p>
                  <p className="text-lg font-semibold text-gray-900 dark:text-white font-mono">
                    {selectedAPI}
                  </p>
                </div>
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Total Requests</p>
                  <p className="text-lg font-semibold text-gray-900 dark:text-white">
                    {overview?.top_apis.find(a => a.api === selectedAPI)?.count.toLocaleString() || 'N/A'}
                  </p>
                </div>
              </div>
              
              <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  Detailed API analytics and endpoint breakdown will be available in the next update.
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-500">
                  This modal demonstrates the drill-down capability. In production, this would show:
                </p>
                <ul className="list-disc list-inside text-sm text-gray-500 dark:text-gray-500 mt-2 space-y-1">
                  <li>Per-endpoint performance metrics</li>
                  <li>Request/response time trends</li>
                  <li>Error rate analysis</li>
                  <li>Top consumers of this API</li>
                  <li>Recent activity timeline</li>
                </ul>
              </div>
            </div>
          )}
        </DetailModal>
      </Layout>
    </ProtectedRoute>
  )
}
