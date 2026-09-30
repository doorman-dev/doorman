'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { getJson, delJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'

interface TierLimits {
  requests_per_second?: number
  requests_per_minute?: number
  requests_per_hour?: number
  requests_per_day?: number
  requests_per_month?: number
  burst_per_second: number
  burst_per_minute: number
  burst_per_hour: number
  monthly_request_quota?: number
  daily_request_quota?: number
  monthly_bandwidth_quota?: number
  enable_throttling: boolean
  max_queue_time_ms: number
}

interface Tier {
  tier_id: string
  name: string
  display_name: string
  description?: string
  limits: TierLimits
  price_monthly?: number
  price_yearly?: number
  features: string[]
  is_default: boolean
  enabled: boolean
  created_at?: string
  updated_at?: string
}

interface TierStats {
  tier_id: string
  tier_name: string
  total_users: number
  active_users: number
  inactive_users: number
}

type TierFilter = 'all' | 'enabled' | 'disabled' | 'default'

export default function TiersPage() {
  const router = useRouter()
  const [tiers, setTiers] = useState<Tier[]>([])
  const [stats, setStats] = useState<TierStats[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState<TierFilter>('all')

  useEffect(() => {
    fetchTiers('', 'all')
    fetchStats()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const fetchTiers = async (search: string, status: TierFilter = filterStatus) => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (search?.trim()) {
        params.append('search', search.trim())
      }
      if (status === 'enabled') {
        params.append('enabled_only', 'true')
      }
      const query = params.toString()
      const data: any = await getJson(`${SERVER_URL}/platform/tiers/${query ? `?${query}` : ''}`)
      // The listing is paginated: {tiers: [...], page, page_size, ...}
      let nextTiers: Tier[] = Array.isArray(data) ? data : (Array.isArray(data?.tiers) ? data.tiers : [])

      if (status === 'disabled') {
        nextTiers = nextTiers.filter(t => !t.enabled)
      } else if (status === 'default') {
        nextTiers = nextTiers.filter(t => t.is_default)
      }

      setTiers(nextTiers)
      setFilterStatus(status)
      setError(null)
    } catch (err) {
      console.error('Failed to fetch tiers:', err)
      setError('Failed to load tiers')
      setTiers([]) // Reset to empty array on error
    } finally {
      setLoading(false)
    }
  }

  const fetchStats = async () => {
    try {
      const data = await getJson(`${SERVER_URL}/platform/tiers/statistics/all`)
      // Ensure data is an array
      setStats(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error('Failed to fetch stats:', err)
      setStats([]) // Reset to empty array on error
    }
  }

  const handleDelete = async (tierId: string) => {
    if (!confirm('Are you sure you want to delete this tier?')) return

    try {
      await delJson(`${SERVER_URL}/platform/tiers/${tierId}`)
      await fetchTiers(searchTerm)
    } catch (err: any) {
      alert(err.message || 'Failed to delete tier')
    }
  }

  const formatNumber = (num?: number) => {
    if (!num) return '-'
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    fetchTiers(searchTerm)
  }

  const handleClearSearch = () => {
    setSearchTerm('')
    fetchTiers('', filterStatus)
  }

  const handleFilterChange = (status: TierFilter) => {
    fetchTiers(searchTerm, status)
  }

  const getTierStats = (tierId: string) => {
    return stats.find(s => s.tier_id === tierId)
  }

  return (
    <ProtectedRoute requiredPermission="manage_tiers">
      <Layout>
        <div className="space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Tier Management
              </h1>
              <p className="mt-2 text-gray-600 dark:text-gray-400">
                Manage pricing tiers and rate limit plans
              </p>
            </div>
            <button
              onClick={() => router.push('/tiers/add')}
              className="btn btn-primary"
            >
              <svg className="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add Tier
            </button>
          </div>

          {/* Search & Filters */}
          <div className="card">
            <div className="flex flex-col sm:flex-row gap-4">
              <form onSubmit={handleSearch} className="flex-1">
                <div className="relative">
                  <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <input
                    type="text"
                    className="search-input"
                    placeholder="Search tiers by name or description..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                  {searchTerm && (
                    <button
                      type="button"
                      className="absolute inset-y-0 right-3 text-gray-400 hover:text-gray-600"
                      onClick={handleClearSearch}
                      aria-label="Clear search"
                    >
                      ✕
                    </button>
                  )}
                </div>
              </form>

              <div className="flex gap-2 flex-wrap sm:flex-nowrap">
                <button
                  type="button"
                  onClick={() => handleFilterChange('all')}
                  className={`btn ${filterStatus === 'all' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  All Tiers
                </button>
                <button
                  type="button"
                  onClick={() => handleFilterChange('enabled')}
                  className={`btn ${filterStatus === 'enabled' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  Enabled
                </button>
                <button
                  type="button"
                  onClick={() => handleFilterChange('disabled')}
                  className={`btn ${filterStatus === 'disabled' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  Disabled
                </button>
                <button
                  type="button"
                  onClick={() => handleFilterChange('default')}
                  className={`btn ${filterStatus === 'default' ? 'btn-primary' : 'btn-secondary'}`}
                >
                  Default
                </button>
              </div>
            </div>
          </div>

          {loading ? (
            <div className="card p-8 text-center">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
              <p className="mt-2 text-gray-600 dark:text-gray-400">Loading tiers...</p>
            </div>
          ) : error ? (
            <div className="card p-8 text-center text-error-600">{error}</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {Array.isArray(tiers) && tiers.map((tier) => {
                const tierStats = getTierStats(tier.tier_id)
                return (
                  <div key={tier.tier_id} className="card p-6 hover:shadow-lg transition-shadow">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                          {tier.display_name}
                        </h3>
                        {tier.is_default && (
                          <span className="inline-block mt-1 px-2 py-1 text-xs font-medium rounded bg-primary-100 text-primary-800 dark:bg-primary-900/20 dark:text-primary-400">
                            Default
                          </span>
                        )}
                      </div>
                      {tier.price_monthly && (
                        <div className="text-right">
                          <p className="text-2xl font-bold text-gray-900 dark:text-white">
                            ${tier.price_monthly}
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">per month</p>
                        </div>
                      )}
                    </div>

                    {tier.description && (
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        {tier.description}
                      </p>
                    )}

                    {/* Limits */}
                    <div className="space-y-2 mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
                      {tier.limits.requests_per_minute && (
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-600 dark:text-gray-400">Per Minute:</span>
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {formatNumber(tier.limits.requests_per_minute)}
                          </span>
                        </div>
                      )}
                      {tier.limits.requests_per_hour && (
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-600 dark:text-gray-400">Per Hour:</span>
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {formatNumber(tier.limits.requests_per_hour)}
                          </span>
                        </div>
                      )}
                      {tier.limits.monthly_request_quota && (
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-600 dark:text-gray-400">Monthly Quota:</span>
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {formatNumber(tier.limits.monthly_request_quota)}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Rate Limiting Status Badges */}
                    <div className="mb-4 flex flex-wrap gap-2">
                      {/* Check if rate limiting is disabled (all limits are 999999) */}
                      {(tier.limits.requests_per_minute ?? 0) >= 999999 && 
                       (tier.limits.requests_per_hour ?? 0) >= 999999 ? (
                        <span className="inline-block px-2 py-1 text-xs font-medium rounded bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400">
                          ♾️ Unlimited
                        </span>
                      ) : null}
                      
                      {tier.limits.enable_throttling && (
                        <span className="inline-block px-2 py-1 text-xs font-medium rounded bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                          🚦 Throttling Enabled
                        </span>
                      )}
                    </div>

                    {/* Stats */}
                    {tierStats && (
                      <div className="mb-4 p-3 rounded bg-gray-50 dark:bg-gray-800">
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-600 dark:text-gray-400">Users:</span>
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {tierStats.active_users} active
                          </span>
                        </div>
                      </div>
                    )}

                  {/* Actions */}
                  <div className="flex gap-2">
                    <button
                      onClick={() => router.push(`/tiers/${tier.tier_id}/users`)}
                      className="flex-1 btn btn-sm btn-primary"
                      title="View assigned users"
                    >
                      <svg className="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                      </svg>
                      Users ({tierStats?.total_users || 0})
                    </button>
                    <button
                      onClick={() => router.push(`/tiers/${tier.tier_id}/edit`)}
                      className="flex-1 btn btn-sm btn-outline"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(tier.tier_id)}
                      className="flex-1 btn btn-sm btn-outline text-error-600 hover:bg-error-50 dark:hover:bg-error-900/20"
                      disabled={tier.is_default}
                    >
                      Delete
                    </button>
                  </div>

                  {!tier.enabled && (
                    <p className="mt-2 text-xs text-center text-gray-500 dark:text-gray-400">
                      Disabled
                    </p>
                  )}
                </div>
              )
            })}
            </div>
          )}
      </div>
    </Layout>
  </ProtectedRoute>
  )
}
