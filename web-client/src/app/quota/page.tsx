'use client'

import React, { useState, useEffect } from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'

interface QuotaStatus {
  quota_type: string
  current_usage: number
  limit: number
  remaining: number
  percentage_used: number
  reset_at: string
  is_warning: boolean
  is_critical: boolean
  is_exhausted: boolean
  burst_used?: number
  burst_limit?: number
  burst_percentage?: number
}

interface TierInfo {
  tier_id: string
  tier_name: string
  display_name: string
  limits: any
  price_monthly?: number
  features: string[]
}

interface DashboardData {
  user_id: string
  tier_info: TierInfo
  quotas: QuotaStatus[]
  usage_summary: {
    total_requests_used: number
    total_requests_limit: number
    has_warnings: boolean
    has_critical: boolean
    has_exhausted: boolean
  }
}

export default function QuotaDashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchQuotaStatus()
  }, [])

  const fetchQuotaStatus = async () => {
    try {
      setLoading(true)
      const response = await getJson(`${SERVER_URL}/platform/quota/status`)
      setData(response)
      setError(null)
    } catch (err) {
      console.error('Failed to fetch quota status:', err)
      setError('Failed to load quota information')
    } finally {
      setLoading(false)
    }
  }

  const getProgressColor = (quota: QuotaStatus) => {
    if (quota.is_exhausted) return 'bg-error-600'
    if (quota.is_critical) return 'bg-error-500'
    if (quota.is_warning) return 'bg-warning-500'
    return 'bg-success-500'
  }

  const getStatusBadge = (quota: QuotaStatus) => {
    if (quota.is_exhausted) return <span className="badge badge-error">Exhausted</span>
    if (quota.is_critical) return <span className="badge badge-error">Critical</span>
    if (quota.is_warning) return <span className="badge badge-warning">Warning</span>
    return <span className="badge badge-success">Healthy</span>
  }

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr)
    return date.toLocaleString()
  }

  const getTimeUntilReset = (resetAt: string) => {
    const now = new Date()
    const reset = new Date(resetAt)
    const diff = reset.getTime() - now.getTime()
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
    
    if (days > 0) return `${days}d ${hours}h`
    if (hours > 0) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }

  return (
    <ProtectedRoute>
      <Layout>
        <div className="space-y-6">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Quota Dashboard</h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">
              Monitor your API usage and limits
            </p>
          </div>

          {loading ? (
            <div className="card p-8 text-center">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
              <p className="mt-2 text-gray-600 dark:text-gray-400">Loading quota information...</p>
            </div>
          ) : error ? (
            <div className="card p-8 text-center text-error-600">{error}</div>
          ) : data ? (
            <>
              {/* Tier Information */}
              <div className="card p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                      {data.tier_info?.display_name || 'Standard Tier'}
                    </h2>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      Current Plan
                    </p>
                  </div>
                  {data.tier_info?.price_monthly && (
                    <div className="text-right">
                      <p className="text-2xl font-bold text-gray-900 dark:text-white">
                        ${data.tier_info.price_monthly}
                      </p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">per month</p>
                    </div>
                  )}
                </div>
                
                {data.tier_info?.features && data.tier_info.features.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Plan Features:
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {data.tier_info.features.map((feature, idx) => (
                        <span
                          key={idx}
                          className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/20 dark:text-primary-400"
                        >
                          {feature}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Alert Banner */}
              {data.usage_summary?.has_exhausted && (
                <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
                  <div className="flex">
                    <svg className="h-5 w-5 text-error-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-error-800 dark:text-error-300">
                        Quota Exhausted
                      </h3>
                      <p className="mt-1 text-sm text-error-700 dark:text-error-400">
                        You have reached your quota limit. Upgrade your plan to continue.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {data.usage_summary.has_critical && !data.usage_summary.has_exhausted && (
                <div className="rounded-lg bg-warning-50 border border-warning-200 p-4 dark:bg-warning-900/20 dark:border-warning-800">
                  <div className="flex">
                    <svg className="h-5 w-5 text-warning-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-warning-800 dark:text-warning-300">
                        Critical Usage Level
                      </h3>
                      <p className="mt-1 text-sm text-warning-700 dark:text-warning-400">
                        You are approaching your quota limit (95%+). Consider upgrading soon.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Quota Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {data.quotas.map((quota) => (
                  <div key={quota.quota_type} className="card p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white capitalize">
                        {quota.quota_type.replace('_', ' ')}
                      </h3>
                      {getStatusBadge(quota)}
                    </div>

                    <div className="space-y-4">
                      <div>
                        <div className="flex justify-between text-sm mb-2">
                          <span className="text-gray-600 dark:text-gray-400">Usage</span>
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {formatNumber(quota.current_usage)} / {formatNumber(quota.limit)}
                          </span>
                        </div>
                        
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                          <div
                            className={`h-3 rounded-full transition-all ${getProgressColor(quota)}`}
                            style={{ width: `${Math.min(quota.percentage_used, 100)}%` }}
                          />
                        </div>
                        
                        <div className="flex justify-between text-xs mt-2">
                          <span className="text-gray-500 dark:text-gray-400">
                            {quota.percentage_used.toFixed(1)}% used
                          </span>
                          <span className="text-gray-500 dark:text-gray-400">
                            {formatNumber(quota.remaining)} remaining
                          </span>
                        </div>
                      </div>

                      {/* Burst Usage (if available) */}
                      {quota.burst_limit && quota.burst_limit > 0 && (
                        <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                          <div className="flex justify-between text-sm mb-2">
                            <span className="text-gray-600 dark:text-gray-400">
                              Burst Capacity
                            </span>
                            <span className="font-semibold text-gray-900 dark:text-white">
                              {quota.burst_used || 0} / {quota.burst_limit}
                            </span>
                          </div>
                          
                          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                              className="h-2 rounded-full transition-all bg-blue-500"
                              style={{ width: `${Math.min(quota.burst_percentage || 0, 100)}%` }}
                            />
                          </div>
                          
                          {quota.burst_used && quota.burst_used > 0 && (
                            <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
                              ⚡ Burst tokens in use
                            </p>
                          )}
                        </div>
                      )}

                      <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-600 dark:text-gray-400">Resets in</span>
                          <span className="font-medium text-gray-900 dark:text-white">
                            {getTimeUntilReset(quota.reset_at)}
                          </span>
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          {formatDate(quota.reset_at)}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Usage Summary */}
              <div className="card p-6">
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                  Usage Summary
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Requests</p>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                      {formatNumber(data.usage_summary.total_requests_used)}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Total Limit</p>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                      {formatNumber(data.usage_summary.total_requests_limit)}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Overall Status</p>
                    <p className="text-2xl font-bold mt-1">
                      {data.usage_summary.has_exhausted ? (
                        <span className="text-error-600">Exhausted</span>
                      ) : data.usage_summary.has_critical ? (
                        <span className="text-warning-600">Critical</span>
                      ) : data.usage_summary.has_warnings ? (
                        <span className="text-warning-600">Warning</span>
                      ) : (
                        <span className="text-success-600">Healthy</span>
                      )}
                    </p>
                  </div>
                </div>
              </div>
            </>
          ) : null}
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
