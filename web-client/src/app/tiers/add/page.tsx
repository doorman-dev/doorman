'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { postJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'

export default function AddTierPage() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [formData, setFormData] = useState({
    tier_id: '',
    display_name: '',
    description: '',
    price_monthly: '',
    price_yearly: '',
    is_default: false,
    enabled: true,
    // Limits
    rate_limiting_enabled: true,
    requests_per_minute: '',
    requests_per_hour: '',
    requests_per_day: '',
    monthly_request_quota: '',
    daily_request_quota: '',
    // Throttling
    enable_throttling: false,
    max_queue_time_ms: '5000'
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      // If rate limiting is disabled, set all limits to 999999
      const rateLimitingDisabled = !formData.rate_limiting_enabled
      const unlimitedValue = 999999
      
      const payload = {
        tier_id: formData.tier_id,
        name: formData.tier_id.toLowerCase().replace(/[^a-z0-9]/g, '_'),
        display_name: formData.display_name,
        description: formData.description || undefined,
        price_monthly: formData.price_monthly ? parseFloat(formData.price_monthly) : undefined,
        price_yearly: formData.price_yearly ? parseFloat(formData.price_yearly) : undefined,
        is_default: formData.is_default,
        enabled: formData.enabled,
        features: [],
        limits: {
          requests_per_minute: rateLimitingDisabled ? unlimitedValue : (formData.requests_per_minute ? parseInt(formData.requests_per_minute) : undefined),
          requests_per_hour: rateLimitingDisabled ? unlimitedValue : (formData.requests_per_hour ? parseInt(formData.requests_per_hour) : undefined),
          requests_per_day: rateLimitingDisabled ? unlimitedValue : (formData.requests_per_day ? parseInt(formData.requests_per_day) : undefined),
          monthly_request_quota: rateLimitingDisabled ? unlimitedValue : (formData.monthly_request_quota ? parseInt(formData.monthly_request_quota) : undefined),
          daily_request_quota: rateLimitingDisabled ? unlimitedValue : (formData.daily_request_quota ? parseInt(formData.daily_request_quota) : undefined),
          burst_per_second: 0,
          burst_per_minute: 0,
          burst_per_hour: 0,
          enable_throttling: formData.enable_throttling,
          max_queue_time_ms: parseInt(formData.max_queue_time_ms) || 5000
        }
      }

      await postJson(`${SERVER_URL}/platform/tiers/`, payload)
      router.push('/tiers')
    } catch (err: any) {
      console.error('Failed to create tier:', err)
      setError(err.message || 'Failed to create tier')
      setLoading(false)
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value, type } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? (e.target as HTMLInputElement).checked : value
    }))
  }

  return (
    <ProtectedRoute requiredPermission="manage_tiers">
      <Layout>
        <div className="max-w-4xl mx-auto space-y-6">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Add Tier</h1>
            <p className="mt-2 text-gray-600 dark:text-gray-400">Create a new pricing tier</p>
          </div>

          {error && (
            <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
              <p className="text-sm text-error-700 dark:text-error-300">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Information */}
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Basic Information
              </h2>
              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Tier ID *
                  </label>
                  <input
                    type="text"
                    name="tier_id"
                    value={formData.tier_id}
                    onChange={handleChange}
                    required
                    className="input w-full"
                    placeholder="e.g., pro_tier"
                  />
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Unique identifier for this tier (lowercase, no spaces)
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Tier Name *
                  </label>
                  <input
                    type="text"
                    name="display_name"
                    value={formData.display_name}
                    onChange={handleChange}
                    required
                    className="input w-full"
                    placeholder="e.g., Professional Plan"
                  />
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Display name shown to users
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Description
                  </label>
                  <textarea
                    name="description"
                    value={formData.description}
                    onChange={handleChange}
                    rows={2}
                    className="input w-full"
                    placeholder="Brief description of this tier"
                  />
                </div>
              </div>
            </div>

            {/* Pricing */}
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Pricing
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Monthly Price ($)
                  </label>
                  <input
                    type="number"
                    name="price_monthly"
                    value={formData.price_monthly}
                    onChange={handleChange}
                    step="0.01"
                    min="0"
                    className="input w-full"
                    placeholder="49.99"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Yearly Price ($)
                  </label>
                  <input
                    type="number"
                    name="price_yearly"
                    value={formData.price_yearly}
                    onChange={handleChange}
                    step="0.01"
                    min="0"
                    className="input w-full"
                    placeholder="499.99"
                  />
                </div>
              </div>
            </div>

            {/* Rate Limits */}
            <div className="card p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Rate Limits
                </h2>
                <label className="flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    name="rate_limiting_enabled"
                    checked={formData.rate_limiting_enabled}
                    onChange={handleChange}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="ml-2 text-sm font-medium text-gray-700 dark:text-gray-300">
                    Enforce tier based rate limiting
                  </span>
                </label>
              </div>
              
              {!formData.rate_limiting_enabled && (
                <div className="mb-4 p-3 rounded bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
                  <p className="text-sm text-blue-800 dark:text-blue-300">
                    ℹ️ Rate limiting is disabled. This tier will have unlimited requests.
                  </p>
                </div>
              )}
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Requests per Minute
                  </label>
                  <input
                    type="number"
                    name="requests_per_minute"
                    value={formData.requests_per_minute}
                    onChange={handleChange}
                    min="0"
                    disabled={!formData.rate_limiting_enabled}
                    className="input w-full disabled:bg-gray-100 disabled:cursor-not-allowed dark:disabled:bg-gray-800"
                    placeholder="100"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Requests per Hour
                  </label>
                  <input
                    type="number"
                    name="requests_per_hour"
                    value={formData.requests_per_hour}
                    onChange={handleChange}
                    min="0"
                    disabled={!formData.rate_limiting_enabled}
                    className="input w-full disabled:bg-gray-100 disabled:cursor-not-allowed dark:disabled:bg-gray-800"
                    placeholder="5000"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Requests per Day
                  </label>
                  <input
                    type="number"
                    name="requests_per_day"
                    value={formData.requests_per_day}
                    onChange={handleChange}
                    min="0"
                    disabled={!formData.rate_limiting_enabled}
                    className="input w-full disabled:bg-gray-100 disabled:cursor-not-allowed dark:disabled:bg-gray-800"
                    placeholder="100000"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Monthly Request Quota
                  </label>
                  <input
                    type="number"
                    name="monthly_request_quota"
                    value={formData.monthly_request_quota}
                    onChange={handleChange}
                    min="0"
                    disabled={!formData.rate_limiting_enabled}
                    className="input w-full disabled:bg-gray-100 disabled:cursor-not-allowed dark:disabled:bg-gray-800"
                    placeholder="1000000"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Daily Request Quota
                  </label>
                  <input
                    type="number"
                    name="daily_request_quota"
                    value={formData.daily_request_quota}
                    onChange={handleChange}
                    min="0"
                    disabled={!formData.rate_limiting_enabled}
                    className="input w-full disabled:bg-gray-100 disabled:cursor-not-allowed dark:disabled:bg-gray-800"
                    placeholder="50000"
                  />
                </div>
              </div>
            </div>

            {/* Throttling */}
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Throttling
              </h2>
              <div className="space-y-4">
                <label className="flex items-start">
                  <input
                    type="checkbox"
                    name="enable_throttling"
                    checked={formData.enable_throttling}
                    onChange={handleChange}
                    className="mt-1 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div className="ml-3">
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                      Enforce tier based throttling
                    </span>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      When enabled, requests exceeding limits will be queued instead of immediately rejected. When disabled, requests return 429 errors.
                    </p>
                  </div>
                </label>

                {formData.enable_throttling && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Max Queue Time (ms)
                    </label>
                    <input
                      type="number"
                      name="max_queue_time_ms"
                      value={formData.max_queue_time_ms}
                      onChange={handleChange}
                      min="0"
                      step="100"
                      className="input w-full"
                      placeholder="5000"
                    />
                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                      Maximum time (in milliseconds) to queue a request before rejecting it
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Settings */}
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Settings
              </h2>
              <div className="space-y-3">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="is_default"
                    checked={formData.is_default}
                    onChange={handleChange}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Set as default tier
                  </span>
                </label>

                <label className="flex items-center">
                  <input
                    type="checkbox"
                    name="enabled"
                    checked={formData.enabled}
                    onChange={handleChange}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable tier immediately
                  </span>
                </label>
              </div>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => router.back()}
                className="btn btn-outline"
                disabled={loading}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={loading}
              >
                {loading ? 'Creating...' : 'Create Tier'}
              </button>
            </div>
          </form>
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
