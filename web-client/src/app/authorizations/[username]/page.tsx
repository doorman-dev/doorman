'use client'

import React, { useCallback, useState, useEffect } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Layout from '@/components/Layout'
import ConfirmModal from '@/components/ConfirmModal'
import SearchableSelect from '@/components/SearchableSelect'
import { SERVER_URL } from '@/utils/config'
import { fetchJson } from '@/utils/http'
import { postJson } from '@/utils/api'
import { LIFECYCLE_BADGE, type LifecycleStatus } from '@/components/ApiLifecyclePanel'

interface Subscription {
  api_name: string
  api_version: string
}

interface Api {
  api_name: string
  api_version: string
  api_description: string
  api_lifecycle_status?: LifecycleStatus
}

const UserSubscriptionsPage = () => {
  const router = useRouter()
  const params = useParams()
  const username = params.username as string

  const [subscriptions, setSubscriptions] = useState<Subscription[]>([])
  const [allApis, setAllApis] = useState<Api[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [selectedApi, setSelectedApi] = useState('')
  const [isAdding, setIsAdding] = useState(false)

  const [showConfirmModal, setShowConfirmModal] = useState(false)
  const [subscriptionToRevoke, setSubscriptionToRevoke] = useState<Subscription | null>(null)
  const [isRevoking, setIsRevoking] = useState(false)

  const fetchSubscriptions = useCallback(async () => {
    try {
      const data = await fetchJson(`${SERVER_URL}/platform/subscription/subscriptions/${username}`)
      const apis: string[] = (data?.apis)
        || (data?.subscriptions?.apis)
        || []
      const subs = apis.map((sub: string) => {
        const [api_name, api_version] = sub.split('/')
        return { api_name, api_version }
      }) || []
      setSubscriptions(subs)
    } catch (err) {
      setError('Failed to load user subscriptions.')
    }
  }, [username])

  const fetchApis = useCallback(async () => {
    try {
      const data = await fetchJson(`${SERVER_URL}/platform/subscription/available-apis/${encodeURIComponent(username)}`)
      setAllApis(data.apis || [])
    } catch (err) {
      setError('Failed to load available APIs.')
    }
  }, [username])

  useEffect(() => {
    if (username) {
      setLoading(true)
      Promise.all([fetchSubscriptions(), fetchApis()])
        .finally(() => setLoading(false))
    }
  }, [username, fetchSubscriptions, fetchApis])

  const handleBack = () => {
    router.push('/authorizations')
  }

  const handleAddSubscription = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedApi) {
      setError('Please select an API to subscribe to.')
      return
    }

    setIsAdding(true)
    setError(null)
    setSuccess(null)

    try {
      const [api_name, api_version] = selectedApi.split('/')
      const body = { username, api_name, api_version }
      const optimisticSub = { api_name, api_version }
      setSubscriptions(curr => curr.some(s => s.api_name === api_name && s.api_version === api_version)
        ? curr
        : [...curr, optimisticSub]
      )

      await postJson(`${SERVER_URL}/platform/subscription/subscribe`, body)

      setSuccess(`Successfully subscribed ${username} to ${selectedApi}.`)
      setSelectedApi('')
      await fetchSubscriptions()
    } catch (err) {
      await fetchSubscriptions()
      setError(err instanceof Error ? err.message : 'An unknown error occurred.')
    } finally {
      setIsAdding(false)
      setTimeout(() => setSuccess(null), 4000)
    }
  }

  const handleRevokeClick = (subscription: Subscription) => {
    setSubscriptionToRevoke(subscription)
    setShowConfirmModal(true)
  }

  const handleRevokeCancel = () => {
    setShowConfirmModal(false)
    setSubscriptionToRevoke(null)
  }

  const handleRevokeConfirm = async () => {
    if (!subscriptionToRevoke) return

    setIsRevoking(true)
    setError(null)
    setSuccess(null)

    try {
      const { api_name, api_version } = subscriptionToRevoke
      const body = { username, api_name, api_version }
      setSubscriptions(curr => curr.filter(s => !(s.api_name === api_name && s.api_version === api_version)))

      await postJson(`${SERVER_URL}/platform/subscription/unsubscribe`, body)

      setSuccess(`Successfully revoked access to ${api_name}/${api_version} for ${username}.`)
      await fetchSubscriptions()
    } catch (err) {
      await fetchSubscriptions()
      setError(err instanceof Error ? err.message : 'An unknown error occurred.')
    } finally {
      setIsRevoking(false)
      setShowConfirmModal(false)
      setSubscriptionToRevoke(null)
      setTimeout(() => setSuccess(null), 4000)
    }
  }

  const availableApis = allApis.filter(api =>
    !subscriptions.some(sub => sub.api_name === api.api_name && sub.api_version === api.api_version)
  )

  return (
    <Layout>
      <div className="space-y-6">
        <div className="page-header">
          <div>
            <h1 className="page-title">Manage Subscriptions</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              API access for <span className="font-semibold text-primary-600 dark:text-primary-400">{username}</span>
            </p>
          </div>
          <button onClick={handleBack} className="btn btn-secondary">
            <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Authorizations
          </button>
        </div>

        {success && (
            <div className="rounded-lg bg-success-50 border border-success-200 p-4 dark:bg-success-900/20 dark:border-success-800">
                <p className="text-sm text-success-700 dark:text-success-300">{success}</p>
            </div>
        )}
        {error && (
            <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
                <p className="text-sm text-error-700 dark:text-error-300">{error}</p>
            </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Current Subscriptions</h3>
              </div>
              <div className="p-6">
                {loading ? (
                  <p>Loading subscriptions...</p>
                ) : subscriptions.length > 0 ? (
                  <ul className="space-y-3">
                    {subscriptions.map(sub => (
                      <li key={`${sub.api_name}/${sub.api_version}`} className="flex items-center justify-between bg-gray-50 dark:bg-dark-surface p-3 rounded-lg">
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">{sub.api_name}</p>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Version: {sub.api_version}</p>
                          {allApis.filter(api => api.api_name === sub.api_name && api.api_version === sub.api_version).map(api => (
                            <span key={`${api.api_name}/${api.api_version}`} className={`badge ${LIFECYCLE_BADGE[api.api_lifecycle_status || 'active']}`}>
                              {api.api_lifecycle_status || 'active'}
                            </span>
                          ))}
                        </div>
                        <button
                          onClick={() => handleRevokeClick(sub)}
                          className="btn btn-error-outline btn-sm"
                        >
                          Revoke
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-gray-500 dark:text-gray-400 text-center py-8">This user has no active API subscriptions.</p>
                )}
              </div>
            </div>
          </div>

          <div>
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Add New Subscription</h3>
              </div>
              <form onSubmit={handleAddSubscription} className="p-6 space-y-4">
                <div>
                  <label htmlFor="api-select" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Available APIs
                  </label>
                  <SearchableSelect
                    key={subscriptions.map(sub => `${sub.api_name}/${sub.api_version}`).join(',')}
                    value={selectedApi}
                    onChange={setSelectedApi}
                    placeholder="Select API"
                    fetchOptions={async () => availableApis.map(api => ({
                      value: `${api.api_name}/${api.api_version}`,
                      label: `${api.api_name}/${api.api_version} (${api.api_lifecycle_status || 'active'})`,
                    }))}
                    disabled={loading || isAdding}
                    restrictToOptions
                  />
                  <ul className="mt-3 space-y-2" aria-label="Available API lifecycles">
                    {availableApis.map(api => (
                      <li key={`${api.api_name}/${api.api_version}`} className="flex flex-wrap items-center gap-2 text-sm">
                        <span>{api.api_name}/{api.api_version}</span>
                        <span className={`badge ${LIFECYCLE_BADGE[api.api_lifecycle_status || 'active']}`}>
                          {api.api_lifecycle_status || 'active'}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
                <button type="submit" className="btn btn-primary w-full" disabled={isAdding || !selectedApi}>
                  {isAdding ? 'Adding...' : 'Add Subscription'}
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      <ConfirmModal
        open={showConfirmModal}
        title="Revoke Subscription"
        message={`Are you sure you want to revoke access to ${subscriptionToRevoke?.api_name}/${subscriptionToRevoke?.api_version} for ${username}?`}
        confirmLabel={isRevoking ? 'Revoking...' : 'Confirm Revoke'}
        cancelLabel="Cancel"
        onCancel={handleRevokeCancel}
        onConfirm={handleRevokeConfirm}
      />
    </Layout>
  )
}

export default UserSubscriptionsPage
