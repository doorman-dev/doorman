'use client'

import React, { useState, useEffect } from 'react'
import ConfirmModal from '@/components/ConfirmModal'
import Link from 'next/link'
import { useRouter, useParams } from 'next/navigation'
import Layout from '@/components/Layout'
import AiBudgetUsageCard from '@/components/AiBudgetUsageCard'
import { SERVER_URL } from '@/utils/config'
import InfoTooltip from '@/components/InfoTooltip'
import FormHelp from '@/components/FormHelp'
import { fetchJson } from '@/utils/http'
import { getJson } from '@/utils/api'
import SearchableSelect from '@/components/SearchableSelect'

interface Group {
  group_name: string
  group_description: string
  api_access?: string[]
}

const GroupDetailPage = () => {
  const router = useRouter()
  const params = useParams()
  const groupName = params.groupName as string

  const [group, setGroup] = useState<Group | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [isEditing, setIsEditing] = useState(false)
  const [editData, setEditData] = useState<Partial<Group>>({})
  const [saving, setSaving] = useState(false)
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteConfirmation, setDeleteConfirmation] = useState('')
  const [grantedApis, setGrantedApis] = useState<string[]>([])

  useEffect(() => {
    fetchGroup()
    fetchGrantedApis()
  }, [groupName])

  const fetchGrantedApis = async () => {
    try {
      // Fetch all APIs and filter those that include this group
      const data = await getJson<any>(`${SERVER_URL}/platform/api/all`)
      const apis = Array.isArray(data) ? data : (data.apis || data.response?.apis || [])
      
      // Filter APIs that have this group in their allowed_groups
      const apisWithAccess = apis
        .filter((api: any) => {
          const allowedGroups = api.api_allowed_groups || []
          return allowedGroups.includes(groupName) || allowedGroups.includes('ALL')
        })
        .map((api: any) => `${api.api_name}/${api.api_version}`)
      
      setGrantedApis(apisWithAccess)
    } catch (err) {
      console.error('Failed to fetch granted APIs:', err)
    }
  }

  const fetchGroup = async () => {
    try {
      setLoading(true)
      setError(null)

      const savedGroup = sessionStorage.getItem('selectedGroup')
      if (savedGroup) {
        const parsedGroup = JSON.parse(savedGroup)
        if (parsedGroup.group_name === groupName) {
          setGroup(parsedGroup)
          setEditData(parsedGroup)
          setLoading(false)
          return
        }
      }

      const data = await fetchJson(`${SERVER_URL}/platform/group/${encodeURIComponent(groupName)}`)
      setGroup(data)
      setEditData(data)
    } catch (err) {
      setError('Failed to load group. Please try again later.')
    } finally {
      setLoading(false)
    }
  }

  const handleBack = () => {
    router.push('/groups')
  }

  const handleExport = async () => {
    try {
      const name = group?.group_name || groupName
      if (!name) throw new Error('Missing group name')
      const payload = await fetchJson(`${SERVER_URL}/platform/config/export/groups?group_name=${encodeURIComponent(String(name))}`)
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `doorman-group-${name}.json`
      a.click()
      URL.revokeObjectURL(a.href)
    } catch (e:any) {
      alert(e?.message || 'Export failed')
    }
  }

  const handleEdit = () => {
    setIsEditing(true)
  }

  const handleCancel = () => {
    setIsEditing(false)
    if (group) {
      setEditData(group)
    }
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      setError(null)

      await (await import('@/utils/api')).putJson(`${SERVER_URL}/platform/group/${encodeURIComponent(groupName)}`, editData)

      let refreshedGroup: any
      try {
        refreshedGroup = await fetchJson(`${SERVER_URL}/platform/group/${encodeURIComponent(groupName)}`)
      } catch (e) {
        await new Promise(r => setTimeout(r, 200))
        refreshedGroup = await fetchJson(`${SERVER_URL}/platform/group/${encodeURIComponent(groupName)}`)
      }
      setGroup(refreshedGroup)
      setEditData(refreshedGroup)
      sessionStorage.setItem('selectedGroup', JSON.stringify(refreshedGroup))
      setIsEditing(false)
      setSuccess('Group updated successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Failed to update group. Please try again.')
      }
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    try {
      setDeleting(true)
      setError(null)

      const { delJson } = await import('@/utils/api')
      await delJson(`${SERVER_URL}/platform/group/${encodeURIComponent(groupName)}`)

      router.push('/groups')
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Failed to delete group. Please try again.')
      }
    } finally {
      setDeleting(false)
      setShowDeleteModal(false)
    }
  }

  const handleInputChange = (field: keyof Group, value: any) => {
    setEditData(prev => ({ ...prev, [field]: value }))
  }

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="spinner mx-auto mb-4"></div>
            <p className="text-gray-600 dark:text-gray-400">Loading group details...</p>
          </div>
        </div>
      </Layout>
    )
  }

  if (error && !group) {
    return (
      <Layout>
        <div className="space-y-6">
          <div className="page-header">
            <div>
              <h1 className="page-title">Group Details</h1>
            </div>
            <button onClick={handleBack} className="btn btn-secondary">
              <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              Back to Groups
            </button>
          </div>
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
        </div>
      </Layout>
    )
  }

  return (
    <Layout>
      <div className="space-y-6">
        <div className="page-header">
          <div>
            <h1 className="page-title">{group?.group_name || 'Group Details'}</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Manage group configuration and API access
            </p>
          </div>
          <div className="flex gap-2">
            {!isEditing ? (
              <>
                <button onClick={handleEdit} className="btn btn-primary">
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                  Edit Group
                </button>
                <button onClick={() => setShowDeleteModal(true)} className="btn btn-error">
                  <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                  Delete Group
                </button>
                <button onClick={handleExport} className="btn btn-secondary">Export</button>
              </>
            ) : (
              <>
                <button onClick={handleSave} disabled={saving} className="btn btn-primary">
                  {saving ? (
                    <div className="flex items-center">
                      <div className="spinner mr-2"></div>
                      Saving...
                    </div>
                  ) : (
                    <>
                      <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      Save Changes
                    </>
                  )}
                </button>
                <button onClick={handleCancel} className="btn btn-secondary">
                  Cancel
                </button>
              </>
            )}
            <button onClick={handleBack} className="btn btn-ghost">
              <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              Back
            </button>
          </div>
        </div>

        <AiBudgetUsageCard scope="group" target={groupName} />

        {success && (
          <div className="rounded-lg bg-success-50 border border-success-200 p-4 dark:bg-success-900/20 dark:border-success-800">
            <div className="flex">
              <svg className="h-5 w-5 text-success-400 dark:text-success-500 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="ml-3">
                <p className="text-sm text-success-700 dark:text-success-300">{success}</p>
              </div>
            </div>
          </div>
        )}

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

        {group && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card">
              <div className="card-header flex items-center justify-between">
                <h3 className="card-title">Basic Information</h3>
                <FormHelp docHref="/docs/using-fields.html#access-control">Groups gate API access alongside roles.</FormHelp>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Group Name
                    <InfoTooltip text="Unique name for the group. Users can belong to multiple groups." />
                  </label>
                  {isEditing ? (
                    <input
                      type="text"
                      value={editData.group_name || ''}
                      onChange={(e) => handleInputChange('group_name', e.target.value)}
                      className="input"
                      placeholder="Enter group name"
                    />
                  ) : (
                    <p className="text-gray-900 dark:text-white">{group.group_name}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Description
                  </label>
                  {isEditing ? (
                    <textarea
                      value={editData.group_description || ''}
                      onChange={(e) => handleInputChange('group_description', e.target.value)}
                      className="input resize-none"
                      rows={3}
                      placeholder="Enter group description"
                    />
                  ) : (
                    <p className="text-gray-600 dark:text-gray-400">{group.group_description || 'No description'}</p>
                  )}
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-header flex items-center justify-between">
                <h3 className="card-title">API Access</h3>
                <FormHelp docHref="/docs/using-fields.html#access-control">APIs that have granted access to this group. Manage from the API settings page.</FormHelp>
              </div>
              <div className="p-6 space-y-4">
                <div className="space-y-2">
                  {grantedApis.map((api, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <span className="text-sm bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200 px-3 py-1 rounded-full flex-1">
                        {api}
                      </span>
                    </div>
                  ))}
                </div>

                {grantedApis.length === 0 && (
                  <p className="text-gray-500 dark:text-gray-400 text-sm">No APIs have granted access to this group yet. Configure API access from the API settings page.</p>
                )}
              </div>
            </div>
          </div>
        )}

        <ConfirmModal
          open={showDeleteModal}
          title="Delete Group"
          message={<>
            This action cannot be undone. This will permanently delete the group "{group?.group_name}".
          </>}
          confirmLabel={deleting ? 'Deleting...' : 'Delete Group'}
          cancelLabel="Cancel"
          onCancel={() => setShowDeleteModal(false)}
          onConfirm={handleDelete}

        />
      </div>
    </Layout>
  )
}

export default GroupDetailPage
