'use client'

import React, { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import Layout from '@/components/Layout'
import Pagination from '@/components/Pagination'
import SearchableSelect from '@/components/SearchableSelect'
import { SERVER_URL } from '@/utils/config'
import { getJson, postJson, putJson, delJson, fetchAllPaginated } from '@/utils/api'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { useAuth } from '@/contexts/AuthContext'

interface CreditTier {
  tier_name: string
  credits: number
  input_limit: number
  output_limit: number
  reset_frequency: string
}

interface CreditDefForm {
  api_credit_group: string
  api_key: string
  api_key_header: string
  credit_tiers_text: string
  working: boolean
  error: string | null
  success: string | null
}

interface UserCreditInfo {
  tier_name: string
  available_credits: number
  reset_date?: string
  user_api_key?: string
}

interface UserCreditsRow {
  username: string
  users_credits: Record<string, UserCreditInfo>
}

export default function CreditsPage() {
  const router = useRouter()
  const { permissions } = useAuth()
  const canManageCredits = !!permissions?.manage_credits
  const [form, setForm] = useState<CreditDefForm>({
    api_credit_group: '',
    api_key: '',
    api_key_header: 'x-api-key',
    credit_tiers_text: '[\n  {"tier_name":"basic","credits":100,"input_limit":150,"output_limit":150,"reset_frequency":"monthly"}\n] ',
    working: false,
    error: null,
    success: null
  })
  const [usersLoading, setUsersLoading] = useState(false)
  const [userRows, setUserRows] = useState<UserCreditsRow[]>([])
  const [allUserRows, setAllUserRows] = useState<UserCreditsRow[]>([])
  const [usersPage, setUsersPage] = useState(1)
  const [usersPageSize, setUsersPageSize] = useState(10)
  const [usersHasNext, setUsersHasNext] = useState(false)
  const [userSearch, setUserSearch] = useState('')
  const [userWorking, setUserWorking] = useState(false)
  const [userError, setUserError] = useState<string | null>(null)
  const [userSuccess, setUserSuccess] = useState<string | null>(null)
  const [showAssignModal, setShowAssignModal] = useState(false)
  const [assignForm, setAssignForm] = useState({
    username: '',
    credit_group: '',
    tier_name: '',
    credits: 0
  })
  const [assigning, setAssigning] = useState(false)

  type TierMeta = { credits: number; reset_frequency?: string }
  const [defs, setDefs] = useState<Record<string, { [tier: string]: TierMeta }>>({})

  const fetchUserOptions = async (): Promise<string[]> => {
    try {
      const users = await fetchAllPaginated<any>(
        (page, size) => `${SERVER_URL}/platform/user/all?page=${page}&page_size=${size}`,
        (data) => (Array.isArray(data) ? data : (data?.users || data?.response?.users || []))
      )
      return users.map((u: any) => u?.username).filter(Boolean)
    } catch (e) {
      console.error('Failed to fetch users:', e)
      return []
    }
  }

  const loadDefs = async () => {
    try {
      const items = await fetchAllPaginated<any>(
        (page, size) => `${SERVER_URL}/platform/credit/defs?page=${page}&page_size=${size}`,
        (data) => (Array.isArray(data) ? data : (data?.items || data?.response?.items || []))
      )
      const map: Record<string, { [tier: string]: TierMeta }> = {}
      for (const it of items) {
        const tiers = it.credit_tiers || []
        const tierMap: Record<string, TierMeta> = {}
        for (const t of tiers) tierMap[t.tier_name] = { credits: Number(t.credits || 0), reset_frequency: t.reset_frequency }
        map[it.api_credit_group] = tierMap
      }
      setDefs(map)
    } catch (e) {
      console.error('Failed to load credit definitions:', e)
    }
  }

  const parseTiers = (): CreditTier[] => {
    try { return JSON.parse(form.credit_tiers_text || '[]') } catch { return [] }
  }

  const handleCreate = async () => {
    setForm(f => ({ ...f, working: true, error: null, success: null }))
    try {
      const tiers = parseTiers()
      if (!form.api_credit_group.trim()) throw new Error('Credit group is required')
      await postJson(`${SERVER_URL}/platform/credit`, { api_credit_group: form.api_credit_group.trim(), api_key: form.api_key, api_key_header: form.api_key_header, credit_tiers: tiers })
      setForm(f => ({ ...f, success: 'Credit definition created' }))
    } catch (e:any) {
      setForm(f => ({ ...f, error: e?.message || 'Failed to create credit definition' }))
    } finally {
      setForm(f => ({ ...f, working: false }))
    }
  }

  const handleUpdate = async () => {
    setForm(f => ({ ...f, working: true, error: null, success: null }))
    try {
      const tiers = parseTiers()
      if (!form.api_credit_group.trim()) throw new Error('Credit group is required')
      await putJson(`${SERVER_URL}/platform/credit/${encodeURIComponent(form.api_credit_group.trim())}`, { api_credit_group: form.api_credit_group.trim(), api_key: form.api_key, api_key_header: form.api_key_header, credit_tiers: tiers })
      setForm(f => ({ ...f, success: 'Credit definition updated' }))
    } catch (e:any) {
      setForm(f => ({ ...f, error: e?.message || 'Failed to update credit definition' }))
    } finally {
      setForm(f => ({ ...f, working: false }))
    }
  }

  const loadAllUserTokens = async () => {
    try {
      setUsersLoading(true); setUserError(null)
      const q = userSearch.trim() ? `&search=${encodeURIComponent(userSearch.trim())}` : ''
      const payload = await getJson<any>(`${SERVER_URL}/platform/credit/all?page=${usersPage}&page_size=${usersPageSize}${q}`)
      const items = payload?.items || payload?.user_credits || []
      setAllUserRows(items)
      setUserRows(items)
      const hn = (payload?.has_next ?? payload?.response?.has_next)
      setUsersHasNext(typeof hn === 'boolean' ? hn : (items || []).length === usersPageSize)
    } catch (e:any) {
      setUserError(e?.message || 'Failed to load user credits')
      setUserRows([])
      setAllUserRows([])
      setUsersHasNext(false)
    } finally {
      setUsersLoading(false)
    }
  }

  const handleAssignCredits = async () => {
    if (!assignForm.username.trim() || !assignForm.credit_group.trim() || !assignForm.tier_name.trim()) {
      alert('Please fill in all fields')
      return
    }

    try {
      setAssigning(true)
      const username = assignForm.username.trim()
      const current = userRows.find(u => u.username === username) || await getJson<any>(`${SERVER_URL}/platform/credit/${encodeURIComponent(username)}`).catch(() => ({}))
      const currentCredits = current.users_credits || {}

      await postJson(`${SERVER_URL}/platform/credit/${encodeURIComponent(username)}`, {
        users_credits: {
          ...currentCredits,
          [assignForm.credit_group.trim()]: {
            tier_name: assignForm.tier_name.trim(),
            available_credits: assignForm.credits || 0
          }
        }
      })

      setUserSuccess(`Credits assigned to ${assignForm.username}`)
      setShowAssignModal(false)
      setAssignForm({ username: '', credit_group: '', tier_name: '', credits: 0 })
      await loadAllUserTokens()
    } catch (e: any) {
      alert(e?.message || 'Failed to assign credits')
    } finally {
      setAssigning(false)
    }
  }

  const handleRemoveUserCredits = async (username: string, creditGroup: string) => {
    if (!confirm(`Remove ${username} from credit group "${creditGroup}"?`)) return

    try {
      const current = userRows.find(u => u.username === username) || await getJson<any>(`${SERVER_URL}/platform/credit/${encodeURIComponent(username)}`).catch(() => ({}))
      const currentCredits = { ...(current.users_credits || {}) }
      delete currentCredits[creditGroup]

      await postJson(`${SERVER_URL}/platform/credit/${encodeURIComponent(username)}`, {
        users_credits: currentCredits
      })

      setUserSuccess(`Removed ${username} from ${creditGroup}`)
      await loadAllUserTokens()
    } catch (e: any) {
      alert(e?.message || 'Failed to remove user credits')
    }
  }

  useEffect(() => {
    if (!canManageCredits) return
    loadAllUserTokens()
    loadDefs()
  }, [usersPage, usersPageSize, canManageCredits])

  // Debounced search to request server-side filtering
  useEffect(() => {
    if (!canManageCredits) return
    const h = setTimeout(() => {
      setUsersPage(1)
      loadAllUserTokens()
    }, 300)
    return () => clearTimeout(h)
  }, [userSearch, canManageCredits])

  return (
    <ProtectedRoute requiredPermission="manage_credits">
    <Layout>
      <div className="space-y-6">
        <div className="page-header">
          <div>
            <h1 className="page-title">Credits</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">Credit definitions and user credit balances</p>
          </div>
        </div>

        {canManageCredits && <>
        <div className="card">
          <div className="p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h3 className="card-title">Credit Definitions</h3>
              <p className="text-gray-600 dark:text-gray-400">Create and manage credit groups, headers, and tiers</p>
            </div>
            <div className="flex gap-2">
              <Link href="/credit-defs" className="btn btn-secondary">View Definitions</Link>
              <Link href="/credit-defs/add" className="btn btn-primary">Add Definition</Link>
            </div>
          </div>
        </div>

        <div className="card -mt-3">
          <form onSubmit={(e) => { e.preventDefault(); setUsersPage(1); loadAllUserTokens() }} className="flex-1">
            <div className="relative">
              <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                className="search-input"
                placeholder="Search users by username or group..."
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
              />
            </div>
          </form>
        </div>

        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h3 className="card-title">User Credits</h3>
            <button
              onClick={() => { void loadDefs(); setShowAssignModal(true) }}
              className="btn btn-primary btn-sm"
            >
              <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Assign Credits
            </button>
          </div>
          <div className="p-6 space-y-4">
            {userError && <div className="text-sm text-error-600">{userError}</div>}
            {userSuccess && <div className="text-sm text-success-600">{userSuccess}</div>}

            <div className="mt-2">
              {usersLoading ? (
                <div className="text-gray-500">Loading...</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="table">
                    <thead><tr><th>Username</th><th>Groups</th><th>Total</th><th>Used</th><th>Left</th><th>Reset Freq</th><th>Reset Dates</th><th>Actions</th></tr></thead>
                    <tbody>
                      {userRows.map((row, idx) => {
                        let total = 0, available = 0
                        const freqs = new Set<string>()
                        const dates = new Set<string>()
                        for (const [group, info] of Object.entries(row.users_credits || {})) {
                          const tmap = defs[group] || {}
                          const meta = tmap[(info as any).tier_name] || { credits: 0, reset_frequency: undefined }
                          total += Number(meta.credits || 0)
                          available += Number((info as any).available_credits || 0)
                          if (meta.reset_frequency) freqs.add(meta.reset_frequency)
                          const rd = (info as any).reset_date
                          if (rd) dates.add(String(rd))
                        }
                        const used = total > 0 ? Math.max(total - available, 0) : 0
                        const groups = Object.keys(row.users_credits || {})
                        return (
                          <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-dark-surfaceHover">
                            <td className="font-medium cursor-pointer" onClick={() => router.push(`/credits/${encodeURIComponent(row.username)}`)}>{row.username}</td>
                            <td className="text-sm text-gray-600">{groups.join(', ') || '-'}</td>
                            <td className="text-sm">{total || 0}</td>
                            <td className="text-sm">{used}</td>
                            <td className="text-sm">{available || 0}</td>
                            <td className="text-sm">{freqs.size ? Array.from(freqs).join(', ') : '-'}</td>
                            <td className="text-sm">{dates.size ? Array.from(dates).join(', ') : '-'}</td>
                            <td>
                              <div className="flex gap-2">
                                <button
                                  onClick={() => router.push(`/credits/${encodeURIComponent(row.username)}`)}
                                  className="btn btn-sm btn-outline"
                                  title="View details"
                                >
                                  View
                                </button>
                                {groups.length > 0 && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      handleRemoveUserCredits(row.username, groups[0])
                                    }}
                                    className="btn btn-sm btn-outline text-error-600"
                                    title="Remove from first group"
                                  >
                                    Remove
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        )
                      })}
                      {userRows.length === 0 && (
                        <tr><td colSpan={8} className="text-gray-500 text-center py-6">No user token records</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
              <Pagination
                page={usersPage}
                pageSize={usersPageSize}
                onPageChange={setUsersPage}
                onPageSizeChange={(s) => { setUsersPageSize(s); setUsersPage(1) }}
                hasNext={usersHasNext}
              />
              <div className="mt-2"><button onClick={loadAllUserTokens} className="btn btn-secondary">Refresh</button></div>
            </div>
          </div>
        </div>
        </>}

      </div>

      {/* Assign Credits Modal */}
      {showAssignModal && canManageCredits && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowAssignModal(false)} />

            <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Assign Credits to User
              </h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Username *
                  </label>
                  <SearchableSelect
                    value={assignForm.username}
                    onChange={(val: string) => setAssignForm({ ...assignForm, username: val })}
                    fetchOptions={fetchUserOptions}
                    placeholder="Select username"
                    restrictToOptions
                  />
                </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Credit Group *
                </label>
                <SearchableSelect
                  value={assignForm.credit_group}
                  onChange={(v: string) => setAssignForm({ ...assignForm, credit_group: v, tier_name: '' })}
                  fetchOptions={async () => Promise.resolve(Object.keys(defs))}
                  placeholder="Select credit group"
                  restrictToOptions
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Select from available credit definitions
                </p>
              </div>

                {assignForm.credit_group && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Tier *
                    </label>
                    <select
                      value={assignForm.tier_name}
                      onChange={(e) => {
                        const tierName = e.target.value
                        const tierMeta = defs[assignForm.credit_group]?.[tierName]
                        setAssignForm({ 
                          ...assignForm, 
                          tier_name: tierName,
                          credits: tierMeta?.credits || 0
                        })
                      }}
                      className="input"
                    >
                      <option value="">Select tier</option>
                      {Object.keys(defs[assignForm.credit_group] || {}).map((tier) => {
                        const meta = defs[assignForm.credit_group][tier]
                        return (
                          <option key={tier} value={tier}>
                            {tier} ({meta.credits} credits, {meta.reset_frequency || 'no reset'})
                          </option>
                        )
                      })}
                    </select>
                  </div>
                )}

                {assignForm.tier_name && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Initial Credits
                    </label>
                    <input
                      type="number"
                      value={assignForm.credits}
                      onChange={(e) => setAssignForm({ ...assignForm, credits: parseInt(e.target.value) || 0 })}
                      className="input"
                      min="0"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Leave as default or override initial credit amount
                    </p>
                  </div>
                )}
              </div>

              <div className="flex gap-2 mt-6">
                <button
                  onClick={handleAssignCredits}
                  disabled={assigning || !assignForm.username || !assignForm.credit_group || !assignForm.tier_name}
                  className="btn btn-primary flex-1"
                >
                  {assigning ? (
                    <>
                      <div className="spinner mr-2"></div>
                      Assigning...
                    </>
                  ) : (
                    'Assign Credits'
                  )}
                </button>
                <button
                  onClick={() => setShowAssignModal(false)}
                  className="btn btn-secondary"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </Layout>
    </ProtectedRoute>
  )
}
