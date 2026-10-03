'use client'

import React, { useEffect, useState } from 'react'
import FormHelp from '@/components/FormHelp'
import { SERVER_URL } from '@/utils/config'
import { getJson } from '@/utils/api'
import ConfirmModal from '@/components/ConfirmModal'

interface UserAuthStatus {
  active: boolean
  revoked: boolean
}

export default function AuthControlPanel() {
  const [username, setUsername] = useState('')
  const [status, setStatus] = useState<UserAuthStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [showConfirm, setShowConfirm] = useState(false)
  const [confirmPath, setConfirmPath] = useState<string>('')
  const [confirmOkMsg, setConfirmOkMsg] = useState<string>('')
  const [confirmTitle, setConfirmTitle] = useState<string>('Confirm Action')
  const [confirmBody, setConfirmBody] = useState<string>('Are you sure?')

  const loadStatus = async (u = username) => {
    if (!u.trim()) return
    try {
      setLoading(true); setError(null)
      const payload = await getJson<any>(`${SERVER_URL}/platform/authorization/admin/status/${encodeURIComponent(u.trim())}`)
      setStatus({ active: !!payload.active, revoked: !!payload.revoked })
    } catch (e:any) {
      setError(e?.message || 'Failed to load status'); setStatus(null)
    } finally { setLoading(false) }
  }

  const action = async (path: string, okMsg: string) => {
    if (!username.trim()) { setError('Username is required'); return }
    try {
      setError(null); setSuccess(null); setLoading(true)
      const { postJson } = await import('@/utils/api')
      await postJson(`${SERVER_URL}${path}/${encodeURIComponent(username.trim())}`, {})
      setSuccess(okMsg)
      setTimeout(() => setSuccess(null), 1500)
      await loadStatus(username)
    } catch (e:any) {
      setError(e?.message || 'Action failed')
    } finally { setLoading(false) }
  }

  const openConfirm = (path: string, okMsg: string, title: string, body: string) => {
    if (!username.trim()) { setError('Username is required'); return }
    setConfirmPath(path)
    setConfirmOkMsg(okMsg)
    setConfirmTitle(title)
    setConfirmBody(body.replace('{username}', username.trim()))
    setShowConfirm(true)
  }

  const onConfirm = async () => {
    const p = confirmPath
    const m = confirmOkMsg
    setShowConfirm(false)
    await action(p, m)
  }

  useEffect(() => {
    if (username.trim()) loadStatus(username)
  }, [])

  return (
      <div className="space-y-6">
        {error && <div className="rounded-md bg-error-50 border border-error-200 p-3 text-error-700 text-sm">{error}</div>}
        {success && <div className="rounded-md bg-success-50 border border-success-200 p-3 text-success-700 text-sm">{success}</div>}

        <div className="card">
          <div className="p-6 space-y-4">
            <FormHelp docHref="/docs/using-fields.html#auth-admin">Look up user status, revoke tokens, and enable/disable accounts.</FormHelp>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium">Username</label>
                <input className="input" value={username} onChange={e => setUsername(e.target.value)} placeholder="username" />
              </div>
              <div className="flex items-end gap-2">
                <button
                  className="btn btn-primary"
                  onClick={() => loadStatus()}
                  disabled={loading || !username.trim()}
                >
                  {loading ? 'Loading…' : 'Load Status'}
                </button>
              </div>
            </div>

            {status && (
              <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-4 text-sm">
                <div><span className="font-medium">Active:</span> {status.active ? 'Yes' : 'No'}</div>
                <div><span className="font-medium">Revoked:</span> {status.revoked ? 'Yes' : 'No'}</div>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              <button
                className="btn btn-error"
                disabled={loading}
                onClick={() => openConfirm('/platform/authorization/admin/revoke', 'Tokens revoked', 'Revoke Tokens', 'Revoke all tokens for {username}?')}
              >
                Revoke Tokens
              </button>
              <button
                className="btn btn-neutral"
                disabled={loading}
                onClick={() => openConfirm('/platform/authorization/admin/unrevoke', 'Revocation cleared', 'Clear Revocation', 'Clear token revocation for {username}?')}
              >
                Clear Revocation
              </button>
              <button
                className="btn btn-error"
                disabled={loading}
                onClick={() => openConfirm('/platform/authorization/admin/disable', 'User disabled', 'Disable User', 'Disable user {username}? They will be unable to authenticate.')}
              >
                Disable User
              </button>
              <button
                className="btn btn-primary"
                disabled={loading}
                onClick={() => openConfirm('/platform/authorization/admin/enable', 'User enabled', 'Enable User', 'Enable user {username}?')}
              >
                Enable User
              </button>
            </div>
          </div>
        </div>
        <ConfirmModal
          open={showConfirm}
          title={confirmTitle}
          message={confirmBody}
          onCancel={() => setShowConfirm(false)}
          onConfirm={onConfirm}
          confirmLabel="Confirm"
          cancelLabel="Cancel"
        />
      </div>
  )
}
