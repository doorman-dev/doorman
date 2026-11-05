'use client'

import React, { useEffect, useState } from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { SERVER_URL } from '@/utils/config'
import { useAuth } from '@/contexts/AuthContext'

interface DashboardData {
  totalRequests: number
  activeUsers: number
  newApis: number
  monthlyUsage: Record<string, number>
  activeUsersList: Array<{ username: string; requests: string; subscribers: number }>
  popularApis: Array<{ name: string; requests: string; subscribers: number }>
}

const emptyDashboard: DashboardData = { totalRequests: 0, activeUsers: 0, newApis: 0, monthlyUsage: {}, activeUsersList: [], popularApis: [] }
const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function Dashboard() {
  const { isAuthenticated, hasUIAccess } = useAuth()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dashboardData, setDashboardData] = useState<DashboardData>(emptyDashboard)

  const fetchData = async () => {
    try {
      setLoading(true); setError(null)
      const { fetchJson } = await import('@/utils/http')
      setDashboardData(await fetchJson<DashboardData>(`${SERVER_URL}/platform/dashboard`))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred')
    } finally { setLoading(false) }
  }

  useEffect(() => { if (isAuthenticated && hasUIAccess) fetchData() }, [isAuthenticated, hasUIAccess])
  const values = months.map(month => dashboardData.monthlyUsage[month] || 0)
  const maxValue = Math.max(...values, 1)

  const card = 'rounded border border-gray-200 bg-white'
  return <ProtectedRoute><Layout><div className="space-y-4">
    <div className="flex items-end justify-between">
      <div><h1 className="text-[22px] font-bold text-gray-900">Dashboard</h1><p className="text-sm text-gray-500">Live traffic and access signals from this Doorman deployment</p></div>
      <button onClick={fetchData} disabled={loading} className="btn btn-primary">{loading ? 'Refreshing…' : 'Refresh'}</button>
    </div>
    {error && <div className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">Gateway data unavailable: {error}</div>}
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      {[['Total requests', dashboardData.totalRequests], ['Active users', dashboardData.activeUsers], ['New APIs', dashboardData.newApis]].map(([label, value]) => <div key={String(label)} className={`${card} p-4`}><div className="text-xs text-gray-500">{label}</div><div className="text-[26px] font-semibold leading-tight text-gray-900">{loading ? '—' : Number(value).toLocaleString()}</div></div>)}
    </div>
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className={`${card} p-4`}>
        <div className="mb-3 flex items-center justify-between"><strong className="text-gray-900">Popular APIs</strong><span className="text-xs text-gray-500">Route activity</span></div>
        <table className="w-full border-collapse text-sm"><thead><tr className="text-left text-gray-500"><th className="border-b border-gray-200 px-1 py-2 font-medium">API</th><th className="border-b border-gray-200 px-1 py-2 font-medium">Requests</th><th className="border-b border-gray-200 px-1 py-2 font-medium">Subscribers</th></tr></thead>
          <tbody>{dashboardData.popularApis.length ? dashboardData.popularApis.map(api => <tr key={api.name}><td className="border-b border-gray-100 px-1 py-2">{api.name}</td><td className="border-b border-gray-100 px-1 py-2">{api.requests}</td><td className="border-b border-gray-100 px-1 py-2">{api.subscribers}</td></tr>) : <tr><td colSpan={3} className="px-1 py-6 text-center text-gray-500">{loading ? 'Loading…' : 'No API activity yet'}</td></tr>}</tbody></table>
      </div>
      <div className={`${card} p-4`}>
        <strong className="text-gray-900">Active users</strong>
        <div className="mt-2">{dashboardData.activeUsersList.length ? dashboardData.activeUsersList.map(u => <div key={u.username} className="flex items-center justify-between border-b border-gray-100 py-2 text-sm"><span>{u.username}</span><span className="text-gray-500">{u.requests} req</span></div>) : <p className="py-6 text-center text-sm text-gray-500">{loading ? 'Loading…' : 'No active users'}</p>}</div>
      </div>
    </div>
    <div className={`${card} p-4`}>
      <div className="mb-3 flex items-center justify-between"><strong className="text-gray-900">Request volume</strong><span className="text-xs text-gray-500">Monthly</span></div>
      <div className="flex h-48 items-end gap-2 border-b border-gray-200 px-1">{months.map((month, i) => <div key={month} className="flex flex-1 flex-col items-center justify-end gap-1" title={`${month}: ${values[i].toLocaleString()}`}><div className="w-full rounded-t bg-primary-600/80" style={{ height: `${Math.max((values[i] / maxValue) * 100, values[i] ? 3 : 0)}%` }} /></div>)}</div>
      <div className="mt-1 flex gap-2 px-1 text-xs text-gray-500">{months.map(m => <span key={m} className="flex-1 text-center">{m}</span>)}</div>
    </div>
  </div></Layout></ProtectedRoute>
}

export default Dashboard
