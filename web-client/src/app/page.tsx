'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/AuthContext'
import { fetchAllPaginated } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { landingPath } from '@/utils/gatewayMode'

export default function Home() {
  const router = useRouter()
  const { isAuthenticated, authResolved, hasUIAccess, permissions } = useAuth()

  useEffect(() => {
    if (!authResolved) {
      return
    }
    if (!isAuthenticated || !hasUIAccess) {
      router.push('/login')
      return
    }
    const hasAiAdmin = !!(permissions?.manage_ai || permissions?.view_analytics)
    const loadTypes = async () => (await fetchAllPaginated<{ api_type: string }>(
      (page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`,
      data => Array.isArray(data) ? data : data.apis || data.response?.apis || []
    )).map(api => api.api_type)
    landingPath(hasAiAdmin, loadTypes).then(path => router.replace(path))
  }, [authResolved, isAuthenticated, hasUIAccess, permissions, router])

  return null
}
