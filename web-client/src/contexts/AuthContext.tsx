'use client'

import React, { createContext, useContext, useState, useEffect, useRef, ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import {
  isAuthenticated,
  canAccessUI,
  canAccessPage,
  getCurrentUser,
  getUserPermissions,
  isTokenValid,
  hasUIAccess,
  isUserActive
} from '@/utils/auth'
import { fetchJson } from '@/utils/http'
import { postJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'

const DEBUG = process.env.NODE_ENV !== 'production'

interface AuthContextType {
  isAuthenticated: boolean
  authResolved: boolean
  hasUIAccess: boolean
  user: { username: string; role: string } | null
  permissions: any
  logsEnabled: boolean
  canAccessPage: (permission: string) => boolean
  logout: () => void
  checkAuth: () => Promise<void>
  refreshAuth: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authState, setAuthState] = useState({
    isAuthenticated: false,
    authResolved: false,
    hasUIAccess: false,
    user: null as { username: string; role: string } | null,
    permissions: null as any,
    logsEnabled: false
  })
  const isAuthenticatedRef = useRef(false)
  const router = useRouter()

  const checkAuth = async () => {
    if (DEBUG) console.log('=== AUTH CONTEXT DEBUG ===')
    try {
      await fetchJson(`${SERVER_URL}/platform/authorization/status`)
      const features: any = await fetchJson(`${SERVER_URL}/api/features`).catch(() => ({ logs_enabled: true }))
      const logsEnabled = (features?.response?.logs_enabled ?? features?.logs_enabled) !== false

      let user = null as any
      let permissions: any = null
      try {
        user = await fetchJson(`${SERVER_URL}/platform/user/me`)
        if (user?.role) {
          try {
            const role = await fetchJson(`${SERVER_URL}/platform/role/${encodeURIComponent(user.role)}`)
            permissions = role || null
          } catch { }
        }
      } catch { }

      setAuthState({
        isAuthenticated: true,
        authResolved: true,
        hasUIAccess: !!(user && user.ui_access === true),
        user,
        permissions,
        logsEnabled
      })
    } catch (error) {
      if (DEBUG) console.warn('AuthContext - Not authenticated or status check failed:', error)
      setAuthState({
        isAuthenticated: false,
        authResolved: true,
        hasUIAccess: false,
        user: null,
        permissions: null,
        logsEnabled: false
      })
    }
  }

  const refreshAuth = async () => {
    try {
      await postJson(`${SERVER_URL}/platform/authorization/refresh`, {})
      await checkAuth()
    } catch (e) {
      if (DEBUG) console.warn('AuthContext - Token refresh failed or not applicable:', e)
    }
  }

  const logout = async () => {
    try {
      await postJson(`${SERVER_URL}/platform/authorization/invalidate`, {})
    } catch (e) {
      if (DEBUG) console.warn('Logout invalidate failed (continuing):', e)
    }
    try {
      // Clear any local/session storage and best-effort cookie removal (preserve theme)
      const theme = localStorage.getItem('theme')
      localStorage.clear()
      if (theme) localStorage.setItem('theme', theme)
      sessionStorage.clear()
      document.cookie = 'access_token_cookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
    } catch { }
    setAuthState({
      isAuthenticated: false,
      authResolved: true,
      hasUIAccess: false,
      user: null,
      permissions: null,
      logsEnabled: false
    })
    router.push('/login')
  }

  const canAccessPagePermission = (permission: string) => {
    if (!authState.isAuthenticated) return false
    // Superadmin bypass: admin always has all permissions
    if (authState.user?.username === 'admin' || authState.user?.role === 'admin') {
      return true
    }
    return !!(authState.permissions && authState.permissions[permission])
  }

  useEffect(() => {
    isAuthenticatedRef.current = authState.isAuthenticated
  }, [authState.isAuthenticated])

  useEffect(() => {
    const timer = setTimeout(() => {
      if (DEBUG) console.log('AuthContext - Initial auth check')
      checkAuth()
    }, 200)

    const interval = setInterval(() => {
      if (DEBUG) console.log('AuthContext - Periodic auth check')
      checkAuth()
    }, 60000)

    const refreshInterval = setInterval(() => {
      if (isAuthenticatedRef.current) {
        if (DEBUG) console.log('AuthContext - Proactive token refresh')
        refreshAuth()
      }
    }, 10 * 60 * 1000)

    return () => {
      clearTimeout(timer)
      clearInterval(interval)
      clearInterval(refreshInterval)
    }
  }, [])

  const value: AuthContextType = {
    isAuthenticated: authState.isAuthenticated,
    authResolved: authState.authResolved,
    hasUIAccess: authState.hasUIAccess,
    user: authState.user,
    permissions: authState.permissions,
    logsEnabled: authState.logsEnabled,
    canAccessPage: canAccessPagePermission,
    logout,
    checkAuth,
    refreshAuth
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
