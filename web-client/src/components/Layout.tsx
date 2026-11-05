'use client'

import Link from 'next/link'
import React, { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/AuthContext'
import { AppShell } from '@/components/signal/Signal'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import type { AiSettings } from '@/utils/ai'
import { modeForPath, storedMode, storeMode, type GatewayMode } from '@/utils/gatewayMode'

const NOTICE_KEY = 'doorman.aiNoticeDismissed'

interface LayoutProps { children: React.ReactNode }
interface MenuItem { label: string; href: string; permission?: string }

const apiItems: MenuItem[] = [
  { label: 'Dashboard', href: '/dashboard' }, { label: 'Analytics', href: '/analytics', permission: 'view_analytics' }, { label: 'Logs', href: '/logging', permission: 'view_logs' }, { label: 'APIs', href: '/apis', permission: 'manage_apis' }, { label: 'Subscriptions', href: '/authorizations', permission: 'manage_subscriptions' }, { label: 'Credits', href: '/credits', permission: 'manage_credits' }, { label: 'Routings', href: '/routings', permission: 'manage_routings' }, { label: 'Security', href: '/security', permission: 'manage_security' }, { label: 'TLS', href: '/tls', permission: 'manage_security' }, { label: 'Tools', href: '/tools', permission: 'manage_security' },
]
const aiItems: MenuItem[] = [
  { label: 'Overview', href: '/ai', permission: 'view_analytics' }, { label: 'Providers', href: '/ai/providers', permission: 'manage_apis' }, { label: 'Allowances', href: '/ai/allowances', permission: 'manage_ai' }, { label: 'Usage', href: '/ai/usage', permission: 'view_analytics' }, { label: 'Policies', href: '/ai/policies', permission: 'ai_policies' }, { label: 'My AI', href: '/my-ai' },
]
const sharedItems: MenuItem[] = [
  { label: 'Users', href: '/users', permission: 'manage_users' }, { label: 'Groups', href: '/groups', permission: 'manage_groups' }, { label: 'Roles', href: '/roles', permission: 'manage_roles' }, { label: 'Tiers', href: '/tiers', permission: 'manage_tiers' }, { label: 'Documentation', href: '/documentation' }, { label: 'Settings', href: '/settings' },
]

export default function Layout({ children }: LayoutProps) {
  const DEBUG = process.env.NODE_ENV !== 'production'
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const pathname = usePathname()
  const router = useRouter()
  const { isAuthenticated, authResolved, hasUIAccess, user, permissions, logsEnabled, logout } = useAuth()
  
  useEffect(() => { 
    if (pathname === '/login' || pathname === '/403') return 
    if (!authResolved) return
    if (!isAuthenticated) { 
      if (DEBUG) console.log('Layout - Redirecting to login:', { pathname }) 
      router.push('/login') 
      return 
    }; 
    if (!hasUIAccess) { 
      if (DEBUG) console.log('Layout - Redirecting to 403 (no UI access):', { pathname }) 
      router.push('/403') 
    } 
  }, [pathname, isAuthenticated, authResolved, hasUIAccess, router, DEBUG])
  
  useEffect(() => { document.documentElement.classList.remove('dark') }, [])

  const [aiNotice, setAiNotice] = useState<string | null>(null)
  useEffect(() => {
    if (!isAuthenticated) return
    let active = true
    getJson<AiSettings>(`${SERVER_URL}/platform/ai/settings`).then(settings => {
      const text = settings.log_level === 'full' ? settings.notice_text?.trim() : ''
      if (!active || !text) return
      let dismissed: string | null = null
      try { dismissed = window.localStorage.getItem(NOTICE_KEY) } catch {}
      if (dismissed !== text) setAiNotice(text)
    }).catch(() => {})
    return () => { active = false }
  }, [isAuthenticated])
  const dismissAiNotice = () => { try { if (aiNotice) window.localStorage.setItem(NOTICE_KEY, aiNotice) } catch {}; setAiNotice(null) }
  
  const allowed = (item: MenuItem) => {
    if (item.href === '/logging' && !logsEnabled) return false
    if (item.href === '/ai/policies') return !!(permissions?.manage_security || permissions?.manage_ai)
    if (item.href === '/tools') return !!(permissions?.manage_security || permissions?.manage_gateway)
    return !item.permission || !!permissions?.[item.permission]
  }
  const visibleApi = apiItems.filter(allowed)
  const visibleAi = aiItems.filter(allowed)
  const visibleShared = sharedItems.filter(allowed)
  // Employees without admin rights get one plain list and no switch.
  const showSwitch = visibleApi.some(item => item.href !== '/dashboard') && visibleAi.some(item => item.href !== '/my-ai')
  const [lastMode, setLastMode] = useState<GatewayMode>('api')
  useEffect(() => { const stored = storedMode(); if (stored) setLastMode(stored) }, [])
  const mode = modeForPath(pathname, lastMode)
  useEffect(() => { if (showSwitch && mode !== lastMode) { setLastMode(mode); storeMode(mode) } }, [mode, lastMode, showSwitch])
  const primaryItems = showSwitch ? (mode === 'ai' ? visibleAi : visibleApi) : [...visibleApi, ...visibleAi]
  const aiHome = visibleAi[0]?.href || '/my-ai'
  const isActive = (href: string) => pathname === href || (href !== '/dashboard' && href !== '/ai' && pathname.startsWith(`${href}/`))
  const navLink = (item: MenuItem) => <Link key={item.href} href={item.href} onClick={() => setSidebarOpen(false)} aria-current={isActive(item.href) ? 'page' : undefined} className={`flex items-center px-3 py-2 transition-colors ${isActive(item.href) ? 'bg-gray-100' : ''}`}>{item.label}</Link>
  
  if (!authResolved && pathname !== '/login' && pathname !== '/403') {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return <AppShell>
    <header className="signal-header">
      <Link href={mode === 'ai' && showSwitch ? aiHome : '/dashboard'} className="signal-brand" aria-label="Doorman home"><span className="signal-brand-mark" aria-hidden="true"><img src="/doorman-mark.svg" alt="" /></span><span className="signal-brand-name">Doorman</span></Link>
    </header>
    <aside className={`sidebar ${sidebarOpen ? 'translate-x-0' : ''}`} aria-label="Control plane navigation"><div className="flex h-full flex-col"><div>{showSwitch
        ? <nav className="sidebar-mode" aria-label="Gateway"><Link href="/dashboard" onClick={() => setSidebarOpen(false)} aria-current={mode === 'api' ? 'page' : undefined} title="API Gateway">API</Link><Link href={aiHome} onClick={() => setSidebarOpen(false)} aria-current={mode === 'ai' ? 'page' : undefined} title="AI Gateway">AI</Link></nav>
        : <p className="text-sm font-bold text-signal-ink">Gateway Control</p>}</div><div className="flex-1 p-3 overflow-y-auto no-scrollbar"><nav className="space-y-1" aria-label={showSwitch ? `${mode === 'ai' ? 'AI' : 'API'} gateway` : 'Main'}>{primaryItems.map(navLink)}</nav>{!!visibleShared.length && <><hr className="sidebar-divider" /><nav className="space-y-1" aria-label="Shared">{visibleShared.map(navLink)}</nav></>}</div><div className="p-3"><p className="signal-signed-in">Signed in as <span>{user?.username || 'Verifying session'}</span></p><button onClick={logout} className="signal-rail-logout">Log out</button></div></div></aside>
    {sidebarOpen && <button className="fixed inset-0 z-30 bg-black/50 lg:hidden" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
    <main className="main-content"><div>{aiNotice && <div role="status" className="mb-4 flex items-start justify-between gap-3 rounded-lg border border-warning-200 bg-warning-50 p-3 text-sm text-warning-800"><p><strong>AI prompts are logged:</strong> {aiNotice}</p><button type="button" className="btn btn-ghost" onClick={dismissAiNotice} aria-label="Dismiss AI logging notice">Dismiss</button></div>}<button onClick={() => setSidebarOpen(true)} className={`signal-sidebar-toggle lg:hidden fixed top-[72px] left-4 z-40 signal-header-control ${sidebarOpen ? 'opacity-0 pointer-events-none' : ''}`} aria-label="Open navigation">Menu</button>{children}</div></main>
  </AppShell>
}
