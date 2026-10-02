'use client'

import Link from 'next/link'
import React, { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { useAuth } from '@/contexts/AuthContext'
import { AppShell } from '@/components/signal/Signal'

interface LayoutProps { children: React.ReactNode }
interface MenuItem { label: string; href: string; permission?: string }

const menuItems: MenuItem[] = [
  { label: 'Dashboard', href: '/dashboard' }, { label: 'Analytics', href: '/analytics', permission: 'view_analytics' }, { label: 'Logs', href: '/logging', permission: 'view_logs' }, { label: 'APIs', href: '/apis', permission: 'manage_apis' }, { label: 'Documentation', href: '/documentation' }, { label: 'Users', href: '/users', permission: 'manage_users' }, { label: 'Groups', href: '/groups', permission: 'manage_groups' }, { label: 'Roles', href: '/roles', permission: 'manage_roles' }, { label: 'Subscriptions', href: '/authorizations', permission: 'manage_subscriptions' }, { label: 'Credits', href: '/credits', permission: 'manage_credits' }, { label: 'Tiers', href: '/tiers', permission: 'manage_tiers' }, { label: 'Routings', href: '/routings', permission: 'manage_routings' }, { label: 'Auth Control', href: '/auth-admin', permission: 'manage_auth' }, { label: 'Security', href: '/security', permission: 'manage_security' }, { label: 'TLS', href: '/tls', permission: 'manage_security' }, { label: 'Tools', href: '/tools', permission: 'manage_security' }, { label: 'Import / Export', href: '/import-export', permission: 'manage_gateway' }, { label: 'Settings', href: '/settings' },
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
  
  const filteredMenuItems = menuItems.filter(item => {
    if (item.href === '/logging' && !logsEnabled) return false
    return !item.permission || permissions?.[item.permission]
  })
  const isActive = (href: string) => pathname === href || (href !== '/dashboard' && pathname.startsWith(`${href}/`))
  
  if (!authResolved && pathname !== '/login' && pathname !== '/403') {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return <AppShell>
    <header className="signal-header">
      <Link href="/dashboard" className="signal-brand" aria-label="Doorman dashboard"><span className="signal-brand-mark" aria-hidden="true"><img src="/doorman-mark.svg" alt="" /></span><span><span className="signal-brand-name">Doorman</span><span className="signal-brand-subtitle">API + AI Gateway</span></span></Link>
    </header>
    <aside className={`sidebar ${sidebarOpen ? 'translate-x-0' : ''}`} aria-label="Control plane navigation"><div className="flex h-full flex-col"><div><p className="text-sm font-bold text-signal-ink">Gateway Control</p></div><div className="flex-1 p-3 overflow-y-auto no-scrollbar"><nav className="space-y-1">{filteredMenuItems.map(item => <Link key={item.href} href={item.href} onClick={() => setSidebarOpen(false)} aria-current={isActive(item.href) ? 'page' : undefined} className={`flex items-center px-3 py-2 transition-colors ${isActive(item.href) ? 'bg-gray-100' : ''}`}>{item.label}</Link>)}</nav></div><div className="p-3"><p className="signal-signed-in">Signed in as <span>{user?.username || 'Verifying session'}</span></p><button onClick={logout} className="signal-rail-logout">Log out</button></div></div></aside>
    {sidebarOpen && <button className="fixed inset-0 z-30 bg-black/50 lg:hidden" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
    <main className="main-content"><div><button onClick={() => setSidebarOpen(true)} className={`signal-sidebar-toggle lg:hidden fixed top-[72px] left-4 z-40 signal-header-control ${sidebarOpen ? 'opacity-0 pointer-events-none' : ''}`} aria-label="Open navigation">Menu</button>{children}</div></main>
  </AppShell>
}
