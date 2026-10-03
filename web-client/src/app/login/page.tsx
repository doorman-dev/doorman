'use client'

import React, { useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useAuth } from '@/contexts/AuthContext'
import { SERVER_URL } from '@/utils/config'
import { postJson, getJson } from '@/utils/api'

const DEFAULT_AUTH_REDIRECT = '/dashboard'

function SiteHeader() {
  const [open, setOpen] = useState(false)
  const links: [string, string][] = [['Gateways', 'https://doorman.dev/#platform'], ['Capabilities', 'https://doorman.dev/#features'], ['Deploy', 'https://doorman.dev/#deploy']]
  return (
    <header className="sh">
      <div className="sh-container">
        <div className="sh-inner">
          <a href="https://doorman.dev/" className="sh-brand" aria-label="Doorman home">
            <img src="/doorman-mark.svg" alt="" aria-hidden="true" />
            <span><span className="sh-name">Doorman</span><span className="sh-sub">API + AI Gateway</span></span>
          </a>
          <nav className="sh-nav" aria-label="Primary navigation">
            {links.map(([label, href]) => <a key={href} href={href}>{label}</a>)}
            <a href="https://github.com/doorman-dev/doorman#readme" target="_blank" rel="noopener noreferrer">Docs</a>
          </nav>
          <div className="sh-actions">
            <a href="https://github.com/doorman-dev/doorman" target="_blank" rel="noopener noreferrer" className="sh-gh" aria-label="GitHub repository" title="View on GitHub"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5A12 12 0 0 0 0 12.7c0 5.37 3.44 9.92 8.21 11.53.6.11.82-.27.82-.6 0-.3-.01-1.1-.02-2.17-3.34.75-4.04-1.65-4.04-1.65-.55-1.42-1.34-1.8-1.34-1.8-1.1-.77.08-.76.08-.76 1.22.09 1.86 1.28 1.86 1.28 1.08 1.9 2.84 1.35 3.53 1.03.11-.81.42-1.35.76-1.66-2.67-.31-5.47-1.39-5.47-6.21 0-1.37.46-2.49 1.22-3.37-.12-.3-.53-1.56.12-3.25 0 0 1.01-.33 3.3 1.29a11.3 11.3 0 0 1 6 0c2.3-1.62 3.3-1.29 3.3-1.29.66 1.69.25 2.95.12 3.25.76.88 1.22 2 1.22 3.37 0 4.83-2.8 5.89-5.47 6.2.43.37.81 1.1.81 2.22 0 1.6-.01 2.9-.01 3.3 0 .33.22.72.83.6A12.2 12.2 0 0 0 24 12.7 12.1 12.1 0 0 0 12 .5z" /></svg></a>
            <a href="/login" className="sh-btn">Log in</a>
            <a href="https://app.doorman.dev/signup" className="sh-btn sh-btn--primary">Get Doorman</a>
            <button type="button" className="sh-burger" aria-label="Toggle menu" aria-expanded={open} onClick={() => setOpen(!open)}><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 7h16M4 12h16M4 17h16" /></svg></button>
          </div>
        </div>
        <nav className={`sh-mobile${open ? ' open' : ''}`} aria-label="Mobile navigation">
          {links.map(([label, href]) => <a key={href} href={href} onClick={() => setOpen(false)}>{label}</a>)}
          <a href="https://github.com/doorman-dev/doorman#readme" target="_blank" rel="noopener noreferrer">Documentation</a>
          <a href="/login">Log in</a>
          <a href="https://app.doorman.dev/signup" className="sh-btn sh-btn--primary">Get Doorman</a>
        </nav>
      </div>
    </header>
  )
}

function getSafeNextPath(nextValue: string | null): string {
  const candidate = nextValue
    ? (() => {
      try {
        return decodeURIComponent(nextValue)
      } catch {
        return nextValue
      }
    })()
    : ''

  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//')) {
    return DEFAULT_AUTH_REDIRECT
  }
  if (candidate === '/login' || candidate.startsWith('/login?')) {
    return DEFAULT_AUTH_REDIRECT
  }
  return candidate
}

function LoginPageContent() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()
  const searchParams = useSearchParams()
  const { checkAuth, isAuthenticated, hasUIAccess } = useAuth()
  const nextPath = getSafeNextPath(searchParams.get('next'))

  useEffect(() => { document.documentElement.classList.remove('dark') }, [])
  useEffect(() => {
    if (isAuthenticated && hasUIAccess) router.push(nextPath)
    else if (isAuthenticated) {
      setErrorMessage('Your account does not have UI access. Contact an administrator.')
      try { void postJson(`${SERVER_URL}/platform/authorization/invalidate`, {}) } catch { }
      try { localStorage.clear(); sessionStorage.clear(); document.cookie = 'access_token_cookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/' } catch { }
    }
  }, [isAuthenticated, hasUIAccess, nextPath, router])

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault(); setIsLoading(true); setErrorMessage('')
    try {
      try { await postJson(`${SERVER_URL}/platform/authorization`, { email, password }) }
      catch (error: any) { setErrorMessage(error?.message || 'Invalid email or password'); return }
      try {
        const meData: any = await getJson(`${SERVER_URL}/platform/user/me`)
        const isSuperAdmin = meData && (meData.username === 'admin' || meData.role === 'admin')
        if (!(meData && (isSuperAdmin || meData.ui_access === true))) {
          setErrorMessage('Your account does not have UI access. Contact an administrator.')
          try { await postJson(`${SERVER_URL}/platform/authorization/invalidate`, {}) } catch { }
          return
        }
      } catch (error: any) {
        setErrorMessage(error?.message || 'Unable to verify account access. Please try again.')
        try { await postJson(`${SERVER_URL}/platform/authorization/invalidate`, {}) } catch { }
        return
      }
      await checkAuth(); router.push(nextPath)
    } catch (error) {
      console.error('Login error:', error); setErrorMessage('Network error. Please try again.')
    } finally { setIsLoading(false) }
  }

  return <><SiteHeader /><main className="login-signal"><section className="login-signal__panel"><header className="login-signal__header"><p className="signal-kicker">Gateway access</p><h1>Sign in to Doorman</h1><p>Use your Doorman account to manage gateway configuration, traffic, and access control.</p></header><form onSubmit={handleLogin} className="login-signal__form"><div><label htmlFor="email">Email</label><input id="email" type="email" value={email} onChange={event => setEmail(event.target.value)} required autoComplete="email" placeholder="you@company.com" className="input" disabled={isLoading} /></div><div><label htmlFor="password">Password</label><input id="password" type="password" value={password} onChange={event => setPassword(event.target.value)} required autoComplete="current-password" placeholder="Enter your password" className="input" disabled={isLoading} /></div>{errorMessage && <div className="login-signal__error">{errorMessage}</div>}<button type="submit" disabled={isLoading} className="signal-button signal-button--primary w-full">{isLoading ? 'Signing in…' : 'Sign in'}</button></form><footer>By signing in, you agree to our <a href="/terms">Terms</a> and <a href="/privacy">Privacy Policy</a>.</footer></section></main></>
}

export default function LoginPage() {
  return (
    <React.Suspense fallback={null}>
      <LoginPageContent />
    </React.Suspense>
  )
}
