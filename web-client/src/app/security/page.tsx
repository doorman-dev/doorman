'use client'

import React, { useState, useEffect } from 'react'
import Layout from '@/components/Layout'
import InfoTooltip from '@/components/InfoTooltip'
import FormHelp from '@/components/FormHelp'
import { SERVER_URL } from '@/utils/config'
import { getJson, postJson, putJson, delJson } from '@/utils/api'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { useAuth } from '@/contexts/AuthContext'
import AuthControlPanel from '@/components/AuthControlPanel'

interface ApiKey {
  id: string
  name: string
  key: string
  created: string
  lastUsed: string
  status: 'active' | 'revoked'
}

interface RateLimit {
  id: string
  path: string
  limit: number
  window: string
  status: 'active' | 'disabled'
}

interface IpWhitelist {
  id: string
  ip: string
  description: string
  created: string
  status: 'active' | 'disabled'
}

interface SecurityPolicy {
  id: string
  name: string
  type: 'jwt' | 'oauth2' | 'api-key' | 'ip-whitelist'
  status: 'active' | 'disabled'
  createdAt: string
}

interface SecuritySettings {
  enable_auto_save: boolean
  auto_save_frequency_seconds: number
  dump_path: string
  ip_whitelist?: string[]
  ip_blacklist?: string[]
  trust_x_forwarded_for?: boolean
  xff_trusted_proxies?: string[]
  allow_localhost_bypass?: boolean
}

const SecurityPage = () => {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([])
  const [rateLimits, setRateLimits] = useState<RateLimit[]>([])
  const [ipWhitelist, setIpWhitelist] = useState<IpWhitelist[]>([])
  const [securityPolicies, setSecurityPolicies] = useState<SecurityPolicy[]>([])
  const [activeTab, setActiveTab] = useState('')
  const [secTab, setSecTab] = useState<'memory' | 'network' | 'gateway' | 'auth'>('memory')
  useEffect(() => {
    const h = window.location.hash.replace('#', '')
    if (h === 'memory' || h === 'network' || h === 'gateway' || h === 'auth') setSecTab(h)
  }, [])
  const selectSecTab = (id: 'memory' | 'network' | 'gateway' | 'auth') => { setSecTab(id); try { window.history.replaceState(null, '', `#${id}`) } catch {} }
  const tabs: { id: string; label: string; icon: string }[] = []
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [settings, setSettings] = useState<SecuritySettings>({
    enable_auto_save: false,
    auto_save_frequency_seconds: 900,
    dump_path: 'data/memory_dump.bin',
    ip_whitelist: [],
    ip_blacklist: [],
    trust_x_forwarded_for: false,
    xff_trusted_proxies: [],
    allow_localhost_bypass: false,
  })
  const [ipWhitelistText, setIpWhitelistText] = useState('')
  const [ipBlacklistText, setIpBlacklistText] = useState('')
  const [trustedProxyText, setTrustedProxyText] = useState('')
  const [memoryOnly, setMemoryOnly] = useState(false)
  const [warnings, setWarnings] = useState<string[]>([])
  const [clientIp, setClientIp] = useState('')
  const [clientIpXff, setClientIpXff] = useState('')
  const [restorePath, setRestorePath] = useState('')
  const [bypassLocked, setBypassLocked] = useState(false)
  const { permissions } = useAuth()

  useEffect(() => {
    fetchSecurityData()
    fetchSecuritySettings()
  }, [])

  const fetchSecurityData = async () => {
    try {
      setLoading(true)
      setError(null)

      setApiKeys([
        { id: '1', name: 'Production API Key', key: 'sk_prod_123456789', created: '2024-01-15', lastUsed: '2024-01-20', status: 'active' },
        { id: '2', name: 'Development API Key', key: 'sk_dev_987654321', created: '2024-01-10', lastUsed: '2024-01-19', status: 'active' }
      ])

      setRateLimits([
        { id: '1', path: '/api/v1/*', limit: 1000, window: '1 hour', status: 'active' },
        { id: '2', path: '/api/v1/auth/*', limit: 100, window: '1 hour', status: 'active' }
      ])

      setIpWhitelist([
        { id: '1', ip: '192.168.1.100', description: 'Office Network', created: '2024-01-15', status: 'active' },
        { id: '2', ip: '10.0.0.50', description: 'VPN Server', created: '2024-01-10', status: 'active' }
      ])

      setSecurityPolicies([
        { id: '1', name: 'JWT Authentication', type: 'jwt', status: 'active', createdAt: '2024-01-15' },
        { id: '2', name: 'API Key Authentication', type: 'api-key', status: 'active', createdAt: '2024-01-10' }
      ])
    } catch (err) {
      setError('Failed to load security data. Please try again later.')
    } finally {
      setLoading(false)
    }
  }

  const fetchSecuritySettings = async () => {
    try {
      setSettingsLoading(true)
      setError(null)
      const data = await getJson<any>(`${SERVER_URL}/platform/security/settings`)
      setSettings({
        enable_auto_save: !!data.enable_auto_save,
        auto_save_frequency_seconds: Number(data.auto_save_frequency_seconds || 900),
        dump_path: data.dump_path || 'data/memory_dump.bin',
        ip_whitelist: Array.isArray(data.ip_whitelist) ? data.ip_whitelist : [],
        ip_blacklist: Array.isArray(data.ip_blacklist) ? data.ip_blacklist : [],
        trust_x_forwarded_for: !!data.trust_x_forwarded_for,
        xff_trusted_proxies: Array.isArray((data as any).xff_trusted_proxies) ? (data as any).xff_trusted_proxies : [],
        allow_localhost_bypass: !!(data as any).allow_localhost_bypass,
      })
      setMemoryOnly(!!data.memory_only)
      setWarnings(Array.isArray((data as any).security_warnings) ? (data as any).security_warnings : [])
      setBypassLocked(!!(data as any).allow_localhost_bypass_locked)
      setClientIp(String(data.client_ip || ''))
      setClientIpXff(String(data.client_ip_xff || ''))
      setIpWhitelistText((Array.isArray(data.ip_whitelist) ? data.ip_whitelist : []).join('\n'))
      setIpBlacklistText((Array.isArray(data.ip_blacklist) ? data.ip_blacklist : []).join('\n'))
      setTrustedProxyText((Array.isArray((data as any).xff_trusted_proxies) ? (data as any).xff_trusted_proxies : []).join('\n'))
    } catch (err) {
      setError('Failed to load security settings. Please try again later.')
    } finally {
      setSettingsLoading(false)
    }
  }

  const handleSaveSettings = async () => {
    try {
      setSettingsSaving(true)
      setError(null)
      const payload = {
        ...settings,
        ip_whitelist: ipWhitelistText.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean),
        ip_blacklist: ipBlacklistText.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean),
        xff_trusted_proxies: trustedProxyText.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean),
      }
      await putJson(`${SERVER_URL}/platform/security/settings`, payload)
      setSuccess('Security settings saved')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings')
    } finally {
      setSettingsSaving(false)
    }
  }

  const handleDumpNow = async () => {
    try {
      setError(null)
      const data = await postJson<any>(`${SERVER_URL}/platform/memory/dump`, { path: settings.dump_path })
      setSuccess(`Memory dump created at ${data.response?.path || settings.dump_path}`)
      setTimeout(() => setSuccess(null), 4000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create memory dump')
    }
  }

  const handleRestore = async () => {
    try {
      setError(null)
      const data = await postJson<any>(`${SERVER_URL}/platform/memory/restore`, { path: restorePath || settings.dump_path })
      setSuccess(`Memory restored (created at ${data.response?.created_at || 'unknown'})`)
      setTimeout(() => setSuccess(null), 4000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to restore memory dump')
    }
  }

  const handleClearCaches = async () => {
    try {
      setError(null)
      console.log('[Security] Clearing caches at:', `${SERVER_URL}/api/caches`)
      const response = await delJson<any>(`${SERVER_URL}/api/caches`)
      console.log('[Security] Clear caches response:', response)
      setSuccess(response?.message || 'All gateway caches cleared')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      console.error('[Security] Clear caches error:', err)
      setError(err instanceof Error ? err.message : 'Failed to clear caches')
    }
  }

  const handleRestartGateway = async () => {
    try {
      setError(null)
      const res = await postJson<any>(`${SERVER_URL}/platform/security/restart`, {})
      setSuccess(res?.message || 'Restart scheduled')
      setTimeout(() => setSuccess(null), 4000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to schedule restart')
    }
  }

  const handleCreateApiKey = async () => {
    try {
      setSuccess('API key created successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError('Failed to create API key. Please try again.')
    }
  }

  const handleRevokeApiKey = async (keyId: string) => {
    try {
      setApiKeys(prev => prev.map(key =>
        key.id === keyId ? { ...key, status: 'revoked' as const } : key
      ))
      setSuccess('API key revoked successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError('Failed to revoke API key. Please try again.')
    }
  }

  const handleAddRateLimit = async () => {
    try {
      setSuccess('Rate limit added successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError('Failed to add rate limit. Please try again.')
    }
  }

  const handleAddIpWhitelist = async () => {
    try {
      setSuccess('IP address added to whitelist successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError('Failed to add IP to whitelist. Please try again.')
    }
  }

  const handleCreateSecurityPolicy = async () => {
    try {
      setSuccess('Security policy created successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError('Failed to create security policy. Please try again.')
    }
  }

  const addMyIpToWhitelist = () => {
    const effectiveIp = (settings.trust_x_forwarded_for && clientIpXff) ? clientIpXff : clientIp
    if (!effectiveIp) return
    const list = ipWhitelistText.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean)
    if (list.includes(effectiveIp)) return
    setIpWhitelistText(prev => (prev && prev.trim().length > 0) ? `${prev.trim()}\n${effectiveIp}` : effectiveIp)
  }

  return (
    <ProtectedRoute requiredPermission="manage_security">
    <Layout>
      <div className="space-y-6">
        <div className="page-header">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="page-title">Security</h1>
              {memoryOnly && (
                <span className="badge badge-gray">Memory Mode</span>
              )}
            </div>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              Manage API keys, rate limits, and security policies
            </p>
          </div>
        </div>

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

        {loading ? (
          <div className="card">
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="spinner mx-auto mb-4"></div>
                <p className="text-gray-600 dark:text-gray-400">Loading security data...</p>
              </div>
            </div>
          </div>
        ) : (
          <>
            {warnings.length > 0 && (
              <div className="rounded-lg bg-warning-50 border border-warning-200 p-4 dark:bg-warning-900/20 dark:border-warning-800 mb-4">
                <div className="text-sm text-warning-800 dark:text-warning-200">
                  <div className="font-medium mb-1">Security Warnings</div>
                  <ul className="list-disc ml-5">
                    {warnings.map((w, i) => (<li key={i}>{w}</li>))}
                  </ul>
                </div>
              </div>
            )}
            <div className="card">
              <div className="p-6 space-y-6">
                <div className="flex items-center justify-between">
                  <div role="tablist" aria-label="Security sections" className="flex gap-1 border-b border-gray-200 flex-1">
                    {([['memory', 'Memory & persistence'], ['network', 'Network access'], ['gateway', 'Gateway'], ['auth', 'Auth control']] as const).filter(([id]) => id === 'auth' ? !!permissions?.manage_auth : (id !== 'gateway' || permissions?.manage_gateway || permissions?.manage_security)).map(([id, label]) => (
                      <button key={id} type="button" role="tab" aria-selected={secTab === id} onClick={() => selectSecTab(id)}
                        className={`-mb-px border-b-2 px-4 py-2 text-sm font-medium ${secTab === id ? 'border-primary-600 text-primary-700' : 'border-transparent text-gray-600 hover:text-gray-900'}`}>{label}</button>
                    ))}
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    <FormHelp docHref="/docs/using-fields.html#security">Configure encrypted memory dumps and clear caches safely.</FormHelp>
                  </div>
                </div>

                {secTab === 'auth' && <AuthControlPanel />}
                <div className={`grid grid-cols-1 md:grid-cols-2 gap-6 ${secTab === 'auth' ? 'hidden' : ''}`}>
                  {secTab === 'memory' && (<>
                  <div className="space-y-2">
                    <label className={`block text-sm font-medium ${memoryOnly ? 'text-gray-400 dark:text-gray-500' : 'text-gray-700 dark:text-gray-300'}`}>
                      Enable Auto-save
                      <InfoTooltip text="When enabled, Doorman periodically writes an encrypted memory dump to the configured path. Requires MEM_ENCRYPTION_KEY on the server. In memory-only mode this is always on." />
                    </label>
                    <div className={`flex items-center gap-3 ${memoryOnly ? 'opacity-60 cursor-not-allowed' : ''}`}>
                      <input
                        type="checkbox"
                        checked={memoryOnly ? true : settings.enable_auto_save}
                        onChange={(e) => setSettings(s => ({ ...s, enable_auto_save: e.target.checked }))}
                        className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                        disabled={settingsLoading || settingsSaving || memoryOnly}
                      />
                      <span className={`text-sm ${memoryOnly ? 'text-gray-500 dark:text-gray-500' : 'text-gray-600 dark:text-gray-400'}`}>
                        {memoryOnly ? 'Always on in memory mode' : 'Periodically save encrypted memory dump'}
                      </span>
                    </div>
                    {memoryOnly && (
                      <p className="text-xs text-gray-500 dark:text-gray-400">Auto-save is enforced in memory mode; adjust only the frequency and dump path.</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Auto-save Frequency (seconds)
                      <InfoTooltip text="Minimum 60s. Choose a value that balances RPO vs. IO overhead. Applies only when auto-save is enabled." />
                    </label>
                    <input
                      type="number"
                      min={60}
                      value={settings.auto_save_frequency_seconds}
                      onChange={(e) => setSettings(s => ({ ...s, auto_save_frequency_seconds: Math.max(60, Number(e.target.value || 60)) }))}
                      className="input"
                      placeholder="900"
                      disabled={settingsLoading || settingsSaving}
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400">Minimum 60 seconds</p>
                  </div>

                  <div className="space-y-2 md:col-span-2">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Dump Path
                      <InfoTooltip text="Filesystem path for the encrypted memory dump. Store on an encrypted volume if possible. Example: data/memory_dump.bin" />
                    </label>
                    <input
                      type="text"
                      value={settings.dump_path}
                      onChange={(e) => setSettings(s => ({ ...s, dump_path: e.target.value }))}
                      className="input"
                      placeholder="data/memory_dump.bin"
                      disabled={settingsLoading || settingsSaving}
                    />
                  </div>

                  <div className="md:col-span-2 flex gap-3">
                    <button onClick={handleSaveSettings} disabled={settingsSaving || settingsLoading} className="btn btn-primary">
                      {settingsSaving ? (
                        <div className="flex items-center"><div className="spinner mr-2"></div>Saving...</div>
                      ) : 'Save Settings'}
                    </button>
                    <button onClick={handleDumpNow} className="btn btn-secondary">Dump Now</button>
                  </div>
                  </>)}

                  {secTab === 'network' && (<>
                      <div className="md:col-span-2 border-t border-gray-200 dark:border-gray-700 pt-4">
                    <h4 className="text-md font-medium text-gray-900 dark:text-white mb-2">IP Access Control <InfoTooltip text="Effective IP: if 'Trust X-Forwarded-For' is enabled and the request includes X-Forwarded-For, the first IP in that header is used. Otherwise the direct client IP is used. Warnings and enforcement follow this rule." /></h4>
                    {(() => {
                      const effectiveIp = (settings.trust_x_forwarded_for && clientIpXff) ? clientIpXff : clientIp
                      const listFromText = (t: string) => t.split(/\r?\n|,/).map(s=>s.trim()).filter(Boolean)
                      const wl = listFromText(ipWhitelistText)
                      const bl = listFromText(ipBlacklistText)
                      const isIPv6 = (s: string) => s.includes(':')
                      const toIPv4 = (s: string) => { const parts = s.split('.'); if (parts.length !== 4) return null as any; return parts.reduce((a,p)=> (a<<8n)+(BigInt(parseInt(p,10)&255)),0n) }
                      const expandIPv6 = (ip: string) => {
                        if (ip.indexOf('::') !== -1) {
                          const [head, tail] = ip.split('::')
                          const headParts = head ? head.split(':') : []
                          const tailParts = tail ? tail.split(':') : []
                          const missing = 8 - (headParts.length + tailParts.length)
                          const zeros = Array(Math.max(0, missing)).fill('0')
                          return [...headParts, ...zeros, ...tailParts].map(h=>h || '0')
                        }
                        return ip.split(':')
                      }
                      const toIPv6 = (s: string) => { const parts = expandIPv6(s); if (parts.length !== 8) return null as any; try { return parts.reduce((acc, h) => (acc<<16n) + BigInt(parseInt(h || '0', 16)), 0n) } catch { return null as any } }
                      const matches = (ip: string, patterns: string[]) => {
                        if (!ip) return false
                        const v6 = isIPv6(ip)
                        const ipVal = v6 ? toIPv6(ip) : toIPv4(ip)
                        return patterns.some(raw => {
                          const p = raw.trim(); if (!p) return false
                          if (p.includes('/')) {
                            const [net, maskStr] = p.split('/')
                            const m = parseInt(maskStr, 10)
                            const n6 = isIPv6(net)
                            if (n6 !== v6) return false
                            const netVal = n6 ? toIPv6(net) : toIPv4(net)
                            if (netVal === null || ipVal === null || isNaN(m as any)) return false
                            const bits = n6 ? 128 : 32
                            const shift = BigInt(bits - Math.min(Math.max(m,0), bits))
                            const mask = ((1n << BigInt(bits)) - 1n) ^ ((1n << shift) - 1n)
                            return ((ipVal & mask) === (netVal & mask))
                          }
                          return p.toLowerCase() === ip.toLowerCase()
                        })
                      }
                      const warnWL = wl.length > 0 && !matches(effectiveIp, wl)
                      const warnBL = matches(effectiveIp, bl)
                      if (!(warnWL || warnBL)) return null
                      return (
                        <div className="rounded-md bg-warning-50 border border-warning-200 p-3 text-warning-800 dark:bg-warning-900/20 dark:border-warning-800 dark:text-warning-200 mb-2">
                          {warnBL ? 'Warning: Your current IP appears in the blacklist and you may lose access after saving.' : 'Warning: Your current IP is not in the whitelist and you may lose access after saving.'}
                          <div className="text-xs mt-1">Your IP: {effectiveIp || 'unknown'} {settings.trust_x_forwarded_for ? '(using X-Forwarded-For)' : ''}</div>
                        </div>
                      )
                    })()}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <div className="flex items-center justify-between">
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Whitelist (one per line or comma-separated)</label>
                          <button type="button" className="btn btn-ghost btn-xs" onClick={addMyIpToWhitelist}>Add My IP</button>
                        </div>
                        <textarea className="input min-h-[120px]" value={ipWhitelistText} onChange={(e)=>setIpWhitelistText(e.target.value)} placeholder="192.168.1.10\n10.0.0.0/8" />
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">If non-empty, only these IPs/CIDRs can access the platform and gateway.</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Blacklist (one per line or comma-separated)</label>
                        <textarea className="input min-h-[120px]" value={ipBlacklistText} onChange={(e)=>setIpBlacklistText(e.target.value)} placeholder="203.0.113.0/24" />
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Denied IPs/CIDRs. Checked after whitelist.</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Trusted Proxies (IPs/CIDRs)</label>
                        <textarea className="input min-h-[120px]" value={trustedProxyText} onChange={(e)=>setTrustedProxyText(e.target.value)} placeholder="10.0.0.0/8\n192.168.0.0/16\nfd00::/8" />
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">When set, X-Forwarded-For/X-Real-IP are only trusted from these addresses.</p>
                      </div>
                      <div className="md:col-span-2 flex items-center gap-2">
                        <input type="checkbox" className="h-4 w-4" checked={!!settings.trust_x_forwarded_for} onChange={(e)=>setSettings(s => ({...s, trust_x_forwarded_for: e.target.checked}))} />
                        <label className="text-sm text-gray-700 dark:text-gray-300">Trust X-Forwarded-For (when behind a proxy)</label>
                        <InfoTooltip text="When enabled, the first IP in X-Forwarded-For is treated as the client IP. Otherwise, the direct source IP is used." />
                      </div>
                      <div className="md:col-span-2 flex items-start gap-2">
                        <input
                          type="checkbox"
                          className="h-4 w-4 mt-1"
                          checked={!!settings.allow_localhost_bypass}
                          onChange={(e)=>setSettings(s => ({...s, allow_localhost_bypass: e.target.checked}))}
                          disabled={bypassLocked}
                        />
                        <div>
                          <div className="flex items-center gap-2">
                            <label className="text-sm text-gray-700 dark:text-gray-300">Never lock out localhost (direct requests only)</label>
                            <InfoTooltip text="If enabled, direct requests from 127.0.0.1/::1 (without any forwarding headers) bypass IP allow/deny checks. Controlled by env LOCAL_HOST_IP_BYPASS when set." />
                          </div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">Do not enable if your reverse proxy runs on localhost and strips forwarding headers.</p>
                          {bypassLocked && (
                            <p className="text-xs text-warning-700 dark:text-warning-300 mt-1">This setting is controlled by environment variable LOCAL_HOST_IP_BYPASS.</p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="md:col-span-2 flex gap-3">
                    <button onClick={handleSaveSettings} disabled={settingsSaving || settingsLoading} className="btn btn-primary">{settingsSaving ? 'Saving…' : 'Save settings'}</button>
                  </div>
                  </>)}

                  {secTab === 'memory' && (<>
                  <div className="md:col-span-2">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Restore From Path
                      <InfoTooltip text="Points to a previously saved encrypted dump file. Requires MEM_ENCRYPTION_KEY to decrypt and restore." />
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={restorePath}
                        onChange={(e) => setRestorePath(e.target.value)}
                        className="input flex-1"
                        placeholder={settings.dump_path}
                      />
                      <button onClick={handleRestore} className="btn btn-secondary">Restore</button>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Requires MEM_ENCRYPTION_KEY to be configured on server.</p>
                  </div>
                  </>)}

                  {secTab === 'gateway' && (<>
                  {(permissions?.manage_gateway || permissions?.manage_security) && (
                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Gateway</label>
                      <div className="flex gap-3">
                        {permissions?.manage_gateway && (
                          <button onClick={handleClearCaches} className="btn btn-secondary">Clear All Caches</button>
                        )}
                        {permissions?.manage_security && (
                          <button onClick={handleRestartGateway} className="btn btn-danger">Restart Gateway</button>
                        )}
                      </div>
                    </div>
                  )}
                  </>)}
                </div>
              </div>
            </div>
            {tabs.length > 0 && (
              <div className="card">
                <div className="border-b border-gray-200 dark:border-gray-700">
                  <nav className="-mb-px flex space-x-8">
                    {tabs.map((tab) => (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`py-2 px-1 border-b-2 font-medium text-sm ${
                          activeTab === tab.id
                            ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                        }`}
                      >
                        <span className="mr-2">{tab.icon}</span>
                        {tab.label}
                      </button>
                    ))}
                  </nav>
                </div>

                <div className="p-6">
                {activeTab === 'settings' && (
                  <div className="space-y-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">Memory & Security Settings</h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Enable Auto-save</label>
                        <div className="flex items-center gap-3">
                          <input
                            type="checkbox"
                            checked={settings.enable_auto_save}
                            onChange={(e) => setSettings(s => ({ ...s, enable_auto_save: e.target.checked }))}
                            className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                            disabled={settingsLoading || settingsSaving}
                          />
                          <span className="text-sm text-gray-600 dark:text-gray-400">Periodically save encrypted memory dump</span>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Auto-save Frequency (seconds)</label>
                        <input
                          type="number"
                          min={60}
                          value={settings.auto_save_frequency_seconds}
                          onChange={(e) => setSettings(s => ({ ...s, auto_save_frequency_seconds: Math.max(60, Number(e.target.value || 60)) }))}
                          className="input"
                          placeholder="900"
                          disabled={settingsLoading || settingsSaving}
                        />
                        <p className="text-xs text-gray-500 dark:text-gray-400">Minimum 60 seconds</p>
                      </div>

                      <div className="space-y-2 md:col-span-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Dump Path</label>
                        <input
                          type="text"
                          value={settings.dump_path}
                          onChange={(e) => setSettings(s => ({ ...s, dump_path: e.target.value }))}
                          className="input"
                          placeholder="data/memory_dump.bin"
                          disabled={settingsLoading || settingsSaving}
                        />
                      </div>

                      <div className="md:col-span-2 flex gap-3">
                        <button onClick={handleSaveSettings} disabled={settingsSaving || settingsLoading} className="btn btn-primary">
                          {settingsSaving ? (
                            <div className="flex items-center"><div className="spinner mr-2"></div>Saving...</div>
                          ) : 'Save Settings'}
                        </button>
                        <button onClick={handleDumpNow} className="btn btn-secondary">Dump Now</button>
                      </div>

                      <div className="md:col-span-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Restore From Path</label>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            value={restorePath}
                            onChange={(e) => setRestorePath(e.target.value)}
                            className="input flex-1"
                            placeholder={settings.dump_path}
                          />
                          <button onClick={handleRestore} className="btn btn-secondary">Restore</button>
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Requires MEM_ENCRYPTION_KEY to be configured on server.</p>
                      </div>

                      {permissions?.manage_gateway && (
                        <div className="md:col-span-2">
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Gateway</label>
                          <button onClick={handleClearCaches} className="btn btn-secondary">Clear All Caches</button>
                        </div>
                      )}
                    </div>
                  </div>
                )}
                {activeTab === 'api-keys' && (
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white">API Keys</h3>
                      <button onClick={handleCreateApiKey} className="btn btn-primary">
                        <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Create API Key
                      </button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Key</th>
                            <th>Created</th>
                            <th>Last Used</th>
                            <th>Status</th>
                            <th></th>
                          </tr>
                        </thead>
                        <tbody>
                          {apiKeys.map((key) => (
                            <tr key={key.id} className="hover:bg-gray-50 dark:hover:bg-dark-surfaceHover transition-colors">
                              <td>
                                <p className="font-medium text-gray-900 dark:text-white">{key.name}</p>
                              </td>
                              <td>
                                <code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded font-mono">
                                  {key.key}
                                </code>
                              </td>
                              <td>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{key.created}</p>
                              </td>
                              <td>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{key.lastUsed}</p>
                              </td>
                              <td>
                                <span className={`badge ${key.status === 'active' ? 'badge-success' : 'badge-error'}`}>
                                  {key.status}
                                </span>
                              </td>
                              <td>
                                {key.status === 'active' && (
                                  <button
                                    onClick={() => handleRevokeApiKey(key.id)}
                                    className="btn btn-ghost btn-sm text-error-600 hover:text-error-700"
                                  >
                                    Revoke
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {activeTab === 'ip-whitelist' && (
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white">IP Whitelist</h3>
                      <button onClick={handleAddIpWhitelist} className="btn btn-primary">
                        <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Add IP Address
                      </button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>IP Address</th>
                            <th>Description</th>
                            <th>Created</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ipWhitelist.map((ip) => (
                            <tr key={ip.id} className="hover:bg-gray-50 dark:hover:bg-dark-surfaceHover transition-colors">
                              <td>
                                <p className="font-medium text-gray-900 dark:text-white">{ip.ip}</p>
                              </td>
                              <td>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{ip.description}</p>
                              </td>
                              <td>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{ip.created}</p>
                              </td>
                              <td>
                                <span className={`badge ${ip.status === 'active' ? 'badge-success' : 'badge-gray'}`}>
                                  {ip.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {activeTab === 'policies' && (
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white">Security Policies</h3>
                      <button onClick={handleCreateSecurityPolicy} className="btn btn-primary">
                        <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Create Policy
                      </button>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="table">
                        <thead>
                          <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Created</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {securityPolicies.map((policy) => (
                            <tr key={policy.id} className="hover:bg-gray-50 dark:hover:bg-dark-surfaceHover transition-colors">
                              <td>
                                <p className="font-medium text-gray-900 dark:text-white">{policy.name}</p>
                              </td>
                              <td>
                                <span className="badge badge-primary">{policy.type}</span>
                              </td>
                              <td>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{policy.createdAt}</p>
                              </td>
                              <td>
                                <span className={`badge ${policy.status === 'active' ? 'badge-success' : 'badge-gray'}`}>
                                  {policy.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
    </ProtectedRoute>
  )
}

export default SecurityPage
