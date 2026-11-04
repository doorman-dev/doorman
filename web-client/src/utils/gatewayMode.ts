export type GatewayMode = 'api' | 'ai'

const MODE_KEY = 'doorman.gatewayMode'
const AI_PREFIXES = ['/ai', '/my-ai']
const API_PREFIXES = ['/dashboard', '/analytics', '/logging', '/authorizations', '/credits', '/credit-defs', '/routings', '/security', '/tls', '/tools', '/quota', '/subscriptions', '/api-builder', '/import-export', '/monitor']

const under = (pathname: string, prefix: string) => pathname === prefix || pathname.startsWith(`${prefix}/`)

export function storedMode(): GatewayMode | null {
  try { const value = window.localStorage.getItem(MODE_KEY); return value === 'ai' || value === 'api' ? value : null } catch { return null }
}

export function storeMode(mode: GatewayMode) {
  try { window.localStorage.setItem(MODE_KEY, mode) } catch {}
}

/** The mode a path belongs to; shared pages (users, groups, settings…) keep the last mode. */
export function modeForPath(pathname: string, fallback: GatewayMode): GatewayMode {
  if (AI_PREFIXES.some(prefix => under(pathname, prefix))) return 'ai'
  if (pathname === '/apis' || API_PREFIXES.some(prefix => under(pathname, prefix))) return 'api'
  return fallback
}

/** Where to land after login: the last mode used, else AI only when every API is an AI API. */
export async function landingPath(hasAiAdmin: boolean, loadApiTypes: () => Promise<string[]>): Promise<string> {
  if (!hasAiAdmin) return '/dashboard'
  const mode = storedMode()
  if (mode) return mode === 'ai' ? '/ai' : '/dashboard'
  try {
    const types = await loadApiTypes()
    return types.length > 0 && types.every(type => type === 'AI') ? '/ai' : '/dashboard'
  } catch { return '/dashboard' }
}
