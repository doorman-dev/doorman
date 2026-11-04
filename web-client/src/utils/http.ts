export function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null
  const match = document.cookie.split('; ').find(c => c.startsWith(name + '='))
  return match ? decodeURIComponent(match.split('=')[1]) : null
}

export async function fetchJson<T = any>(url: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    ...(init.headers as any)
  }
  const csrf = getCookie('csrf_token')
  if (csrf) headers['X-CSRF-Token'] = csrf

  const resp = await fetch(url, {
    credentials: 'include',
    ...init,
    headers
  })
  const data = await resp.json().catch(() => ({}))
  const unwrapped = (data && typeof data === 'object' && 'response' in data) ? (data as any).response : data
  if (!resp.ok) {
    const msg = (unwrapped && (unwrapped.error_message || unwrapped.message)) || resp.statusText
    throw Object.assign(new Error(msg), { status: resp.status, error_code: unwrapped?.error_code })
  }
  return unwrapped as T
}

export async function fetchWithCsrf(url: string, init: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    ...(init.headers as any)
  }
  const csrf = getCookie('csrf_token')
  if (csrf) headers['X-CSRF-Token'] = csrf

  return fetch(url, {
    credentials: 'include',
    ...init,
    headers
  })
}
