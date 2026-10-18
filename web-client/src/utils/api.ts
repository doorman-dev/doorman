'use client'

import { fetchJson } from './http'

export async function getJson<T = any>(url: string): Promise<T> {
  return fetchJson<T>(url)
}

function withCsrf(headers: Record<string, string> = {}) {
  try {
    const mod = require('./http') as any
    const cookie = mod.getCookie ? mod.getCookie('csrf_token') : null
    if (cookie) return { 'X-CSRF-Token': cookie, ...headers }
  } catch {}
  return headers
}

export async function postJson<T = any>(url: string, body: any, headers: Record<string, string> = {}): Promise<T> {
  return fetchJson<T>(url, {
    method: 'POST',
    headers: withCsrf({ 'Content-Type': 'application/json', ...headers }),
    body: JSON.stringify(body)
  })
}

export async function putJson<T = any>(url: string, body: any, headers: Record<string, string> = {}): Promise<T> {
  return fetchJson<T>(url, {
    method: 'PUT',
    headers: withCsrf({ 'Content-Type': 'application/json', ...headers }),
    body: JSON.stringify(body)
  })
}

export async function delJson<T = any>(url: string, body?: any, headers: Record<string, string> = {}): Promise<T> {
  return fetchJson<T>(url, {
    method: 'DELETE',
    headers: withCsrf(body ? { 'Content-Type': 'application/json', ...headers } : headers),
    ...(body ? { body: JSON.stringify(body) } : {})
  })
}

/**
 * Fetch all pages from a paginated endpoint with graceful page-size fallback.
 *
 * Usage example:
 *   const items = await fetchAllPaginated(
 *     (page, size) => `${SERVER_URL}/platform/user/all?page=${page}&page_size=${size}`,
 *     (data) => (Array.isArray(data) ? data : (data.users || data.response?.users || []))
 *   )
 */
const __paginatedCache: Map<string, any[]> = new Map()

export async function fetchAllPaginated<T = any>(
  buildUrl: (page: number, size: number) => string,
  extractItems: (data: any) => T[],
  pageSizes: number[] = [50, 25, 10, 5, 3, 2, 1],
  maxPages: number = 50,
  cacheKey?: string
): Promise<T[]> {
  if (cacheKey && __paginatedCache.has(cacheKey)) {
    return (__paginatedCache.get(cacheKey) as T[]) || []
  }
  for (const size of pageSizes) {
    const out: T[] = []
    try {
      let page = 1
      let previousBatch: string | undefined
      while (true) {
        const url = buildUrl(page, size)
        const data = await getJson<any>(url)
        const batch = extractItems(data) || []
        if (!Number.isFinite(maxPages)) {
          const signature = JSON.stringify(batch)
          if (signature === previousBatch) break
          previousBatch = signature
        }
        out.push(...batch)
        if (!Array.isArray(batch) || batch.length !== size) break
        page += 1
        if (page > maxPages) break
      }
      if (cacheKey) __paginatedCache.set(cacheKey, out)
      return out
    } catch (e: any) {
      const msg = String(e?.message || '').toLowerCase()
      // Try next smaller size on paging validation failures
      if (msg.includes('page') || msg.includes('size')) continue
      // Non-paging failure: bubble up
      throw e
    }
  }
  return []
}
