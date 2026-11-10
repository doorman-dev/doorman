'use client'

import { useEffect, useState } from 'react'
import { fetchAllPaginated, getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import { findUnpricedModels, type AiApiSummary, type AiPricingRow } from '@/utils/ai'

/** Warns that a dollar limit counts these AI models as $0 because they have no price. */
export default function UnpricedModelsNotice() {
  const [models, setModels] = useState<string[]>([])
  useEffect(() => {
    let active = true
    Promise.all([
      fetchAllPaginated<AiApiSummary>((page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data.apis || []),
      getJson<{ pricing: AiPricingRow[] }>(`${SERVER_URL}/platform/ai/pricing`),
    ])
      .then(([apis, pricing]) => { if (active) setModels(findUnpricedModels(apis, pricing.pricing)) })
      .catch(() => {}) // Without access to APIs or prices there is nothing to warn about.
    return () => { active = false }
  }, [])
  if (!models.length) return null
  return <p className="text-sm rounded border border-amber-300 bg-amber-50 px-3 py-2 text-amber-900">These models have no price, so their spend counts as $0 toward a dollar limit: {models.join(', ')}. <a href="/ai/providers#prices" className="font-medium">Add model prices →</a></p>
}
