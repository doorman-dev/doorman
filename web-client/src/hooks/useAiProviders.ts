'use client'

import { useEffect, useState } from 'react'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import type { AiProviderPreset } from '@/utils/ai'

let providersRequest: Promise<AiProviderPreset[]> | undefined

export function useAiProviders() {
  const [providers, setProviders] = useState<AiProviderPreset[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    providersRequest ??= getJson<{ providers: AiProviderPreset[] }>(`${SERVER_URL}/platform/ai/providers`)
      .then(data => data.providers)
    providersRequest.then(data => {
      if (active) setProviders(data)
    }).catch((reason: unknown) => {
      if (!active) return
      setError(reason instanceof Error ? reason.message : 'Unable to load AI providers')
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [])

  return { providers, loading, error }
}
