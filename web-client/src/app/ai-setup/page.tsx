'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function AiSetupRedirect() {
  const router = useRouter()
  useEffect(() => { router.replace('/ai/setup') }, [router])
  return null
}
