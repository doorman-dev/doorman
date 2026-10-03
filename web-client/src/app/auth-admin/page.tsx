'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

// Auth Control now lives under Security; keep this route so old links still work.
export default function AuthAdminRedirect() {
  const router = useRouter()
  useEffect(() => { router.replace('/security#auth') }, [router])
  return null
}
