'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function ReportsRedirect() {
  const router = useRouter()
  useEffect(() => {
    router.replace('/ai/usage#chargeback')
  }, [router])
  return null
}

