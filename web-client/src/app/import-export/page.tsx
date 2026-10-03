'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

// Import / Export now lives on the Tools page; keep this route so old links still work.
export default function ImportExportRedirect() {
  const router = useRouter()
  useEffect(() => { router.replace('/tools#import-export') }, [router])
  return null
}
