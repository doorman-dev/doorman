'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

/** Keeps old AI Gateway links working after pages were merged. */
export default function AiRedirect({ to }: { to: string }) {
  const router = useRouter()
  useEffect(() => { router.replace(to) }, [router, to])
  return null
}
