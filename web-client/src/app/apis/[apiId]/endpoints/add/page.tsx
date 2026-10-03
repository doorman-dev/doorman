'use client'

import { useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'

// Endpoints are added inline from the endpoints table; keep this route so old links still work.
export default function AddEndpointRedirect() {
  const params = useParams()
  const router = useRouter()
  useEffect(() => { router.replace(`/apis/${encodeURIComponent(params.apiId as string)}/endpoints?add=1`) }, [params.apiId, router])
  return null
}
