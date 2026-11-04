'use client'

import AiPage from '@/components/AiPage'
import AiPricingPanel from '@/components/AiPricingPanel'
import { useAuth } from '@/contexts/AuthContext'

export default function AiPricingPage() {
  const { permissions } = useAuth()
  return <AiPage title="Pricing" description="Model prices used to turn token usage into spend." permission="view_analytics"><div className="card p-6"><AiPricingPanel canManage={!!permissions?.manage_ai} /></div></AiPage>
}
