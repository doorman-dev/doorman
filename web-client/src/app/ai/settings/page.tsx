'use client'

import AiPage from '@/components/AiPage'
import AiSettingsPanel from '@/components/AiSettingsPanel'

export default function AiSettingsPage() {
  return <AiPage title="AI Settings" description="Prompt logging, employee notice, retention and egress IPs." permission="manage_ai"><AiSettingsPanel /></AiPage>
}
