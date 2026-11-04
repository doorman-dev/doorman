'use client'

import AiPage from '@/components/AiPage'
import AiGuardrailsPanel from '@/components/AiGuardrailsPanel'

export default function AiGuardrailsPage() {
  return <AiPage title="Guardrails" description="Block or redact sensitive content in prompts and responses." permission="manage_security"><div className="card p-6"><AiGuardrailsPanel /></div></AiPage>
}
