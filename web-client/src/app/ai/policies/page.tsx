'use client'

import AiPage from '@/components/AiPage'
import AiTabs, { useHashTab } from '@/components/AiTabs'
import AiGuardrailsPanel from '@/components/AiGuardrailsPanel'
import AiSettingsPanel from '@/components/AiSettingsPanel'
import { useAuth } from '@/contexts/AuthContext'

export default function AiPoliciesPage() {
  const { permissions } = useAuth()
  const tabs = [...(permissions?.manage_security ? [{ id: 'guardrails', label: 'Guardrails' }] : []), ...(permissions?.manage_ai ? [{ id: 'logging', label: 'Prompt logging' }] : [])]
  const [tab, setTab] = useHashTab(tabs)
  return <AiPage title="Policies" description="What employees may send to AI providers, and what Doorman keeps.">
    <AiTabs tabs={tabs} value={tab} onChange={setTab} label="Policy sections" />
    {tab === 'guardrails' && <div className="card p-6"><AiGuardrailsPanel /></div>}
    {tab === 'logging' && <AiSettingsPanel />}
    {!tabs.length && <p className="text-sm text-gray-500">You need the Manage security or Manage AI permission to change AI policies.</p>}
  </AiPage>
}
