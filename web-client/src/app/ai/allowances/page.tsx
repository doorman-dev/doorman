'use client'

import AiPage from '@/components/AiPage'
import AiBudgetsPanel from '@/components/AiBudgetsPanel'

export default function AiAllowancesPage() {
  return <AiPage title="Allowances" description="How much AI each employee, group or tier may use." permission="manage_ai"><AiBudgetsPanel /></AiPage>
}
