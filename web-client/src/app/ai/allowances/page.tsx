'use client'

import AiPage from '@/components/AiPage'
import AiBudgetsPanel from '@/components/AiBudgetsPanel'

export default function AiAllowancesPage() {
  return <AiPage title="Allowances" description="How much AI each employee, group, tier or the whole company may use, per provider." permission="manage_ai"><div className="card p-6"><AiBudgetsPanel /></div></AiPage>
}
