'use client'

import { useEffect, useState } from 'react'

export interface AiTab { id: string; label: string }

/** Tab state kept in the URL hash so each tab can be linked to. */
export function useHashTab(tabs: AiTab[]): [string, (id: string) => void] {
  const [tab, setTab] = useState(tabs[0]?.id || '')
  const ids = tabs.map(item => item.id).join(',')
  useEffect(() => {
    const sync = () => { const hash = window.location.hash.slice(1); if (ids.split(',').includes(hash)) setTab(hash) }
    sync(); window.addEventListener('hashchange', sync)
    return () => window.removeEventListener('hashchange', sync)
  }, [ids])
  const select = (id: string) => { setTab(id); try { window.history.replaceState(null, '', `#${id}`) } catch {} }
  return [tabs.some(item => item.id === tab) ? tab : tabs[0]?.id || '', select]
}

export default function AiTabs({ tabs, value, onChange, label }: { tabs: AiTab[]; value: string; onChange: (id: string) => void; label: string }) {
  if (tabs.length < 2) return null
  return <div role="tablist" aria-label={label} className="ai-tabs">
    {tabs.map(tab => <button key={tab.id} type="button" role="tab" aria-selected={value === tab.id} onClick={() => onChange(tab.id)}>{tab.label}</button>)}
  </div>
}
