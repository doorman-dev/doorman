'use client'

import { useEffect, useState } from 'react'
import { getJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'

type PromptLog = { log_id: string; request_id: string; at: string | number; username: string; api: string; model: string; redactions: { detector: string; count: number }[]; prompt: string | null; completion: string | null }

export default function AiPromptLogModal({ logId, onClose }: { logId: string; onClose: () => void }) {
  const [log, setLog] = useState<PromptLog | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let active = true
    getJson<PromptLog>(`${SERVER_URL}/platform/ai/prompt-logs/${encodeURIComponent(logId)}`)
      .then(result => { if (active) setLog(result) })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : 'Unable to load prompt') })
    return () => { active = false }
  }, [logId])
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  const pretty = (text: string | null) => {
    if (text == null) return '(not stored)'
    try { return JSON.stringify(JSON.parse(text), null, 2) } catch { return text }
  }
  return <div className="fixed inset-0 bg-black/50 z-[60] flex items-center justify-center p-4" onClick={onClose}>
    <div role="dialog" aria-modal="true" aria-label="AI prompt log" className="bg-white dark:bg-gray-900 rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto p-6 space-y-4" onClick={event => event.stopPropagation()}>
      <div className="flex justify-between gap-3"><h3 className="text-lg font-semibold">AI prompt</h3><button type="button" className="btn btn-ghost" onClick={onClose}>Close</button></div>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      {!log && !error && <p className="text-sm">Loading prompt…</p>}
      {log && <>
        <dl className="grid grid-cols-2 gap-2 text-sm"><dt className="text-gray-500">User</dt><dd>{log.username}</dd><dt className="text-gray-500">API</dt><dd>{log.api}</dd><dt className="text-gray-500">Model</dt><dd className="font-mono">{log.model}</dd><dt className="text-gray-500">Request</dt><dd className="font-mono text-xs">{log.request_id}</dd></dl>
        <div className="text-sm"><p className="font-medium">Redactions applied</p>{log.redactions.length ? <ul className="list-disc ml-5">{log.redactions.map(r => <li key={r.detector}>{r.detector}: {r.count}</li>)}</ul> : <p className="text-gray-500">None</p>}</div>
        <div><p className="text-sm font-medium mb-1">Prompt</p><pre className="whitespace-pre-wrap bg-gray-50 dark:bg-gray-800 p-3 rounded text-xs max-h-80 overflow-auto">{pretty(log.prompt)}</pre></div>
        <div><p className="text-sm font-medium mb-1">Completion</p><pre className="whitespace-pre-wrap bg-gray-50 dark:bg-gray-800 p-3 rounded text-xs max-h-80 overflow-auto">{pretty(log.completion)}</pre></div>
      </>}
    </div>
  </div>
}
