'use client'

import { useCallback, useEffect, useState } from 'react'
import ConfirmModal from '@/components/ConfirmModal'
import { delJson, fetchAllPaginated, getJson, postJson, putJson } from '@/utils/api'
import { SERVER_URL } from '@/utils/config'
import type { AiBuiltinDetector, AiDetector, AiGuardrail } from '@/utils/ai'

const DIRECTION_LABELS: Record<string, string> = { input: 'Prompts', output: 'Responses', both: 'Prompts and responses' }
const appliesTo = (apis: string[], groups: string[]) => {
  const all = (list: string[]) => !list.length || list.includes('*')
  const apiText = all(apis) ? 'All providers' : apis.join(', ')
  return all(groups) ? apiText : `${apiText} · ${groups.join(', ')}`
}

const BUILTINS: [AiBuiltinDetector, string][] = [['email', 'Email address'], ['us_ssn', 'US SSN'], ['credit_card', 'Credit card (Luhn)'], ['aws_access_key', 'AWS access key'], ['private_key_pem', 'PEM private key'], ['generic_api_key', 'Generic API key / token']]
type Draft = Omit<AiGuardrail, 'detectors'> & { builtins: AiBuiltinDetector[]; regexes: string[]; keywords: string; apis: string; groups: string }
type TestResult = { matches: { detector: string; start: number; end: number }[]; redacted: string }
type SampleResult = { sampled: number; counts: Record<string, number> }

const fresh = (): Draft => ({ guardrail_id: '', name: '', enabled: true, applies_to: { apis: ['*'], groups: ['*'] }, direction: 'input', action: 'redact', mode: 'enforce', builtins: [], regexes: [], keywords: '', apis: '*', groups: '*' })
const list = (text: string) => text.split(/[\n,]/).map(value => value.trim()).filter(Boolean)
const toDraft = (rail: AiGuardrail): Draft => ({
  ...rail,
  builtins: rail.detectors.flatMap(d => d.type === 'builtin' ? [d.id] : []),
  regexes: rail.detectors.flatMap(d => d.type === 'regex' ? [d.pattern] : []),
  keywords: rail.detectors.flatMap(d => d.type === 'keywords' ? d.values : []).join('\n'),
  apis: rail.applies_to.apis.join(', '),
  groups: rail.applies_to.groups.join(', '),
})
const toDoc = (draft: Draft): Omit<AiGuardrail, 'guardrail_id'> => {
  const detectors: AiDetector[] = [
    ...draft.builtins.map(id => ({ type: 'builtin' as const, id })),
    ...draft.regexes.map(pattern => pattern.trim()).filter(Boolean).map(pattern => ({ type: 'regex' as const, pattern })),
  ]
  const keywords = list(draft.keywords)
  if (keywords.length) detectors.push({ type: 'keywords', values: keywords })
  return { name: draft.name, enabled: draft.enabled, applies_to: { apis: list(draft.apis), groups: list(draft.groups) }, direction: draft.direction, detectors, action: draft.action, mode: draft.mode }
}

export default function AiGuardrailsPanel() {
  const [rows, setRows] = useState<AiGuardrail[]>([])
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [removing, setRemoving] = useState<AiGuardrail | null>(null)
  const [apiOptions, setApiOptions] = useState<string[]>([])
  const [testText, setTestText] = useState('')
  const [sampleN, setSampleN] = useState(50)
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [sampleResult, setSampleResult] = useState<SampleResult | null>(null)
  const [hasPromptLogs, setHasPromptLogs] = useState(false)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try { setRows((await getJson<{ guardrails: AiGuardrail[] }>(`${SERVER_URL}/platform/ai/guardrails`)).guardrails) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to load guardrails') }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { load() }, [load])
  useEffect(() => {
    let active = true
    fetchAllPaginated<{ api_name: string; api_version: string; api_type: string }>((page, size) => `${SERVER_URL}/platform/api/all?page=${page}&page_size=${size}`, data => Array.isArray(data) ? data : data.apis || [])
      .then(result => { if (active) setApiOptions(result.filter(api => api.api_type === 'AI').map(api => `${api.api_name}/${api.api_version}`)) })
      .catch(() => {})
    getJson<{ logs: unknown[] }>(`${SERVER_URL}/platform/ai/prompt-logs?limit=1`)
      .then(result => { if (active) setHasPromptLogs(result.logs.length > 0) })
      .catch(() => {})
    return () => { active = false }
  }, [])

  const update = (value: Partial<Draft>) => setDraft(current => current ? { ...current, ...value } : current)
  const open = (next: Draft) => { setDraft(next); setError(null); setTestResult(null); setSampleResult(null) }
  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!draft) return
    setWorking(true); setError(null)
    try {
      const body = toDoc(draft)
      if (draft.guardrail_id) await putJson(`${SERVER_URL}/platform/ai/guardrails/${encodeURIComponent(draft.guardrail_id)}`, body)
      else await postJson(`${SERVER_URL}/platform/ai/guardrails`, body)
      setDraft(null); await load()
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to save guardrail') }
    finally { setWorking(false) }
  }
  const toggle = async (rail: AiGuardrail) => {
    setWorking(true); setError(null)
    try { await putJson(`${SERVER_URL}/platform/ai/guardrails/${encodeURIComponent(rail.guardrail_id)}`, { enabled: !rail.enabled }); await load() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to update guardrail') }
    finally { setWorking(false) }
  }
  const remove = async () => {
    if (!removing) return
    setWorking(true)
    try { await delJson(`${SERVER_URL}/platform/ai/guardrails/${encodeURIComponent(removing.guardrail_id)}`); setRemoving(null); await load() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to delete guardrail') }
    finally { setWorking(false) }
  }
  const runTest = async (sample: boolean) => {
    if (!draft) return
    setWorking(true); setError(null)
    try {
      const guardrail = { guardrail_id: draft.guardrail_id || 'preview', ...toDoc(draft) }
      if (sample) { setSampleResult(await postJson<SampleResult>(`${SERVER_URL}/platform/ai/guardrails/test`, { guardrail, sample_last_n: sampleN })); setTestResult(null) }
      else { setTestResult(await postJson<TestResult>(`${SERVER_URL}/platform/ai/guardrails/test`, { guardrail, text: testText })); setSampleResult(null) }
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Guardrail test failed') }
    finally { setWorking(false) }
  }

  const detectorSummary = (rail: AiGuardrail) => rail.detectors.map(d => d.type === 'builtin' ? (BUILTINS.find(([id]) => id === d.id)?.[1] || d.id) : d.type === 'regex' ? 'Custom pattern' : `${d.values.length} keyword${d.values.length === 1 ? '' : 's'}`).join(', ') || '—'
  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3"><p className="text-sm text-gray-500 max-w-2xl">Redact or block personal data and secrets in prompts and responses. Matched text is never logged. Response checks don&apos;t change streamed replies; they only log matches.</p><button type="button" className="btn btn-primary shrink-0" onClick={() => open(fresh())}>Add guardrail</button></div>
    {error && !draft && <p role="alert" className="text-sm text-red-600">{error}</p>}
    {loading ? <p className="text-sm text-gray-500">Loading guardrails…</p> : rows.length ? <div className="overflow-x-auto"><table className="table w-full text-sm"><thead><tr><th>Name</th><th>Applies to</th><th>Checks</th><th>Looks for</th><th>Action</th><th>On</th><th /></tr></thead><tbody>{rows.map(rail => <tr key={rail.guardrail_id}>
      <td className="font-medium">{rail.name}</td>
      <td>{appliesTo(rail.applies_to.apis, rail.applies_to.groups)}</td>
      <td>{DIRECTION_LABELS[rail.direction] || rail.direction}</td>
      <td className="max-w-xs">{detectorSummary(rail)}</td>
      <td>{rail.action === 'redact' ? 'Redact' : rail.action === 'block' ? 'Block' : rail.action}{rail.mode === 'dry_run' && <span className="block text-xs text-gray-500">Dry run</span>}</td>
      <td><input type="checkbox" aria-label={`Turn ${rail.name} ${rail.enabled ? 'off' : 'on'}`} checked={rail.enabled} disabled={working} onChange={() => toggle(rail)} /></td>
      <td><div className="flex gap-2"><button type="button" className="btn btn-ghost" onClick={() => open(toDraft(rail))}>Edit</button><button type="button" className="btn btn-ghost" onClick={() => setRemoving(rail)}>Delete</button></div></td>
    </tr>)}</tbody></table></div> : <p className="text-sm text-gray-500">No guardrails yet.</p>}

    {draft && <div className="fixed inset-0 bg-black/50 z-[60] flex justify-end"><form role="dialog" aria-modal="true" aria-label={draft.guardrail_id ? 'Edit AI guardrail' : 'Create AI guardrail'} onSubmit={save} className="bg-white dark:bg-gray-900 w-full max-w-xl h-full overflow-y-auto p-6 space-y-4">
      <h3 className="text-lg font-semibold">{draft.guardrail_id ? 'Edit guardrail' : 'Add guardrail'}</h3>
      <label className="block text-sm">Name<input className="input w-full mt-1" required value={draft.name} onChange={e => update({ name: e.target.value })} /></label>
      <label className="block text-sm">Applies to APIs<input className="input w-full mt-1" list="ai-guardrail-apis" value={draft.apis} onChange={e => update({ apis: e.target.value })} /><span className="text-xs text-gray-500">Comma-separated <code>name/version</code>, or <code>*</code> for all AI APIs.</span></label>
      <datalist id="ai-guardrail-apis">{apiOptions.map(api => <option key={api} value={api} />)}</datalist>
      <label className="block text-sm">Applies to groups<input className="input w-full mt-1" value={draft.groups} onChange={e => update({ groups: e.target.value })} /><span className="text-xs text-gray-500">Comma-separated group names, or <code>*</code> for everyone.</span></label>
      <label className="block text-sm">Direction<select className="input w-full mt-1" value={draft.direction} onChange={e => update({ direction: e.target.value as Draft['direction'] })}><option value="input">Input (prompts)</option><option value="output">Output (responses)</option><option value="both">Both</option></select></label>
      {draft.direction !== 'input' && <p className="text-xs text-gray-500">Output checks are log-only on streaming requests.</p>}
      <fieldset className="text-sm space-y-1"><legend className="mb-1">Built-in detectors</legend>{BUILTINS.map(([id, label]) => <label key={id} className="flex gap-2"><input type="checkbox" checked={draft.builtins.includes(id)} onChange={e => update({ builtins: e.target.checked ? [...draft.builtins, id] : draft.builtins.filter(b => b !== id) })} />{label}</label>)}</fieldset>
      <fieldset className="text-sm space-y-2"><legend className="mb-1">Regex patterns</legend>
        {draft.regexes.map((pattern, index) => <div key={index} className="flex gap-2"><input className="input w-full font-mono" aria-label={`Regex ${index + 1}`} value={pattern} onChange={e => update({ regexes: draft.regexes.map((p, i) => i === index ? e.target.value : p) })} /><button type="button" className="btn btn-ghost" onClick={() => update({ regexes: draft.regexes.filter((_, i) => i !== index) })}>Remove</button></div>)}
        <button type="button" className="btn btn-secondary" onClick={() => update({ regexes: [...draft.regexes, ''] })}>Add regex</button>
        <p className="text-xs text-gray-500">Rust regex syntax, up to 1 KB each. Use <code>(?i)</code> for case-insensitive.</p>
      </fieldset>
      <label className="block text-sm">Keywords<textarea className="input w-full mt-1" rows={3} value={draft.keywords} onChange={e => update({ keywords: e.target.value })} /><span className="text-xs text-gray-500">One per line or comma-separated.</span></label>
      <label className="block text-sm">Action<select className="input w-full mt-1" value={draft.action} onChange={e => update({ action: e.target.value as Draft['action'] })}><option value="redact">Redact</option><option value="block">Block (AI005)</option><option value="log_only">Log only</option></select></label>
      <label className="block text-sm">Mode<select className="input w-full mt-1" value={draft.mode} onChange={e => update({ mode: e.target.value as Draft['mode'] })}><option value="enforce">Enforce</option><option value="dry_run">Dry run (record would-match only)</option></select></label>
      <label className="flex gap-2 text-sm"><input type="checkbox" checked={draft.enabled} onChange={e => update({ enabled: e.target.checked })} />Enabled</label>

      <div className="border-t pt-4 space-y-2"><h4 className="font-medium text-sm">Test</h4>
        <textarea className="input w-full" rows={4} aria-label="Sample text" placeholder="Paste sample prompt text" value={testText} onChange={e => setTestText(e.target.value)} />
        <div className="flex flex-wrap gap-2 items-center"><button type="button" className="btn btn-secondary" disabled={working || !testText} onClick={() => runTest(false)}>Test text</button>
          {hasPromptLogs && <><label className="text-sm flex items-center gap-1">Last<input type="number" className="input w-20" min={1} max={500} value={sampleN} onChange={e => setSampleN(Math.max(1, Math.min(500, Number(e.target.value) || 1)))} />prompts</label><button type="button" className="btn btn-secondary" disabled={working} onClick={() => runTest(true)}>Run on last N prompts</button></>}
        </div>
        {testResult && <div className="text-sm space-y-1"><p>{testResult.matches.length} match{testResult.matches.length === 1 ? '' : 'es'}{testResult.matches.length > 0 && `: ${[...new Set(testResult.matches.map(m => m.detector))].join(', ')}`}</p><pre className="whitespace-pre-wrap bg-gray-50 p-2 rounded text-xs">{testResult.redacted}</pre></div>}
        {sampleResult && <div className="text-sm"><p>Sampled {sampleResult.sampled} prompt{sampleResult.sampled === 1 ? '' : 's'}.</p>{Object.keys(sampleResult.counts).length ? <ul className="list-disc ml-5">{Object.entries(sampleResult.counts).map(([detector, count]) => <li key={detector}>{detector}: {count}</li>)}</ul> : <p className="text-gray-500">No matches.</p>}</div>}
      </div>

      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <div className="flex gap-2"><button type="submit" className="btn btn-primary" disabled={working}>Save guardrail</button><button type="button" className="btn btn-secondary" disabled={working} onClick={() => setDraft(null)}>Cancel</button></div>
    </form></div>}
    <ConfirmModal open={!!removing} title="Delete AI guardrail?" message={`Delete ${removing?.name || ''}? It will stop applying immediately.`} onConfirm={remove} onCancel={() => { if (!working) setRemoving(null) }} loading={working} confirmLabel="Delete guardrail" />
  </div>
}
