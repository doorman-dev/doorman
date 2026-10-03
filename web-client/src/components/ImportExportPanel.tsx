'use client'

import React, { useState } from 'react'
import { SERVER_URL } from '@/utils/config'
import { postJson, delJson } from '@/utils/api'
import { fetchWithCsrf } from '@/utils/http'
import ConfirmModal from '@/components/ConfirmModal'
import { useToast } from '@/contexts/ToastContext'

export default function ImportExportPanel() {
  const toast = useToast()
  const [exportWorking, setExportWorking] = useState<string | null>(null)
  const [importWorking, setImportWorking] = useState(false)
  const [conflictQueue, setConflictQueue] = useState<{ api_name: string; api_version: string }[]>([])
  const [currentConflict, setCurrentConflict] = useState<{ api_name: string; api_version: string } | null>(null)
  const [pendingImport, setPendingImport] = useState<any>(null)
  const [showConflictModal, setShowConflictModal] = useState(false)

  const startExport = async (key: string, path: string) => {
    try {
      setExportWorking(key)
      const payload = await (await import('@/utils/http')).fetchJson<any>(`${SERVER_URL}${path}`)
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `doorman-${key}-export.json`
      a.click()
      URL.revokeObjectURL(a.href)
    } catch (e:any) {
      toast.error(e?.message || 'Export failed')
    } finally {
      setExportWorking(null)
    }
  }

  const onImportFile = async (file?: File | null) => {
    if (!file) return
    try {
      setImportWorking(true)
      const text = await file.text()
      const obj = JSON.parse(text)
      const apis: { api_name: string; api_version: string }[] = (obj?.apis || []).map((a:any) => ({ api_name: a.api_name, api_version: a.api_version }))
      const conflicts: { api_name: string; api_version: string }[] = []
      for (const a of apis) {
        try {
          const res = await fetchWithCsrf(`${SERVER_URL}/platform/api/${encodeURIComponent(a.api_name)}/${encodeURIComponent(a.api_version)}`)
          if (res.ok) conflicts.push(a)
        } catch {}
      }
      setPendingImport(obj)
      if (conflicts.length > 0) {
        setConflictQueue(conflicts)
        setCurrentConflict(conflicts[0])
        setShowConflictModal(true)
      } else {
        await postJson(`${SERVER_URL}/platform/config/import`, obj)
        toast.success('Import completed')
      }
    } catch (e:any) {
      toast.error(e?.message || 'Invalid import file')
    } finally {
      setImportWorking(false)
    }
  }

  const advanceConflict = async () => {
    const queue = [...conflictQueue]
    queue.shift()
    if (queue.length === 0) {
      setShowConflictModal(false)
      try {
        if (pendingImport) {
          await postJson(`${SERVER_URL}/platform/config/import`, pendingImport)
          toast.success('Import completed')
        }
      } catch (e:any) {
        toast.error(e?.message || 'Import failed')
      } finally {
        setPendingImport(null)
        setCurrentConflict(null)
        setConflictQueue([])
      }
      return
    }
    setConflictQueue(queue)
    setCurrentConflict(queue[0])
    setShowConflictModal(true)
  }

  return (
      <div className="space-y-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">Export</h3></div>
          <div className="p-6 space-y-3">
            <div className="flex flex-wrap gap-2">
              <button className="btn btn-secondary" disabled={!!exportWorking} onClick={() => startExport('all', '/platform/config/export/all')}>{exportWorking==='all'?'Exporting…':'Export All'}</button>
              <button className="btn btn-secondary" disabled={!!exportWorking} onClick={() => startExport('apis', '/platform/config/export/apis')}>{exportWorking==='apis'?'Exporting…':'Export APIs'}</button>
              <button className="btn btn-secondary" disabled={!!exportWorking} onClick={() => startExport('endpoints', '/platform/config/export/endpoints')}>{exportWorking==='endpoints'?'Exporting…':'Export Endpoints'}</button>
              <button className="btn btn-secondary" disabled={!!exportWorking} onClick={() => startExport('roles', '/platform/config/export/roles')}>{exportWorking==='roles'?'Exporting…':'Export Roles'}</button>
              <button className="btn btn-secondary" disabled={!!exportWorking} onClick={() => startExport('groups', '/platform/config/export/groups')}>{exportWorking==='groups'?'Exporting…':'Export Groups'}</button>
              <button className="btn btn-secondary" disabled={!!exportWorking} onClick={() => startExport('routings', '/platform/config/export/routings')}>{exportWorking==='routings'?'Exporting…':'Export Routings'}</button>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400">Exports never include passwords, tokens, or secrets.</p>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h3 className="card-title">Import</h3></div>
          <div className="p-6 space-y-3">
            <input className="signal-file-picker" type="file" accept="application/json,.json" onChange={(e)=> onImportFile(e.target.files?.[0])} />
            <p className="text-xs text-gray-500 dark:text-gray-400">Upload a JSON containing any of: apis, endpoints, roles, groups, routings. Conflicting APIs will prompt you to keep system or replace with your upload.</p>
          </div>
        </div>

        <ConfirmModal
          open={showConflictModal}
          title="API Conflict Detected"
          message={<div>
            <p className="mb-2">API already exists: <code className="font-mono">{currentConflict?.api_name}/{currentConflict?.api_version}</code></p>
            <p className="text-sm">Choose which version to keep:</p>
            <ul className="list-disc ml-6 mt-2 text-sm">
              <li><b>Keep System</b>: keep the existing API; skip this API from import.</li>
              <li><b>Use Upload</b>: permanently delete the existing API, then import the uploaded version.</li>
            </ul>
          </div>}
          confirmLabel="Use Upload (Delete System)"
          cancelLabel="Keep System"
          onCancel={async () => {
            if (!currentConflict || !pendingImport) { setShowConflictModal(false); return }
            const { api_name, api_version } = currentConflict
            const next = { ...pendingImport, apis: (pendingImport.apis || []).filter((a:any) => !(a.api_name === api_name && a.api_version === api_version)) }
            setPendingImport(next)
            advanceConflict()
          }}
          onConfirm={async () => {
            try {
              if (currentConflict) {
                await delJson(`${SERVER_URL}/platform/api/${encodeURIComponent(currentConflict.api_name)}/${encodeURIComponent(currentConflict.api_version)}`)
              }
            } catch (e:any) {
              toast.error(e?.message || 'Failed to delete existing API')
            } finally {
              advanceConflict()
            }
          }}
        />
      </div>
  )
}
