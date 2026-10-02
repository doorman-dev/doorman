'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import yaml from 'js-yaml'
import { SERVER_URL } from '@/utils/config'
import { postJson, getJson } from '@/utils/api'
import { fetchJson } from '@/utils/http'
import toast from 'react-hot-toast'
import ConfirmModal from '@/components/ConfirmModal'

interface ParsedEndpoint {
  id: string;
  method: string;
  path: string;
  description: string;
  selected: boolean;
  upstream_server: string;
  auth_required: boolean;
  client_uri: string;
  rate_limit: number;
}

export default function ImportSwaggerPage() {
  const router = useRouter()
  const [file, setFile] = useState<File | null>(null)
  const [parsing, setParsing] = useState(false)
  
  const [apiName, setApiName] = useState('')
  const [apiVersion, setApiVersion] = useState('v1')
  
  const [apiTargetMode, setApiTargetMode] = useState<'new' | 'existing'>('new')
  const [existingApis, setExistingApis] = useState<{api_name: string, api_version: string}[]>([])
  
  useEffect(() => {
    const fetchApis = async () => {
      try {
        const data = await getJson<any>(`${SERVER_URL}/platform/api/all?page=1&page_size=200`)
        const apisList = Array.isArray(data) ? data : (data.apis || data.response?.apis || [])
        setExistingApis(apisList.map((a: any) => ({ api_name: a.api_name || a.name, api_version: a.api_version || a.version })))
      } catch (err) {
        console.error('Failed to load APIs', err)
      }
    }
    fetchApis()
  }, [])
  
  const [endpoints, setEndpoints] = useState<ParsedEndpoint[]>([])
  
  // Bulk settings
  const [bulkServer, setBulkServer] = useState('')
  const [bulkAuth, setBulkAuth] = useState(false)
  const [bulkRateLimit, setBulkRateLimit] = useState(100)
  const [bulkPrefix, setBulkPrefix] = useState('')

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return
    const uploadedFile = e.target.files[0]
    setFile(uploadedFile)
    setParsing(true)
    
    try {
      const text = await uploadedFile.text()
      let spec: any
      if (uploadedFile.name.endsWith('.json')) {
        spec = JSON.parse(text)
      } else {
        spec = yaml.load(text)
      }
      
      if (spec?.info?.title) setApiName(spec.info.title.replace(/[^a-zA-Z0-9_-]/g, '-'))
      if (spec?.info?.version) setApiVersion(spec.info.version.replace(/[^a-zA-Z0-9._-]/g, '-'))
      
      const parsed: ParsedEndpoint[] = []
      if (spec.paths) {
        Object.keys(spec.paths).forEach(path => {
          const methods = spec.paths[path]
          Object.keys(methods).forEach(method => {
            if (['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method.toLowerCase())) {
              parsed.push({
                id: `${method.toUpperCase()}-${path}`,
                method: method.toUpperCase(),
                path,
                description: methods[method].summary || methods[method].description || '',
                selected: true,
                upstream_server: '',
                client_uri: path,
                auth_required: false,
                rate_limit: 100
              })
            }
          })
        })
      }
      setEndpoints(parsed)
    } catch (err: any) {
      toast.error('Failed to parse Swagger/OpenAPI file: ' + err.message)
    } finally {
      setParsing(false)
    }
  }
  
  const applyBulkSettings = () => {
    setEndpoints(prev => prev.map(ep => 
      ep.selected ? {
        ...ep,
        upstream_server: bulkServer || ep.upstream_server,
        auth_required: bulkAuth,
        rate_limit: bulkRateLimit,
        client_uri: bulkPrefix ? (bulkPrefix + ep.path).replace(/\/\//g, '/') : ep.client_uri
      } : ep
    ))
    toast.success('Bulk settings applied to selected endpoints')
  }

  const toggleEndpoint = (id: string) => {
    setEndpoints(prev => prev.map(ep => ep.id === id ? { ...ep, selected: !ep.selected } : ep))
  }
  
  const toggleAll = (select: boolean) => {
    setEndpoints(prev => prev.map(ep => ({ ...ep, selected: select })))
  }

  const [publishing, setPublishing] = useState(false)
  const [showAppendModal, setShowAppendModal] = useState(false)
  
  const createEndpoints = async () => {
    setPublishing(true)
    setShowAppendModal(false)
    const selectedEndpoints = endpoints.filter(e => e.selected)
    try {
      // 2. Create endpoints
      for (const ep of selectedEndpoints) {
        const epPayload = {
          api_name: apiName,
          api_version: apiVersion,
          endpoint_method: ep.method,
          endpoint_uri: ep.path,
          client_uri: ep.client_uri !== ep.path ? ep.client_uri : undefined,
          auth_required: ep.auth_required,
          rate_limit: ep.rate_limit,
          endpoint_servers: ep.upstream_server ? ep.upstream_server.split(',').map(s=>s.trim()).filter(Boolean) : []
        }
        await postJson(`${SERVER_URL}/platform/endpoint`, epPayload)
      }
      
      toast.success(`Published ${selectedEndpoints.length} endpoints successfully!`)
      router.push(`/apis/${apiName}:${apiVersion}`)
      
    } catch (err: any) {
      toast.error(err.message)
    } finally {
      setPublishing(false)
    }
  }

  const publish = async () => {
    if (!apiName || !apiVersion || (apiTargetMode === 'existing' && !existingApis.some(a => a.api_name === apiName && a.api_version === apiVersion))) {
      toast.error('Valid API Name and Version are required')
      return
    }
    
    const selectedEndpoints = endpoints.filter(e => e.selected)
    if (selectedEndpoints.length === 0) {
      toast.error('No endpoints selected to publish')
      return
    }

    setPublishing(true)
    try {
      if (apiTargetMode === 'new') {
        // 1. Create API
        const apiPayload = {
          api_name: apiName,
          api_version: apiVersion,
          api_description: `Imported via Swagger`,
          api_type: 'http',
          api_servers: bulkServer ? bulkServer.split(',').map(s=>s.trim()).filter(Boolean) : []
        }
        
        try {
          await postJson(`${SERVER_URL}/platform/api`, apiPayload)
        } catch (err: any) {
          if (err.message.includes('already exists')) {
            setShowAppendModal(true)
            setPublishing(false)
            return
          } else {
            throw new Error('Failed to create API: ' + err.message)
          }
        }
      }
      
      // If we are in 'existing' mode or API creation succeeded
      await createEndpoints()
    } catch (err: any) {
      toast.error(err.message)
      setPublishing(false)
    }
  }

  return (
    <Layout>
      <div className="page-header">
        <div>
          <h1 className="page-title">Swagger Import</h1>
          <p className="page-subtitle mt-2">Import an OpenAPI/Swagger spec to bulk-create Gateway routing rules.</p>
        </div>
      </div>

      <div className="bg-white border-2 border-gray-900 shadow-[4px_4px_0px_0px_rgba(15,23,42,1)] p-6 mb-8">
        <h2 className="text-lg font-bold text-gray-900 mb-4 uppercase tracking-wider">1. Upload Spec</h2>
        <input 
          type="file" 
          accept=".json,.yaml,.yml" 
          onChange={handleFileUpload}
          className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:border-2 file:border-gray-900 file:text-sm file:font-bold file:bg-gray-100 hover:file:bg-gray-200 cursor-pointer"
        />
      </div>

      {endpoints.length > 0 && (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
          
          <div className="bg-white border-2 border-gray-900 shadow-[4px_4px_0px_0px_rgba(15,23,42,1)] p-0 overflow-hidden">
            <div className="p-4 border-b-2 border-gray-900 bg-gray-50">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold text-gray-900 uppercase tracking-wider">3. Review Endpoints ({endpoints.filter(e=>e.selected).length} selected)</h2>
                <div className="space-x-4">
                  <button onClick={() => toggleAll(true)} className="text-sm font-bold text-gray-600 hover:text-gray-900 uppercase transition-colors">Select All</button>
                  <button onClick={() => toggleAll(false)} className="text-sm font-bold text-gray-600 hover:text-gray-900 uppercase transition-colors">Deselect All</button>
                </div>
              </div>
              
              <div className="bg-gray-200 border-2 border-gray-900 p-3 flex flex-wrap gap-4 items-end">
                <div className="flex-1 min-w-[200px]">
                  <label className="block text-xs font-bold uppercase text-gray-600 mb-1">Servers (comma separated)</label>
                  <input type="text" placeholder="http://api1, http://api2" value={bulkServer} onChange={e => setBulkServer(e.target.value)} className="w-full border-2 border-gray-900 p-1.5 text-sm" />
                </div>
                <div className="w-48">
                  <label className="block text-xs font-bold uppercase text-gray-600 mb-1">Path Prefix</label>
                  <input type="text" placeholder="/api/v1" value={bulkPrefix} onChange={e => setBulkPrefix(e.target.value)} className="w-full border-2 border-gray-900 p-1.5 text-sm" />
                </div>
                <div className="w-24">
                  <label className="block text-xs font-bold uppercase text-gray-600 mb-1">Rate Limit</label>
                  <input type="number" value={bulkRateLimit} onChange={e => setBulkRateLimit(parseInt(e.target.value) || 0)} className="w-full border-2 border-gray-900 p-1.5 text-sm" />
                </div>
                <div className="flex items-center gap-2 pb-2">
                  <input type="checkbox" checked={bulkAuth} onChange={e => setBulkAuth(e.target.checked)} className="w-4 h-4 cursor-pointer border-2 border-gray-900" />
                  <span className="text-sm font-bold uppercase text-gray-700">Auth</span>
                </div>
                <button onClick={applyBulkSettings} className="px-4 py-1.5 bg-gray-900 text-white font-bold uppercase text-xs hover:bg-gray-800 transition-colors">
                  Bulk Apply
                </button>
              </div>
            </div>
            
            <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
              <table className="w-full text-left border-collapse">
                <thead className="bg-gray-100 border-b-2 border-gray-900 sticky top-0 z-10">
                  <tr>
                    <th className="p-3 w-10"></th>
                    <th className="p-3 text-xs font-bold uppercase text-gray-600 whitespace-nowrap">Method</th>
                    <th className="p-3 text-xs font-bold uppercase text-gray-600 whitespace-nowrap">Backend Path</th>
                    <th className="p-3 text-xs font-bold uppercase text-gray-600 whitespace-nowrap">New Path (optional)</th>
                    <th className="p-3 text-xs font-bold uppercase text-gray-600 whitespace-nowrap">Servers</th>
                    <th className="p-3 text-xs font-bold uppercase text-gray-600 whitespace-nowrap">Config</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((ep, idx) => (
                    <tr key={ep.id} className="border-b border-gray-200 hover:bg-gray-50 transition-colors">
                      <td className="p-3 text-center align-middle">
                        <input type="checkbox" checked={ep.selected} onChange={() => toggleEndpoint(ep.id)} className="w-4 h-4 cursor-pointer" />
                      </td>
                      <td className="p-3 align-middle">
                        <span className={`inline-block px-2 py-1 text-[10px] font-bold uppercase border-2 border-gray-900 ${ep.method === 'GET' ? 'bg-[#38bdf8] text-gray-900' : ep.method === 'POST' ? 'bg-[#a3e635] text-gray-900' : ep.method === 'DELETE' ? 'bg-[#fb7185] text-gray-900' : ep.method === 'PUT' ? 'bg-[#fbbf24] text-gray-900' : 'bg-gray-200 text-gray-900'}`}>
                          {ep.method}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-sm align-middle truncate max-w-[200px]" title={ep.path}>{ep.path}</td>
                      <td className="p-3 align-middle">
                        <input type="text" value={ep.client_uri} onChange={e => {
                          const val = e.target.value
                          setEndpoints(prev => prev.map(p => p.id === ep.id ? {...p, client_uri: val} : p))
                        }} className="w-full p-1 border-2 border-gray-900 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#38bdf8]" />
                      </td>
                      <td className="p-3 align-middle">
                        <input type="text" value={ep.upstream_server} onChange={e => {
                          const val = e.target.value
                          setEndpoints(prev => prev.map(p => p.id === ep.id ? {...p, upstream_server: val} : p))
                        }} placeholder="Inherit from API (comma separate for multiple)" className="w-full p-1 border-2 border-gray-900 text-sm focus:outline-none focus:ring-2 focus:ring-[#38bdf8]" />
                      </td>
                      <td className="p-3 text-xs align-middle">
                        <div className="flex items-center gap-3">
                          <label className="flex items-center gap-1 cursor-pointer font-bold uppercase text-gray-600">
                            <input type="checkbox" checked={ep.auth_required} onChange={e => {
                              const val = e.target.checked
                              setEndpoints(prev => prev.map(p => p.id === ep.id ? {...p, auth_required: val} : p))
                            }} className="cursor-pointer" /> Auth
                          </label>
                          <div className="flex items-center gap-1">
                            <input type="number" value={ep.rate_limit} onChange={e => {
                                const val = parseInt(e.target.value) || 0
                                setEndpoints(prev => prev.map(p => p.id === ep.id ? {...p, rate_limit: val} : p))
                            }} className="w-16 p-1 border-2 border-gray-900 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-[#a3e635]" title="Rate Limit" />
                            <span className="font-bold uppercase text-[10px] text-gray-500">req/m</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          
          <div className="flex justify-end pt-4 pb-12">
            <button 
              onClick={publish} 
              disabled={publishing || endpoints.filter(e=>e.selected).length === 0}
              className="px-8 py-3 bg-[#a3e635] text-gray-900 font-bold uppercase tracking-wider border-2 border-gray-900 shadow-[4px_4px_0px_0px_rgba(15,23,42,1)] hover:translate-y-1 hover:shadow-[2px_2px_0px_0px_rgba(15,23,42,1)] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {publishing ? 'Publishing...' : 'Publish Gateway Rules'}
            </button>
          </div>
        </div>
      )}
          <ConfirmModal
        open={showAppendModal}
        title="API Already Exists"
        message={
          <div>
            <p className="mb-2">The API <code className="font-mono bg-gray-100 px-1">{apiName} ({apiVersion})</code> already exists in Doorman.</p>
            <p>Do you want to append these endpoints to the existing API?</p>
          </div>
        }
        confirmLabel="Append Endpoints"
        onConfirm={createEndpoints}
        onCancel={() => setShowAppendModal(false)}
      />
    </Layout>

  )
}
