'use client'

import React, { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import Layout from '@/components/Layout'
import { SERVER_URL } from '@/utils/config'
import { postJson, fetchAllPaginated, getJson } from '@/utils/api'
import SearchableSelect from '@/components/SearchableSelect'

interface TableOption {
  table_name?: string
  collection_name: string
  schema: Record<string, any>
  fields?: string[]
}

interface CrudBinding {
  resource_name: string
  collection_name: string
  table_name: string
  schema: Record<string, any>
  selected_fields: string[]
  field_mappings: Array<{
    field: string
    request_path: string
    response_path: string
  }>
}

const normalizeResourceName = (raw: string) => {
  const cleaned = (raw || '')
    .toLowerCase()
    .replace(/^crud_data_/, '')
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
  return cleaned || 'items'
}

const setJsonPathValue = (target: Record<string, any>, path: string, value: any) => {
  const parts = (path || '').split('.').filter(Boolean)
  if (parts.length === 0) return
  let current: Record<string, any> = target
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i]
    const isLast = i === parts.length - 1
    if (isLast) {
      current[part] = value
      return
    }
    const next = current[part]
    if (!next || typeof next !== 'object' || Array.isArray(next)) {
      current[part] = {}
    }
    current = current[part]
  }
}

const sampleValueForRules = (rules: any) => {
  const type = rules?.type
  if (type === 'number' || type === 'integer') return 123
  if (type === 'boolean') return true
  if (type === 'array') return []
  if (type === 'object') return {}
  return 'example'
}

const ApiBuilderPage = () => {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [loadingTables, setLoadingTables] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [tables, setTables] = useState<TableOption[]>([])
  const [selectedCollections, setSelectedCollections] = useState<string[]>([])
  const [selectedFieldsByCollection, setSelectedFieldsByCollection] = useState<Record<string, string[]>>({})
  const [fieldPathByCollection, setFieldPathByCollection] = useState<Record<string, Record<string, string>>>({})

  const [formData, setFormData] = useState({
    api_name: '',
    api_version: 'v1',
    api_type: 'REST',
    api_description: '',
    api_allowed_roles: [] as string[],
    api_allowed_groups: ['ALL'] as string[],
    active: true
  })

  const [newRole, setNewRole] = useState('')
  const [newGroup, setNewGroup] = useState('')

  const selectedTables = useMemo(
    () => selectedCollections.map(c => tables.find(t => t.collection_name === c)).filter(Boolean) as TableOption[],
    [selectedCollections, tables]
  )

  const resourceNameByCollection = useMemo(() => {
    const used = new Set<string>()
    const out: Record<string, string> = {}
    selectedTables.forEach((table) => {
      const base = normalizeResourceName(table.table_name || table.collection_name)
      let candidate = base
      let idx = 2
      while (used.has(candidate)) {
        candidate = `${base}_${idx}`
        idx += 1
      }
      used.add(candidate)
      out[table.collection_name] = candidate
    })
    return out
  }, [selectedTables])

  const apiPreview = useMemo(() => {
    const paths: Record<string, any> = {}

    selectedTables.forEach(table => {
      const selectedFields = selectedFieldsByCollection[table.collection_name] || []
      const resourceName = resourceNameByCollection[table.collection_name] || normalizeResourceName(table.table_name || table.collection_name)
      const fieldPaths = fieldPathByCollection[table.collection_name] || {}
      const requestExample: Record<string, any> = {}

      selectedFields.forEach((fieldName) => {
        const customPath = (fieldPaths[fieldName] || fieldName).trim()
        if (!customPath) return
        const rules = table.schema?.[fieldName]
        setJsonPathValue(requestExample, customPath, sampleValueForRules(rules))
      })

      const responseExample = { _id: '<id>', ...requestExample }
      const collectionPath = `/${resourceName}`
      const itemPath = `/${resourceName}/{id}`

      paths[collectionPath] = {
        'POST request': requestExample,
        'POST response': responseExample,
        'GET list response': { items: [responseExample] },
      }
      paths[itemPath] = {
        'GET response': responseExample,
        'PUT request': requestExample,
        'PUT response': responseExample,
      }
    })

    return {
      api: {
        name: formData.api_name || '<api_name>',
        version: formData.api_version || 'v1',
        type: formData.api_type,
      },
      paths,
    }
  }, [selectedTables, selectedFieldsByCollection, fieldPathByCollection, formData.api_name, formData.api_version, formData.api_type, resourceNameByCollection])

  const fetchRoles = async (): Promise<string[]> => {
    const items = await fetchAllPaginated<any>(
      (p, s) => `${SERVER_URL}/platform/role/all?page=${p}&page_size=${s}`,
      (data) => (Array.isArray(data) ? data : (data.roles || data.response?.roles || [])),
      undefined,
      undefined,
      'cache:roles:all'
    )
    return items.map((r: any) => r.role_name || r.name || r).filter(Boolean)
  }

  const fetchGroups = async (): Promise<string[]> => {
    const items = await fetchAllPaginated<any>(
      (p, s) => `${SERVER_URL}/platform/group/all?page=${p}&page_size=${s}`,
      (data) => (Array.isArray(data) ? data : (data.groups || data.response?.groups || [])),
      undefined,
      undefined,
      'cache:groups:all'
    )
    return items.map((g: any) => g.group_name || g.name || g).filter(Boolean)
  }

  const fetchTables = async () => {
    try {
      setLoadingTables(true)
      const data = await getJson<{ tables?: TableOption[] }>(`${SERVER_URL}/platform/api-builder/tables`)
      const nextTables = data?.tables || []
      setTables(nextTables)
    } catch (err: any) {
      setError(err?.message || 'Failed to load tables')
    } finally {
      setLoadingTables(false)
    }
  }

  useEffect(() => {
    fetchTables()
  }, [])

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? (e.target as HTMLInputElement).checked : value
    }))
  }

  const addRole = () => {
    const v = newRole.trim()
    if (!v) return
    if (formData.api_allowed_roles.includes(v)) return
    setFormData(prev => ({ ...prev, api_allowed_roles: [...prev.api_allowed_roles, v] }))
    setNewRole('')
  }

  const removeRole = (index: number) => {
    setFormData(prev => ({ ...prev, api_allowed_roles: prev.api_allowed_roles.filter((_, i) => i !== index) }))
  }

  const addGroup = () => {
    const v = newGroup.trim()
    if (!v) return
    if (formData.api_allowed_groups.includes(v)) return
    setFormData(prev => ({ ...prev, api_allowed_groups: [...prev.api_allowed_groups, v] }))
    setNewGroup('')
  }

  const removeGroup = (index: number) => {
    setFormData(prev => ({ ...prev, api_allowed_groups: prev.api_allowed_groups.filter((_, i) => i !== index) }))
  }

  const toggleTable = (table: TableOption) => {
    const collection = table.collection_name
    const fields = table.fields && table.fields.length > 0
      ? table.fields
      : Object.keys(table.schema || {})

    setSelectedCollections(prev => {
      if (prev.includes(collection)) {
        return prev.filter(c => c !== collection)
      }
      return [...prev, collection]
    })

    setSelectedFieldsByCollection(prev => {
      if (prev[collection]) return prev
      return { ...prev, [collection]: fields }
    })

    setFieldPathByCollection(prev => {
      if (prev[collection]) return prev
      const next: Record<string, string> = {}
      fields.forEach((field) => {
        next[field] = field
      })
      return { ...prev, [collection]: next }
    })
  }

  const toggleField = (collection: string, fieldName: string) => {
    setSelectedFieldsByCollection(prev => {
      const curr = prev[collection] || []
      if (curr.includes(fieldName)) {
        return { ...prev, [collection]: curr.filter(f => f !== fieldName) }
      }
      return { ...prev, [collection]: [...curr, fieldName] }
    })

    setFieldPathByCollection(prev => ({
      ...prev,
      [collection]: {
        ...(prev[collection] || {}),
        [fieldName]: (prev[collection]?.[fieldName] || fieldName),
      },
    }))
  }

  const selectAllFields = (collection: string, fields: string[]) => {
    setSelectedFieldsByCollection(prev => ({ ...prev, [collection]: fields }))
  }

  const clearFields = (collection: string) => {
    setSelectedFieldsByCollection(prev => ({ ...prev, [collection]: [] }))
  }

  const updateFieldPath = (collection: string, fieldName: string, value: string) => {
    setFieldPathByCollection(prev => ({
      ...prev,
      [collection]: {
        ...(prev[collection] || {}),
        [fieldName]: value,
      },
    }))
  }

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    setLoading(true)
    setError(null)

    if (selectedTables.length === 0) {
      setError('Select at least one table.')
      setLoading(false)
      return
    }

    try {
      const bindings: CrudBinding[] = selectedTables.map(table => {
        const availableFields = table.fields && table.fields.length > 0
          ? table.fields
          : Object.keys(table.schema || {})
        const selectedFields = selectedFieldsByCollection[table.collection_name] || []
        if (availableFields.length > 0 && selectedFields.length === 0) {
          throw new Error(`Select at least one field for ${(table.table_name || table.collection_name)}.`)
        }

        const selectedSchema = selectedFields.reduce((acc, fieldName) => {
          const rules = table.schema?.[fieldName]
          if (rules !== undefined) acc[fieldName] = rules
          return acc
        }, {} as Record<string, any>)

        const resourceName = resourceNameByCollection[table.collection_name] || normalizeResourceName(table.table_name || table.collection_name)
        const fieldPaths = fieldPathByCollection[table.collection_name] || {}
        const fieldMappings = selectedFields.map((fieldName) => {
          const customPath = (fieldPaths[fieldName] || fieldName).trim()
          if (!customPath) {
            throw new Error(`Field mapping path is required for ${fieldName} in ${(table.table_name || table.collection_name)}.`)
          }
          return {
            field: fieldName,
            request_path: customPath,
            response_path: customPath,
          }
        })

        return {
          resource_name: resourceName,
          collection_name: table.collection_name,
          table_name: table.table_name || table.collection_name,
          schema: selectedSchema,
          selected_fields: selectedFields,
          field_mappings: fieldMappings,
        }
      })

      const duplicateResource = bindings.find((b, idx) => bindings.findIndex(other => other.resource_name === b.resource_name) !== idx)
      if (duplicateResource) {
        throw new Error(`Duplicate resource path found: ${duplicateResource.resource_name}. Use unique resource names.`)
      }

      const primary = bindings[0]
      const apiPayload = {
        api_name: formData.api_name,
        api_version: formData.api_version,
        api_description: formData.api_description,
        api_type: formData.api_type,
        api_is_crud: true,
        api_crud_collection: primary.collection_name,
        api_crud_schema: primary.schema,
        api_crud_bindings: bindings.map(b => ({
          resource_name: b.resource_name,
          collection_name: b.collection_name,
          table_name: b.table_name,
          schema: b.schema,
          selected_fields: b.selected_fields,
          field_mappings: b.field_mappings,
        })),
        api_allowed_roles: formData.api_allowed_roles.length > 0 ? formData.api_allowed_roles : undefined,
        api_allowed_groups: formData.api_allowed_groups.length > 0 ? formData.api_allowed_groups : ['ALL'],
        api_servers: [],
        active: formData.active,
        api_auth_required: true
      }

      await postJson(`${SERVER_URL}/platform/api`, apiPayload)

      const endpoints = bindings.flatMap(binding => {
        const resource = `/${binding.resource_name}`
        const resourceId = `${resource}/{id}`
        const label = binding.table_name || binding.resource_name
        return [
          { method: 'GET', uri: resource, desc: `List all ${label}` },
          { method: 'POST', uri: resource, desc: `Create new ${label}` },
          { method: 'GET', uri: resourceId, desc: `Get single ${label} by ID` },
          { method: 'PUT', uri: resourceId, desc: `Update ${label} by ID` },
          { method: 'DELETE', uri: resourceId, desc: `Delete ${label} by ID` },
        ]
      })

      for (const ep of endpoints) {
        await postJson(`${SERVER_URL}/platform/endpoint`, {
          api_name: formData.api_name,
          api_version: formData.api_version,
          endpoint_method: ep.method,
          endpoint_uri: ep.uri,
          endpoint_description: ep.desc,
        })
      }

      router.push('/apis')
    } catch (err: any) {
      setError(err?.message || 'Failed to create API.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <div className="flex h-[calc(100vh-100px)] gap-6">
        {/* Main Content Area */}
        <div className="flex-1 flex flex-col space-y-6 overflow-hidden">
          <div className="flex items-center justify-between shrink-0">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">API Builder</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">Design your API schema and endpoints</p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <button
                onClick={handleSubmit}
                disabled={loading}
                className="btn btn-primary"
              >
                {loading ? (
                  <> <div className="spinner mr-2"></div> Publishing... </>
                ) : 'Publish API'}
              </button>
              <p className="builder-existing-api-note">Adding an existing API? <Link href="/apis">Go to the APIs page</Link>.</p>
            </div>
          </div>
        </div>

        {error && (
          <div className="rounded-lg bg-error-50 border border-error-200 p-4 text-error-700 dark:bg-error-900/20 dark:border-error-800 dark:text-error-300">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="card xl:col-span-2 p-6 space-y-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">API Settings</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="label">API Name *</label>
                <input name="api_name" className="input" placeholder="e.g. commerce-api" value={formData.api_name} onChange={handleChange} required />
              </div>
              <div>
                <label className="label">Version *</label>
                <input name="api_version" className="input" placeholder="v1" value={formData.api_version} onChange={handleChange} required />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="label">Protocol</label>
                <select name="api_type" className="input" value={formData.api_type} onChange={handleChange}>
                  <option value="REST">REST</option>
                  <option value="GRAPHQL">GraphQL</option>
                  <option value="SOAP">SOAP</option>
                  <option value="GRPC">gRPC</option>
                </select>
              </div>
              <div>
                <label className="label">Description</label>
                <input name="api_description" className="input" value={formData.api_description} onChange={handleChange} placeholder="Optional description" />
              </div>
            </div>

            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Table Bindings</h3>
              {loadingTables ? (
                <p className="text-sm text-gray-500">Loading tables...</p>
              ) : tables.length === 0 ? (
                <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4 bg-gray-50 dark:bg-white/5">
                  <p className="text-sm text-gray-600 dark:text-gray-300">No tables available yet. Create one on the Tables page first.</p>
                  <Link href="/api-builder/tables" className="btn btn-secondary btn-sm mt-3">Go To Tables</Link>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-auto border border-gray-200 dark:border-gray-700 rounded p-3">
                    {tables.map(table => {
                      const selected = selectedCollections.includes(table.collection_name)
                      return (
                        <label key={table.collection_name} className="flex items-center gap-2 text-sm cursor-pointer">
                          <input type="checkbox" checked={selected} onChange={() => toggleTable(table)} />
                          <span>{table.table_name || table.collection_name}</span>
                          <span className="font-mono text-xs text-gray-500">({table.collection_name})</span>
                        </label>
                      )
                    })}
                  </div>

                  {selectedTables.map(table => {
                    const availableFields = table.fields && table.fields.length > 0
                      ? table.fields
                      : Object.keys(table.schema || {})
                    const selectedFields = selectedFieldsByCollection[table.collection_name] || []
                    const resourceValue = resourceNameByCollection[table.collection_name] || normalizeResourceName(table.table_name || table.collection_name)
                    const fieldPaths = fieldPathByCollection[table.collection_name] || {}

                    return (
                      <div key={table.collection_name} className="rounded border border-gray-200 dark:border-gray-700 p-4 space-y-3">
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <p className="text-sm font-medium text-gray-900 dark:text-white">{table.table_name || table.collection_name}</p>
                            <p className="font-mono text-xs text-gray-500">{table.collection_name}</p>
                          </div>
                          <div className="text-right">
                            <p className="text-xs text-gray-500">Resource Path</p>
                            <p className="font-mono text-sm text-gray-700 dark:text-gray-200">/{resourceValue}</p>
                          </div>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <label className="label mb-0">Fields</label>
                            <div className="flex gap-2">
                              <button type="button" className="btn btn-ghost btn-sm" onClick={() => selectAllFields(table.collection_name, availableFields)}>Select All</button>
                              <button type="button" className="btn btn-ghost btn-sm" onClick={() => clearFields(table.collection_name)}>Clear</button>
                            </div>
                          </div>
                          {availableFields.length === 0 ? (
                            <p className="text-xs text-gray-500">No table-level schema defined. This binding will publish with an open schema.</p>
                          ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-auto border border-gray-200 dark:border-gray-700 rounded p-3">
                              {availableFields.map(fieldName => (
                                <label key={`${table.collection_name}:${fieldName}`} className="flex items-center gap-2 text-sm cursor-pointer">
                                  <input
                                    type="checkbox"
                                    checked={selectedFields.includes(fieldName)}
                                    onChange={() => toggleField(table.collection_name, fieldName)}
                                  />
                                  <span className="font-mono">{fieldName}</span>
                                </label>
                              ))}
                            </div>
                          )}
                        </div>

                        {selectedFields.length > 0 && (
                          <div>
                            <label className="label mb-2">JSON Path Mapping</label>
                            <div className="space-y-2 border border-gray-200 dark:border-gray-700 rounded p-3">
                              {selectedFields.map((fieldName) => (
                                <div key={`${table.collection_name}:map:${fieldName}`} className="grid grid-cols-1 md:grid-cols-[180px_1fr] gap-2 items-center">
                                  <span className="text-xs font-mono text-gray-600 dark:text-gray-300">{fieldName}</span>
                                  <input
                                    className="input input-sm font-mono"
                                    value={fieldPaths[fieldName] || fieldName}
                                    onChange={(e) => updateFieldPath(table.collection_name, fieldName, e.target.value)}
                                    placeholder="e.g. profile.customer.name"
                                  />
                                </div>
                              ))}
                            </div>
                            <p className="text-xs text-gray-500 mt-2">
                              Map each table field to any request/response JSON path.
                            </p>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Access Control</h3>
              <div>
                <label className="label">Allowed Roles</label>
                <SearchableSelect value={newRole} onChange={setNewRole} onAdd={addRole} onKeyPress={e => e.key === 'Enter' && addRole()} placeholder="Select role" fetchOptions={fetchRoles} addButtonText="Add" restrictToOptions />
                <div className="flex flex-wrap gap-2 mt-2">
                  {formData.api_allowed_roles.map((r, i) => (
                    <span key={i} className="badge badge-primary flex items-center gap-1">{r} <button onClick={() => removeRole(i)} className="hover:text-white">×</button></span>
                  ))}
                </div>
              </div>
              <div>
                <label className="label">Allowed Groups</label>
                <SearchableSelect value={newGroup} onChange={setNewGroup} onAdd={addGroup} onKeyPress={e => e.key === 'Enter' && addGroup()} placeholder="Select group" fetchOptions={fetchGroups} addButtonText="Add" restrictToOptions />
                <div className="flex flex-wrap gap-2 mt-2">
                  {formData.api_allowed_groups.map((g, i) => (
                    <span key={i} className="badge badge-success flex items-center gap-1">{g} <button onClick={() => removeGroup(i)} className="hover:text-white">×</button></span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="card p-4 h-fit">
            <h3 className="font-medium mb-2 text-sm">API Preview</h3>
            <pre className="bg-gray-50 border border-gray-200 text-gray-800 p-3 rounded text-xs overflow-auto max-h-[500px]">
              {JSON.stringify(apiPreview, null, 2)}
            </pre>
            <p className="text-xs text-gray-500 mt-2">
              Generated endpoint payload shapes based on your field-to-JSON-path mapping.
            </p>
          </div>
        </div>
      </div>
    </Layout>
  )
}

export default ApiBuilderPage
