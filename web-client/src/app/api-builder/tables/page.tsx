'use client'

import React, { useCallback, useEffect, useMemo, useState } from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { SERVER_URL } from '@/utils/config'
import { delJson, getJson, postJson, putJson } from '@/utils/api'

interface ApiRef {
  api_name: string
  api_version: string
}

interface Table {
  table_name?: string
  collection_name: string
  row_count: number
  api_refs: ApiRef[]
  schema: Record<string, any>
  fields?: string[]
  source?: 'table_registry' | 'api_legacy'
}

interface TableRowsResponse {
  collection_name: string
  table_name?: string
  items: Record<string, any>[]
  page: number
  page_size: number
  has_next: boolean
  total?: number
}

interface QueryFilter {
  id: string
  field: string
  op: string
  value: string
}

interface QueryDraft {
  search: string
  logic: 'and' | 'or'
  sort_by: string
  sort_order: 'asc' | 'desc'
  filters: QueryFilter[]
}

interface QueryPayload {
  search: string
  logic: 'and' | 'or'
  sort_by: string
  sort_order: 'asc' | 'desc'
  filters: Array<{ field: string, op: string, value: any }>
}

interface SchemaField {
  name: string
  type: 'string' | 'number' | 'boolean' | 'array' | 'object'
  required: boolean
  min_length?: number
  max_length?: number
  min_value?: number
  max_value?: number
  pattern?: string
  enum?: string
  properties?: SchemaField[]
}

const newFilter = (): QueryFilter => ({
  id: `${Date.now()}-${Math.random()}`,
  field: '',
  op: 'eq',
  value: '',
})

const defaultQueryDraft = (): QueryDraft => ({
  search: '',
  logic: 'and',
  sort_by: '_id',
  sort_order: 'asc',
  filters: [newFilter()],
})

const formatCell = (value: any): string => {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

const normalizeSchemaType = (rawType: any): SchemaField['type'] => {
  if (rawType === 'string' || rawType === 'number' || rawType === 'boolean' || rawType === 'array' || rawType === 'object') {
    return rawType
  }
  return 'string'
}

const convertFromBackendSchema = (schema: Record<string, any>): SchemaField[] => {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return []

  return Object.entries(schema).map(([fieldName, rawRules]) => {
    const rules = rawRules && typeof rawRules === 'object' && !Array.isArray(rawRules)
      ? rawRules
      : {}

    const field: SchemaField = {
      name: fieldName,
      type: normalizeSchemaType(rules.type),
      required: Boolean(rules.required),
    }

    if (typeof rules.min_length === 'number') field.min_length = rules.min_length
    if (typeof rules.max_length === 'number') field.max_length = rules.max_length
    if (typeof rules.min_value === 'number') field.min_value = rules.min_value
    if (typeof rules.max_value === 'number') field.max_value = rules.max_value
    if (typeof rules.pattern === 'string') field.pattern = rules.pattern

    if (Array.isArray(rules.enum)) {
      field.enum = rules.enum.map((value: any) => String(value)).join(', ')
    } else if (typeof rules.enum === 'string') {
      field.enum = rules.enum
    }

    if (field.type === 'object' && rules.properties && typeof rules.properties === 'object' && !Array.isArray(rules.properties)) {
      field.properties = convertFromBackendSchema(rules.properties)
    }

    return field
  })
}

const convertToBackendSchema = (fields: SchemaField[]): Record<string, any> => {
  const schemaDict: Record<string, any> = {}
  fields.forEach((field) => {
    const rules: any = {
      type: field.type,
      required: field.required,
    }

    if (field.min_length !== undefined) rules.min_length = field.min_length
    if (field.max_length !== undefined) rules.max_length = field.max_length
    if (field.min_value !== undefined) rules.min_value = field.min_value
    if (field.max_value !== undefined) rules.max_value = field.max_value
    if (field.pattern) rules.pattern = field.pattern
    if (field.enum) rules.enum = field.enum.split(',').map((value) => value.trim()).filter(Boolean)

    if (field.type === 'object' && field.properties && field.properties.length > 0) {
      rules.properties = convertToBackendSchema(field.properties)
    }

    schemaDict[field.name] = rules
  })

  return schemaDict
}

const buildPreviewObject = (fields: SchemaField[]): Record<string, any> => {
  const next: Record<string, any> = {}

  fields.forEach((field) => {
    if (field.type === 'string') next[field.name] = 'example'
    if (field.type === 'number') next[field.name] = 123
    if (field.type === 'boolean') next[field.name] = true
    if (field.type === 'array') next[field.name] = []
    if (field.type === 'object') next[field.name] = buildPreviewObject(field.properties || [])
  })

  return next
}

const generateJsonPreview = (fields: SchemaField[]) => {
  return JSON.stringify(buildPreviewObject(fields), null, 2)
}

const FieldEditor = ({
  fields,
  onChange,
  level = 0,
}: {
  fields: SchemaField[]
  onChange: (fields: SchemaField[]) => void
  level?: number
}) => {
  const [editingIndex, setEditingIndex] = useState<number | null>(null)
  const [newField, setNewField] = useState<SchemaField>({
    name: '',
    type: 'string',
    required: false,
  })

  const handleAddField = () => {
    if (!newField.name.trim()) return
    onChange([...fields, { ...newField, name: newField.name.trim() }])
    setNewField({ name: '', type: 'string', required: false })
    setEditingIndex(null)
  }

  const handleRemoveField = (index: number) => {
    onChange(fields.filter((_, i) => i !== index))
  }

  const handleUpdateField = (index: number, updated: SchemaField) => {
    const next = [...fields]
    next[index] = updated
    onChange(next)
  }

  return (
    <div className={`space-y-4 ${level > 0 ? 'ml-4 border-l-2 border-gray-200 dark:border-gray-700 pl-4' : ''}`}>
      {fields.map((field, index) => (
        <div key={`${field.name}:${index}`} className="group">
          <div className="flex items-center gap-3 p-2 rounded hover:bg-gray-50 dark:hover:bg-white/5 border border-transparent hover:border-gray-200 dark:hover:border-gray-700">
            <span className="font-mono text-sm font-medium">{field.name}</span>
            <span
              className={`px-2 py-0.5 rounded text-xs ${
                field.type === 'string'
                  ? 'bg-blue-100 text-blue-800'
                  : field.type === 'number'
                    ? 'bg-green-100 text-green-800'
                    : field.type === 'object'
                      ? 'bg-purple-100 text-purple-800'
                      : 'bg-gray-100 text-gray-800'
              }`}
            >
              {field.type}
            </span>
            {field.required && <span className="text-xs text-error-600 font-medium">Req</span>}

            <div className="flex-1" />

            <button
              onClick={() => handleRemoveField(index)}
              className="opacity-0 group-hover:opacity-100 text-error-600 hover:text-error-800 text-xs px-2"
            >
              Delete
            </button>
          </div>

          {field.type === 'object' && (
            <div className="mt-2 text-sm">
              <div className="text-gray-500 mb-2 text-xs uppercase tracking-wide font-semibold pl-2">
                Properties of {field.name}:
              </div>
              <FieldEditor
                fields={field.properties || []}
                onChange={(newProperties) => handleUpdateField(index, { ...field, properties: newProperties })}
                level={level + 1}
              />
            </div>
          )}
        </div>
      ))}

      {editingIndex === -1 ? (
        <div className="card p-3 bg-gray-50 dark:bg-gray-800/50 border border-dashed border-gray-300 dark:border-gray-700">
          <div className="flex gap-2 mb-2">
            <input
              placeholder="Field Name"
              className="input input-sm flex-1"
              value={newField.name}
              onChange={(event) => setNewField((previous) => ({ ...previous, name: event.target.value }))}
              autoFocus
            />
            <select
              className="input input-sm w-32"
              value={newField.type}
              onChange={(event) => setNewField((previous) => ({ ...previous, type: event.target.value as SchemaField['type'] }))}
            >
              <option value="string">String</option>
              <option value="number">Number</option>
              <option value="boolean">Boolean</option>
              <option value="array">Array</option>
              <option value="object">Object</option>
            </select>
          </div>

          <div className="flex items-center gap-4 mb-2 flex-wrap">
            <label className="flex items-center gap-2 text-xs cursor-pointer select-none">
              <input
                type="checkbox"
                checked={newField.required}
                onChange={(event) => setNewField((previous) => ({ ...previous, required: event.target.checked }))}
              />
              Required
            </label>

            {newField.type === 'string' && (
              <>
                <input
                  placeholder="Min Len"
                  type="number"
                  className="input input-sm w-20"
                  value={newField.min_length || ''}
                  onChange={(event) => setNewField((previous) => ({ ...previous, min_length: parseInt(event.target.value, 10) || undefined }))}
                />
                <input
                  placeholder="Max Len"
                  type="number"
                  className="input input-sm w-20"
                  value={newField.max_length || ''}
                  onChange={(event) => setNewField((previous) => ({ ...previous, max_length: parseInt(event.target.value, 10) || undefined }))}
                />
              </>
            )}

            {newField.type === 'number' && (
              <>
                <input
                  placeholder="Min Val"
                  type="number"
                  className="input input-sm w-20"
                  value={newField.min_value || ''}
                  onChange={(event) => setNewField((previous) => ({ ...previous, min_value: parseInt(event.target.value, 10) || undefined }))}
                />
                <input
                  placeholder="Max Val"
                  type="number"
                  className="input input-sm w-20"
                  value={newField.max_value || ''}
                  onChange={(event) => setNewField((previous) => ({ ...previous, max_value: parseInt(event.target.value, 10) || undefined }))}
                />
              </>
            )}
          </div>

          <div className="flex justify-end gap-2">
            <button onClick={() => setEditingIndex(null)} className="btn btn-xs btn-ghost">
              Cancel
            </button>
            <button onClick={handleAddField} className="btn btn-xs btn-primary" disabled={!newField.name.trim()}>
              Add Field
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setEditingIndex(-1)}
          className="flex items-center gap-2 text-sm text-gray-500 hover:text-primary-600 transition-colors py-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add {level > 0 ? 'Nested ' : ''}Field
        </button>
      )}
    </div>
  )
}

const SchemaSummary = ({ fields, level = 0 }: { fields: SchemaField[], level?: number }) => {
  return (
    <div className={`space-y-2 ${level > 0 ? 'ml-3 pl-3 border-l border-gray-200 dark:border-gray-700' : ''}`}>
      {fields.map((field, index) => (
        <div key={`${field.name}:${level}:${index}`}>
          <div className="flex items-center gap-2 text-sm">
            <span className="font-mono text-gray-900 dark:text-gray-100">{field.name}</span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300">
              {field.type}
            </span>
            {field.required && <span className="text-[10px] text-error-600 uppercase">required</span>}
          </div>
          {field.type === 'object' && field.properties && field.properties.length > 0 && (
            <SchemaSummary fields={field.properties} level={level + 1} />
          )}
        </div>
      ))}
    </div>
  )
}

const TablesPage = () => {
  const [loadingTables, setLoadingTables] = useState(true)
  const [loadingRows, setLoadingRows] = useState(false)
  const [creating, setCreating] = useState(false)
  const [savingEdit, setSavingEdit] = useState(false)
  const [deletingTable, setDeletingTable] = useState(false)

  const [error, setError] = useState<string | null>(null)
  const [createError, setCreateError] = useState<string | null>(null)
  const [createSuccess, setCreateSuccess] = useState<string | null>(null)

  const [tables, setTables] = useState<Table[]>([])
  const [selectedCollection, setSelectedCollection] = useState<string>('')
  const [rows, setRows] = useState<TableRowsResponse | null>(null)
  const [rowPage, setRowPage] = useState(1)
  const rowPageSize = 20

  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState({
    table_name: '',
    collection_name: '',
  })
  const [createFields, setCreateFields] = useState<SchemaField[]>([])

  const [queryDraft, setQueryDraft] = useState<QueryDraft>(defaultQueryDraft)
  const [appliedQuery, setAppliedQuery] = useState<QueryPayload | null>(null)

  const [isEditOpen, setIsEditOpen] = useState(false)
  const [editTableName, setEditTableName] = useState('')
  const [editFields, setEditFields] = useState<SchemaField[]>([])

  const selectedTable = useMemo(
    () => tables.find((table) => table.collection_name === selectedCollection) || null,
    [tables, selectedCollection]
  )

  const tableSchemaFields = useMemo(() => {
    return convertFromBackendSchema(selectedTable?.schema || {})
  }, [selectedTable])

  const rowColumns = useMemo(() => {
    const preferred = selectedTable?.fields && selectedTable.fields.length > 0
      ? selectedTable.fields
      : Object.keys(selectedTable?.schema || {})

    const keys = new Set<string>(['_id', ...preferred])
    for (const item of rows?.items || []) {
      Object.keys(item || {}).forEach((key) => keys.add(key))
    }

    return Array.from(keys)
  }, [selectedTable, rows])

  const fetchTables = useCallback(async () => {
    try {
      setLoadingTables(true)
      setError(null)
      const data = await getJson<{ tables?: Table[] }>(`${SERVER_URL}/platform/api-builder/tables`)
      const nextTables = data?.tables || []
      setTables(nextTables)

      if (nextTables.length === 0) {
        setSelectedCollection('')
        setRows(null)
        return
      }

      setSelectedCollection((previous) => (
        previous && nextTables.some((table) => table.collection_name === previous)
          ? previous
          : nextTables[0].collection_name
      ))
    } catch (requestError: any) {
      setError(requestError?.message || 'Failed to load tables')
      setTables([])
      setRows(null)
    } finally {
      setLoadingTables(false)
    }
  }, [])

  const fetchRows = async (collection: string, page: number, query: QueryPayload | null) => {
    if (!collection) {
      setRows(null)
      return
    }

    try {
      setLoadingRows(true)
      setError(null)

      if (query) {
        const data = await postJson<TableRowsResponse>(
          `${SERVER_URL}/platform/api-builder/tables/${encodeURIComponent(collection)}/query`,
          {
            ...query,
            page,
            page_size: rowPageSize,
          }
        )
        setRows(data)
      } else {
        const data = await getJson<TableRowsResponse>(
          `${SERVER_URL}/platform/api-builder/tables/${encodeURIComponent(collection)}?page=${page}&page_size=${rowPageSize}`
        )
        setRows(data)
      }
    } catch (requestError: any) {
      setError(requestError?.message || 'Failed to load table rows')
      setRows(null)
    } finally {
      setLoadingRows(false)
    }
  }

  const openCreateDialog = () => {
    setCreateError(null)
    setCreateForm({ table_name: '', collection_name: '' })
    setCreateFields([])
    setIsCreateOpen(true)
  }

  const handleCreateTable = async () => {
    setCreateError(null)
    setCreateSuccess(null)

    const name = createForm.table_name.trim()
    if (!name) {
      setCreateError('Table name is required.')
      return
    }

    try {
      setCreating(true)
      const schema = convertToBackendSchema(createFields)
      const result = await postJson<{ table?: Table }>(`${SERVER_URL}/platform/api-builder/tables`, {
        table_name: name,
        collection_name: createForm.collection_name.trim() || undefined,
        schema,
      })

      const createdCollection = result?.table?.collection_name
      setCreateSuccess('Table created successfully.')
      setCreateForm({ table_name: '', collection_name: '' })
      setCreateFields([])
      setIsCreateOpen(false)
      await fetchTables()
      if (createdCollection) setSelectedCollection(createdCollection)
    } catch (requestError: any) {
      setCreateError(requestError?.message || 'Failed to create table')
    } finally {
      setCreating(false)
    }
  }

  const handleApplyQuery = () => {
    const filters = (queryDraft.filters || [])
      .map((filter) => ({ ...filter, field: filter.field.trim(), op: filter.op.trim(), value: filter.value }))
      .filter((filter) => filter.field && (filter.op === 'exists' || String(filter.value || '').trim() !== ''))
      .map((filter) => ({ field: filter.field, op: filter.op, value: filter.value }))

    const nextQuery: QueryPayload = {
      search: queryDraft.search.trim(),
      logic: queryDraft.logic,
      sort_by: (queryDraft.sort_by || '_id').trim(),
      sort_order: queryDraft.sort_order,
      filters,
    }

    setAppliedQuery(nextQuery)
    setRowPage(1)
  }

  const handleClearQuery = () => {
    setQueryDraft(defaultQueryDraft())
    setAppliedQuery(null)
    setRowPage(1)
  }

  const addFilterRow = () => {
    setQueryDraft((previous) => ({ ...previous, filters: [...previous.filters, newFilter()] }))
  }

  const removeFilterRow = (id: string) => {
    setQueryDraft((previous) => {
      const next = previous.filters.filter((filter) => filter.id !== id)
      return { ...previous, filters: next.length > 0 ? next : [newFilter()] }
    })
  }

  const updateFilterRow = (id: string, patch: Partial<QueryFilter>) => {
    setQueryDraft((previous) => ({
      ...previous,
      filters: previous.filters.map((filter) => (filter.id === id ? { ...filter, ...patch } : filter)),
    }))
  }

  const openEditDialog = () => {
    if (!selectedTable || selectedTable.source !== 'table_registry') return
    setCreateError(null)
    setEditTableName(selectedTable.table_name || selectedTable.collection_name)
    setEditFields(convertFromBackendSchema(selectedTable.schema || {}))
    setIsEditOpen(true)
  }

  const handleSaveEdit = async () => {
    if (!selectedTable) return

    const nextTableName = editTableName.trim()
    if (!nextTableName) {
      setCreateError('Table name is required.')
      return
    }

    try {
      setSavingEdit(true)
      setError(null)
      setCreateError(null)
      setCreateSuccess(null)

      await putJson(`${SERVER_URL}/platform/api-builder/tables/${encodeURIComponent(selectedTable.collection_name)}`, {
        table_name: nextTableName,
        schema: convertToBackendSchema(editFields),
      })

      setCreateSuccess('Table updated successfully.')
      setIsEditOpen(false)
      await fetchTables()
    } catch (requestError: any) {
      setCreateError(requestError?.message || 'Failed to update table')
    } finally {
      setSavingEdit(false)
    }
  }

  const handleDeleteTable = async () => {
    if (!selectedTable || selectedTable.source !== 'table_registry') return

    const tableLabel = selectedTable.table_name || selectedTable.collection_name
    const hasBindings = (selectedTable.api_refs || []).length > 0

    if (hasBindings) {
      const forceOk = window.confirm(
        `Table "${tableLabel}" is attached to API definitions. Continue deleting the table definition anyway?`
      )
      if (!forceOk) return
    } else {
      const proceed = window.confirm(`Delete table "${tableLabel}"?`)
      if (!proceed) return
    }

    const dropData = window.confirm('Also delete all records from the underlying collection? Click OK to purge data, Cancel to keep data.')

    try {
      setDeletingTable(true)
      setError(null)
      await delJson(`${SERVER_URL}/platform/api-builder/tables/${encodeURIComponent(selectedTable.collection_name)}`, {
        drop_data: dropData,
        force: hasBindings,
      })

      setCreateSuccess('Table deleted successfully.')
      await fetchTables()
    } catch (requestError: any) {
      setError(requestError?.message || 'Failed to delete table')
    } finally {
      setDeletingTable(false)
    }
  }

  useEffect(() => {
    fetchTables()
  }, [fetchTables])

  useEffect(() => {
    setRowPage(1)
    setAppliedQuery(null)
    setQueryDraft(defaultQueryDraft())
  }, [selectedCollection])

  useEffect(() => {
    if (selectedCollection) {
      fetchRows(selectedCollection, rowPage, appliedQuery)
    }
  }, [selectedCollection, rowPage, appliedQuery])

  const filterFieldOptions = useMemo(() => {
    return rowColumns.length > 0 ? rowColumns : ['_id']
  }, [rowColumns])

  return (
    <ProtectedRoute requiredPermission="view_builder_tables">
      <Layout>
        <div className="space-y-6">
          <div className="page-header">
            <div>
              <h1 className="page-title">Tables</h1>
              <p className="text-gray-600 dark:text-gray-400 mt-1">
                Firebase-style table explorer with schema editing, record querying, and table lifecycle controls.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button className="btn btn-secondary" onClick={fetchTables} disabled={loadingTables}>
                {loadingTables ? 'Refreshing...' : 'Refresh'}
              </button>
              <button className="btn btn-primary" onClick={openCreateDialog}>
                Create Table
              </button>
            </div>
          </div>

          {(error || createError || createSuccess) && (
            <div className="space-y-3">
              {error && (
                <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
                  <p className="text-sm text-error-700 dark:text-error-300">{error}</p>
                </div>
              )}
              {createError && (
                <div className="rounded-lg bg-error-50 border border-error-200 p-4 dark:bg-error-900/20 dark:border-error-800">
                  <p className="text-sm text-error-700 dark:text-error-300">{createError}</p>
                </div>
              )}
              {createSuccess && (
                <div className="rounded-lg bg-success-50 border border-success-200 p-4 dark:bg-success-900/20 dark:border-success-800">
                  <p className="text-sm text-success-700 dark:text-success-300">{createSuccess}</p>
                </div>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 xl:grid-cols-[320px_1fr] gap-6">
            <div className="card p-0 overflow-hidden h-fit">
              <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                <h3 className="font-medium text-gray-900 dark:text-white">Tables</h3>
              </div>
              <div className="p-2 max-h-[70vh] overflow-auto">
                {loadingTables ? (
                  <p className="text-sm text-gray-500 p-3">Loading tables...</p>
                ) : tables.length === 0 ? (
                  <p className="text-sm text-gray-500 p-3">No tables found.</p>
                ) : (
                  <div className="space-y-1">
                    {tables.map((table) => (
                      <button
                        key={table.collection_name}
                        onClick={() => setSelectedCollection(table.collection_name)}
                        className={`w-full text-left rounded-md px-3 py-2 border transition-colors ${
                          selectedCollection === table.collection_name
                            ? 'bg-primary-50 border-primary-200 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300 dark:border-primary-700/40'
                            : 'border-transparent hover:bg-gray-50 dark:hover:bg-white/5 text-gray-700 dark:text-gray-300'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm font-medium truncate">{table.table_name || table.collection_name}</p>
                            <p className="font-mono text-xs opacity-80 truncate">{table.collection_name}</p>
                            <p className="text-xs opacity-80">{table.row_count} rows</p>
                          </div>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded ${
                              table.source === 'table_registry' ? 'bg-success-100 text-success-800' : 'bg-warning-100 text-warning-800'
                            }`}
                          >
                            {table.source === 'table_registry' ? 'registry' : 'legacy'}
                          </span>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="card p-0 overflow-hidden">
              <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-start justify-between gap-3">
                <div>
                  <h3 className="font-medium text-gray-900 dark:text-white">
                    {selectedTable?.table_name || selectedCollection || 'Select a table'}
                  </h3>
                  {selectedTable && (
                    <p className="text-xs text-gray-500 mt-1">
                      Collection: <span className="font-mono">{selectedTable.collection_name}</span>
                      {selectedTable.source === 'api_legacy' && <span className="ml-2">(discovered from legacy API)</span>}
                    </p>
                  )}
                </div>

                {selectedTable && (
                  <div className="flex items-center gap-2">
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={openEditDialog}
                      disabled={selectedTable.source !== 'table_registry'}
                      title={selectedTable.source !== 'table_registry' ? 'Legacy-discovered tables are read-only here' : 'Edit table'}
                    >
                      Edit
                    </button>
                    <button
                      className="btn btn-error-outline btn-sm"
                      onClick={handleDeleteTable}
                      disabled={deletingTable || selectedTable.source !== 'table_registry'}
                      title={selectedTable.source !== 'table_registry' ? 'Legacy-discovered tables are read-only here' : 'Delete table'}
                    >
                      {deletingTable ? 'Deleting...' : 'Delete'}
                    </button>
                  </div>
                )}
              </div>

              <div className="p-4 space-y-4">
                {selectedTable ? (
                  <>
                    <div className="rounded border border-gray-200 dark:border-gray-700 p-3">
                      <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-3">Schema</h4>
                      {tableSchemaFields.length === 0 ? (
                        <p className="text-xs text-gray-500">No fields defined yet. Add fields when you edit this table.</p>
                      ) : (
                        <SchemaSummary fields={tableSchemaFields} />
                      )}
                      {selectedTable.api_refs?.length > 0 && (
                        <p className="text-xs text-gray-500 mt-3">
                          APIs: {selectedTable.api_refs.map((ref) => `${ref.api_name}/${ref.api_version}`).join(', ')}
                        </p>
                      )}
                    </div>

                    <div className="rounded border border-gray-200 dark:border-gray-700 p-3">
                      <div className="flex items-center justify-between gap-3 mb-3">
                        <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200">Query Records</h4>
                        <div className="flex items-center gap-2">
                          <button className="btn btn-secondary btn-sm" onClick={handleClearQuery}>Clear</button>
                          <button className="btn btn-primary btn-sm" onClick={handleApplyQuery}>Apply Query</button>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
                        <div>
                          <label className="label">Search</label>
                          <input
                            className="input input-sm"
                            placeholder="Full-text in row JSON"
                            value={queryDraft.search}
                            onChange={(event) => setQueryDraft((previous) => ({ ...previous, search: event.target.value }))}
                          />
                        </div>
                        <div className="grid grid-cols-3 gap-2">
                          <div className="col-span-1">
                            <label className="label">Logic</label>
                            <select
                              className="input input-sm"
                              value={queryDraft.logic}
                              onChange={(event) => setQueryDraft((previous) => ({ ...previous, logic: event.target.value as 'and' | 'or' }))}
                            >
                              <option value="and">AND</option>
                              <option value="or">OR</option>
                            </select>
                          </div>
                          <div className="col-span-1">
                            <label className="label">Sort</label>
                            <select
                              className="input input-sm"
                              value={queryDraft.sort_by}
                              onChange={(event) => setQueryDraft((previous) => ({ ...previous, sort_by: event.target.value }))}
                            >
                              {filterFieldOptions.map((field) => (
                                <option key={field} value={field}>{field}</option>
                              ))}
                            </select>
                          </div>
                          <div className="col-span-1">
                            <label className="label">Order</label>
                            <select
                              className="input input-sm"
                              value={queryDraft.sort_order}
                              onChange={(event) => setQueryDraft((previous) => ({ ...previous, sort_order: event.target.value as 'asc' | 'desc' }))}
                            >
                              <option value="asc">ASC</option>
                              <option value="desc">DESC</option>
                            </select>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-2">
                        {queryDraft.filters.map((filter) => (
                          <div key={filter.id} className="grid grid-cols-12 gap-2 items-center">
                            <select
                              className="input input-sm col-span-4"
                              value={filter.field}
                              onChange={(event) => updateFilterRow(filter.id, { field: event.target.value })}
                            >
                              <option value="">Field</option>
                              {filterFieldOptions.map((field) => (
                                <option key={field} value={field}>{field}</option>
                              ))}
                            </select>
                            <select
                              className="input input-sm col-span-3"
                              value={filter.op}
                              onChange={(event) => updateFilterRow(filter.id, { op: event.target.value })}
                            >
                              <option value="eq">equals</option>
                              <option value="ne">not equals</option>
                              <option value="contains">contains</option>
                              <option value="starts_with">starts_with</option>
                              <option value="ends_with">ends_with</option>
                              <option value="gt">&gt;</option>
                              <option value="gte">&gt;=</option>
                              <option value="lt">&lt;</option>
                              <option value="lte">&lt;=</option>
                              <option value="in">in</option>
                              <option value="nin">not in</option>
                              <option value="exists">exists</option>
                            </select>
                            <input
                              className="input input-sm col-span-4"
                              placeholder={filter.op === 'exists' ? 'true/false' : 'Value'}
                              value={filter.value}
                              onChange={(event) => updateFilterRow(filter.id, { value: event.target.value })}
                            />
                            <button className="btn btn-ghost btn-sm col-span-1" onClick={() => removeFilterRow(filter.id)}>×</button>
                          </div>
                        ))}
                        <button className="btn btn-ghost btn-sm" onClick={addFilterRow}>+ Add Filter</button>
                      </div>
                    </div>

                    <div className="rounded border border-gray-200 dark:border-gray-700 overflow-hidden">
                      <div className="px-3 py-2 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                        <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200">Records</h4>
                        {rows && (
                          <div className="flex items-center gap-2">
                            <button
                              className="btn btn-ghost btn-sm"
                              disabled={loadingRows || rowPage <= 1}
                              onClick={() => setRowPage((previous) => Math.max(1, previous - 1))}
                            >
                              Prev
                            </button>
                            <span className="text-xs text-gray-500">Page {rowPage}</span>
                            <button
                              className="btn btn-ghost btn-sm"
                              disabled={loadingRows || !rows.has_next}
                              onClick={() => setRowPage((previous) => previous + 1)}
                            >
                              Next
                            </button>
                          </div>
                        )}
                      </div>

                      {loadingRows ? (
                        <p className="text-sm text-gray-500 p-3">Loading rows...</p>
                      ) : !rows || rows.items.length === 0 ? (
                        <p className="text-sm text-gray-500 p-3">No rows found for this table.</p>
                      ) : (
                        <div className="overflow-auto max-h-[46vh]">
                          <table className="table w-full text-xs">
                            <thead>
                              <tr>
                                {rowColumns.map((column) => (
                                  <th key={column} className="whitespace-nowrap">{column}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody>
                              {rows.items.map((item, index) => (
                                <tr key={`${item._id || index}`}>
                                  {rowColumns.map((column) => (
                                    <td key={`${item._id || index}:${column}`} className="align-top">
                                      <div className="max-w-[320px] truncate" title={formatCell(item?.[column])}>
                                        {formatCell(item?.[column])}
                                      </div>
                                    </td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-gray-500">Select a table to view schema and rows.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      </Layout>

      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <div className="w-full max-w-5xl rounded-lg bg-white dark:bg-dark-surface border border-gray-200 dark:border-gray-700 shadow-xl max-h-[92vh] overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Create Table</h3>
                <p className="text-xs text-gray-500 mt-0.5">Schema is optional. You can add fields later.</p>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => setIsCreateOpen(false)} disabled={creating}>Close</button>
            </div>

            <div className="p-4 space-y-4 overflow-auto max-h-[calc(92vh-70px)]">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="label">Table Name *</label>
                  <input
                    className="input"
                    placeholder="e.g. Customer Records"
                    value={createForm.table_name}
                    onChange={(event) => setCreateForm((previous) => ({ ...previous, table_name: event.target.value }))}
                    disabled={creating}
                  />
                </div>
                <div>
                  <label className="label">Collection Name (optional)</label>
                  <input
                    className="input"
                    placeholder="e.g. crud_data_customers"
                    value={createForm.collection_name}
                    onChange={(event) => setCreateForm((previous) => ({ ...previous, collection_name: event.target.value }))}
                    disabled={creating}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6">
                <div>
                  <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-2">Schema</h4>
                  <FieldEditor fields={createFields} onChange={setCreateFields} />
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-2">API Preview</h4>
                  <pre className="bg-gray-50 border border-gray-200 text-gray-800 rounded p-3 text-xs overflow-auto max-h-80">
                    {generateJsonPreview(createFields)}
                  </pre>
                </div>
              </div>

              <div className="flex justify-end gap-2">
                <button className="btn btn-secondary" onClick={() => setIsCreateOpen(false)} disabled={creating}>Cancel</button>
                <button className="btn btn-primary" onClick={handleCreateTable} disabled={creating}>
                  {creating ? 'Creating...' : 'Create Table'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isEditOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <div className="w-full max-w-5xl rounded-lg bg-white dark:bg-dark-surface border border-gray-200 dark:border-gray-700 shadow-xl max-h-[92vh] overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Edit Table</h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setIsEditOpen(false)} disabled={savingEdit}>Close</button>
            </div>

            <div className="p-4 space-y-4 overflow-auto max-h-[calc(92vh-70px)]">
              <div>
                <label className="label">Table Name</label>
                <input className="input" value={editTableName} onChange={(event) => setEditTableName(event.target.value)} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6">
                <div>
                  <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-2">Schema</h4>
                  <FieldEditor fields={editFields} onChange={setEditFields} />
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-2">API Preview</h4>
                  <pre className="bg-gray-50 border border-gray-200 text-gray-800 rounded p-3 text-xs overflow-auto max-h-80">
                    {generateJsonPreview(editFields)}
                  </pre>
                </div>
              </div>

              <div className="flex justify-end gap-2">
                <button className="btn btn-secondary" onClick={() => setIsEditOpen(false)} disabled={savingEdit}>Cancel</button>
                <button className="btn btn-primary" onClick={handleSaveEdit} disabled={savingEdit}>
                  {savingEdit ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </ProtectedRoute>
  )
}

export default TablesPage
