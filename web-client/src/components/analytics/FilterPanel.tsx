'use client'

import React, { useState } from 'react'
import DateRangePicker from './DateRangePicker'

interface FilterPanelProps {
  // Available options
  availableAPIs: string[]
  availableUsers: string[]
  
  // Current selections
  selectedAPIs: string[]
  selectedUsers: string[]
  selectedStatusCodes: string[]
  selectedMethods: string[]
  searchQuery: string
  startDate: string
  endDate: string
  
  // Callbacks
  onAPIsChange: (apis: string[]) => void
  onUsersChange: (users: string[]) => void
  onStatusCodesChange: (codes: string[]) => void
  onMethodsChange: (methods: string[]) => void
  onSearchChange: (query: string) => void
  onStartDateChange: (date: string) => void
  onEndDateChange: (date: string) => void
  onApplyFilters: () => void
  onClearFilters: () => void
  onSaveView?: () => void
  aiMode?: boolean
  aiControls?: React.ReactNode
}

const STATUS_CODE_OPTIONS = [
  { label: '2xx Success', value: '2xx' },
  { label: '4xx Client Error', value: '4xx' },
  { label: '5xx Server Error', value: '5xx' }
]

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

export default function FilterPanel({
  availableAPIs,
  availableUsers,
  selectedAPIs,
  selectedUsers,
  selectedStatusCodes,
  selectedMethods,
  searchQuery,
  startDate,
  endDate,
  onAPIsChange,
  onUsersChange,
  onStatusCodesChange,
  onMethodsChange,
  onSearchChange,
  onStartDateChange,
  onEndDateChange,
  onApplyFilters,
  onClearFilters,
  onSaveView,
  aiMode = false,
  aiControls,
}: FilterPanelProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [apiDropdownOpen, setApiDropdownOpen] = useState(false)
  const [userDropdownOpen, setUserDropdownOpen] = useState(false)

  if (aiMode) return <div className="card p-4 space-y-3"><h3 className="text-lg font-semibold">AI usage filters</h3><div className="grid md:grid-cols-3 gap-4 items-end">{aiControls}<div><p className="text-sm mb-2">Date range (UTC days)</p><DateRangePicker startDate={startDate} endDate={endDate} onStartDateChange={onStartDateChange} onEndDateChange={onEndDateChange} onApply={onApplyFilters} onClear={onClearFilters} /></div></div><button type="button" className="btn btn-secondary btn-sm" onClick={onClearFilters}>Clear filters</button></div>

  // Multi-select handlers
  const toggleAPI = (api: string) => {
    if (selectedAPIs.includes(api)) {
      onAPIsChange(selectedAPIs.filter(a => a !== api))
    } else {
      onAPIsChange([...selectedAPIs, api])
    }
  }

  const toggleUser = (user: string) => {
    if (selectedUsers.includes(user)) {
      onUsersChange(selectedUsers.filter(u => u !== user))
    } else {
      onUsersChange([...selectedUsers, user])
    }
  }

  const toggleStatusCode = (code: string) => {
    if (selectedStatusCodes.includes(code)) {
      onStatusCodesChange(selectedStatusCodes.filter(c => c !== code))
    } else {
      onStatusCodesChange([...selectedStatusCodes, code])
    }
  }

  const toggleMethod = (method: string) => {
    if (selectedMethods.includes(method)) {
      onMethodsChange(selectedMethods.filter(m => m !== method))
    } else {
      onMethodsChange([...selectedMethods, method])
    }
  }

  const hasActiveFilters = 
    selectedAPIs.length > 0 ||
    selectedUsers.length > 0 ||
    selectedStatusCodes.length > 0 ||
    selectedMethods.length > 0 ||
    searchQuery.length > 0 ||
    (startDate && endDate)

  return (
    <div className="card">
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center gap-2 text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
            >
              <svg className={`h-5 w-5 transition-transform ${isExpanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
              <h3 className="text-lg font-semibold">Filters & Search</h3>
            </button>
            {hasActiveFilters && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/20 dark:text-primary-400">
                Active
              </span>
            )}
          </div>
          
          <div className="flex items-center gap-2">
            {onSaveView && (
              <button
                onClick={onSaveView}
                className="btn btn-outline btn-sm"
                disabled
              >
                <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z" />
                </svg>
                Save View
              </button>
            )}
            {hasActiveFilters && (
              <button
                onClick={onClearFilters}
                className="btn btn-outline btn-sm text-error-600 hover:bg-error-50 dark:hover:bg-error-900/20"
              >
                Clear All
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Filter Content */}
      {isExpanded && (
        <div className="p-4 space-y-4">
          {/* Search Bar */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Search
            </label>
            <div className="relative">
              <input
                type="text"
                placeholder="Search by API name, endpoint, or user..."
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                className="input pl-10 w-full"
              />
              <svg className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* API Selector */}
            <div className="relative">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                APIs
              </label>
              <button
                onClick={() => setApiDropdownOpen(!apiDropdownOpen)}
                className="w-full flex items-center justify-between px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  {selectedAPIs.length > 0 ? `${selectedAPIs.length} selected` : 'All APIs'}
                </span>
                <svg className="h-4 w-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {apiDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setApiDropdownOpen(false)} />
                  <div className="absolute z-20 mt-2 w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 max-h-60 overflow-y-auto">
                    {availableAPIs.length > 0 ? (
                      availableAPIs.map((api) => (
                        <label
                          key={api}
                          className="flex items-center px-4 py-2 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={selectedAPIs.includes(api)}
                            onChange={() => toggleAPI(api)}
                            className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="ml-3 text-sm text-gray-700 dark:text-gray-300 font-mono">
                            {api}
                          </span>
                        </label>
                      ))
                    ) : (
                      <div className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                        No APIs available
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* User Selector */}
            <div className="relative">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Users
              </label>
              <button
                onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                className="w-full flex items-center justify-between px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  {selectedUsers.length > 0 ? `${selectedUsers.length} selected` : 'All Users'}
                </span>
                <svg className="h-4 w-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {userDropdownOpen && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setUserDropdownOpen(false)} />
                  <div className="absolute z-20 mt-2 w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 max-h-60 overflow-y-auto">
                    {availableUsers.length > 0 ? (
                      availableUsers.map((user) => (
                        <label
                          key={user}
                          className="flex items-center px-4 py-2 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={selectedUsers.includes(user)}
                            onChange={() => toggleUser(user)}
                            className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="ml-3 text-sm text-gray-700 dark:text-gray-300">
                            {user}
                          </span>
                        </label>
                      ))
                    ) : (
                      <div className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                        No users available
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Date Range Picker */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Date Range
              </label>
              <DateRangePicker
                startDate={startDate}
                endDate={endDate}
                onStartDateChange={onStartDateChange}
                onEndDateChange={onEndDateChange}
                onApply={onApplyFilters}
                onClear={() => {
                  onStartDateChange('')
                  onEndDateChange('')
                }}
              />
            </div>
          </div>

          {/* Status Codes & Methods */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Status Codes */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Status Codes
              </label>
              <div className="flex flex-wrap gap-2">
                {STATUS_CODE_OPTIONS.map((option) => (
                  <button
                    key={option.value}
                    onClick={() => toggleStatusCode(option.value)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      selectedStatusCodes.includes(option.value)
                        ? 'bg-gray-950 text-white'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                    }`}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Methods */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                HTTP Methods
              </label>
              <div className="flex flex-wrap gap-2">
                {METHOD_OPTIONS.map((method) => (
                  <button
                    key={method}
                    onClick={() => toggleMethod(method)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      selectedMethods.includes(method)
                        ? 'bg-gray-950 text-white'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                    }`}
                  >
                    {method}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Apply Button */}
          <div className="flex items-center justify-end pt-4 border-t border-gray-200 dark:border-gray-700">
            <button
              onClick={onApplyFilters}
              className="btn btn-primary"
            >
              <svg className="h-4 w-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
              </svg>
              Apply Filters
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
