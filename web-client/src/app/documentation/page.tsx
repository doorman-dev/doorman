'use client'

import React from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import OpenApiViewer from '@/components/OpenApiViewer'
import { SERVER_URL } from '@/utils/config'

export default function DocumentationPage() {
  const openapiUrl = `${SERVER_URL}/platform/openapi.json`
  const swaggerUrl = `${SERVER_URL}/platform/docs`

  return (
    <ProtectedRoute>
      <Layout>
        <div className="space-y-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">API Reference</h1>
            </div>
            <div className="flex items-center gap-2">
              <a href="/docs/ai-gateway.md" target="_blank" rel="noreferrer" className="btn btn-outline">AI Gateway guide</a>
              <a href={openapiUrl} target="_blank" rel="noreferrer" className="btn btn-outline">OpenAPI JSON</a>
              <a href={swaggerUrl} target="_blank" rel="noreferrer" className="btn btn-secondary">Swagger UI</a>
            </div>
          </div>

          <div className="relative rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-dark-surface shadow-sm overflow-hidden p-4">
            <OpenApiViewer openapiUrl={openapiUrl} />
          </div>
        </div>
      </Layout>
    </ProtectedRoute>
  )
}
