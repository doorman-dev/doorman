'use client'

import React from 'react'
import Layout from '@/components/Layout'
import { ProtectedRoute } from '@/components/ProtectedRoute'

/** Page frame for the AI Gateway section. */
export default function AiPage({ title, description, permission, actions, children }: { title: string; description: string; permission?: string; actions?: React.ReactNode; children: React.ReactNode }) {
  return <ProtectedRoute requiredPermission={permission}><Layout><div className="space-y-6">
    <div className="page-header flex flex-wrap items-end justify-between gap-3">
      <div><h1 className="page-title">{title}</h1><p className="text-gray-600 mt-1">{description}</p></div>
      {actions}
    </div>
    {children}
  </div></Layout></ProtectedRoute>
}
