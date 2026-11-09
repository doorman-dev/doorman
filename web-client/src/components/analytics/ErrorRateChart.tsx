'use client'

import React from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine
} from 'recharts'

interface ErrorRateDataPoint {
  timestamp: number
  error_rate: number
  error_count: number
  count: number
}

interface ErrorRateChartProps {
  data: ErrorRateDataPoint[]
  title?: string
  threshold?: number
  showGrid?: boolean
  height?: number
}

export default function ErrorRateChart({
  data,
  title = 'Error Rate Over Time',
  threshold = 0.05, // 5% threshold
  showGrid = true,
  height = 300
}: ErrorRateChartProps) {
  // Format timestamp for display
  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp * 1000)
    const hours = date.getHours().toString().padStart(2, '0')
    const minutes = date.getMinutes().toString().padStart(2, '0')
    return `${hours}:${minutes}`
  }

  // Format error rate as percentage
  const formatErrorRate = (value: number): string => {
    return `${(value * 100).toFixed(2)}%`
  }

  // Custom tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      const date = new Date(data.timestamp * 1000)
      
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            {date.toLocaleString()}
          </p>
          <p className="text-sm text-error-600 dark:text-error-400">
            <span className="font-medium">Error Rate:</span> {formatErrorRate(data.error_rate)}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            <span className="font-medium">Errors:</span> {data.error_count} / {data.count}
          </p>
        </div>
      )
    }
    return null
  }

  return (
    <div className="w-full">
      {title && (
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          {title}
        </h3>
      )}
      
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart
          data={data}
          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
        >
          <defs>
            <linearGradient id="errorRateGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.1} />
            </linearGradient>
          </defs>
          
          {showGrid && (
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#232327"
              className="dark:stroke-gray-700"
            />
          )}
          
          <XAxis
            dataKey="timestamp"
            tickFormatter={formatTimestamp}
            stroke="#6e6e78"
            className="dark:stroke-gray-500"
            style={{ fontSize: '12px' }}
          />
          
          <YAxis
            tickFormatter={formatErrorRate}
            stroke="#6e6e78"
            className="dark:stroke-gray-500"
            style={{ fontSize: '12px' }}
          />
          
          <Tooltip content={<CustomTooltip />} />
          
          <Legend
            wrapperStyle={{ fontSize: '14px' }}
            iconType="rect"
          />
          
          {/* Threshold line */}
          {threshold && (
            <ReferenceLine
              y={threshold}
              stroke="#f59e0b"
              strokeDasharray="5 5"
              label={{
                value: `Threshold (${(threshold * 100).toFixed(0)}%)`,
                position: 'right',
                fill: '#f59e0b',
                fontSize: 12
              }}
            />
          )}
          
          <Area
            type="monotone"
            dataKey="error_rate"
            stroke="#ef4444"
            strokeWidth={2}
            fill="url(#errorRateGradient)"
            name="Error Rate"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
