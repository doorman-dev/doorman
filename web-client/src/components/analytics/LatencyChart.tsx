'use client'

import React from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts'

interface LatencyDataPoint {
  timestamp: number
  percentiles: {
    p50: number
    p75: number
    p90: number
    p95: number
    p99: number
  }
}

interface LatencyChartProps {
  data: LatencyDataPoint[]
  title?: string
  showGrid?: boolean
  height?: number
}

export default function LatencyChart({
  data,
  title = 'Latency Percentiles Over Time',
  showGrid = true,
  height = 300
}: LatencyChartProps) {
  // Transform data for chart
  const chartData = data.map(point => ({
    timestamp: point.timestamp,
    p50: point.percentiles.p50,
    p75: point.percentiles.p75,
    p90: point.percentiles.p90,
    p95: point.percentiles.p95,
    p99: point.percentiles.p99
  }))

  // Format timestamp for display
  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp * 1000)
    const hours = date.getHours().toString().padStart(2, '0')
    const minutes = date.getMinutes().toString().padStart(2, '0')
    return `${hours}:${minutes}`
  }

  // Format latency value
  const formatLatency = (value: number): string => {
    return `${value.toFixed(1)}ms`
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
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              <span className="font-medium">{entry.name}:</span> {formatLatency(entry.value)}
            </p>
          ))}
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
        <LineChart
          data={chartData}
          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
        >
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
            tickFormatter={formatLatency}
            stroke="#6e6e78"
            className="dark:stroke-gray-500"
            style={{ fontSize: '12px' }}
          />
          
          <Tooltip content={<CustomTooltip />} />
          
          <Legend
            wrapperStyle={{ fontSize: '14px' }}
            iconType="line"
          />
          
          {/* p50 - Green */}
          <Line
            type="monotone"
            dataKey="p50"
            stroke="#10b981"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6 }}
            name="p50 (Median)"
          />
          
          {/* p75 - Blue */}
          <Line
            type="monotone"
            dataKey="p75"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6 }}
            name="p75"
          />
          
          {/* p90 - Yellow */}
          <Line
            type="monotone"
            dataKey="p90"
            stroke="#f59e0b"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6 }}
            name="p90"
          />
          
          {/* p95 - Orange */}
          <Line
            type="monotone"
            dataKey="p95"
            stroke="#f97316"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6 }}
            name="p95"
          />
          
          {/* p99 - Red */}
          <Line
            type="monotone"
            dataKey="p99"
            stroke="#ef4444"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6 }}
            name="p99"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
