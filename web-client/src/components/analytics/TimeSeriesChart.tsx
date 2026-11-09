'use client'

import React from 'react'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts'

interface TimeSeriesDataPoint {
  timestamp: number
  count: number
  error_count?: number
  avg_ms?: number
}

interface TimeSeriesChartProps {
  data: TimeSeriesDataPoint[]
  title?: string
  dataKey?: string
  color?: string
  showGrid?: boolean
  height?: number
  series?: { key: string; label: string; color: string }[]
  stacked?: boolean
  valueFormatter?: (value: number) => string
  timestampFormatter?: (timestamp: number) => string
}

export default function TimeSeriesChart({
  data,
  title = 'Request Volume Over Time',
  dataKey = 'count',
  color = '#3b82f6',
  showGrid = true,
  height = 300,
  series,
  stacked = false,
  valueFormatter,
  timestampFormatter,
}: TimeSeriesChartProps) {
  const Chart = stacked ? AreaChart : LineChart
  // Format timestamp for display
  const formatTimestamp = (timestamp: number): string => {
    if (timestampFormatter) return timestampFormatter(timestamp)
    const date = new Date(timestamp * 1000)
    const hours = date.getHours().toString().padStart(2, '0')
    const minutes = date.getMinutes().toString().padStart(2, '0')
    return `${hours}:${minutes}`
  }

  // Format value for display
  const formatValue = (value: number): string => {
    if (valueFormatter) return valueFormatter(value)
    if (dataKey === 'avg_ms') {
      return `${value.toFixed(1)}ms`
    }
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K`
    return value.toString()
  }

  // Custom tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      const date = new Date(data.timestamp * 1000)
      
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
            {timestampFormatter ? timestampFormatter(data.timestamp) : date.toLocaleString()}
          </p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              <span className="font-medium">{entry.name}:</span> {formatValue(entry.value)}
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
        <Chart
          data={data}
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
            tickFormatter={formatValue}
            stroke="#6e6e78"
            className="dark:stroke-gray-500"
            style={{ fontSize: '12px' }}
          />
          
          <Tooltip content={<CustomTooltip />} />
          
          <Legend
            wrapperStyle={{ fontSize: '14px' }}
            iconType="line"
          />
          
          {series ? series.map(item => stacked ? <Area key={item.key} type="monotone" dataKey={item.key} name={item.label} stackId="spend" stroke={item.color} fill={item.color} fillOpacity={0.6} /> : <Line key={item.key} type="monotone" dataKey={item.key} name={item.label} stroke={item.color} strokeWidth={2} dot={false} />) : <Line
            type="monotone"
            dataKey={dataKey}
            stroke={color}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 6 }}
            name={dataKey === 'count' ? 'Requests' : dataKey === 'avg_ms' ? 'Avg Latency' : dataKey}
          />}
        </Chart>
      </ResponsiveContainer>
    </div>
  )
}
