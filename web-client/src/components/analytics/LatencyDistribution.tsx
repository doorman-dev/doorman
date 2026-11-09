'use client'

import React from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts'

interface LatencyDistributionProps {
  data: Array<{
    timestamp: number
    percentiles: {
      p50: number
      p75: number
      p90: number
      p95: number
      p99: number
    }
  }>
  title?: string
  height?: number
}

export default function LatencyDistribution({
  data,
  title = 'Response Time Distribution',
  height = 300
}: LatencyDistributionProps) {
  // Create histogram buckets from percentile data
  const createHistogram = () => {
    if (!data || data.length === 0) return []

    // Collect all latency values
    const allLatencies: number[] = []
    data.forEach(point => {
      allLatencies.push(
        point.percentiles.p50,
        point.percentiles.p75,
        point.percentiles.p90,
        point.percentiles.p95,
        point.percentiles.p99
      )
    })

    // Find min and max
    const min = Math.min(...allLatencies)
    const max = Math.max(...allLatencies)

    // Create buckets
    const bucketCount = 10
    const bucketSize = (max - min) / bucketCount
    const buckets = Array(bucketCount).fill(0).map((_, i) => ({
      range: `${Math.round(min + i * bucketSize)}-${Math.round(min + (i + 1) * bucketSize)}ms`,
      count: 0,
      min: min + i * bucketSize,
      max: min + (i + 1) * bucketSize
    }))

    // Fill buckets
    allLatencies.forEach(latency => {
      const bucketIndex = Math.min(
        Math.floor((latency - min) / bucketSize),
        bucketCount - 1
      )
      if (bucketIndex >= 0 && bucketIndex < bucketCount) {
        buckets[bucketIndex].count++
      }
    })

    return buckets
  }

  const histogram = createHistogram()

  // Custom tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-1">
            {data.range}
          </p>
          <p className="text-sm text-primary-600 dark:text-primary-400">
            <span className="font-medium">Requests:</span> {data.count}
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
      
      {histogram.length > 0 ? (
        <ResponsiveContainer width="100%" height={height}>
          <BarChart
            data={histogram}
            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#232327"
              className="dark:stroke-gray-700"
            />
            
            <XAxis
              dataKey="range"
              stroke="#6e6e78"
              className="dark:stroke-gray-500"
              style={{ fontSize: '12px' }}
              angle={-45}
              textAnchor="end"
              height={80}
            />
            
            <YAxis
              stroke="#6e6e78"
              className="dark:stroke-gray-500"
              style={{ fontSize: '12px' }}
              label={{ value: 'Frequency', angle: -90, position: 'insideLeft' }}
            />
            
            <Tooltip content={<CustomTooltip />} />
            
            <Legend
              wrapperStyle={{ fontSize: '14px' }}
              iconType="rect"
            />
            
            <Bar
              dataKey="count"
              fill="#3b82f6"
              name="Request Count"
              radius={[4, 4, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex items-center justify-center h-64 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <p className="text-gray-500 dark:text-gray-400">No distribution data available</p>
        </div>
      )}
    </div>
  )
}
