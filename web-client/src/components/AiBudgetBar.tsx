/** Budget usage bar: red when over the limit, amber from the warning threshold. */
export default function AiBudgetBar({ percent, warnAt = 80, label, className = '' }: { percent: number; warnAt?: number; label: string; className?: string }) {
  const color = percent >= 100 ? 'bg-red-600' : percent >= warnAt ? 'bg-amber-500' : 'bg-green-600'
  return <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.min(100, percent)} className={`h-2 w-full overflow-hidden rounded bg-gray-200 ${className}`}>
    <div className={`h-full ${color}`} style={{ width: `${Math.min(100, Math.max(0, percent))}%` }} />
  </div>
}
