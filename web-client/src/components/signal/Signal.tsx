'use client'

import Link from 'next/link'
import React, { cloneElement, isValidElement, useState, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react'

type Tone = 'ink' | 'white' | 'lime' | 'terracotta' | 'blue' | 'dark'
type Status = 'healthy' | 'attention' | 'info' | 'critical' | 'neutral'

function stripDot(n: ReactNode): ReactNode {
  if (typeof n === 'string') return n.replace(/\.\s*$/, '')
  if (Array.isArray(n)) return n.map((c, i) => (i === n.length - 1 ? stripDot(c) : c))
  if (isValidElement(n) && (n.props as { children?: ReactNode }).children !== undefined) return cloneElement(n as React.ReactElement<{ children?: ReactNode }>, undefined, stripDot((n.props as { children?: ReactNode }).children))
  return n
}

export function SignalPageHeader({ kicker, title, description, actions, className = '' }: { kicker: string; title: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string }) {
  return <header className={`signal-page-header ${className}`}><div><p className="signal-kicker">{kicker}</p><h1 className="signal-page-title">{stripDot(title)}</h1>{description && <p className="signal-page-description">{description}</p>}</div>{actions && <div className="signal-page-actions">{actions}</div>}</header>
}

export function SignalPanel({ children, tone = 'white', title, kicker, className = '', ...props }: HTMLAttributes<HTMLElement> & { tone?: Tone; title?: ReactNode; kicker?: ReactNode }) {
  return <section className={`signal-panel signal-panel--${tone} ${className}`} {...props}>{(title || kicker) && <header className="signal-panel__header"><div>{kicker && <p className="signal-kicker">{kicker}</p>}{title && <h2>{title}</h2>}</div></header>}<div className="signal-panel__body">{children}</div></section>
}

export function SignalMetric({ label, value, detail, tone = 'white' }: { label: ReactNode; value: ReactNode; detail?: ReactNode; tone?: Tone }) { return <div className={`signal-metric signal-metric--${tone}`}><p>{label}</p><strong>{value}</strong>{detail && <span>{detail}</span>}</div> }
export type SignalRecordIconKind = 'user' | 'group' | 'role' | 'routing'

export function SignalRecordIcon({ kind, className = '' }: { kind: SignalRecordIconKind; className?: string }) {
  const artwork: Record<SignalRecordIconKind, ReactNode> = {
    user: <><circle cx="12" cy="8" r="3" /><path d="M5 20c.6-3.4 2.9-5 7-5s6.4 1.6 7 5" /></>,
    group: <><circle cx="8" cy="9" r="2.5" /><circle cx="16" cy="9" r="2.5" /><path d="M3.5 20c.4-3 2.1-4.5 4.5-4.5M16 15.5c2.4 0 4.1 1.5 4.5 4.5M7 18c.5-2.8 2.1-4.2 5-4.2s4.5 1.4 5 4.2" /></>,
    role: <><path d="M12 3 19 6v5c0 4.4-2.8 7.7-7 10-4.2-2.3-7-5.6-7-10V6l7-3Z" /><path d="m9 12 2 2 4-4" /></>,
    routing: <><path d="M4 7h10" /><path d="m11 4 3 3-3 3" /><path d="M20 17H10" /><path d="m13 14-3 3 3 3" /></>,
  }
  return <span className={`signal-record-icon signal-record-icon--${kind} ${className}`} aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{artwork[kind]}</svg></span>
}

export function SignalStatusTag({ children, status = 'neutral' }: { children: ReactNode; status?: Status }) { return <span className={`signal-status signal-status--${status}`}>{children}</span> }
export function SignalTable({ className = '', children, ...props }: HTMLAttributes<HTMLTableElement>) { return <div className="signal-table-wrap"><table className={`signal-table ${className}`} {...props}>{children}</table></div> }
export function SignalFormSection({ number, title, description, children, className = '' }: { number: string; title: ReactNode; description?: ReactNode; children: ReactNode; className?: string }) { return <section className={`signal-form-section ${className}`}><header><span>{number}</span><div><h2>{title}</h2>{description && <p>{description}</p>}</div></header><div className="signal-form-section__body">{children}</div></section> }
export function SignalEmptyState({ title, children, action }: { title: ReactNode; children?: ReactNode; action?: ReactNode }) { return <div className="signal-empty"><p className="signal-kicker">NO RECORDS</p><h2>{title}</h2>{children && <p>{children}</p>}{action && <div>{action}</div>}</div> }
export function SignalSidebarRail({ title = 'OPERATIONS', children, className = '' }: { title?: ReactNode; children: ReactNode; className?: string }) { return <aside className={`signal-sidebar-rail ${className}`}><p className="signal-kicker">{title}</p>{children}</aside> }
export function SignalPrimaryButton({ className = '', children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) { return <button className={`signal-button signal-button--primary ${className}`} {...props}>{children}</button> }
export function SignalDangerButton({ className = '', children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) { return <button className={`signal-button signal-button--danger ${className}`} {...props}>{children}</button> }
export function SignalPrimaryLink({ href, className = '', children }: { href: string; className?: string; children: ReactNode }) { return <Link href={href} className={`signal-button signal-button--primary ${className}`}>{children}</Link> }

export function AppShell({ children }: { children: ReactNode }) {
  return <div className="signal-app-shell">{children}</div>
}

export interface BreadcrumbItem {
  label: string
  href?: string
}

export function SignalBreadcrumbs({ items, className = '' }: { items: BreadcrumbItem[]; className?: string }) {
  return (
    <nav aria-label="Breadcrumb" className={`signal-breadcrumbs mb-4 ${className}`}>
      <ol className="flex flex-wrap items-center gap-2 font-mono text-xs uppercase tracking-wider text-signal-mist">
        {items.map((item, idx) => {
          const isLast = idx === items.length - 1
          return (
            <li key={idx} className="flex items-center gap-2">
              {idx > 0 && <span className="text-signal-ink font-bold select-none">/</span>}
              {item.href && !isLast ? (
                <Link href={item.href} className="hover:text-signal-terra hover:underline underline-offset-4 transition-colors font-bold text-signal-ink">
                  {item.label}
                </Link>
              ) : (
                <span className={isLast ? 'font-bold text-signal-ink bg-white border border-signal-ink px-1.5 py-0.5 shadow-[2px_2px_0px_0px_rgba(25,32,28,1)]' : ''}>
                  {item.label}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

export function SignalCopyButton({ text, label = 'Copy', className = '' }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  const onCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy', err)
    }
  }
  return (
    <button
      type="button"
      onClick={onCopy}
      title={`Copy "${text}"`}
      className={`signal-button text-[10px] py-0.5 px-2 min-h-0 border border-signal-ink ${copied ? 'bg-signal-lime font-bold !shadow-none' : 'bg-white hover:bg-signal-warm'} ${className}`}
    >
      {copied ? 'COPIED!' : label}
    </button>
  )
}

export function SignalSearchInput({
  value,
  onChange,
  onClear,
  placeholder = 'Search...',
  className = ''
}: {
  value: string
  onChange: (val: string) => void
  onClear?: () => void
  placeholder?: string
  className?: string
}) {
  return (
    <div className={`relative flex items-center ${className}`}>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="search-input w-full pr-8"
      />
      {value && (
        <button
          type="button"
          onClick={() => {
            onChange('')
            onClear?.()
          }}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 font-mono text-xs font-bold text-signal-mist hover:text-signal-terra p-1"
          title="Clear search"
        >
          ✕
        </button>
      )}
    </div>
  )
}

export function SignalMethodFilter({
  selected,
  onChange,
  counts
}: {
  selected: string
  onChange: (method: string) => void
  counts?: Record<string, number>
}) {
  const methods = ['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH']
  const getTone = (m: string) => {
    if (m === 'GET') return 'bg-[#38bdf8] text-signal-ink'
    if (m === 'POST') return 'bg-signal-lime text-signal-ink'
    if (m === 'PUT') return 'bg-[#fbbf24] text-signal-ink'
    if (m === 'DELETE') return 'bg-red-500/10 text-red-700'
    if (m === 'PATCH') return 'bg-[#c084fc] text-signal-ink'
    return 'bg-white text-signal-ink'
  }
  return (
    <div className="flex flex-wrap gap-1">
      {methods.map(m => {
        const active = selected.toUpperCase() === m
        return (
          <button
            key={m}
            type="button"
            onClick={() => onChange(m)}
            className={`font-mono text-xs font-bold uppercase px-2.5 py-1 border-2 border-signal-ink transition-all ${
              active ? `${getTone(m)} shadow-[2px_2px_0px_0px_rgba(25,32,28,1)] translate-x-[-1px] translate-y-[-1px]` : 'bg-white text-signal-ink hover:bg-signal-warm'
            }`}
          >
            {m} {counts?.[m] !== undefined && <span className="opacity-75">({counts[m]})</span>}
          </button>
        )
      })}
    </div>
  )
}

export function SignalSecretMask({
  value,
  visibleChars = 4,
  className = '',
}: {
  value: string
  visibleChars?: number
  className?: string
}) {
  const [revealed, setRevealed] = useState(false)

  if (!value) {
    return <span className="text-signal-mist font-mono text-xs">—</span>
  }

  const maskSecret = (str: string) => {
    if (str.length <= visibleChars * 2) {
      return '••••••••'
    }
    const prefix = str.slice(0, visibleChars)
    const suffix = str.slice(-visibleChars)
    return `${prefix}••••••••${suffix}`
  }

  return (
    <div className={`inline-flex items-center gap-1.5 font-mono text-xs ${className}`}>
      <code className="bg-signal-warm/80 px-2 py-0.5 border border-signal-ink select-all text-signal-ink">
        {revealed ? value : maskSecret(value)}
      </code>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation()
          setRevealed(!revealed)
        }}
        title={revealed ? 'Hide secret' : 'Reveal secret'}
        className="signal-button text-[10px] py-0.5 px-2 min-h-0 border border-signal-ink bg-white hover:bg-signal-warm"
      >
        {revealed ? 'HIDE' : 'SHOW'}
      </button>
      <SignalCopyButton text={value} label="COPY" />
    </div>
  )
}
