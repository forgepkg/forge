import type { ComponentPropsWithoutRef, ReactNode } from 'react'
import clsx from 'clsx'

import { Icon, type IconName } from './icons'

/**
 * The table of record: a quiet header row, 44px rows, hover. The first column
 * is the row's name (`lead`); sizes and counts align right. Inside a `flush`
 * panel it runs edge to edge under the panel heading.
 */
export function Table({
  caption,
  dense = false,
  className,
  children,
}: {
  /** A caption for assistive technology (visually hidden). */
  caption?: string
  dense?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <div className={clsx('fg-table-wrap', className)}>
      <table className={clsx('fg-table', dense && 'fg-table--dense')}>
        {caption && <caption className="fg-sr">{caption}</caption>}
        {children}
      </table>
    </div>
  )
}

export function TableHead({ children }: { children: ReactNode }) {
  return (
    <thead>
      <tr>{children}</tr>
    </thead>
  )
}

export function TableBody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>
}

export function TableRow({
  selected = false,
  className,
  ...props
}: ComponentPropsWithoutRef<'tr'> & { selected?: boolean }) {
  return <tr {...props} className={clsx(selected && 'is-selected', className)} />
}

/** A column header (`scope="col"`); `hint` explains it as a tooltip. */
export function TableHeader({
  align,
  width,
  hint,
  className,
  children,
}: {
  align?: 'left' | 'right'
  width?: string
  hint?: string
  className?: string
  children?: ReactNode
}) {
  return (
    <th
      scope="col"
      title={hint}
      className={clsx(align === 'right' && 'is-right', className)}
      style={width ? { width } : undefined}
    >
      {children}
    </th>
  )
}

/** A cell. `lead` is the row's name (full ink); the rest are muted. */
export function TableCell({
  align,
  nowrap = false,
  lead = false,
  className,
  ...props
}: ComponentPropsWithoutRef<'td'> & {
  align?: 'left' | 'right'
  nowrap?: boolean
  lead?: boolean
}) {
  return (
    <td
      {...props}
      className={clsx(
        align === 'right' && 'is-right',
        nowrap && 'is-nowrap',
        lead && 'is-lead',
        className,
      )}
    />
  )
}

/** A name with a line under it in a table cell (a URL, a description). */
export function CellStack({
  children,
  sub,
  className,
}: {
  children: ReactNode
  sub?: ReactNode
  className?: string
}) {
  return (
    <span className={clsx('fg-cell-link', className)}>
      {children}
      {sub && <span className="fg-cell-sub">{sub}</span>}
    </span>
  )
}

/** Right-aligned buttons at the end of a row. */
export function CellActions({ children }: { children: ReactNode }) {
  return <span className="fg-cell-actions">{children}</span>
}

export interface Fact {
  term: ReactNode
  value: ReactNode
  mono?: boolean
}

/**
 * Term and value pairs in two columns, for an object's settings at a glance.
 * Terms use the same words as the form fields they come from.
 */
export function FactList({ items, className }: { items: Fact[]; className?: string }) {
  return (
    <dl className={clsx('fg-facts', className)}>
      {items.map((it, i) => (
        <FactRow key={i} {...it} />
      ))}
    </dl>
  )
}

function FactRow({ term, value, mono }: Fact) {
  return (
    <>
      <dt>{term}</dt>
      <dd className={mono ? 'is-mono' : undefined}>{value}</dd>
    </>
  )
}

/**
 * One number with its label, for the overview row of a screen: what the
 * number covers, or when it was measured, goes in `sub`.
 */
export function Stat({
  label,
  value,
  unit,
  sub,
  icon,
  className,
}: {
  label: ReactNode
  value: ReactNode
  unit?: ReactNode
  sub?: ReactNode
  icon?: IconName
  className?: string
}) {
  return (
    <div className={clsx('fg-stat', className)}>
      <div className="fg-stat-label">
        {icon && <Icon name={icon} size={14} />}
        {label}
      </div>
      <div className="fg-stat-value">
        {value}
        {unit && <span className="fg-stat-unit">{unit}</span>}
      </div>
      {sub && <div className="fg-stat-sub">{sub}</div>}
    </div>
  )
}

/** A row of `Stat`s above the panels. */
export function StatRow({ children }: { children: ReactNode }) {
  return <div className="fg-stats">{children}</div>
}

/**
 * Progress of a long job with a known size (an import, a retention run).
 * `tone="ok"` when done, `danger` when stopped by errors.
 */
export function ProgressBar({
  value,
  max = 100,
  label,
  valueText,
  sub,
  tone,
  className,
}: {
  value: number
  max?: number
  label?: string
  valueText?: string
  sub?: ReactNode
  tone?: 'ok' | 'danger'
  className?: string
}) {
  const v = Math.max(0, Math.min(max, value))
  const pct = max > 0 ? Math.round((v / max) * 100) : 0
  return (
    <div className={clsx('fg-progress', className)}>
      {label && (
        <div className="fg-progress-head">
          <span className="fg-progress-label">{label}</span>
          <span className="fg-progress-value">{valueText ?? `${pct}%`}</span>
        </div>
      )}
      <div
        className="fg-progress-track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={v}
        aria-valuetext={valueText}
        aria-label={label ?? 'Progress'}
      >
        <div
          className={clsx('fg-progress-fill', tone && `fg-progress-fill--${tone}`)}
          style={{ width: `${pct}%` }}
        />
      </div>
      {sub && <div className="fg-progress-sub">{sub}</div>}
    </div>
  )
}

/**
 * The shape of content that is still loading, so the layout does not jump.
 * `label` is what a screen reader hears ("Loading packages…"). First loads
 * only; when paging, keep the previous page visible instead.
 */
export function Skeleton({
  variant = 'text',
  lines = 3,
  rows = 4,
  columns = 3,
  label = 'Loading…',
  className,
}: {
  variant?: 'text' | 'table'
  lines?: number
  rows?: number
  columns?: number
  label?: string
  className?: string
}) {
  if (variant === 'table') {
    return (
      <div className={clsx('fg-skel-table', className)} role="status" aria-label={label}>
        {Array.from({ length: rows }, (_, r) => (
          <div key={r} className="fg-skel-row">
            {Array.from({ length: columns }, (_, c) => (
              <span
                key={c}
                className="fg-skel fg-skel--line"
                style={{
                  width: `${c === 0 ? 40 + ((r * 13) % 30) : 20 + ((r * 7 + c * 11) % 25)}%`,
                }}
              />
            ))}
          </div>
        ))}
      </div>
    )
  }
  return (
    <div className={clsx('fg-skel-text', className)} role="status" aria-label={label}>
      {Array.from({ length: lines }, (_, i) => (
        <span
          key={i}
          className="fg-skel fg-skel--line"
          style={{ width: `${i === lines - 1 ? 60 : 100 - i * 8}%` }}
        />
      ))}
    </div>
  )
}
