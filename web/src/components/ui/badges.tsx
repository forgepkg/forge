import type { ReactNode } from 'react'
import clsx from 'clsx'

import { Icon, type IconName } from './icons'
import { CopyButton } from './code'

const KINDS = new Set(['hosted', 'proxy', 'group'])

/**
 * The repository kind on its own tint: hosted (blue), proxy (teal), group
 * (violet). The kind colours mean kinds and nothing else; any other value
 * renders neutral, so a future kind never goes unlabelled.
 */
export function KindBadge({
  kind,
  title,
  className,
}: {
  kind: string
  title?: string
  className?: string
}) {
  const k = kind.toLowerCase()
  return (
    <span
      className={clsx('fg-kind', KINDS.has(k) ? `fg-kind--${k}` : 'fg-kind--other', className)}
      title={title}
    >
      {k || 'unknown'}
    </span>
  )
}

const FORMATS: Record<string, { label: string; icon: IconName }> = {
  nuget: { label: 'NuGet', icon: 'Package' },
  docker: { label: 'Docker', icon: 'Layers' },
  raw: { label: 'Raw', icon: 'Folder' },
}

/** Display name of a repository format (`NuGet`, `Docker`, a plugin's id). */
export function formatLabel(format: string): string {
  return FORMATS[format]?.label ?? format
}

/** The icon of a repository format (`Package` for formats Forge does not know). */
export function formatIcon(format: string): IconName {
  return FORMATS[format]?.icon ?? 'Package'
}

/**
 * The repository format with a generic glyph. Neutral on purpose: colour is
 * reserved for the kind. Placed after the `KindBadge`.
 */
export function FormatTag({ format, className }: { format: string; className?: string }) {
  return (
    <span className={clsx('fg-format', className)}>
      <Icon name={formatIcon(format)} size={13} />
      {formatLabel(format) || 'unknown'}
    </span>
  )
}

export type Tone = 'neutral' | 'ok' | 'warn' | 'danger' | 'heat'

/**
 * One or two lowercase words of state on a soft fill: `ok` (available,
 * active), `warn` (delayed, expired), `danger` (pending prune, invalid),
 * `neutral` (unlisted, offline, revoked), `heat` (admin, writable). The dot's
 * shape repeats the tone for colour-blind readers; `icon` replaces it.
 * Explanations go in `title`.
 */
export function StatusBadge({
  tone = 'neutral',
  icon,
  dot = true,
  title,
  children,
  className,
}: {
  tone?: Tone
  icon?: IconName
  dot?: boolean
  title?: string
  children?: ReactNode
  className?: string
}) {
  return (
    <span className={clsx('fg-badge', `fg-badge--${tone}`, className)} title={title}>
      {icon ? (
        <Icon name={icon} size={12} strokeWidth={1.75} />
      ) : dot ? (
        <span className="fg-badge-dot" aria-hidden="true" />
      ) : null}
      {children}
    </span>
  )
}

/** A neutral mono chip: a platform, a tag, a scope. */
export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={clsx('fg-chip', className)}>{children}</span>
}

function splitVersion(v: string): [string, string, string] {
  const m = /^(\d+(?:\.\d+)*)(-[^+]*)?(\+.*)?$/.exec(v)
  return m ? [m[1], m[2] ?? '', m[3] ?? ''] : [v, '', '']
}

/**
 * A package version in mono, exactly as published; the prerelease suffix and
 * build metadata are faint. `latest` adds the latest tag; `listed={false}`
 * fades an unlisted version.
 */
export function Version({
  value,
  latest = false,
  listed = true,
  className,
}: {
  value: string
  latest?: boolean
  listed?: boolean
  className?: string
}) {
  const [core, pre, meta] = splitVersion(value)
  return (
    <span className={clsx('fg-version', !listed && 'fg-version--unlisted', className)}>
      <span className="fg-version-core">{core}</span>
      {pre && <span className="fg-version-pre">{pre}</span>}
      {meta && <span className="fg-version-meta">{meta}</span>}
      {latest && <span className="fg-version-latest">latest</span>}
    </span>
  )
}

/**
 * A content digest the Docker way (algorithm plus 12 hex characters), the
 * full value as tooltip, with a copy button. `full` shows the whole digest
 * with a faint tail.
 */
export function Digest({
  value,
  length = 12,
  full = false,
  showAlgorithm = true,
  copy = true,
  copyLabel = 'Copy digest',
  className,
}: {
  value: string
  length?: number
  full?: boolean
  showAlgorithm?: boolean
  copy?: boolean
  copyLabel?: string
  className?: string
}) {
  const i = value.indexOf(':')
  const algo = i >= 0 ? value.slice(0, i + 1) : ''
  const hex = i >= 0 ? value.slice(i + 1) : value
  return (
    <span className={clsx('fg-digest', className)}>
      <span className="fg-digest-text" title={value}>
        {showAlgorithm && algo && <span className="fg-digest-algo">{algo}</span>}
        <span className="fg-digest-short">{hex.slice(0, length)}</span>
        {full && <span className="fg-digest-rest">{hex.slice(length)}</span>}
      </span>
      {copy && <CopyButton value={value} label={copyLabel} />}
    </span>
  )
}
