import clsx from 'clsx'

import type { DetailVersion } from '~/api/packages'
import { DelayBadge } from './DelayBadge'
import { RetentionBadge } from './RetentionBadge'

/**
 * Per-version table for the package-detail view. Columns: version, published
 * time, size, listed/unlisted, and proxy delay + retention badges. Download
 * counts are intentionally absent — slice 1 has no counters (see
 * `src/api/packages.ts`).
 */
export function VersionTable({ versions }: { versions: DetailVersion[] }) {
  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b border-slate-200 text-left text-slate-500">
          <th className="py-2 pr-4 font-medium">Version</th>
          <th className="py-2 pr-4 font-medium">Published</th>
          <th className="py-2 pr-4 font-medium">Size</th>
          <th className="py-2 pr-4 font-medium">Status</th>
        </tr>
      </thead>
      <tbody>
        {versions.map((v) => (
          <tr
            key={v.version}
            className="border-b border-slate-100 last:border-0"
          >
            <td className="py-2 pr-4 font-mono">
              <span className={clsx(!v.listed && 'text-slate-400')}>
                {v.version_original}
              </span>
            </td>
            <td className="py-2 pr-4 text-slate-600">
              {formatDate(v.published_at)}
            </td>
            <td className="py-2 pr-4 text-slate-600">{formatSize(v.size)}</td>
            <td className="py-2 pr-4">
              <span className="flex flex-wrap items-center gap-1.5">
                {!v.listed && (
                  <span className="inline-block rounded bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600">
                    unlisted
                  </span>
                )}
                <DelayBadge status={v.delay_status} delayedUntil={v.delayed_until} />
                <RetentionBadge status={v.retention_status} />
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

function formatSize(bytes: number | null): string {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  const kb = bytes / 1024
  if (kb < 1024) return `${kb.toFixed(1)} KB`
  return `${(kb / 1024).toFixed(1)} MB`
}
