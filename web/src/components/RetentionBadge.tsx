import clsx from 'clsx'

/**
 * Retention-status badge. The backend reports `retention_status` as `null`
 * throughout slice 1 (retention policy lands in §12.1), so this renders nothing
 * today; the values are wired so the UI is forward-compatible without a rewrite.
 */
const RETENTION_STYLES: Record<string, string> = {
  kept: 'bg-slate-100 text-slate-700',
  pending_prune: 'bg-rose-100 text-rose-800',
}

export function RetentionBadge({ status }: { status: string | null | undefined }) {
  if (!status) return null
  return (
    <span
      className={clsx(
        'inline-block rounded px-1.5 py-0.5 text-xs font-medium',
        RETENTION_STYLES[status] ?? 'bg-slate-100 text-slate-700',
      )}
    >
      {status.replace(/_/g, ' ')}
    </span>
  )
}
