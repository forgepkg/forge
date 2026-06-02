import clsx from 'clsx'

import type { DelayStatus } from '~/api/packages'

/**
 * Proxy package-delay badge. Only meaningful for proxy versions:
 *
 *  - `available`     — past the package-delay window, downloadable.
 *  - `delayed_until` — discovered upstream but still inside the delay window;
 *    not yet downloadable. `delayedUntil` (when present) gives the ETA.
 *
 * Hosted / group versions pass `status = null` and render nothing.
 */
export function DelayBadge({
  status,
  delayedUntil,
}: {
  status: DelayStatus | null | undefined
  delayedUntil?: string | null
}) {
  if (!status) return null

  if (status === 'available') {
    return (
      <span className="inline-block rounded bg-emerald-100 px-1.5 py-0.5 text-xs font-medium text-emerald-800">
        available
      </span>
    )
  }

  const eta = delayedUntil ? formatEta(delayedUntil) : null
  return (
    <span
      className={clsx(
        'inline-block rounded px-1.5 py-0.5 text-xs font-medium',
        'bg-amber-100 text-amber-800',
      )}
      title={delayedUntil ? `available ${new Date(delayedUntil).toLocaleString()}` : undefined}
    >
      delayed{eta ? ` · ${eta}` : ''}
    </span>
  )
}

/** Compact "in 2h 5m" / "soon" rendering of a future timestamp. */
function formatEta(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now()
  if (Number.isNaN(ms) || ms <= 0) return 'soon'
  const mins = Math.round(ms / 60_000)
  if (mins < 60) return `in ${mins}m`
  const hours = Math.floor(mins / 60)
  const rem = mins % 60
  return rem ? `in ${hours}h ${rem}m` : `in ${hours}h`
}
