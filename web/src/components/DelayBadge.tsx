import { StatusBadge } from '~/components/ui'
import { delaySourceLabel, type AppliedDelay, type DelayStatus } from '~/api/packages'

/**
 * Proxy package-delay badge. Only meaningful for proxy versions:
 *
 *  - `available`     — past the package-delay window, downloadable. When an
 *    administrator released the version early (`releasedAt`), it says so;
 *    when an override exempts the package (`delay` of 0 from a selector or
 *    a pattern), it names the override: "no delay: trusted-vendors".
 *  - `delayed_until` — discovered upstream but still inside the delay window;
 *    not yet downloadable. `delayedUntil` (when present) gives the ETA, and
 *    the title names the override that decides the delay, if one does.
 *
 * Hosted / group versions pass `status = null` and render nothing.
 */
export function DelayBadge({
  status,
  delayedUntil,
  releasedAt,
  delay,
}: {
  status: DelayStatus | null | undefined
  delayedUntil?: string | null
  /** When the version was released from the delay early, if it was. */
  releasedAt?: string | null
  /** The package's delay and what decides it. */
  delay?: AppliedDelay
}) {
  if (!status) return null
  const override = delaySourceLabel(delay?.source)

  if (status === 'available') {
    if (releasedAt) {
      return (
        <StatusBadge
          tone="ok"
          icon="Check"
          title={`released from the package delay early, ${new Date(releasedAt).toLocaleString()}`}
        >
          released early
        </StatusBadge>
      )
    }
    if (override && delay?.delay_seconds === 0) {
      return (
        <StatusBadge tone="ok" title="an override exempts this package from the package delay">
          no delay: {override}
        </StatusBadge>
      )
    }
    return <StatusBadge tone="ok">available</StatusBadge>
  }

  const eta = delayedUntil ? formatEta(delayedUntil) : null
  const why =
    override && delay ? `${formatDelay(delay.delay_seconds)} delay: ${override}` : null
  const title = [
    delayedUntil ? `available ${new Date(delayedUntil).toLocaleString()}` : null,
    why,
  ]
    .filter(Boolean)
    .join(' · ')
  return (
    <StatusBadge tone="warn" icon="Clock" title={title || undefined}>
      delayed{eta ? ` · ${eta}` : ''}
    </StatusBadge>
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

/** A delay in the largest whole unit ("14 d", "36 h", "90 min", "45 s"; "no" for none), to precede "delay". */
export function formatDelay(seconds: number): string {
  if (seconds <= 0) return 'no'
  if (seconds % 86_400 === 0) return `${seconds / 86_400} d`
  if (seconds % 3_600 === 0) return `${seconds / 3_600} h`
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}
