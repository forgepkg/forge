import { StatusBadge, type Tone } from '~/components/ui'

/**
 * Retention-status badge. The browse API always reports `retention_status` as
 * `null`, so this renders nothing today; the values are wired so the UI is
 * forward-compatible without a rewrite.
 */
const RETENTION_TONES: Record<string, Tone> = {
  kept: 'neutral',
  pending_prune: 'danger',
}

export function RetentionBadge({ status }: { status: string | null | undefined }) {
  if (!status) return null
  return (
    <StatusBadge tone={RETENTION_TONES[status] ?? 'neutral'}>
      {status.replace(/_/g, ' ')}
    </StatusBadge>
  )
}
