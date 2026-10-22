import { Badge } from '~/components/catalyst/badge'

/**
 * Retention-status badge. The browse API always reports `retention_status` as
 * `null`, so this renders nothing today; the values are wired so the UI is
 * forward-compatible without a rewrite.
 */
const RETENTION_COLORS: Record<string, React.ComponentProps<typeof Badge>['color']> = {
  kept: 'zinc',
  pending_prune: 'rose',
}

export function RetentionBadge({ status }: { status: string | null | undefined }) {
  if (!status) return null
  return (
    <Badge color={RETENTION_COLORS[status] ?? 'zinc'}>
      {status.replace(/_/g, ' ')}
    </Badge>
  )
}
