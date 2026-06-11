import { Badge } from '~/components/catalyst/badge'

/**
 * Retention-status badge. The backend reports `retention_status` as `null`
 * throughout slice 1 (retention policy lands in §12.1), so this renders nothing
 * today; the values are wired so the UI is forward-compatible without a rewrite.
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
