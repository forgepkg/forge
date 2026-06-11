import { Badge } from '~/components/catalyst/badge'

/**
 * Colored badge for a repository kind (`hosted` | `proxy` | `group`). Unknown
 * kinds fall back to a neutral style so a future kind never renders untyped.
 */
const KIND_COLORS: Record<string, React.ComponentProps<typeof Badge>['color']> = {
  hosted: 'sky',
  proxy: 'amber',
  group: 'purple',
}

export function RepoKindBadge({ kind }: { kind: string }) {
  return <Badge color={KIND_COLORS[kind] ?? 'zinc'}>{kind}</Badge>
}
