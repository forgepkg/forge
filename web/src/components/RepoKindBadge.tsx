import { KindBadge } from '~/components/ui'

/**
 * The repository kind (`hosted` | `proxy` | `group`) on its own tint. Unknown
 * kinds render neutral so a future kind never renders untyped.
 */
export function RepoKindBadge({ kind }: { kind: string }) {
  return <KindBadge kind={kind} />
}
