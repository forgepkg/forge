import type { TokenView } from '~/api/tokens'
import { Badge } from '~/components/catalyst/badge'

/**
 * Status and scope cells shared by the self-service and the admin token
 * tables. A token stops working once revoked or past `expires_at`; the scope
 * is the stored `{"actions": [...], "repositories": [...]}` document (or
 * `null` for an unscoped token), shown so a narrowed or admin token is
 * recognizable.
 */

export type TokenStatus = 'active' | 'expired' | 'revoked'

/** Revoked wins over expired; a token without `expires_at` never expires. */
export function tokenStatus(token: TokenView, now = Date.now()): TokenStatus {
  if (token.revoked_at != null) return 'revoked'
  if (token.expires_at != null) {
    const expires = Date.parse(token.expires_at)
    if (!Number.isNaN(expires) && expires <= now) return 'expired'
  }
  return 'active'
}

export function TokenStatusBadge({ token }: { token: TokenView }) {
  switch (tokenStatus(token)) {
    case 'revoked':
      return <Badge color="zinc">revoked</Badge>
    case 'expired':
      return <Badge color="amber">expired</Badge>
    default:
      return <Badge color="emerald">active</Badge>
  }
}

const ACTIONS = new Set(['read', 'write', 'delete', 'admin'])

/**
 * The scope as the server reads it: `null` when unscoped (the owner's access
 * without `admin`), `'invalid'` when the stored document does not parse (the
 * server then denies the token everything), otherwise its parts.
 */
export function parseTokenScope(
  scope: unknown,
): { actions?: string[]; repositories?: number[] } | null | 'invalid' {
  if (scope == null) return null
  if (typeof scope !== 'object' || Array.isArray(scope)) return 'invalid'
  const { actions, repositories, ...rest } = scope as Record<string, unknown>
  if (Object.keys(rest).length > 0) return 'invalid'
  if (
    actions != null &&
    !(Array.isArray(actions) && actions.every((a) => ACTIONS.has(a as string)))
  ) {
    return 'invalid'
  }
  if (
    repositories != null &&
    !(Array.isArray(repositories) && repositories.every(Number.isInteger))
  ) {
    return 'invalid'
  }
  return {
    actions: (actions ?? undefined) as string[] | undefined,
    repositories: (repositories ?? undefined) as number[] | undefined,
  }
}

export function TokenScopeBadges({ scope }: { scope: TokenView['scope'] }) {
  const parsed = parseTokenScope(scope)
  if (parsed === 'invalid') {
    return (
      <Badge color="red" title="The stored scope does not parse; the token is denied">
        invalid scope
      </Badge>
    )
  }
  const actions = parsed?.actions
  const repositories = parsed?.repositories
  if (actions === undefined && repositories === undefined) {
    return (
      <span
        className="text-zinc-500 dark:text-zinc-400"
        title="The owner's read, write and delete access; never admin"
      >
        unscoped
      </span>
    )
  }
  const other = (actions ?? []).filter((a) => a !== 'admin')
  return (
    <span className="flex flex-wrap items-center gap-1">
      {actions?.includes('admin') && <Badge color="red">admin</Badge>}
      {actions !== undefined && other.length > 0 && (
        <Badge color="zinc">{other.join(', ')}</Badge>
      )}
      {actions !== undefined && actions.length === 0 && (
        <Badge color="zinc">no actions</Badge>
      )}
      {repositories !== undefined && (
        <Badge color="sky">
          {repositories.length === 1
            ? '1 repository'
            : `${repositories.length} repositories`}
        </Badge>
      )}
    </span>
  )
}
