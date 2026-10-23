import type { TokenView } from '~/api/tokens'
import { StatusBadge } from '~/components/ui'

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
      return <StatusBadge tone="neutral">revoked</StatusBadge>
    case 'expired':
      return <StatusBadge tone="warn">expired</StatusBadge>
    default:
      return <StatusBadge tone="ok">active</StatusBadge>
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
      <StatusBadge
        tone="danger"
        title="The stored scope does not parse; the token is denied"
      >
        invalid scope
      </StatusBadge>
    )
  }
  const actions = parsed?.actions
  const repositories = parsed?.repositories
  if (actions === undefined && repositories === undefined) {
    return (
      <span
        className="fg-muted"
        title="The owner's read, write and delete access; never admin"
      >
        unscoped
      </span>
    )
  }
  const other = (actions ?? []).filter((a) => a !== 'admin')
  return (
    <span className="fg-cell-badges">
      {actions?.includes('admin') && (
        <StatusBadge tone="heat" dot={false}>
          admin
        </StatusBadge>
      )}
      {actions !== undefined && other.length > 0 && (
        <StatusBadge dot={false}>{other.join(', ')}</StatusBadge>
      )}
      {actions !== undefined && actions.length === 0 && (
        <StatusBadge dot={false}>no actions</StatusBadge>
      )}
      {repositories !== undefined && (
        <StatusBadge icon="Repository">
          {repositories.length === 1
            ? '1 repository'
            : `${repositories.length} repositories`}
        </StatusBadge>
      )}
    </span>
  )
}
