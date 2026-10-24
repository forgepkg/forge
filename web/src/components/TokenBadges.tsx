import { LEVEL_COVERS, LEVELS, type Level } from '~/api/rbac'
import type { TokenView } from '~/api/tokens'
import { StatusBadge } from '~/components/ui'

/**
 * Status and scope cells shared by the self-service and the admin token
 * tables. A token stops working once revoked or past `expires_at`; the scope
 * is the stored `{"level": ..., "admin": true, "repositories": [...]}`
 * document (or `null` for an unscoped token), shown so a narrowed or admin
 * token is recognizable.
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

export function formatTokenExpiry(expiresAt: string | null): string {
  if (expiresAt === null) return 'never'
  const date = new Date(expiresAt)
  return Number.isNaN(date.getTime())
    ? expiresAt
    : date.toLocaleDateString(undefined, { dateStyle: 'medium' })
}

const LEVEL_SET = new Set<string>(LEVELS)

/**
 * The scope as the server reads it: `null` when unscoped (the owner's access
 * without `admin`), `'invalid'` when the stored document does not parse (the
 * server then denies the token everything; a scope still listing `actions`
 * is one), otherwise its parts.
 */
export function parseTokenScope(
  scope: unknown,
): { level?: Level; admin?: boolean; repositories?: number[] } | null | 'invalid' {
  if (scope == null) return null
  if (typeof scope !== 'object' || Array.isArray(scope)) return 'invalid'
  const { level, admin, repositories, ...rest } = scope as Record<string, unknown>
  if (Object.keys(rest).length > 0) return 'invalid'
  if (level != null && !LEVEL_SET.has(level as string)) return 'invalid'
  if (admin != null && typeof admin !== 'boolean') return 'invalid'
  if (
    repositories != null &&
    !(Array.isArray(repositories) && repositories.every(Number.isInteger))
  ) {
    return 'invalid'
  }
  return {
    level: (level ?? undefined) as Level | undefined,
    admin: admin === true ? true : undefined,
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
  const level = parsed?.level
  const admin = parsed?.admin
  const repositories = parsed?.repositories
  if (level === undefined && !admin && repositories === undefined) {
    return (
      <span className="fg-muted" title="The owner's levels; never admin">
        unscoped
      </span>
    )
  }
  return (
    <span className="fg-cell-badges">
      {admin && (
        <StatusBadge tone="heat" dot={false}>
          admin
        </StatusBadge>
      )}
      {level !== undefined && (
        <StatusBadge dot={false} title={`At most ${level}: ${LEVEL_COVERS[level]}`}>
          {level}
        </StatusBadge>
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
