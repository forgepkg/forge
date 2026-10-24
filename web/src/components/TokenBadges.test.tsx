import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { TokenView } from '~/api/tokens'
import {
  TokenScopeBadges,
  TokenStatusBadge,
  parseTokenScope,
  tokenStatus,
} from './TokenBadges'

function token(over: Partial<TokenView>): TokenView {
  return {
    id: 1,
    user_id: 2,
    name: 'ci',
    expires_at: null,
    revoked_at: null,
    last_used_at: null,
    created_at: '2026-01-01T00:00:00Z',
    scope: null,
    ...over,
  }
}

describe('token status', () => {
  const now = Date.parse('2026-06-01T00:00:00Z')

  it('is expired once expires_at has passed, and revoked wins', () => {
    expect(tokenStatus(token({}), now)).toBe('active')
    expect(tokenStatus(token({ expires_at: '2026-07-01T00:00:00Z' }), now)).toBe('active')
    expect(tokenStatus(token({ expires_at: '2026-05-01T00:00:00Z' }), now)).toBe('expired')
    expect(
      tokenStatus(
        token({ expires_at: '2026-05-01T00:00:00Z', revoked_at: '2026-04-01T00:00:00Z' }),
        now,
      ),
    ).toBe('revoked')
  })

  it('renders "expired" instead of "active" for a past expiry', () => {
    render(<TokenStatusBadge token={token({ expires_at: '2000-01-01T00:00:00Z' })} />)
    expect(screen.getByText('expired')).toBeInTheDocument()
    expect(screen.queryByText('active')).toBeNull()
  })
})

describe('token scope', () => {
  it('reads the stored scope as the server does', () => {
    expect(parseTokenScope(null)).toBeNull()
    expect(parseTokenScope({ level: 'read', repositories: [3] })).toEqual({
      level: 'read',
      repositories: [3],
    })
    expect(parseTokenScope({ admin: true, level: null })).toEqual({ admin: true })
    // Unknown keys and bad values do not parse; the server denies the token.
    expect(parseTokenScope({ repos: [3] })).toBe('invalid')
    expect(parseTokenScope({ level: 'admin' })).toBe('invalid')
    expect(parseTokenScope({ admin: 'yes' })).toBe('invalid')
    expect(parseTokenScope('admin')).toBe('invalid')
    // `actions`, which `level` and `admin` replaced, is refused too.
    expect(parseTokenScope({ actions: ['read'] })).toBe('invalid')
  })

  it('shows admin, the level and the number of repositories', () => {
    render(
      <TokenScopeBadges scope={{ level: 'read', admin: true, repositories: [3, 4] }} />,
    )
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('read')).toHaveAttribute('title', 'At most read: browse, read')
    expect(screen.getByText('2 repositories')).toBeInTheDocument()
  })

  it('says when a token is unscoped or its scope is broken', () => {
    const { unmount } = render(<TokenScopeBadges scope={null} />)
    expect(screen.getByText('unscoped')).toBeInTheDocument()
    unmount()
    const { unmount: unmountEmpty } = render(<TokenScopeBadges scope={{ admin: false }} />)
    expect(screen.getByText('unscoped')).toBeInTheDocument()
    unmountEmpty()
    render(<TokenScopeBadges scope={{ repos: [3] } as never} />)
    expect(screen.getByText('invalid scope')).toBeInTheDocument()
  })
})
