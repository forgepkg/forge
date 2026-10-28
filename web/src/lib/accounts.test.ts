import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  MAX_ACCOUNTS,
  beginOidcSignIn,
  clearPendingSignIn,
  completePendingSignIn,
  forgetAccount,
  forgetAllAccounts,
  listAccounts,
  rememberAccount,
} from './accounts'

/**
 * The remembered-accounts store: newest first, at most five, one entry per
 * account whatever the case of its identifier, nothing but the identifier,
 * name, method and realm kept, and every access survives blocked storage.
 * An OIDC sign-in is remembered from the pending marker the login screen
 * leaves, by the first `/auth/me` after the round trip.
 */
describe('remembered accounts', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
    sessionStorage.clear()
  })

  it('keeps the newest first and updates an account signed in again', () => {
    rememberAccount({ identifier: 'alice@corp.example', method: 'password', realm: 'local' }, 1)
    rememberAccount({ identifier: 'bob@corp.example', method: 'oidc', realm: 'corp' }, 2)
    expect(listAccounts().map((a) => a.identifier)).toEqual([
      'bob@corp.example',
      'alice@corp.example',
    ])

    // The same account, typed differently, replaces its entry and moves up.
    rememberAccount({ identifier: 'Alice@Corp.example', method: 'oidc', realm: 'corp' }, 3)
    expect(listAccounts()).toEqual([
      { identifier: 'Alice@Corp.example', method: 'oidc', realm: 'corp', last_used: 3 },
      { identifier: 'bob@corp.example', method: 'oidc', realm: 'corp', last_used: 2 },
    ])
  })

  it(`keeps at most ${MAX_ACCOUNTS}, dropping the oldest`, () => {
    for (let i = 1; i <= MAX_ACCOUNTS + 2; i++) {
      rememberAccount({ identifier: `user${i}@corp.example`, method: 'password' }, i)
    }
    const kept = listAccounts().map((a) => a.identifier)
    expect(kept).toHaveLength(MAX_ACCOUNTS)
    expect(kept[0]).toBe(`user${MAX_ACCOUNTS + 2}@corp.example`)
    expect(kept).not.toContain('user1@corp.example')
    expect(kept).not.toContain('user2@corp.example')
  })

  it('forgets one account, or all of them', () => {
    rememberAccount({ identifier: 'alice@corp.example', method: 'password' }, 1)
    rememberAccount({ identifier: 'bob@corp.example', method: 'password' }, 2)
    forgetAccount('ALICE@corp.example')
    expect(listAccounts().map((a) => a.identifier)).toEqual(['bob@corp.example'])

    beginOidcSignIn('corp')
    forgetAllAccounts()
    expect(listAccounts()).toEqual([])
    expect(localStorage.getItem('forge.accounts')).toBeNull()
    // A pending sign-in goes too: nothing is remembered afterwards.
    completePendingSignIn({ username: 'carol@corp.example' })
    expect(listAccounts()).toEqual([])
  })

  it('stores nothing that works as a credential', () => {
    rememberAccount({
      identifier: 'alice@corp.example',
      display_name: 'Alice Example',
      method: 'password',
      realm: 'local',
      // A caller passing more than an entry holds (a session, a password).
      ...({ csrf_token: 'csrf-secret', password: 'hunter2' } as object),
    })
    const raw = localStorage.getItem('forge.accounts') ?? ''
    expect(raw).not.toContain('csrf-secret')
    expect(raw).not.toContain('hunter2')
    expect(Object.keys(JSON.parse(raw)[0]).sort()).toEqual([
      'display_name',
      'identifier',
      'last_used',
      'method',
      'realm',
    ])
  })

  it('reads a damaged or foreign value as no accounts', () => {
    for (const raw of ['not json', '{"identifier":"x"}', '42', 'null']) {
      localStorage.setItem('forge.accounts', raw)
      expect(listAccounts()).toEqual([])
    }
    localStorage.setItem(
      'forge.accounts',
      JSON.stringify([
        { identifier: 'ok@corp.example', method: 'oidc', realm: 'corp', last_used: 1 },
        { identifier: 'x', method: 'token', last_used: 2 },
        { identifier: '', method: 'password', last_used: 3 },
        { identifier: 'y'.repeat(300), method: 'password', last_used: 4 },
        'alice',
      ]),
    )
    expect(listAccounts().map((a) => a.identifier)).toEqual(['ok@corp.example'])
  })

  it('works without storage: nothing is listed and nothing throws', () => {
    const blocked = () => {
      throw new DOMException('blocked', 'SecurityError')
    }
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(blocked)
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(blocked)
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(blocked)

    expect(() =>
      rememberAccount({ identifier: 'alice@corp.example', method: 'password' }),
    ).not.toThrow()
    expect(listAccounts()).toEqual([])
    expect(() => forgetAccount('alice@corp.example')).not.toThrow()
    expect(() => forgetAllAccounts()).not.toThrow()
    expect(() => beginOidcSignIn('corp')).not.toThrow()
    expect(() => completePendingSignIn({ username: 'alice@corp.example' })).not.toThrow()
  })

  describe('an OIDC sign-in', () => {
    it('is remembered by the first identity after the round trip, once', () => {
      beginOidcSignIn('corp', 1_000)
      completePendingSignIn({ username: 'alice@corp.example', display_name: 'Alice' }, 2_000)
      expect(listAccounts()).toEqual([
        {
          identifier: 'alice@corp.example',
          display_name: 'Alice',
          method: 'oidc',
          realm: 'corp',
          last_used: 2_000,
        },
      ])
      // Later identities (every app load) do not touch it again.
      forgetAccount('alice@corp.example')
      completePendingSignIn({ username: 'alice@corp.example' }, 3_000)
      expect(listAccounts()).toEqual([])
    })

    it('is not remembered when it is abandoned or too old', () => {
      beginOidcSignIn('corp', 1_000)
      clearPendingSignIn()
      completePendingSignIn({ username: 'alice@corp.example' }, 2_000)
      expect(listAccounts()).toEqual([])

      beginOidcSignIn('corp', 1_000)
      completePendingSignIn({ username: 'alice@corp.example' }, 1_000 + 11 * 60 * 1000)
      expect(listAccounts()).toEqual([])
    })

    it('without a display name keeps none', () => {
      beginOidcSignIn('corp', 1_000)
      completePendingSignIn({ username: 'alice@corp.example', display_name: null }, 1_500)
      expect(listAccounts()[0]).not.toHaveProperty('display_name')
    })
  })
})
