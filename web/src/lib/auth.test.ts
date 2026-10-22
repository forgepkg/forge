import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  authHeaders,
  clearSession,
  getCsrfToken,
  isAuthenticated,
  onAuthChange,
  setSession,
} from './auth'

/**
 * Behavior tests for the single auth module. The UI holds only a cookie
 * session: the CSRF token is stored (the session itself lives in the httpOnly
 * cookie) and attached as `X-CSRF-Token`; no Authorization header is ever
 * emitted — registry tokens are not a UI credential.
 */
describe('auth', () => {
  beforeEach(() => clearSession())
  afterEach(() => clearSession())

  it('reports unauthenticated and emits no headers before a session is set', () => {
    expect(getCsrfToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(authHeaders()).toEqual({})
  })

  it('stores the CSRF token and emits X-CSRF-Token, never an Authorization header', () => {
    setSession('csrf-123')

    expect(getCsrfToken()).toBe('csrf-123')
    expect(isAuthenticated()).toBe(true)
    expect(authHeaders()).toEqual({ 'X-CSRF-Token': 'csrf-123' })
    expect(authHeaders().Authorization).toBeUndefined()
  })

  it('clears the session, dropping both the header and the authenticated state', () => {
    setSession('abc')
    clearSession()

    expect(getCsrfToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(authHeaders()).toEqual({})
  })

  it('removes a leftover legacy slice-1 token from storage', () => {
    localStorage.setItem('forge.token', 'stale-registry-token')

    setSession('csrf-123')
    expect(localStorage.getItem('forge.token')).toBeNull()

    localStorage.setItem('forge.token', 'stale-registry-token')
    clearSession()
    expect(localStorage.getItem('forge.token')).toBeNull()
  })

  it('notifies in-tab subscribers when the credential is set or cleared', () => {
    const listener = vi.fn()
    const unsubscribe = onAuthChange(listener)

    setSession('one')
    expect(listener).toHaveBeenCalledTimes(1)

    clearSession()
    expect(listener).toHaveBeenCalledTimes(2)

    unsubscribe()
    setSession('two')
    expect(listener).toHaveBeenCalledTimes(2) // no calls after unsubscribe
  })

  it('does not notify when clearing a session that was never stored (H4)', () => {
    // Every 401 calls clearSession; a notification makes the app shell
    // refetch its identity, so notifying for an already-cleared session fed
    // an endless 401 -> notify -> refetch -> 401 loop.
    const listener = vi.fn()
    const unsubscribe = onAuthChange(listener)

    clearSession()
    clearSession()
    expect(listener).not.toHaveBeenCalled()

    setSession('one')
    clearSession()
    clearSession()
    expect(listener).toHaveBeenCalledTimes(2) // the set + the first clear only

    unsubscribe()
  })
})
