import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  authHeaders,
  clearToken,
  getAuthMode,
  getCsrfToken,
  getToken,
  isAuthenticated,
  onAuthChange,
  setSession,
  setToken,
} from './auth'

/**
 * Behavior tests for the single auth module (plan §3, §6 + §12.7 sessions).
 * Token mode: the credential is stored, attached as HTTP Basic with the token
 * as the *secret*, and changes are observable so the shell can react.
 * Session mode: only the CSRF token is stored (the session lives in the
 * cookie) and it is attached as `X-CSRF-Token` with no Authorization header.
 */
describe('auth', () => {
  beforeEach(() => clearToken())
  afterEach(() => clearToken())

  it('reports unauthenticated and emits no auth header before a token is set', () => {
    expect(getToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(authHeaders()).toEqual({})
  })

  it('stores a token and attaches it as the HTTP Basic secret', () => {
    setToken('s3cret-token')

    expect(getToken()).toBe('s3cret-token')
    expect(isAuthenticated()).toBe(true)

    const header = authHeaders().Authorization
    expect(header).toMatch(/^Basic /)
    // The token is the Basic *secret*, with the literal user "token" (slice-1 §5).
    expect(atob(header.slice('Basic '.length))).toBe('token:s3cret-token')
  })

  it('clears the token, dropping both the header and the authenticated state', () => {
    setToken('abc')
    clearToken()

    expect(getToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(authHeaders()).toEqual({})
  })

  it('session mode: stores the CSRF token and emits X-CSRF-Token, no Basic header', () => {
    setSession('csrf-123')

    expect(getAuthMode()).toBe('session')
    expect(getCsrfToken()).toBe('csrf-123')
    expect(getToken()).toBeNull()
    expect(isAuthenticated()).toBe(true)
    expect(authHeaders()).toEqual({ 'X-CSRF-Token': 'csrf-123' })
  })

  it('setting one credential kind replaces the other', () => {
    setToken('a-token')
    setSession('a-csrf')
    expect(getAuthMode()).toBe('session')
    expect(getToken()).toBeNull()

    setToken('b-token')
    expect(getAuthMode()).toBe('token')
    expect(getCsrfToken()).toBeNull()
    expect(authHeaders().Authorization).toMatch(/^Basic /)
  })

  it('clearToken clears a session credential too', () => {
    setSession('csrf-123')
    clearToken()

    expect(getAuthMode()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(authHeaders()).toEqual({})
  })

  it('notifies in-tab subscribers when the credential is set or cleared', () => {
    const listener = vi.fn()
    const unsubscribe = onAuthChange(listener)

    setToken('one')
    expect(listener).toHaveBeenCalledTimes(1)

    clearToken()
    expect(listener).toHaveBeenCalledTimes(2)

    unsubscribe()
    setToken('two')
    expect(listener).toHaveBeenCalledTimes(2) // no calls after unsubscribe
  })
})
