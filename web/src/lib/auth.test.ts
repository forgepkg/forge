import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  authHeaders,
  clearToken,
  getToken,
  isAuthenticated,
  onAuthChange,
  setToken,
} from './auth'

/**
 * Behavior tests for the single auth module (plan §3, §6). The whole token ->
 * cookie-session swap lives here, so these lock the slice-1 token behavior:
 * the credential is stored, attached as HTTP Basic with the token as the
 * *secret*, and changes are observable so the shell can react.
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
