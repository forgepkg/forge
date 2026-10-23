import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { httpClient, ApiError, onUnauthorized } from './httpClient'
import { setSession, clearSession, getCsrfToken } from './auth'

/**
 * Smoke tests: the shared `httpClient` injects the CSRF header for the cookie
 * session, resolves the (relative, single-origin) base URL, and clears the
 * stored session on a 401.
 */
describe('httpClient', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }

  it('resolves a relative same-origin URL and parses JSON', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))

    const result = await httpClient.get<{ ok: boolean }>('/admin/me')

    expect(result).toEqual({ ok: true })
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/admin/me')
    expect(init.credentials).toBe('same-origin')
  })

  it('injects the X-CSRF-Token header when a session is active', async () => {
    setSession('csrf-123')
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))

    await httpClient.get('/admin/me')

    const [, init] = fetchMock.mock.calls[0]
    const headers = init.headers as Record<string, string>
    expect(headers['X-CSRF-Token']).toBe('csrf-123')
    expect(headers.Authorization).toBeUndefined()
  })

  it('sends no auth headers when unauthenticated', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))

    await httpClient.get('/admin/me')

    const [, init] = fetchMock.mock.calls[0]
    const headers = init.headers as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
    expect(headers['X-CSRF-Token']).toBeUndefined()
  })

  it('throws ApiError and clears the session on 401', async () => {
    setSession('stale')
    fetchMock.mockResolvedValueOnce(
      new Response('authentication required', { status: 401 }),
    )

    await expect(httpClient.get('/admin/me')).rejects.toBeInstanceOf(ApiError)
    expect(localStorage.getItem('forge.session.csrf')).toBeNull()
  })

  it('reports a 401 to the registered handler, unless the call opts out', async () => {
    const handler = vi.fn()
    const unregister = onUnauthorized(handler)
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response('authentication required', { status: 401 })),
    )

    await expect(httpClient.get('/admin/me')).rejects.toMatchObject({ status: 401 })
    expect(handler).toHaveBeenCalledTimes(1)

    await expect(
      httpClient.post('/auth/logout', undefined, { skipUnauthorizedHandler: true }),
    ).rejects.toMatchObject({ status: 401 })
    expect(handler).toHaveBeenCalledTimes(1)

    unregister()
    await expect(httpClient.get('/admin/me')).rejects.toMatchObject({ status: 401 })
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('a stale unregister does not remove a newer handler', async () => {
    const first = vi.fn()
    const second = vi.fn()
    const unregisterFirst = onUnauthorized(first)
    const unregisterSecond = onUnauthorized(second)
    unregisterFirst() // e.g. a StrictMode / remount cleanup running late
    fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }))

    await expect(httpClient.get('/admin/me')).rejects.toBeInstanceOf(ApiError)
    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledTimes(1)
    unregisterSecond()
  })

  it('re-syncs the CSRF token from /auth/me after a CSRF 403 and retries once', async () => {
    setSession('stale-csrf')
    const seen: Array<[string, string, string | undefined]> = []
    fetchMock.mockImplementation((url: string, init: RequestInit) => {
      const csrf = (init.headers as Record<string, string>)['X-CSRF-Token']
      seen.push([init.method ?? 'GET', url, csrf])
      if (url === '/auth/me') {
        return Promise.resolve(
          jsonResponse({ user_id: 1, username: 'a', is_admin: false, csrf_token: 'fresh-csrf' }),
        )
      }
      if (csrf === 'fresh-csrf') return Promise.resolve(jsonResponse({ ok: true }))
      return Promise.resolve(
        new Response('missing or invalid csrf token', { status: 403 }),
      )
    })

    const result = await httpClient.post<{ ok: boolean }>('/admin/me/tokens', { name: 't' })

    expect(result).toEqual({ ok: true })
    expect(getCsrfToken()).toBe('fresh-csrf')
    expect(seen).toEqual([
      ['POST', '/admin/me/tokens', 'stale-csrf'],
      ['GET', '/auth/me', 'stale-csrf'],
      ['POST', '/admin/me/tokens', 'fresh-csrf'],
    ])
    // The retried request carried the original body.
    expect(fetchMock.mock.calls[2][1].body).toBe(JSON.stringify({ name: 't' }))
  })

  it('does not retry a CSRF 403 when the session token did not change', async () => {
    setSession('same-csrf')
    fetchMock.mockImplementation((url: string) => {
      if (url === '/auth/me') {
        return Promise.resolve(
          jsonResponse({ user_id: 1, username: 'a', is_admin: false, csrf_token: 'same-csrf' }),
        )
      }
      return Promise.resolve(
        new Response('missing or invalid csrf token', { status: 403 }),
      )
    })

    await expect(httpClient.delete('/admin/tokens/1')).rejects.toMatchObject({
      status: 403,
    })
    expect(fetchMock).toHaveBeenCalledTimes(2) // the DELETE + one /auth/me
  })

  it('does not re-sync on a 403 that is not a CSRF rejection, or on a read', async () => {
    setSession('csrf')
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response('admin privileges required', { status: 403 })),
    )
    await expect(httpClient.put('/admin/repositories/x', {})).rejects.toMatchObject({
      status: 403,
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)

    fetchMock.mockReset()
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response('missing or invalid csrf token', { status: 403 })),
    )
    await expect(httpClient.get('/admin/repositories')).rejects.toMatchObject({
      status: 403,
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('exposes Retry-After (seconds) on the error', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response('too many failed sign-in attempts; try again later', {
        status: 429,
        headers: { 'retry-after': '120' },
      }),
    )
    await expect(httpClient.post('/auth/login', {})).rejects.toMatchObject({
      status: 429,
      retryAfterSeconds: 120,
    })
  })

  it('appends defined query parameters and drops undefined ones', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, items: [] }))

    await httpClient.get('/browse/packages', {
      query: { q: 'json', take: 20, repo: undefined },
    })

    const [url] = fetchMock.mock.calls[0]
    expect(url).toBe('/browse/packages?q=json&take=20')
  })
})
