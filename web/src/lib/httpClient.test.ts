import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { httpClient, ApiError } from './httpClient'
import { setToken, clearToken } from './auth'

/**
 * Phase 1 smoke tests (plan §Testing): the shared `httpClient` injects the auth
 * header, resolves the (relative, single-origin) base URL, and clears the
 * stored token on a 401.
 */
describe('httpClient', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearToken()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearToken()
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

  it('injects an HTTP Basic auth header carrying the token as the secret', async () => {
    setToken('s3cret-token')
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))

    await httpClient.get('/admin/me')

    const [, init] = fetchMock.mock.calls[0]
    const auth = (init.headers as Record<string, string>).Authorization
    expect(auth).toMatch(/^Basic /)
    // base64("token:s3cret-token")
    const decoded = atob(auth.slice('Basic '.length))
    expect(decoded).toBe('token:s3cret-token')
  })

  it('sends no auth header when unauthenticated', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))

    await httpClient.get('/admin/me')

    const [, init] = fetchMock.mock.calls[0]
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined()
  })

  it('throws ApiError and clears the token on 401', async () => {
    setToken('stale')
    fetchMock.mockResolvedValueOnce(
      new Response('authentication required', { status: 401 }),
    )

    await expect(httpClient.get('/admin/me')).rejects.toBeInstanceOf(ApiError)
    expect(localStorage.getItem('forge.token')).toBeNull()
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
