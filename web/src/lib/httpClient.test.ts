import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { httpClient, ApiError } from './httpClient'
import { setSession, clearSession } from './auth'

/**
 * Smoke tests (plan §Testing): the shared `httpClient` injects the CSRF header
 * for the cookie session, resolves the (relative, single-origin) base URL, and
 * clears the stored session on a 401.
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

  it('appends defined query parameters and drops undefined ones', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, items: [] }))

    await httpClient.get('/browse/packages', {
      query: { q: 'json', take: 20, repo: undefined },
    })

    const [url] = fetchMock.mock.calls[0]
    expect(url).toBe('/browse/packages?q=json&take=20')
  })
})
