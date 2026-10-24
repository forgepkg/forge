import { expect, test } from '@playwright/test'

import { createRepo, facts } from '../helpers'

/**
 * Single-origin serving. The Rust server serves the SPA and the API on one
 * origin: deep links resolve to index.html (SPA fallback), API routes are never
 * shadowed by the fallback, and API responses carry no CORS header (proving the
 * browser uses the same origin — no Node proxy).
 */
test.describe('single-origin serving', () => {
  test('root boots the SPA and gates anonymous visitors at login', async ({
    page,
  }) => {
    // Browsing requires a signed-in user, so an unauthenticated visitor is
    // client-side-redirected to the sign-in screen — the SPA shell is alive.
    await page.goto('/')
    await expect(page).toHaveURL(/\/login/)
    await expect(page.getByLabel(/^username$/i)).toBeVisible()
  })

  test('deep link is served by the SPA history fallback', async ({ page }) => {
    // A client-only route that is not a real file must return index.html (200)
    // and resolve client-side (the SPA app chrome renders), not a 404.
    const res = await page.goto('/packages/does-not-exist/whatever')
    expect(res?.status()).toBe(200)
    // The SPA took over: the login gate redirected this anonymous visitor to
    // the sign-in screen (a 404 would have rendered no SPA at all).
    await expect(page).toHaveURL(/\/login/)
    await expect(page.getByLabel(/^username$/i)).toBeVisible()
  })

  test('an admin UI deep link bounces an anonymous user to login', async ({
    page,
  }) => {
    // The server serves index.html (200) for /manage/*; the client-side guard
    // then redirects an anonymous user to login, remembering the target.
    const res = await page.goto('/manage/users')
    expect(res?.status()).toBe(200)
    await expect(page).toHaveURL(/\/login\?.*redirect=%2Fmanage%2Fusers/)
  })

  test('index.html is revalidated; hashed assets are immutable; a stale chunk is a 404', async ({
    request,
  }) => {
    const f = facts()
    const index = await request.get(`${f.baseUrl}/`)
    expect(index.headers()['cache-control']).toBe('no-cache')
    // Pick a real hashed asset out of the built index.html.
    const html = await index.text()
    const asset = html.match(/\/assets\/[^"']+\.js/)?.[0]
    expect(asset, 'index.html references a hashed asset').toBeTruthy()
    const hit = await request.get(`${f.baseUrl}${asset}`)
    expect(hit.status()).toBe(200)
    expect(hit.headers()['cache-control']).toBe(
      'public, max-age=31536000, immutable',
    )
    const miss = await request.get(`${f.baseUrl}/assets/Gone-0ld0ld0l.js`)
    expect(miss.status()).toBe(404)
    expect(await miss.text()).not.toContain('<div id="root"')
  })

  test('API routes are not shadowed by the SPA fallback', async ({ request }) => {
    const f = facts()
    // /admin/me is an API route: it must be handled by the API (200 when authed,
    // 401 when not) and must NOT return the SPA's index.html.
    const res = await request.get(`${f.baseUrl}/admin/me`)
    expect([200, 401]).toContain(res.status())
    const ct = res.headers()['content-type'] ?? ''
    expect(ct).not.toContain('text/html')
    const body = await res.text()
    expect(body).not.toContain('<!doctype html')
    expect(body).not.toContain('<div id="root"')
  })

  test('the V3 service index is served by the API', async ({ request }) => {
    const f = facts()
    // Create a hosted, anon-readable repo (with the admin-scoped token: the
    // admin API refuses a password over Basic), then its index.json must be
    // JSON. A retry finds the repo already there (409).
    const created = await createRepo({
      name: 'svcidx',
      kind: 'hosted',
      anonymous_read: true,
    })
    expect([200, 201, 409]).toContain(created.status)
    const res = await request.get(`${f.baseUrl}/repository/svcidx/index.json`)
    expect(res.ok()).toBeTruthy()
    const body = await res.json()
    expect(JSON.stringify(body)).toContain('PackagePublish')
  })

  test('prod API has no Access-Control-Allow-Origin header', async ({
    request,
  }) => {
    const f = facts()
    const res = await request.get(`${f.baseUrl}/admin/me`)
    expect(res.headers()['access-control-allow-origin']).toBeUndefined()
  })
})
