import { expect, test } from '@playwright/test'

import { facts } from '../helpers'

/**
 * Single-origin serving (plan §Testing #1, #8). The Rust server serves the SPA
 * and the API on one origin: deep links resolve to index.html (SPA fallback),
 * API routes are never shadowed by the fallback, and API responses carry no CORS
 * header (proving the browser uses the same origin — no Node proxy).
 */
test.describe('single-origin serving', () => {
  test('root boots the SPA into Browse', async ({ page }) => {
    // Anonymous reads are enabled, so an unauthenticated visitor lands on the
    // Browse screen — the SPA shell is alive and client-rendered.
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: /^browse$/i }),
    ).toBeVisible()
  })

  test('deep link is served by the SPA history fallback', async ({ page }) => {
    // A client-only route that is not a real file must return index.html (200)
    // and resolve client-side (the SPA app chrome renders), not a 404.
    const res = await page.goto('/packages/does-not-exist/whatever')
    expect(res?.status()).toBe(200)
    // The SPA took over: the app nav (a Browse link in the shell) is present.
    await expect(page.getByRole('link', { name: /^browse$/i })).toBeVisible()
  })

  test('the /admin landing deep link bounces an anonymous user to login', async ({
    page,
  }) => {
    // `/admin` (exactly) has no API route, so the server serves index.html
    // (200); the client-side admin guard then redirects an anonymous user to
    // login. (Deeper /admin/* paths collide with the API — see
    // admin-deeplink.spec.ts.)
    const res = await page.goto('/admin')
    expect(res?.status()).toBe(200)
    await expect(page).toHaveURL(/\/login/)
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
    // Create a hosted, anon-readable repo, then its index.json must be JSON.
    await request.post(`${f.baseUrl}/admin/repositories`, {
      headers: {
        authorization:
          'Basic ' +
          Buffer.from(`${f.adminUser}:${f.adminPass}`).toString('base64'),
      },
      data: { name: 'svcidx', kind: 'hosted', anonymous_read: true },
    })
    const res = await request.get(`${f.baseUrl}/v3/svcidx/index.json`)
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
