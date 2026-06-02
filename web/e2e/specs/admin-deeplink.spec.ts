import { expect, test } from '@playwright/test'

import { facts } from '../helpers'

/**
 * KNOWN LIMITATION — admin UI routes collide with the admin API namespace.
 *
 * The admin REST API lives under `/admin/*` (e.g. `GET /admin/repositories`,
 * `GET /admin/repositories/{name}`). The admin **UI** routes in the SPA reuse
 * the same paths (`/admin/repositories`, `/admin/repositories/new`, ...). Since
 * the API router is mounted before the SPA fallback (correctly — it must own
 * `/admin/*`), a **hard navigation / refresh / bookmark** to an admin sub-page
 * is served by the API, not the SPA.
 *
 * In-app (client-side) navigation is unaffected: TanStack Router never
 * re-requests the document, so clicking through the nav works (covered in
 * auth.spec.ts / repos-and-packages.spec.ts). Only a fresh browser load of a
 * deep `/admin/...` URL is affected.
 *
 * These tests pin the CURRENT behavior so the collision is visible and tracked.
 * The fix (move the admin UI under a non-API prefix, e.g. `/manage/*`, leaving
 * the API at `/admin/*`) is deferred to a follow-up — it is a cross-cutting
 * rename of the Phase 4/5 route tree, out of scope for the Phase 6 pipeline.
 */
test.describe('admin UI / API path collision (known limitation)', () => {
  test('hard-loading /admin/repositories hits the API, not the SPA', async ({
    request,
  }) => {
    const f = facts()
    // No SPA index.html here: the API answers (401 unauthenticated).
    const res = await request.get(`${f.baseUrl}/admin/repositories`)
    expect(res.status()).toBe(401)
    const body = await res.text()
    expect(body).not.toContain('<!doctype html')
  })

  test('/admin (exactly) is served by the SPA (no API route at that path)', async ({
    request,
  }) => {
    const f = facts()
    const res = await request.get(`${f.baseUrl}/admin`)
    expect(res.ok()).toBeTruthy()
    expect(res.headers()['content-type'] ?? '').toContain('text/html')
  })
})
