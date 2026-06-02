import { expect, test } from '@playwright/test'

import { facts, fetchPackageDetail } from '../helpers'

/**
 * Proxy delay status (plan §Testing #7).
 *
 * An admin configures a proxy with a long package delay through the repository
 * form. A version freshly discovered upstream is inside the delay window, so:
 *
 *   - the package-detail view renders the `DelayBadge` as **delayed** (the
 *     version exists upstream but is not yet downloadable);
 *   - the version is **absent from downloadable browse** — search never surfaces
 *     a delay-gated proxy version, so the package does not appear in the Browse
 *     list until the window elapses.
 *
 * The upstream is the loopback mock feed booted by the harness
 * (`facts().upstreamIndexUrl`); a loopback remote requires `allow_private_upstream`
 * to clear the SSRF guard, which the form exposes as a checkbox.
 *
 * Admin UI sub-routes collide with the admin API namespace, so the proxy is
 * created via in-app navigation (never a hard `/admin/...` load).
 */

const TOKEN_KEY = 'forge.token'

test.beforeEach(async ({ page }) => {
  const f = facts()
  await page.addInitScript(
    ({ key, token }) => window.localStorage.setItem(key, token),
    { key: TOKEN_KEY, token: f.adminToken },
  )
})

test('a delayed proxy version shows the delay badge and is absent from browse', async ({
  page,
}) => {
  const f = facts()
  const proxy = `dlyproxy${Date.now()}`

  // 1. Create the proxy via the UI: a 1-hour delay so a just-discovered version
  //    stays inside the window for the whole test.
  await page.goto('/')
  await page.getByRole('link', { name: /^admin$/i }).click()
  await page.getByRole('link', { name: /repositor/i }).first().click()
  await expect(page).toHaveURL(/\/admin\/repositories$/)
  await page.getByRole('link', { name: /new repository/i }).click()

  await page.locator('#repo-name').fill(proxy)
  await page.locator('#repo-kind').selectOption('proxy')
  await page.locator('#repo-anon').check()
  await page.locator('#repo-remote-url').fill(f.upstreamIndexUrl)
  await page.locator('#repo-delay').fill('3600')
  await page.locator('#repo-allow-private').check()
  await page.getByRole('button', { name: /create repository/i }).click()
  await expect(page).toHaveURL(new RegExp(`/admin/repositories/${proxy}`))

  // 2. Trigger upstream discovery: hitting the detail read path runs the proxy
  //    read ops, which stamp `first_seen_at` and (because the delay has not
  //    elapsed) surface the version as `delayed_until`.
  const detail = await fetchPackageDetail(proxy, 'Sample.Lib')
  const delayed = detail.versions.find((v) => v.delay_status === 'delayed_until')
  expect(delayed, 'a delayed version should be surfaced').toBeTruthy()
  expect(delayed?.delayed_until).toBeTruthy()

  // 3. Package detail in the browser: the delay badge reads "delayed". (For a
  //    delayed-only proxy package there is no cached original casing yet, so the
  //    heading shows the requested lowercased id — match case-insensitively.)
  await page.goto(`/packages/${proxy}/sample.lib`)
  await expect(page.getByRole('heading', { name: /sample\.lib/i })).toBeVisible()
  // The version row carries the delayed badge.
  const row = page.getByRole('row', { name: /1\.2\.3/ })
  await expect(row).toBeVisible()
  await expect(row.getByText(/delayed/)).toBeVisible()

  // 4. The delay-gated version is absent from downloadable browse: search never
  //    surfaces a delay-gated proxy version, so no Browse row points at THIS
  //    proxy. (Other specs may have published Sample.Lib to hosted repos in this
  //    shared server, so we assert on the proxy's row specifically, not on the
  //    id alone.)
  await page.goto('/')
  await page.getByRole('searchbox').fill('Sample.Lib')
  // Let the debounced search settle and any hosted rows render first.
  await expect(page.getByRole('searchbox')).toHaveValue('Sample.Lib')
  await page.waitForLoadState('networkidle')
  // No row mentions this proxy repository while its only version is delayed.
  await expect(page.getByRole('cell', { name: proxy, exact: true })).toHaveCount(0)

  // Cross-check via the read API: a repo-scoped search returns nothing for the
  // delayed proxy (the version is delay-gated out of the searchable set).
  const scoped = await fetch(
    `${f.baseUrl}/browse/packages?q=Sample.Lib&repo=${proxy}`,
  )
  expect(scoped.ok).toBeTruthy()
  const body: { total: number; items: unknown[] } = await scoped.json()
  expect(body.total).toBe(0)
  expect(body.items).toHaveLength(0)
})
