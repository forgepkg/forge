import { expect, test } from '@playwright/test'

import {
  adminBasic,
  facts,
  fetchPackageDetail,
  openFromRail,
  signInSession,
} from '../helpers'

/**
 * Proxy delay status.
 *
 * An admin configures a proxy with a long package delay through the repository
 * form. The package page shows what the proxy has cached and asks no upstream
 * (#836), so the package is **not cached** until **Refresh from upstream**
 * discovers it. A version freshly discovered upstream is inside the delay
 * window, so:
 *
 *   - the package-detail view renders the `DelayBadge` as **delayed** (the
 *     version exists upstream but is not yet downloadable);
 *   - the version is **absent from downloadable browse** — search never surfaces
 *     a delay-gated proxy version, so the package does not appear in the Browse
 *     list until the window elapses.
 *
 * The upstream is the loopback mock feed booted by the harness
 * (`facts().upstreamIndexUrl`).
 *
 * The proxy is created via in-app navigation (Browse -> Admin nav).
 */

test.beforeEach(async ({ page }) => {
  await signInSession(page)
})

test('a delayed proxy version shows the delay badge and is absent from browse', async ({
  page,
}) => {
  const f = facts()
  const proxy = `dlyproxy${Date.now()}`

  // 1. Create the proxy via the UI: a 1-hour delay so a just-discovered version
  //    stays inside the window for the whole test.
  await page.goto('/')
  await openFromRail(page, 'Repositories')
  await expect(page).toHaveURL(/\/manage\/repositories$/)
  await page.getByRole('link', { name: /new repository/i }).click()

  // (The SSRF guard checks only the scheme, so the loopback upstream needs no
  // allow-private flag.)
  await page.getByLabel(/^name$/i).fill(proxy)
  await page.getByLabel(/^kind$/i).selectOption('proxy')
  await page.getByLabel(/allow anonymous read/i).check()
  await page.getByLabel(/remote url/i).fill(f.upstreamIndexUrl)
  await page.getByLabel('Package delay (seconds)').fill('3600')
  await page.getByRole('button', { name: /create repository/i }).click()
  await expect(page).toHaveURL(new RegExp(`/manage/repositories/${proxy}`))

  // 2. The package page answers from the cache and asks no upstream: the proxy
  //    holds nothing of the package yet, so the page says it is not cached
  //    (looking does not discover it). The page shows that once its detail
  //    query has given up on the 404, after two retries a few seconds apart.
  await page.goto(`/packages/${proxy}/sample.lib`)
  await expect(page.getByText('Package not cached')).toBeVisible({ timeout: 15_000 })

  // 3. Refresh from upstream asks the upstream, as a client's install does:
  //    it stamps the version's `first_seen_at`, and as the delay has not
  //    elapsed the page shows it delayed. (For a delayed-only proxy package
  //    there is no cached original casing yet, so the heading shows the
  //    requested lowercased id — match case-insensitively.)
  await page.getByRole('button', { name: 'Refresh from upstream' }).click()
  // The version row carries the delayed badge.
  const row = page
    .getByRole('table', { name: /^Versions of / })
    .getByRole('row', { name: /1\.2\.3/ })
  await expect(row).toBeVisible()
  await expect(row.getByText(/delayed/)).toBeVisible()
  await expect(page.getByRole('heading', { name: /sample\.lib/i })).toBeVisible()

  // The detail API, from the cache now, surfaces the version as delayed.
  const detail = await fetchPackageDetail(proxy, 'Sample.Lib')
  const delayed = detail.versions.find((v) => v.delay_status === 'delayed_until')
  expect(delayed, 'a delayed version should be surfaced').toBeTruthy()
  expect(delayed?.delayed_until).toBeTruthy()

  // 4. The delay-gated version is absent from downloadable browse: search in
  //    THIS proxy's folder view never surfaces a delay-gated version, so the
  //    repository renders its empty state.
  await page.goto(`/repos/${proxy}?q=Sample.Lib`)
  await expect(page.getByRole('searchbox')).toHaveValue('Sample.Lib')
  await expect(page.getByText('No packages found')).toBeVisible()

  // Cross-check via the read API: a repo-scoped search returns nothing for the
  // delayed proxy (the version is delay-gated out of the searchable set).
  const scoped = await fetch(
    `${f.baseUrl}/browse/packages?q=Sample.Lib&repo=${proxy}`,
    { headers: { authorization: adminBasic() } },
  )
  expect(scoped.ok).toBeTruthy()
  const body: { total: number; items: unknown[] } = await scoped.json()
  expect(body.total).toBe(0)
  expect(body.items).toHaveLength(0)
})
