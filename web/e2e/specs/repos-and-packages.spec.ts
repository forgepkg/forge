import { expect, test } from '@playwright/test'

import { facts, pushNupkg, readFixture, waitForPackage } from '../helpers'

/**
 * Create-a-repo flow + push-then-see-package (plan §Testing #4, #5).
 *
 * An admin creates a hosted repo through the UI; it appears in the repositories
 * list and its V3 index advertises PackagePublish. A `.nupkg` pushed via the
 * NuGet API then shows up in Browse and in package detail with its version and
 * dependency groups.
 */

const TOKEN_KEY = 'forge.token'

async function signIn(page: import('@playwright/test').Page) {
  const f = facts()
  await page.addInitScript(
    ({ key, token }) => window.localStorage.setItem(key, token),
    { key: TOKEN_KEY, token: f.adminToken },
  )
}

test.beforeEach(async ({ page }) => {
  await signIn(page)
})

/**
 * Navigate (client-side) from Browse to the admin repositories list. Hard
 * navigation to /admin/repositories hits the same-named API route, so the UI is
 * always reached via in-app links (see admin-deeplink.spec.ts).
 */
async function gotoRepositoriesList(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByRole('link', { name: /^admin$/i }).click()
  await page.getByRole('link', { name: /repositor/i }).first().click()
  await expect(page).toHaveURL(/\/admin\/repositories$/)
}

test('admin creates a hosted repo via the UI and it appears in the list', async ({
  page,
  request,
}) => {
  const f = facts()
  const name = `uihosted${Date.now()}`

  await gotoRepositoriesList(page)
  await page.getByRole('link', { name: /new repository/i }).click()
  await expect(page).toHaveURL(/\/admin\/repositories\/new/)

  await page.locator('#repo-name').fill(name)
  await page.locator('#repo-kind').selectOption('hosted')
  await page.locator('#repo-anon').check()
  await page.getByRole('button', { name: /create repository/i }).click()

  // On success we navigate (client-side) to the new repo's edit page.
  await expect(page).toHaveURL(new RegExp(`/admin/repositories/${name}`))

  // It shows in the list (the name is rendered as a table cell, not a link).
  await gotoRepositoriesList(page)
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible()

  // And the V3 service index advertises PackagePublish (verified via the API).
  const idx = await request.get(`${f.baseUrl}/v3/${name}/index.json`)
  expect(idx.ok()).toBeTruthy()
  expect(JSON.stringify(await idx.json())).toContain('PackagePublish')
})

test('a pushed package appears in Browse and in package detail', async ({
  page,
}) => {
  const f = facts()
  const repo = `pushseen${Date.now()}`

  // Create a hosted, anon-readable repo via the UI (client-side navigation).
  await gotoRepositoriesList(page)
  await page.getByRole('link', { name: /new repository/i }).click()
  await expect(page).toHaveURL(/\/admin\/repositories\/new/)
  await page.locator('#repo-name').fill(repo)
  await page.locator('#repo-kind').selectOption('hosted')
  await page.locator('#repo-anon').check()
  await page.getByRole('button', { name: /create repository/i }).click()
  await expect(page).toHaveURL(new RegExp(`/admin/repositories/${repo}`))

  // Push the fixture .nupkg (Sample.Lib) via the NuGet API, then wait for the
  // browse index to reflect it (outbox/indexing is async).
  const bytes = readFixture('nuget/sample.lib.1.0.0.nupkg')
  const res = await pushNupkg(repo, bytes)
  expect([200, 201, 202, 204]).toContain(res.status)
  await waitForPackage(repo, 'Sample.Lib')

  // Browse shows it.
  await page.goto('/')
  await page.getByRole('searchbox').fill('Sample.Lib')
  const pkgLink = page.getByRole('link', { name: 'Sample.Lib' })
  await expect(pkgLink).toBeVisible({ timeout: 15_000 })

  // Package detail shows the version + a dependency.
  await pkgLink.click()
  await expect(page).toHaveURL(/\/packages\//)
  await expect(page.getByText(/Sample\.Lib/).first()).toBeVisible()
  // The pushed version (normalized 1.2.3) is listed.
  await expect(page.getByText('1.2.3').first()).toBeVisible()
  // A dependency from the nuspec is rendered.
  await expect(page.getByText(/Newtonsoft\.Json/).first()).toBeVisible()
})
