import { expect, test } from '@playwright/test'

import {
  facts,
  openFromRail,
  pushNupkg,
  readFixture,
  signInSession,
  waitForPackage,
} from '../helpers'

/**
 * Create-a-repo flow + push-then-see-package.
 *
 * An admin creates a hosted repo through the UI; it appears in the repositories
 * list and its V3 index advertises PackagePublish. A `.nupkg` pushed via the
 * NuGet API then shows up under that repository in the folder-view Browse and
 * in package detail with its version and dependency groups.
 */

test.beforeEach(async ({ page }) => {
  await signInSession(page)
})

/**
 * Navigate (client-side) from Browse to the admin repositories list, the way a
 * user does (hard loads of /manage/* are covered in admin-deeplink.spec.ts).
 */
async function gotoRepositoriesList(page: import('@playwright/test').Page) {
  await page.goto('/')
  await openFromRail(page, 'Repositories')
  await expect(page).toHaveURL(/\/manage\/repositories$/)
}

/** Create a hosted, anon-readable repo through the real UI form. */
async function createHostedViaUi(
  page: import('@playwright/test').Page,
  name: string,
) {
  await gotoRepositoriesList(page)
  await page.getByRole('link', { name: /new repository/i }).click()
  await expect(page).toHaveURL(/\/manage\/repositories\/new/)

  await page.getByLabel(/^name$/i).fill(name)
  await page.getByLabel(/^kind$/i).selectOption('hosted')
  await page.getByLabel(/allow anonymous read/i).check()
  await page.getByRole('button', { name: /create repository/i }).click()

  // On success we navigate (client-side) to the new repo's edit page.
  await expect(page).toHaveURL(new RegExp(`/manage/repositories/${name}`))
}

test('admin creates a hosted repo via the UI and it appears in the list', async ({
  page,
  request,
}) => {
  const f = facts()
  const name = `uihosted${Date.now()}`

  await createHostedViaUi(page, name)

  // It shows in the repositories list.
  await gotoRepositoriesList(page)
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible()

  // And the V3 service index advertises PackagePublish (verified via the API).
  const idx = await request.get(`${f.baseUrl}/v3/${name}/index.json`)
  expect(idx.ok()).toBeTruthy()
  expect(JSON.stringify(await idx.json())).toContain('PackagePublish')
})

test('a pushed package appears in the repo folder view and in package detail', async ({
  page,
}) => {
  const repo = `pushseen${Date.now()}`

  await createHostedViaUi(page, repo)

  // Push the fixture .nupkg (Sample.Lib) via the NuGet API, then wait for the
  // browse index to reflect it (outbox/indexing is async).
  const bytes = readFixture('nuget/sample.lib.1.0.0.nupkg')
  const res = await pushNupkg(repo, bytes)
  expect([200, 201, 202, 204]).toContain(res.status)
  await waitForPackage(repo, 'Sample.Lib')

  // Folder view: open the repository from the Browse root, then search within
  // it — search is per repository now, so there is no cross-repo ambiguity.
  await page.goto('/')
  // (The rail lists the repository too; open it from the page.)
  await page
    .getByRole('main')
    .getByRole('link', { name: new RegExp(`\\b${repo}\\b`) })
    .click()
  await expect(page).toHaveURL(new RegExp(`/repos/${repo}`))
  await page.getByRole('searchbox').fill('Sample.Lib')
  const pkgLink = page.getByRole('link', { name: /Sample\.Lib/ })
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
