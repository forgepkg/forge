import { expect, test } from '@playwright/test'

import {
  createRepo,
  fetchPackageDetail,
  pushNupkg,
  readFixture,
  signInSession,
  waitForPackage,
} from '../helpers'

/**
 * Group + priority (plan §Testing #6).
 *
 * An admin creates a group of two members and sets their priorities through the
 * `PriorityList` editor (the Members screen). Both members publish the SAME
 * package id + version, but with a DISTINCT dependency, so the group's resolved
 * package detail reveals which member won: per slice-1 §7 the highest-priority
 * member wins ties, and the group's registration surfaces that member's
 * dependency group.
 *
 * Member fixtures:
 *   - winner  → `sample.lib.winner.1.0.0.nupkg`  (dep `WinnerMarker.Dependency`)
 *   - loser   → `sample.lib.1.0.0.nupkg`         (dep `Newtonsoft.Json`)
 * Both are `Sample.Lib` @ `1.2.3`.
 *
 * The admin UI is reached via in-app navigation (Browse -> Admin nav); hard
 * loads of `/manage/...` deep links are covered in admin-deeplink.spec.ts.
 */

test.beforeEach(async ({ page }) => {
  await signInSession(page)
})

test('a group resolves the highest-priority member for an overlapping id+version', async ({
  page,
}) => {
  const stamp = Date.now()
  const winner = `grpwin${stamp}`
  const loser = `grplose${stamp}`
  const group = `grp${stamp}`

  // 1. Two hosted, anon-readable members, each with the same Sample.Lib@1.2.3
  //    but a distinct dependency. (Arranged over the API — the create-repo and
  //    push flows already have dedicated UI coverage in repos-and-packages.)
  for (const name of [winner, loser]) {
    const res = await createRepo({ name, kind: 'hosted', anonymous_read: true })
    expect([200, 201]).toContain(res.status)
  }
  expect([200, 201, 202, 204]).toContain(
    (await pushNupkg(winner, readFixture('nuget/sample.lib.winner.1.0.0.nupkg')))
      .status,
  )
  expect([200, 201, 202, 204]).toContain(
    (await pushNupkg(loser, readFixture('nuget/sample.lib.1.0.0.nupkg'))).status,
  )
  await waitForPackage(winner, 'Sample.Lib')
  await waitForPackage(loser, 'Sample.Lib')

  // 2. Create the group via the UI (client-side navigation only).
  await page.goto('/')
  await page.getByRole('link', { name: /^admin$/i }).click()
  await page.getByRole('link', { name: /repositor/i }).first().click()
  await expect(page).toHaveURL(/\/manage\/repositories$/)
  await page.getByRole('link', { name: /new repository/i }).click()
  await page.getByLabel(/^name$/i).fill(group)
  await page.getByLabel(/^kind$/i).selectOption('group')
  await page.getByLabel(/allow anonymous read/i).check()
  await page.getByRole('button', { name: /create repository/i }).click()
  await expect(page).toHaveURL(new RegExp(`/manage/repositories/${group}`))

  // 3. Open the group's Members screen and add both members with priorities via
  //    the PriorityList add form: winner HIGH (200), loser LOW (100).
  await page.getByRole('link', { name: /members/i }).first().click()
  await expect(page).toHaveURL(
    new RegExp(`/manage/repositories/${group}/members`),
  )

  await page.getByLabel(/^repository$/i).selectOption(winner)
  await page.getByRole('spinbutton', { name: /^priority$/i }).fill('200')
  await page.getByRole('button', { name: /add member/i }).click()
  // The winner row appears in the priority list.
  await expect(page.getByText(winner, { exact: false })).toBeVisible()

  await page.getByLabel(/^repository$/i).selectOption(loser)
  await page.getByRole('spinbutton', { name: /^priority$/i }).fill('100')
  await page.getByRole('button', { name: /add member/i }).click()
  await expect(page.getByText(loser, { exact: false })).toBeVisible()

  // The PriorityList orders members by descending priority — winner first.
  const priorities = page.locator('[aria-label="priority"]')
  await expect(priorities.first()).toHaveText('200')
  await expect(priorities.nth(1)).toHaveText('100')

  // 4. Browse the GROUP's package detail: the resolved version comes from the
  //    highest-priority member, so its distinct dependency is what shows.
  await page.goto(`/packages/${group}/sample.lib`)
  await expect(page.getByRole('heading', { name: /Sample\.Lib/ })).toBeVisible()
  await expect(page.getByText('1.2.3').first()).toBeVisible()
  // Winner's dependency is present; the loser's is not.
  await expect(page.getByText(/WinnerMarker\.Dependency/).first()).toBeVisible()
  await expect(page.getByText(/Newtonsoft\.Json/)).toHaveCount(0)

  // 5. Cross-check via the read API the SPA uses: same winner resolution.
  const detail = await fetchPackageDetail(group, 'sample.lib')
  expect(detail.repo_kind).toBe('group')
  const deps = Object.values(detail.dependency_groups_by_version)
    .flat()
    .flatMap((g) => g.dependencies.map((d) => d.id))
  expect(deps).toContain('WinnerMarker.Dependency')
  expect(deps).not.toContain('Newtonsoft.Json')
})
