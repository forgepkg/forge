import { expect, test } from '@playwright/test'

import { adminBasic, facts } from '../helpers'

/**
 * Token sign-in + admin gating (plan §Testing #2, #3).
 *
 * Slice 1 has no sessions yet, so auth is token-paste: the Login screen verifies
 * the pasted token via GET /admin/me and only then stores it. An invalid token
 * stays on Login with an error; an admin token reveals the Admin nav; a
 * non-admin token cannot reach /admin/* (the route guard redirects to login).
 */

/** Seed the token into localStorage before the SPA boots (avoids retyping it). */
async function signInWithToken(page: import('@playwright/test').Page, token: string) {
  await page.addInitScript((t) => {
    window.localStorage.setItem('forge.token', t)
  }, token)
}

/** Create a non-admin user + token via the admin API, return the plaintext token. */
async function mintNonAdminToken(
  request: import('@playwright/test').APIRequestContext,
): Promise<string> {
  const f = facts()
  const username = `reader_${Date.now()}`
  const createUser = await request.post(`${f.baseUrl}/admin/users`, {
    headers: { authorization: adminBasic() },
    data: { username, password: 'reader-pw', is_admin: false },
  })
  expect(createUser.ok()).toBeTruthy()
  const user = await createUser.json()
  const createTok = await request.post(
    `${f.baseUrl}/admin/users/${user.id}/tokens`,
    { headers: { authorization: adminBasic() }, data: { name: 'e2e-reader' } },
  )
  expect(createTok.ok()).toBeTruthy()
  const body = await createTok.json()
  return body.token as string
}

test('invalid token stays on login with an error', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel(/registry token/i).fill('definitely-not-a-real-token')
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByRole('alert')).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
})

test('valid admin token lands on Browse and reveals the Admin nav', async ({
  page,
}) => {
  const f = facts()
  await page.goto('/login')
  await page.getByLabel(/registry token/i).fill(f.adminToken)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  // Lands on Browse.
  await expect(page).toHaveURL(/\/$|\/\?/)
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
  // Admin nav link is visible for an admin.
  await expect(page.getByRole('link', { name: /^admin$/i })).toBeVisible()
})

test('admin can navigate to the repositories admin screen', async ({ page }) => {
  const f = facts()
  await signInWithToken(page, f.adminToken)
  // Drive via in-app (client-side) navigation: land on Browse, then use the
  // Admin nav. (Hard-navigating to /admin/repositories hits the same-named API
  // route — see admin-deeplink.spec.ts for that documented collision.)
  await page.goto('/')
  await page.getByRole('link', { name: /^admin$/i }).click()
  await expect(page).toHaveURL(/\/admin$/)
  await page.getByRole('link', { name: /repositor/i }).first().click()
  await expect(page).toHaveURL(/\/admin\/repositories/)
  await expect(
    page.getByRole('heading', { name: /^repositories$/i }),
  ).toBeVisible()
})

test('a non-admin reader never sees the Admin nav (gating)', async ({
  page,
  request,
}) => {
  const token = await mintNonAdminToken(request)
  await signInWithToken(page, token)
  // The reader sees Browse but NOT the Admin nav link (cosmetic gate), so there
  // is no in-app path to any admin screen.
  await page.goto('/')
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
  await expect(page.getByRole('link', { name: /^admin$/i })).toHaveCount(0)
})

test('the admin route guard redirects a non-admin away from /admin (hard nav)', async ({
  page,
  request,
}) => {
  const token = await mintNonAdminToken(request)
  await signInWithToken(page, token)
  // `/admin` (exactly) has no API route, so the SPA serves it; the client-side
  // guard then redirects an authenticated non-admin to Browse.
  await page.goto('/admin')
  await expect(page).toHaveURL(/\/$|\/\?/)
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
})

test('sign out clears the credential and returns to login', async ({ page }) => {
  const f = facts()
  await signInWithToken(page, f.adminToken)
  await page.goto('/')
  await page.getByRole('button', { name: /sign out/i }).click()
  await expect(page).toHaveURL(/\/login/)
  const stored = await page.evaluate(() =>
    window.localStorage.getItem('forge.token'),
  )
  expect(stored).toBeNull()
})
