import { expect, test } from '@playwright/test'

import { adminBasic, facts, signInSession } from '../helpers'

/**
 * Password sign-in + admin gating (plan §Testing #2, #3).
 *
 * The UI signs in with username+password (or a realm); registry-token sign-in
 * does not exist. A wrong password stays on Login with the uniform error; an
 * admin session reveals the Admin nav; a non-admin session cannot reach
 * /admin/* (the route guard redirects to Browse); signing out invalidates the
 * cookie session and clears the stored CSRF token.
 */

/**
 * Drive the real Login screen. Handles both layouts: identifier-first (type
 * username, Continue, then password) and combined (both fields at once).
 */
async function uiSignIn(
  page: import('@playwright/test').Page,
  username: string,
  password: string,
) {
  await page.goto('/login')
  await page.getByLabel(/^username$/i).fill(username)
  const passwordField = page.getByLabel(/^password$/i)
  if (!(await passwordField.isVisible().catch(() => false))) {
    await page.getByRole('button', { name: /^continue$/i }).click()
    await passwordField.waitFor()
  }
  await passwordField.fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
}

/** Create a non-admin user via the admin API; returns its credentials. */
async function createReader(
  request: import('@playwright/test').APIRequestContext,
): Promise<{ username: string; password: string }> {
  const f = facts()
  const username = `reader_${Date.now()}`
  const password = 'reader-pw'
  const createUser = await request.post(`${f.baseUrl}/admin/users`, {
    headers: { authorization: adminBasic() },
    data: { username, password, is_admin: false },
  })
  expect(createUser.ok()).toBeTruthy()
  return { username, password }
}

test('a wrong password stays on login with the uniform error', async ({
  page,
}) => {
  const f = facts()
  await uiSignIn(page, f.adminUser, 'definitely-not-the-password')
  await expect(page.getByRole('alert')).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
})

test('password sign-in lands on Browse and reveals the Admin nav', async ({
  page,
}) => {
  const f = facts()
  await uiSignIn(page, f.adminUser, f.adminPass)
  // Lands on Browse.
  await expect(page).toHaveURL(/\/$|\/\?/)
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
  // Admin nav link is visible for an admin.
  await expect(page.getByRole('link', { name: /^admin$/i })).toBeVisible()
})

test('admin can navigate to the repositories admin screen', async ({ page }) => {
  await signInSession(page)
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
  const reader = await createReader(request)
  await signInSession(page, reader.username, reader.password)
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
  const reader = await createReader(request)
  await signInSession(page, reader.username, reader.password)
  // `/admin` (exactly) has no API route, so the SPA serves it; the client-side
  // guard then redirects an authenticated non-admin to Browse.
  await page.goto('/admin')
  await expect(page).toHaveURL(/\/$|\/\?/)
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
})

test('sign out invalidates the session and returns to login', async ({
  page,
}) => {
  await signInSession(page)
  await page.goto('/')
  await page.getByRole('button', { name: /sign out/i }).click()
  await expect(page).toHaveURL(/\/login/)
  const stored = await page.evaluate(() =>
    window.localStorage.getItem('forge.session.csrf'),
  )
  expect(stored).toBeNull()
  // The cookie session is dead server-side too: /auth/me is 401 again.
  const me = await page.request.get(`${facts().baseUrl}/auth/me`)
  expect(me.status()).toBe(401)
})
