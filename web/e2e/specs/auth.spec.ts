import { expect, test } from '@playwright/test'

import { adminBasic, facts, openFromRail, rail, signInSession } from '../helpers'

/**
 * Password sign-in + admin gating.
 *
 * The UI signs in with username+password (or a realm); registry-token sign-in
 * does not exist. A wrong password stays on Login with the uniform error; an
 * admin session reveals the Admin nav; a non-admin session cannot reach
 * /manage/* (the route guard redirects to Browse); signing out invalidates the
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

/**
 * Create a non-admin user the way an administrator and its user do (#322):
 * the admin invites it and, with no email service configured, gets the
 * invitation link; the user chooses the password from it. Returns its
 * credentials.
 */
async function createReader(
  request: import('@playwright/test').APIRequestContext,
): Promise<{ username: string; password: string }> {
  const f = facts()
  const username = `reader_${Date.now()}@example.com`
  const password = 'reader-password'
  const createUser = await request.post(`${f.baseUrl}/admin/users`, {
    headers: { authorization: adminBasic() },
    data: { username },
  })
  expect(createUser.ok()).toBeTruthy()
  const created = (await createUser.json()) as { invitation: { link: string } }
  const token = created.invitation.link.split('#')[1]
  const accepted = await request.post(`${f.baseUrl}/auth/invitations/accept`, {
    data: { token, password },
  })
  expect(accepted.ok()).toBeTruthy()
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

test('password sign-in lands on Browse and reveals the Administration links', async ({
  page,
}) => {
  const f = facts()
  await uiSignIn(page, f.adminUser, f.adminPass)
  // Lands on Browse.
  await expect(page).toHaveURL(/\/$|\/\?/)
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
  // The rail's Administration links are visible for an admin.
  await expect(rail(page).getByRole('link', { name: 'Overview', exact: true })).toBeVisible()
})

test('admin can navigate to the repositories admin screen', async ({ page }) => {
  await signInSession(page)
  // Drive via in-app (client-side) navigation: land on Browse, then use the
  // rail's Administration links. (Hard loads of /manage/* deep links are
  // covered in admin-deeplink.spec.ts.)
  await page.goto('/')
  await openFromRail(page, 'Overview')
  await expect(page).toHaveURL(/\/manage$/)
  await openFromRail(page, 'Repositories')
  await expect(page).toHaveURL(/\/manage\/repositories/)
  await expect(
    page.getByRole('heading', { name: /^repositories$/i }),
  ).toBeVisible()
})

test('a non-admin reader never sees the Administration links (gating)', async ({
  page,
  request,
}) => {
  const reader = await createReader(request)
  await signInSession(page, reader.username, reader.password)
  // The reader sees Browse but NOT the Administration links (cosmetic gate),
  // so there is no in-app path to any admin screen.
  await page.goto('/')
  await expect(page.getByRole('heading', { name: /^browse$/i })).toBeVisible()
  await expect(rail(page).getByRole('link', { name: 'Overview', exact: true })).toHaveCount(0)
  await expect(rail(page).getByText('Administration')).toHaveCount(0)
})

test('the admin route guard redirects a non-admin away from /manage (hard nav)', async ({
  page,
  request,
}) => {
  const reader = await createReader(request)
  await signInSession(page, reader.username, reader.password)
  // The SPA serves /manage/*; the client-side guard then redirects an
  // authenticated non-admin to Browse.
  await page.goto('/manage/repositories')
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
