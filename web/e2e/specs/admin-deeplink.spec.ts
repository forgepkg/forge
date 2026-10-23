import { expect, test } from '@playwright/test'

import { adminBasic, createRepo, facts, signInSession } from '../helpers'

/**
 * Admin UI deep links (M17).
 *
 * The admin REST API owns `/admin/*`; the admin **UI** lives under `/manage/*`
 * so a hard navigation / refresh / bookmark of any admin screen is served by
 * the SPA (index.html) and resolved client-side.
 */
test.describe('admin UI deep links', () => {
  test('hard-loading and refreshing /manage/repositories renders the list', async ({
    page,
  }) => {
    await signInSession(page)
    const res = await page.goto('/manage/repositories')
    expect(res?.status()).toBe(200)
    await expect(
      page.getByRole('heading', { name: /^repositories$/i }),
    ).toBeVisible()

    await page.reload()
    await expect(page).toHaveURL(/\/manage\/repositories$/)
    await expect(
      page.getByRole('heading', { name: /^repositories$/i }),
    ).toBeVisible()
  })

  test('deep links to a repository and a user resolve to their screens', async ({
    page,
    request,
  }) => {
    const f = facts()
    const name = `deeplink${Date.now()}`
    const created = await createRepo({ name, kind: 'hosted' })
    expect([200, 201]).toContain(created.status)
    const users = (await (
      await request.get(`${f.baseUrl}/admin/users`, {
        headers: { authorization: adminBasic() },
      })
    ).json()) as Array<{ id: number; username: string }>
    const admin = users.find((u) => u.username === f.adminUser)
    expect(admin, 'bootstrap admin listed').toBeTruthy()

    await signInSession(page)

    // Formerly the raw `GET /admin/repositories/{name}` JSON.
    await page.goto(`/manage/repositories/${name}`)
    await expect(
      page.getByRole('heading', { name: new RegExp(`edit ${name}`, 'i') }),
    ).toBeVisible()

    // Formerly a 405 (the API only has `DELETE /admin/users/{id}`).
    await page.goto(`/manage/users/${admin!.id}`)
    await expect(
      page.getByRole('heading', { level: 1, name: f.adminUser, exact: true }),
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { level: 2, name: /^tokens$/i }),
    ).toBeVisible()
  })

  test('a deep link while signed out returns there after sign-in', async ({
    page,
  }) => {
    const f = facts()
    await page.goto('/manage/realms')
    await expect(page).toHaveURL(/\/login\?.*redirect=%2Fmanage%2Frealms/)

    // Identifier-first or combined, depending on the login options.
    await page.getByLabel(/^username$/i).fill(f.adminUser)
    const cont = page.getByRole('button', { name: /^continue$/i })
    if (await cont.isVisible()) await cont.click()
    await page.getByLabel(/^password$/i).fill(f.adminPass)
    await page.getByRole('button', { name: /^sign in$/i }).click()

    await expect(page).toHaveURL(/\/manage\/realms$/)
    await expect(
      page.getByRole('heading', { name: /^authentication$/i }),
    ).toBeVisible()
  })

  test('requests to /admin/* are answered by the API', async ({
    request,
  }) => {
    const f = facts()
    // Unauthenticated JSON client: the API's 401, not a redirect or HTML.
    const anon = await request.get(`${f.baseUrl}/admin/repositories`, {
      headers: { accept: 'application/json' },
      maxRedirects: 0,
    })
    expect(anon.status()).toBe(401)
    expect(await anon.text()).not.toContain('<!doctype html')

    // Authenticated: the repository list as JSON.
    const authed = await request.get(`${f.baseUrl}/admin/repositories`, {
      headers: { accept: 'application/json', authorization: adminBasic() },
      maxRedirects: 0,
    })
    expect(authed.status()).toBe(200)
    expect(Array.isArray(await authed.json())).toBe(true)
  })
})
