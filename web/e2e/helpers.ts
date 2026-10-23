/**
 * Spec-side helpers: read the harness facts and talk to the Rust API directly
 * (the same single-origin API the browser uses) for arrange/assert steps that
 * are clearer done over HTTP than through the UI.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))

export interface HarnessFacts {
  baseUrl: string
  adminUser: string
  adminPass: string
  adminToken: string
  /** Service-index URL of the loopback mock upstream feed (proxy-delay spec). */
  upstreamIndexUrl: string
}

let cached: HarnessFacts | null = null

export function facts(): HarnessFacts {
  if (cached) return cached
  const raw = readFileSync(path.join(here, '.harness-facts.json'), 'utf8')
  cached = JSON.parse(raw) as HarnessFacts
  return cached
}

/**
 * Basic credentials for the admin API: the admin's username and its
 * admin-scoped token (the admin API refuses a password sent over Basic).
 */
export function adminBasic(): string {
  const f = facts()
  return 'Basic ' + Buffer.from(`${f.adminUser}:${f.adminToken}`).toString('base64')
}

/**
 * Sign the page's browser context in with a password session (the only UI
 * credential; there is no token sign-in): POST /auth/login through the
 * context's request API (so the `forge_session` cookie lands in the context's
 * cookie jar) and seed the returned CSRF token into localStorage before the
 * SPA boots — exactly what the Login screen does.
 */
export async function signInSession(
  page: import('@playwright/test').Page,
  username?: string,
  password?: string,
): Promise<void> {
  const f = facts()
  const res = await page.request.post(`${f.baseUrl}/auth/login`, {
    data: {
      username: username ?? f.adminUser,
      password: password ?? f.adminPass,
    },
  })
  if (!res.ok()) {
    throw new Error(`POST /auth/login -> ${res.status()}`)
  }
  const body = (await res.json()) as { csrf_token: string }
  await page.addInitScript((csrf) => {
    window.localStorage.setItem('forge.session.csrf', csrf)
  }, body.csrf_token)
}

/** Create a repository via the admin API (used by specs that need a fixture repo). */
export async function createRepo(body: Record<string, unknown>): Promise<Response> {
  const f = facts()
  return fetch(`${f.baseUrl}/admin/repositories`, {
    method: 'POST',
    headers: { authorization: adminBasic(), 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

/** Add a member (a repo name + a unique priority) to a group via the admin API. */
export async function addGroupMember(
  group: string,
  member: string,
  priority: number,
): Promise<Response> {
  const f = facts()
  return fetch(`${f.baseUrl}/admin/repositories/${group}/members`, {
    method: 'POST',
    headers: { authorization: adminBasic(), 'content-type': 'application/json' },
    body: JSON.stringify({ member, priority }),
  })
}

/**
 * Fetch a package's browse detail (the read endpoint the SPA's detail page
 * uses). For a proxy this also drives upstream **discovery** (it runs the
 * proxy read ops), so calling it stamps `first_seen_at` and surfaces a
 * still-delayed version with `delay_status = "delayed_until"`.
 */
export async function fetchPackageDetail(
  repo: string,
  id: string,
): Promise<{
  repo: string
  repo_kind: string
  versions: Array<{
    version: string
    version_original: string
    delay_status: string | null
    delayed_until?: string | null
  }>
  dependency_groups_by_version: Record<
    string,
    Array<{ dependencies: Array<{ id: string }> }>
  >
}> {
  const f = facts()
  // Browsing requires a signed-in user; authenticate the API probe as admin.
  const res = await fetch(
    `${f.baseUrl}/browse/packages/${encodeURIComponent(repo)}/${encodeURIComponent(id)}`,
    { headers: { authorization: adminBasic() } },
  )
  if (!res.ok) throw new Error(`GET package detail ${repo}/${id} -> ${res.status}`)
  return res.json()
}

/** Push a `.nupkg` (bytes) to a hosted repo via the NuGet multipart PUT. */
export async function pushNupkg(repo: string, bytes: Buffer): Promise<Response> {
  const f = facts()
  const form = new FormData()
  // Copy into a plain Uint8Array (over a non-shared ArrayBuffer) so the Blob
  // part typing is satisfied across Node Buffer versions.
  const view = new Uint8Array(bytes.byteLength)
  view.set(bytes)
  form.append('package', new Blob([view]), 'package.nupkg')
  return fetch(`${f.baseUrl}/v3/${repo}/package`, {
    method: 'PUT',
    headers: { 'X-NuGet-ApiKey': f.adminToken },
    body: form,
  })
}

/** Read a fixture `.nupkg` from the repo's fixtures/ dir. */
export function readFixture(rel: string): Buffer {
  const repoRoot = path.resolve(here, '..', '..')
  return readFileSync(path.join(repoRoot, 'fixtures', rel))
}

/** Poll the browse API until `id` appears under `repo`, or time out. */
export async function waitForPackage(
  repo: string,
  originalId: string,
  timeoutMs = 30_000,
): Promise<void> {
  const f = facts()
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const res = await fetch(
      `${f.baseUrl}/browse/packages?q=${encodeURIComponent(originalId)}`,
      { headers: { authorization: adminBasic() } },
    )
    if (res.ok) {
      const body: { items: Array<{ repo: string; original_id: string }> } =
        await res.json()
      if (body.items.some((i) => i.repo === repo && i.original_id === originalId)) {
        return
      }
    }
    await new Promise((r) => setTimeout(r, 1000))
  }
  throw new Error(`package ${originalId} never appeared in ${repo}`)
}
