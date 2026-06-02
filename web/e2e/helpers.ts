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
}

let cached: HarnessFacts | null = null

export function facts(): HarnessFacts {
  if (cached) return cached
  const raw = readFileSync(path.join(here, '.harness-facts.json'), 'utf8')
  cached = JSON.parse(raw) as HarnessFacts
  return cached
}

export function adminBasic(): string {
  const f = facts()
  return 'Basic ' + Buffer.from(`${f.adminUser}:${f.adminPass}`).toString('base64')
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
