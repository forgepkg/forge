/**
 * E2E harness: bring up the infra (Postgres + versitygw) and a real
 * `forge-server` process serving the built SPA, then expose its base URL +
 * bootstrap-admin credentials to the Playwright specs.
 *
 * This deliberately drives the **actual Rust server binary** against the same
 * container images the Rust testcontainers harness uses (Postgres 17 +
 * versity/versitygw:v1.4.1), proving the single-origin serving model end to end:
 * the browser hits `/`, `/admin/*`, `/browse/*`, `/v3/*` on one origin with no
 * Node proxy.
 *
 * Lifecycle is owned by Playwright's globalSetup/globalTeardown; the resolved
 * facts (base URL, admin token) are handed to specs via env vars + a JSON file.
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { startMockUpstream, type MockUpstream } from './mock-upstream'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..', '..')
const webDir = path.resolve(here, '..')

const COMPOSE_PROJECT = 'forge-web-e2e'
const COMPOSE_FILE = path.join(here, 'docker-compose.e2e.yml')

// Distinct host ports from the dev stack (5433 / 8422) so e2e never collides.
// All three stay below 32768, outside Linux's ephemeral port range
// (32768-60999): a port in it can already be the local end of an outgoing
// connection (the CI runner's own, a registry pull), and binding it then fails
// with "address already in use".
const PG_PORT = 25432
const S3_PORT = 27070
// The server under test listens here (distinct from dev :8421).
const SERVER_PORT = 28421

// Host where the compose-published container ports are reachable. Defaults to
// loopback (local + GitHub runners). With a remote Docker daemon (e.g. a
// Docker-in-Docker service named `docker`), published ports live on the
// daemon's host — set FORGE_E2E_DOCKER_HOST to it.
const DOCKER_HOST_NAME = process.env.FORGE_E2E_DOCKER_HOST ?? '127.0.0.1'

export const ADMIN_USER = 'admin@example.com'
export const ADMIN_PASS = 'changeme'
export const BASE_URL = `http://127.0.0.1:${SERVER_PORT}`

/** Facts the specs need, persisted to disk so each worker can read them. */
export interface HarnessFacts {
  baseUrl: string
  adminUser: string
  adminPass: string
  adminToken: string
  /**
   * Service-index URL of the in-process mock upstream NuGet feed (loopback).
   * Configured as a proxy repo's `remote_url` by the proxy-delay spec. It is a
   * fake *upstream registry*, not a proxy of the forge API.
   */
  upstreamIndexUrl: string
}

export const FACTS_PATH = path.join(here, '.harness-facts.json')

let serverProc: ChildProcess | null = null
let mockUpstream: MockUpstream | null = null

/** Read a fixture `.nupkg` from the repo's fixtures/ dir. */
function readFixture(rel: string): Buffer {
  return readFileSync(path.join(repoRoot, 'fixtures', rel))
}

function run(cmd: string, args: string[], opts: { cwd?: string } = {}) {
  const res = spawnSync(cmd, args, {
    cwd: opts.cwd ?? repoRoot,
    stdio: 'inherit',
    env: process.env,
  })
  if (res.status !== 0) {
    throw new Error(`\`${cmd} ${args.join(' ')}\` failed (exit ${res.status})`)
  }
}

function compose(args: string[]) {
  run('docker', ['compose', '-p', COMPOSE_PROJECT, '-f', COMPOSE_FILE, ...args])
}

async function sleep(ms: number) {
  await new Promise((r) => setTimeout(r, ms))
}

/** Poll until `fn` returns true or the deadline passes. */
async function waitFor(
  label: string,
  fn: () => Promise<boolean>,
  timeoutMs = 60_000,
  intervalMs = 1000,
) {
  const deadline = Date.now() + timeoutMs
  let lastErr: unknown
  while (Date.now() < deadline) {
    try {
      if (await fn()) return
    } catch (e) {
      lastErr = e
    }
    await sleep(intervalMs)
  }
  throw new Error(`timed out waiting for ${label}: ${String(lastErr)}`)
}

/** Build the SPA into web/dist (the server serves this directory). */
function buildSpa() {
  run('pnpm', ['run', 'build'], { cwd: webDir })
}

/** Build the server binary once up front so the boot wait isn't a compile wait. */
function buildServer() {
  run('cargo', ['build', '-p', 'forge-server'])
  process.env.SQLX_OFFLINE = 'true'
}

/** Launch the server process with env config pointed at the e2e infra. */
function startServer() {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    SQLX_OFFLINE: 'true',
    // database
    FORGE_DATABASE__URL: `postgres://forge:forge@${DOCKER_HOST_NAME}:${PG_PORT}/forge`,
    // s3 (versitygw)
    FORGE_S3__ENDPOINT: `http://${DOCKER_HOST_NAME}:${S3_PORT}`,
    FORGE_S3__REGION: 'us-east-1',
    FORGE_S3__BUCKET: 'forge',
    FORGE_S3__ACCESS_KEY: 'test',
    FORGE_S3__SECRET_KEY: 'test',
    FORGE_S3__FORCE_PATH_STYLE: 'true',
    // server
    FORGE_SERVER__BIND: `127.0.0.1:${SERVER_PORT}`,
    FORGE_SERVER__PUBLIC_BASE_URL: BASE_URL,
    // The e2e bootstrap admin uses the placeholder password (dev stack only).
    FORGE_SERVER__ALLOW_INSECURE_DEFAULTS: 'true',
    // auth: anonymous reads and password Basic are auth settings, stored in
    // the database (`openAccess` sets them once the server is up).
    FORGE_AUTH__BOOTSTRAP_ADMIN__USERNAME: ADMIN_USER,
    FORGE_AUTH__BOOTSTRAP_ADMIN__PASSWORD: ADMIN_PASS,
    // web UI: serve the freshly built dist (single origin).
    FORGE_WEB__ENABLED: 'true',
    FORGE_WEB__ASSETS_DIR: path.join(webDir, 'dist'),
    // outbox: drain quickly so a pushed package becomes visible fast.
    FORGE_OUTBOX__POLL_INTERVAL_SECONDS: '1',
    FORGE_OUTBOX__GRACE_SECONDS: '0',
    // secret encryption (required), with a fixed *test* root key.
    FORGE_CRYPTO__ROOT__PROVIDER: 'env',
    FORGE_ROOT_KEY: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
  }
  serverProc = spawn('cargo', ['run', '-p', 'forge-server'], {
    cwd: repoRoot,
    env,
    stdio: 'inherit',
  })
  serverProc.on('exit', (code) => {
    if (code && code !== 0 && code !== null) {
      // eslint-disable-next-line no-console
      console.error(`forge-server exited early with code ${code}`)
    }
  })
}

/** A signed-in admin session: the cookie pair and its CSRF token. */
interface AdminSession {
  cookie: string
  csrf: string
}

/**
 * Sign the bootstrap admin in. The admin API refuses a password sent over
 * HTTP Basic, so this goes through `/auth/login` (session cookie + CSRF
 * token).
 */
async function signInAdmin(): Promise<AdminSession> {
  const login = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS }),
  })
  if (!login.ok) throw new Error(`POST /auth/login -> ${login.status}`)
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0]
  const { csrf_token: csrf }: { csrf_token: string } = await login.json()
  if (!cookie || !csrf) throw new Error('login returned no session')
  return { cookie, csrf }
}

/**
 * Open anonymous reads (so the Browse screen works without a token) and
 * password Basic (so specs can use the bootstrap admin's password on the
 * feeds): auth settings, changed through the admin API.
 */
async function openAccess({ cookie, csrf }: AdminSession): Promise<void> {
  const res = await fetch(`${BASE_URL}/admin/settings/auth`, {
    method: 'PUT',
    headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' },
    body: JSON.stringify({ anonymous_mode: 'all', allow_password_basic: true }),
  })
  if (!res.ok) throw new Error(`PUT /admin/settings/auth -> ${res.status}`)
}

/** Mint an admin-scoped API token for the bootstrap admin from its session. */
async function mintAdminToken({ cookie, csrf }: AdminSession): Promise<string> {
  const tokRes = await fetch(`${BASE_URL}/admin/me/tokens`, {
    method: 'POST',
    headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'e2e', scope: { actions: ['admin'] } }),
  })
  if (!tokRes.ok) throw new Error(`POST /admin/me/tokens -> ${tokRes.status}`)
  const body: { token: string } = await tokRes.json()
  if (!body.token) throw new Error('token response missing plaintext token')
  return body.token
}

/** Full bring-up: infra -> build -> server -> mint token -> persist facts. */
export async function setup(): Promise<HarnessFacts> {
  // 1. Infra (idempotent: --wait blocks until healthy).
  compose(['up', '-d', '--wait'])

  // 2. Build artefacts (UI + server) before launching.
  buildSpa()
  buildServer()

  // 3. Wait for Postgres to actually accept TCP from the host before the server
  //    tries to connect (compose --wait uses the in-container healthcheck).
  await waitFor('postgres tcp', async () => {
    const probe = spawnSync('docker', [
      'compose',
      '-p',
      COMPOSE_PROJECT,
      '-f',
      COMPOSE_FILE,
      'exec',
      '-T',
      'db',
      'pg_isready',
      '-U',
      'forge',
      '-d',
      'forge',
    ])
    return probe.status === 0
  })

  // 3b. Wait for versitygw to accept HTTP (the image has no healthcheck tool,
  //     so we probe from the host). Any HTTP response — including a 403/400 —
  //     proves the gateway is listening before the server's ensure_bucket runs.
  await waitFor('versitygw http', async () => {
    try {
      await fetch(`http://${DOCKER_HOST_NAME}:${S3_PORT}/`)
      return true
    } catch {
      return false
    }
  })

  // 4. Launch the server; it runs migrations + bootstraps the admin on boot.
  startServer()

  // 5. Wait for the SPA index to be served (proves UI + server are up).
  await waitFor('server /', async () => {
    const res = await fetch(`${BASE_URL}/`)
    return res.ok
  })

  // 6. Open anonymous reads and password Basic, and mint an admin token for
  //    the token-sign-in spec.
  const session = await signInAdmin()
  await openAccess(session)
  const adminToken = await mintAdminToken(session)

  // 7. Boot the mock upstream feed (loopback) for the proxy-delay spec. It
  //    serves the `Sample.Lib` fixture at the upstream's original version casing
  //    (`1.02.3`), which the proxy normalizes to `1.2.3` on discovery.
  mockUpstream = await startMockUpstream([
    {
      id: 'Sample.Lib',
      versions: { '1.02.3': readFixture('nuget/sample.lib.1.0.0.nupkg') },
    },
  ])

  const facts: HarnessFacts = {
    baseUrl: BASE_URL,
    adminUser: ADMIN_USER,
    adminPass: ADMIN_PASS,
    adminToken,
    upstreamIndexUrl: mockUpstream.indexUrl,
  }
  writeFileSync(FACTS_PATH, JSON.stringify(facts, null, 2))
  return facts
}

/** Tear everything down: stop the mock upstream, the server, then containers. */
export async function teardown() {
  if (mockUpstream) {
    try {
      await mockUpstream.close()
    } catch {
      // best-effort
    }
    mockUpstream = null
  }
  if (serverProc && !serverProc.killed) {
    serverProc.kill('SIGTERM')
    // Give it a moment to exit cleanly before compose down.
    await sleep(1000)
    if (!serverProc.killed) serverProc.kill('SIGKILL')
  }
  try {
    compose(['down', '-v'])
  } catch {
    // best-effort cleanup
  }
  try {
    rmSync(FACTS_PATH, { force: true })
  } catch {
    // ignore
  }
}
