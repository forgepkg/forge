/**
 * In-process mock upstream NuGet V3 feed for the proxy-delay e2e scenario.
 *
 * This is the Node twin of the Rust `crates/e2e/src/mock_upstream.rs`: it serves
 * the same three shapes the slice-1 proxy client consumes —
 *
 *  - `GET /index.json` — a service index advertising `PackageBaseAddress/3.0.0`,
 *    `RegistrationsBaseUrl`, and `SearchQueryService`;
 *  - `GET /flat/{id}/index.json` — the flat-container version index
 *    (`{ "versions": [...] }`), which is what `discover_versions` reads to stamp
 *    `first_seen_at` on each version;
 *  - `GET /flat/{id}/{version}/{file}` — the raw `.nupkg` bytes;
 *  - `GET /registration/{id}/index.json` — the registration index.
 *
 * It listens on an ephemeral **loopback** port so the forge-server (running on
 * the same host in the harness) can reach it; the proxy repo is therefore
 * created with `allow_private_upstream: true` to clear the SSRF guard.
 *
 * The corpus is `lowerId -> { version -> nupkg bytes }`; unknown ids 404 (a
 * genuine upstream miss). No Node proxy of the forge API is involved — this is a
 * standalone fake *upstream registry*, exactly the role nuget.org would play.
 */
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

/** One package in the mock corpus: an id plus its versions and bytes. */
export interface UpstreamPackage {
  /** Package id as the upstream advertises it (matched case-insensitively). */
  id: string
  /** `version -> nupkg bytes`. */
  versions: Record<string, Buffer>
}

/** A running mock upstream feed; holds the server and exposes its base URL. */
export interface MockUpstream {
  /** Base URL (no trailing slash), e.g. `http://127.0.0.1:54321`. */
  base: string
  /** The service-index URL to configure as a proxy's `remote_url`. */
  indexUrl: string
  /** Stop the server. */
  close: () => Promise<void>
}

function json(res: import('node:http').ServerResponse, status: number, body: unknown) {
  const payload = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(payload)
}

/** Boot the mock feed on an ephemeral loopback port with the given corpus. */
export async function startMockUpstream(
  packages: UpstreamPackage[],
): Promise<MockUpstream> {
  // lowerId -> { version -> bytes }
  const corpus = new Map<string, Record<string, Buffer>>()
  for (const p of packages) {
    corpus.set(p.id.toLowerCase(), p.versions)
  }

  // Resolved once the server is listening (used to build absolute @id URLs).
  let base = ''

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', base || 'http://127.0.0.1')
    const path = url.pathname

    // Service index.
    if (path === '/index.json') {
      json(res, 200, {
        version: '3.0.0',
        resources: [
          { '@id': `${base}/flat/`, '@type': 'PackageBaseAddress/3.0.0' },
          { '@id': `${base}/registration/`, '@type': 'RegistrationsBaseUrl/3.6.0' },
          { '@id': `${base}/query`, '@type': 'SearchQueryService/3.5.0' },
        ],
      })
      return
    }

    // Flat version index: /flat/{id}/index.json
    const flatIndex = path.match(/^\/flat\/([^/]+)\/index\.json$/)
    if (flatIndex) {
      const id = decodeURIComponent(flatIndex[1]).toLowerCase()
      const vers = corpus.get(id)
      if (!vers) {
        res.writeHead(404).end()
        return
      }
      json(res, 200, { versions: Object.keys(vers).sort() })
      return
    }

    // Nupkg bytes: /flat/{id}/{version}/{file}
    const nupkg = path.match(/^\/flat\/([^/]+)\/([^/]+)\/[^/]+$/)
    if (nupkg) {
      const id = decodeURIComponent(nupkg[1]).toLowerCase()
      const version = decodeURIComponent(nupkg[2])
      const bytes = corpus.get(id)?.[version]
      if (!bytes) {
        res.writeHead(404).end()
        return
      }
      res.writeHead(200, { 'content-type': 'application/octet-stream' })
      res.end(bytes)
      return
    }

    // Registration index: /registration/{id}/index.json
    const reg = path.match(/^\/registration\/([^/]+)\/index\.json$/)
    if (reg) {
      const rawId = decodeURIComponent(reg[1])
      const lower = rawId.toLowerCase()
      const vers = corpus.get(lower)
      if (!vers) {
        res.writeHead(404).end()
        return
      }
      const items = Object.keys(vers).map((v) => ({
        catalogEntry: { id: rawId, version: v, listed: true },
        packageContent: `${base}/flat/${lower}/${v}/${lower}.${v}.nupkg`,
      }))
      json(res, 200, { count: 1, items: [{ count: items.length, items }] })
      return
    }

    res.writeHead(404).end()
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve)
  })
  const addr = server.address() as AddressInfo
  base = `http://127.0.0.1:${addr.port}`

  return {
    base,
    indexUrl: `${base}/index.json`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  }
}
