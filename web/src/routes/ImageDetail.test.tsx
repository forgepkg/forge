import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { ChartDetail, ImageDetail } from '~/api/images'
import { textContent } from '~/test/text'
import { routeTree } from '~/routeTree.gen'
import { searchOptions } from '~/lib/search'

/**
 * Image-detail screen of a docker repository: the pull commands (selected /
 * default tag and by digest), the tags table (short digest + copy, size,
 * platforms), the manifests table (kind, referrer hint, source in groups),
 * and the not-found / error states. Drives the real route tree (the image
 * name is the `/images/$repo/$` splat, slashes included) + `useImageDetail`.
 */

const readerMe: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}
const adminMe: Me = {
  user: { id: 1, username: 'admin', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read'],
}

const INDEX = 'sha256:1111111111aa' + '0'.repeat(52)
const AMD64 = 'sha256:2222222222bb' + '0'.repeat(52)
const ARM64 = 'sha256:3333333333cc' + '0'.repeat(52)
const SIG = 'sha256:4444444444dd' + '0'.repeat(52)

const hostedDetail: ImageDetail = {
  repo: 'docker-hosted',
  repo_kind: 'hosted',
  image: 'team/app',
  registry: 'forge.example.com',
  pull_name: 'forge.example.com/docker-hosted/team/app',
  tags: [
    {
      tag: '1.36',
      digest: INDEX,
      media_type: 'application/vnd.oci.image.index.v1+json',
      size: 4_412_804,
      platforms: ['linux/amd64', 'linux/arm64/v8'],
    },
    {
      tag: 'latest',
      digest: AMD64,
      media_type: 'application/vnd.oci.image.manifest.v1+json',
      size: 2_206_402,
      platforms: ['linux/amd64'],
    },
  ],
  manifests: [
    {
      digest: INDEX,
      media_type: 'application/vnd.oci.image.index.v1+json',
      artifact_type: null,
      subject_digest: null,
      manifest_size: 610,
      size: 4_412_804,
      platforms: ['linux/amd64', 'linux/arm64/v8'],
      tags: ['1.36'],
      children: [AMD64, ARM64],
      created_at: '2026-10-21T10:58:44Z',
      last_pulled_at: null,
    },
    {
      digest: AMD64,
      media_type: 'application/vnd.oci.image.manifest.v1+json',
      artifact_type: 'application/vnd.oci.image.config.v1+json',
      subject_digest: null,
      manifest_size: 480,
      size: 2_206_402,
      platforms: ['linux/amd64'],
      tags: ['latest'],
      children: [],
      created_at: '2026-10-21T10:58:44Z',
      last_pulled_at: '2026-10-21T11:00:00Z',
    },
    {
      digest: ARM64,
      media_type: 'application/vnd.oci.image.manifest.v1+json',
      artifact_type: 'application/vnd.oci.image.config.v1+json',
      subject_digest: null,
      manifest_size: 480,
      size: 2_206_402,
      platforms: ['linux/arm64/v8'],
      tags: [],
      children: [],
      created_at: '2026-10-21T10:58:44Z',
      last_pulled_at: null,
    },
    {
      digest: SIG,
      media_type: 'application/vnd.oci.image.manifest.v1+json',
      artifact_type: 'application/vnd.dev.cosign.artifact.sig.v1+json',
      subject_digest: INDEX,
      manifest_size: 320,
      size: null,
      platforms: [],
      tags: [],
      children: [],
      created_at: '2026-10-21T10:59:00Z',
      last_pulled_at: null,
    },
  ],
}

const fetchMock = vi.fn()

/**
 * Route the mock: `/admin/me` -> identity (`me`, a reader by default),
 * `/browse/images/{repo}/{image…}`, `/browse/chart` -> `chart` (404 without
 * one), and a `DELETE /admin/repositories/{repo}/images` -> `deleteImage`.
 */
function mockApi(
  detail: (repo: string, image: string) => Response,
  chart?: (query: URLSearchParams) => Response,
  {
    me = readerMe,
    deleteImage,
  }: {
    me?: Me
    deleteImage?: (repo: string, query: URLSearchParams) => Response | Promise<Response>
  } = {},
) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) {
      return Promise.resolve(jsonResponse(me))
    }
    const del = url.pathname.match(/^\/admin\/repositories\/([^/]+)\/images$/)
    if (del && init?.method === 'DELETE' && deleteImage) {
      return Promise.resolve(deleteImage(decodeURIComponent(del[1]), url.searchParams))
    }
    if (url.pathname.endsWith('/browse/chart')) {
      return Promise.resolve(
        chart ? chart(url.searchParams) : new Response('chart not found', { status: 404 }),
      )
    }
    const m = url.pathname.match(/\/browse\/images\/([^/]+)\/(.+)$/)
    if (m) return Promise.resolve(detail(m[1], m[2]))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

/** Test query client with retries off so error/empty states resolve promptly. */
function testQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
}

async function renderDetail(path: string) {
  const queryClient = testQueryClient()
  const router = createRouter({
    routeTree,
    ...searchOptions,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [path] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

describe('ImageDetail', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    clearSession()
  })

  it('fetches the image by its full (slashed) name and shows breadcrumbs', async () => {
    const requested: string[] = []
    mockApi((repo, image) => {
      requested.push(`${repo}|${image}`)
      return jsonResponse(hostedDetail)
    })

    await renderDetail('/images/docker-hosted/team/app')

    expect(
      await screen.findByRole('heading', { name: 'team/app' }),
    ).toBeInTheDocument()
    expect(requested).toContain('docker-hosted|team/app')
    const crumbs = screen.getByRole('navigation', { name: 'Breadcrumb' })
    expect(within(crumbs).getByRole('link', { name: 'docker-hosted' })).toHaveAttribute(
      'href',
      '/repos/docker-hosted',
    )
    expect(within(crumbs).getByText('team/app')).toBeInTheDocument()
  })

  it('shows pull commands for `latest` and by digest; the tag select switches them', async () => {
    mockApi(() => jsonResponse(hostedDetail))

    const user = userEvent.setup()
    const router = await renderDetail('/images/docker-hosted/team/app')

    const pull = await screen.findByRole('region', { name: 'Pull' })
    // `latest`, though `1.36` sorts first.
    expect(
      within(pull).getByText('docker pull forge.example.com/docker-hosted/team/app:latest'),
    ).toBeInTheDocument()
    expect(
      within(pull).getByText(`docker pull forge.example.com/docker-hosted/team/app@${AMD64}`),
    ).toBeInTheDocument()
    // The login hint names the registry and links to the Tokens page.
    expect(within(pull).getByText('docker login forge.example.com')).toBeInTheDocument()
    expect(within(pull).getByRole('link', { name: 'Your tokens' })).toHaveAttribute(
      'href',
      '/tokens',
    )

    await user.selectOptions(within(pull).getByLabelText('Tag'), '1.36')

    expect(
      await within(pull).findByText(
        'docker pull forge.example.com/docker-hosted/team/app:1.36',
      ),
    ).toBeInTheDocument()
    expect(
      within(pull).getByText(`docker pull forge.example.com/docker-hosted/team/app@${INDEX}`),
    ).toBeInTheDocument()
    expect(router.state.location.search).toMatchObject({ tag: '1.36' })
    // Written as typed, as a link to the page would be (#403).
    expect(router.state.location.searchStr).toBe('?tag=1.36')
  })

  it('without `latest`, starts with the newest image tag, not a signature tag', async () => {
    const sigTag = `sha256-${INDEX.slice('sha256:'.length)}.sig`
    const image = (digest: string, created_at: string) => ({
      ...hostedDetail.manifests[1],
      digest,
      created_at,
    })
    const OLD = 'sha256:5555555555ee' + '0'.repeat(52)
    mockApi(() =>
      jsonResponse({
        ...hostedDetail,
        // As the server sends them: sorted by name.
        tags: [
          { ...hostedDetail.tags[1], tag: '1.10', digest: OLD },
          { ...hostedDetail.tags[0], tag: '1.9' },
          { ...hostedDetail.tags[1], tag: sigTag, digest: SIG },
        ],
        manifests: [
          { ...hostedDetail.manifests[0], created_at: '2026-10-21T10:58:44Z' },
          image(OLD, '2026-09-01T08:00:00Z'),
          { ...hostedDetail.manifests[3], tags: [sigTag], created_at: '2026-10-22T09:00:00Z' },
        ],
      }),
    )

    await renderDetail('/images/docker-hosted/team/app')

    const pull = await screen.findByRole('region', { name: 'Pull' })
    expect(
      within(pull).getByText('docker pull forge.example.com/docker-hosted/team/app:1.9'),
    ).toBeInTheDocument()
    expect(
      within(pull).getByText(`docker pull forge.example.com/docker-hosted/team/app@${INDEX}`),
    ).toBeInTheDocument()
  })

  it('a ?tag= deep link selects that tag', async () => {
    mockApi(() =>
      jsonResponse({
        ...hostedDetail,
        tags: [...hostedDetail.tags, { ...hostedDetail.tags[0], tag: 'stable' }],
      }),
    )

    await renderDetail('/images/docker-hosted/team/app?tag=stable')

    const pull = await screen.findByRole('region', { name: 'Pull' })
    expect(
      within(pull).getByText('docker pull forge.example.com/docker-hosted/team/app:stable'),
    ).toBeInTheDocument()
  })

  it.each([
    // A number to JSON: 1.1 (#403).
    ['?tag=1.10', '1.10'],
    ['?tag=1.36', '1.36'],
    ['?tag=2', '2'],
    // As the router wrote a numeric-looking tag before.
    ['?tag=%221.36%22', '1.36'],
  ])('a %s deep link selects the tag %s', async (search, tag) => {
    mockApi(() =>
      jsonResponse({
        ...hostedDetail,
        tags: [
          ...hostedDetail.tags,
          { ...hostedDetail.tags[0], tag: '1.10' },
          { ...hostedDetail.tags[0], tag: '2' },
        ],
      }),
    )

    await renderDetail(`/images/docker-hosted/team/app${search}`)

    const pull = await screen.findByRole('region', { name: 'Pull' })
    expect(
      within(pull).getByText(`docker pull forge.example.com/docker-hosted/team/app:${tag}`),
    ).toBeInTheDocument()
    expect(within(pull).getByLabelText('Tag')).toHaveValue(tag)
  })

  it('renders the tags table with short digests, sizes and platforms', async () => {
    mockApi(() => jsonResponse(hostedDetail))

    await renderDetail('/images/docker-hosted/team/app')

    const tags = await screen.findByRole('region', { name: 'Tags' })
    const row = within(tags).getByText('1.36').closest('tr') as HTMLElement
    const short = within(row).getByText('1111111111aa')
    // The full digest is the tooltip.
    expect(short).toHaveAttribute('title', INDEX)
    expect(within(row).getByText('4.2 MiB')).toBeInTheDocument()
    expect(within(row).getByText('linux/amd64')).toBeInTheDocument()
    expect(within(row).getByText('linux/arm64/v8')).toBeInTheDocument()

    const latest = within(tags).getByText('latest').closest('tr') as HTMLElement
    expect(within(latest).getByText('2222222222bb')).toBeInTheDocument()
    expect(within(latest).getByText('2.1 MiB')).toBeInTheDocument()
  })

  it('copies a tag digest in full', async () => {
    if (!navigator.clipboard) {
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText: () => Promise.resolve() },
        configurable: true,
      })
    }
    const writeText = vi
      .spyOn(navigator.clipboard, 'writeText')
      .mockResolvedValue(undefined)
    mockApi(() => jsonResponse(hostedDetail))

    await renderDetail('/images/docker-hosted/team/app')

    const tags = await screen.findByRole('region', { name: 'Tags' })
    fireEvent.click(within(tags).getByRole('button', { name: 'Copy digest of 1.36' }))
    expect(writeText).toHaveBeenCalledWith(INDEX)
  })

  it('renders the manifests table: kinds, index children, referrer hint, sizes', async () => {
    mockApi(() => jsonResponse(hostedDetail))

    await renderDetail('/images/docker-hosted/team/app')

    const manifests = await screen.findByRole('region', { name: 'Manifests' })
    // (A referrer names its subject's short digest too: find rows by their
    // own digest's copy button.)
    const rowOf = (short: string) =>
      within(manifests)
        .getByRole('button', { name: `Copy digest ${short}` })
        .closest('tr') as HTMLElement

    const index = rowOf('1111111111aa')
    expect(within(index).getByText('Index')).toBeInTheDocument()
    expect(within(index).getByText('lists 2 manifests')).toBeInTheDocument()
    expect(within(index).getByText('1.36')).toBeInTheDocument()

    const amd64 = rowOf('2222222222bb')
    expect(within(amd64).getByText('Image')).toBeInTheDocument()
    expect(within(amd64).getByText('latest')).toBeInTheDocument()

    const sig = rowOf('4444444444dd')
    expect(within(sig).getByText('Artifact')).toBeInTheDocument()
    expect(within(sig).getByText(/Signature · refers to/)).toHaveTextContent(
      'Signature · refers to 1111111111aa (1.36)',
    )
    // Unknown size and never pulled render as dashes.
    expect(within(sig).getAllByText('—').length).toBeGreaterThanOrEqual(2)

    // Not a group: no Source column.
    expect(within(manifests).queryByRole('columnheader', { name: 'Source' })).toBeNull()
    // A hosted repository's manifests were pushed to it.
    expect(within(manifests).getByRole('columnheader', { name: 'Pushed' })).toBeInTheDocument()
    expect(within(manifests).queryByRole('columnheader', { name: 'Cached' })).toBeNull()
  })

  it('labels the manifest time column "Cached" on a proxy (#248)', async () => {
    mockApi(() =>
      jsonResponse({
        ...hostedDetail,
        repo: 'docker-hub',
        repo_kind: 'proxy',
        pull_name: 'forge.example.com/docker-hub/team/app',
      }),
    )

    await renderDetail('/images/docker-hub/team/app')

    const manifests = await screen.findByRole('region', { name: 'Manifests' })
    expect(within(manifests).getByRole('columnheader', { name: 'Cached' })).toHaveAttribute(
      'title',
      'When Forge first cached this manifest from the upstream',
    )
    expect(within(manifests).queryByRole('columnheader', { name: 'Pushed' })).toBeNull()
  })

  it('shows the member each manifest comes from in a group', async () => {
    mockApi(() =>
      jsonResponse({
        ...hostedDetail,
        repo: 'docker-group',
        repo_kind: 'group',
        pull_name: 'forge.example.com/docker-group/team/app',
        manifests: hostedDetail.manifests.map((m) => ({
          ...m,
          source: 'docker-hosted',
        })),
      }),
    )

    await renderDetail('/images/docker-group/team/app')

    const manifests = await screen.findByRole('region', { name: 'Manifests' })
    expect(
      within(manifests).getByRole('columnheader', { name: 'Source' }),
    ).toBeInTheDocument()
    expect(within(manifests).getAllByText('docker-hosted')).toHaveLength(4)
  })

  it('pulls an untagged image by the digest of its top-level manifest', async () => {
    mockApi(() =>
      jsonResponse({
        ...hostedDetail,
        tags: [],
        manifests: [hostedDetail.manifests[3], hostedDetail.manifests[1]].map(
          (m) => ({ ...m, tags: [] }),
        ),
      }),
    )

    await renderDetail('/images/docker-hosted/team/app')

    const pull = await screen.findByRole('region', { name: 'Pull' })
    // The signature (a referrer) is skipped: the image itself is pulled.
    expect(
      within(pull).getByText(`docker pull forge.example.com/docker-hosted/team/app@${AMD64}`),
    ).toBeInTheDocument()
    expect(within(pull).queryByText(/team\/app:/)).toBeNull()
    expect(screen.getByText('No tags')).toBeInTheDocument()
  })

  it('renders a not-found empty state on 404', async () => {
    mockApi(() => new Response('image not found', { status: 404 }))

    await renderDetail('/images/docker-hosted/team/missing')

    expect(await screen.findByText('Image not found')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'team/missing' })).toBeInTheDocument()
    expect(screen.getByText('team/missing', { selector: 'code' })).toBeInTheDocument()
  })

  it('renders an error state on a server error', async () => {
    mockApi(() => new Response('boom', { status: 500 }))

    await renderDetail('/images/docker-hosted/team/app')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load image')).toBeInTheDocument()
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  describe('a Helm chart', () => {
    const CHART_OLD = 'sha256:5555555555ee' + '0'.repeat(52)
    const CHART_NEW = 'sha256:6666666666ff' + '0'.repeat(52)
    const HELM = 'application/vnd.cncf.helm.config.v1+json'
    const chartManifest = (digest: string, tag: string, created_at: string) => ({
      digest,
      media_type: 'application/vnd.oci.image.manifest.v1+json',
      artifact_type: HELM,
      subject_digest: null,
      manifest_size: 400,
      size: 3_210,
      platforms: [],
      tags: [tag],
      children: [],
      created_at,
      last_pulled_at: null,
    })
    const chartDetail: ImageDetail = {
      repo: 'charts',
      repo_kind: 'hosted',
      image: 'stable/web',
      registry: 'forge.example.com',
      pull_name: 'forge.example.com/charts/stable/web',
      tags: [
        { tag: '1.10.0', digest: CHART_NEW, media_type: 'application/vnd.oci.image.manifest.v1+json', size: 3_210, platforms: [] },
        { tag: '1.9.0', digest: CHART_OLD, media_type: 'application/vnd.oci.image.manifest.v1+json', size: 3_210, platforms: [] },
      ],
      manifests: [
        // The older version was pushed last: the newest version still leads.
        chartManifest(CHART_NEW, '1.10.0', '2026-10-20T10:00:00Z'),
        chartManifest(CHART_OLD, '1.9.0', '2026-10-21T10:00:00Z'),
      ],
    }
    const stored = (digest: string): ChartDetail => ({
      digest,
      metadata: {
        name: 'web',
        version: digest === CHART_NEW ? '1.10.0' : '1.9.0',
        appVersion: '2.4.1',
        description: 'A web server',
        home: 'https://example.com/web',
        sources: ['javascript:alert(1)'],
        maintainers: [{ name: 'Ops', email: 'ops@example.com' }],
        dependencies: [{ name: 'redis', version: '>=17', repository: 'oci://registry/charts' }],
      },
      readme: { name: 'README.md', text: `# web ${digest === CHART_NEW ? 'new' : 'old'}`, truncated: false },
      values: { name: 'values.yaml', text: 'replicas: 1\n', truncated: true },
      archive_stored: true,
    })

    it('shows the helm commands, facts, README and values of the newest version', async () => {
      const asked: string[] = []
      mockApi(
        () => jsonResponse(chartDetail),
        (q) => {
          asked.push(`${q.get('repo')}|${q.get('image')}|${q.get('digest')}`)
          return jsonResponse(stored(q.get('digest') ?? ''))
        },
      )

      const user = userEvent.setup()
      const router = await renderDetail('/images/charts/stable/web')

      expect(await screen.findByText('Helm chart')).toBeInTheDocument()
      expect(screen.queryByRole('region', { name: 'Pull' })).toBeNull()
      const install = screen.getByRole('region', { name: 'Install' })
      expect(
        within(install).getByText(
          textContent('helm install <release> oci://forge.example.com/charts/stable/web --version 1.10.0'),
        ),
      ).toBeInTheDocument()
      expect(
        within(install).getByText('helm pull oci://forge.example.com/charts/stable/web --version 1.10.0'),
      ).toBeInTheDocument()
      expect(
        within(install).getByText(
          textContent('helm registry login forge.example.com --username <username>'),
        ),
      ).toBeInTheDocument()

      expect(await screen.findByText('# web new')).toBeInTheDocument()
      expect(asked).toEqual([`charts|stable/web|${CHART_NEW}`])
      const facts = screen.getByRole('region', { name: 'Chart' })
      expect(within(facts).getByText('2.4.1')).toBeInTheDocument()
      expect(within(facts).getByRole('link', { name: 'https://example.com/web' })).toHaveAttribute(
        'href',
        'https://example.com/web',
      )
      // Only http(s) URLs become links.
      expect(within(facts).getByText('javascript:alert(1)').closest('a')).toBeNull()
      expect(within(facts).getByText('ops@example.com', { exact: false })).toBeInTheDocument()
      const values = screen.getByRole('region', { name: 'Default values' })
      expect(within(values).getByText('values.yaml')).toBeInTheDocument()
      expect(within(values).getByText(/Cut at 512 KiB/)).toBeInTheDocument()

      await user.selectOptions(within(install).getByLabelText('Version'), '1.9.0')
      expect(await screen.findByText('# web old')).toBeInTheDocument()
      expect(
        within(install).getByText('helm pull oci://forge.example.com/charts/stable/web --version 1.9.0'),
      ).toBeInTheDocument()
      expect(router.state.location.search).toMatchObject({ tag: '1.9.0' })
    })

    it('says when a proxy has not stored the chart yet', async () => {
      mockApi(
        () => jsonResponse({ ...chartDetail, repo_kind: 'proxy' }),
        (q) =>
          jsonResponse({
            digest: q.get('digest'),
            metadata: null,
            readme: null,
            values: null,
            archive_stored: false,
          }),
      )

      await renderDetail('/images/charts/stable/web')

      expect(await screen.findByText('Not stored yet')).toBeInTheDocument()
      expect(screen.queryByRole('region', { name: 'README' })).toBeNull()
      expect(screen.queryByRole('region', { name: 'Chart' })).toBeNull()
    })

    it('lets an administrator delete a version: its manifest', async () => {
      const asked: string[] = []
      let current = chartDetail
      mockApi(
        () => jsonResponse(current),
        (q) => jsonResponse(stored(q.get('digest') ?? '')),
        {
          me: adminMe,
          deleteImage: (repo, q) => {
            asked.push(`${repo}|${q.get('image')}|${q.get('reference')}`)
            current = {
              ...chartDetail,
              tags: chartDetail.tags.filter((t) => t.digest !== CHART_OLD),
              manifests: chartDetail.manifests.filter((m) => m.digest !== CHART_OLD),
            }
            return jsonResponse({ manifests: 1, tags: 1 })
          },
        },
      )

      const user = userEvent.setup()
      await renderDetail('/images/charts/stable/web')

      await user.click(await screen.findByRole('button', { name: 'Delete chart…' }))
      expect(screen.getByRole('dialog')).toHaveTextContent(
        'Permanently delete chart stable/web from repository charts: 2 versions and 2 manifests.',
      )
      await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
      await user.click(screen.getByRole('button', { name: 'Delete version 1.9.0' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog).toHaveTextContent('Delete stable/web 1.9.0?')
      expect(dialog).toHaveTextContent('This cannot be undone')
      await user.click(within(dialog).getByRole('button', { name: 'Delete version' }))

      await waitFor(() =>
        expect(screen.queryByRole('button', { name: 'Delete version 1.9.0' })).toBeNull(),
      )
      expect(asked).toEqual([`charts|stable/web|${CHART_OLD}`])
      expect(screen.queryByRole('dialog')).toBeNull()
      expect(screen.getByRole('button', { name: 'Delete version 1.10.0' })).toBeInTheDocument()
    })

    it('renders an error state when the chart cannot be read', async () => {
      mockApi(
        () => jsonResponse(chartDetail),
        () => new Response('boom', { status: 500 }),
      )

      await renderDetail('/images/charts/stable/web')

      const alert = await screen.findByRole('alert')
      expect(within(alert).getByText('Could not load the chart')).toBeInTheDocument()
    })
  })

  describe('deleting (administrators)', () => {
    /** The detail after deleting `digests` (and the tags on them) or `tag`. */
    function without(digests: string[], tag?: string): ImageDetail {
      return {
        ...hostedDetail,
        tags: hostedDetail.tags.filter((t) => t.tag !== tag && !digests.includes(t.digest)),
        manifests: hostedDetail.manifests
          .filter((m) => !digests.includes(m.digest))
          .map((m) => ({ ...m, tags: m.tags.filter((t) => t !== tag) })),
      }
    }

    /** An admin's page whose deletes answer `answer` and leave `after`. */
    function mockDelete(after: ImageDetail | null, answer = jsonResponse({ manifests: 1, tags: 0 })) {
      const asked: { repo: string; image: string | null; reference: string | null }[] = []
      let current: ImageDetail | null = hostedDetail
      mockApi(
        () => (current ? jsonResponse(current) : new Response('image not found', { status: 404 })),
        undefined,
        {
          me: adminMe,
          deleteImage: (repo, q) => {
            asked.push({ repo, image: q.get('image'), reference: q.get('reference') })
            if (answer.ok) current = after
            return answer
          },
        },
      )
      return asked
    }

    it('offers no delete to a reader, nor in a proxy or a group', async () => {
      mockApi(() => jsonResponse(hostedDetail))
      await renderDetail('/images/docker-hosted/team/app')
      await screen.findByRole('table', { name: 'Tags' })
      expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull()
      cleanup()

      for (const repo_kind of ['proxy', 'group']) {
        mockApi(() => jsonResponse({ ...hostedDetail, repo_kind }), undefined, { me: adminMe })
        await renderDetail('/images/docker-hosted/team/app')
        await screen.findByRole('table', { name: 'Tags' })
        expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull()
        cleanup()
      }
    })

    it('removes a tag after confirming; its manifest stays', async () => {
      const asked = mockDelete(without([], '1.36'), jsonResponse({ manifests: 0, tags: 1 }))
      const user = userEvent.setup()
      await renderDetail('/images/docker-hosted/team/app')

      await user.click(await screen.findByRole('button', { name: 'Delete tag 1.36' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog).toHaveTextContent('Delete tag 1.36?')
      expect(dialog).toHaveTextContent('can still be pulled by digest')
      await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
      expect(asked).toEqual([])

      await user.click(screen.getByRole('button', { name: 'Delete tag 1.36' }))
      await user.click(
        within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete tag' }),
      )

      await waitFor(() =>
        expect(screen.queryByRole('button', { name: 'Delete tag 1.36' })).toBeNull(),
      )
      expect(asked).toEqual([{ repo: 'docker-hosted', image: 'team/app', reference: '1.36' }])
      expect(screen.queryByRole('dialog')).toBeNull()
      // The index stays, untagged.
      const manifests = screen.getByRole('table', { name: 'Manifests' })
      expect(within(manifests).getAllByRole('button', { name: /^Delete manifest/ })).toHaveLength(4)
    })

    it('deletes an index with what only it keeps, saying so first', async () => {
      const asked = mockDelete(without([INDEX, ARM64, SIG]), jsonResponse({ manifests: 3, tags: 1 }))
      const user = userEvent.setup()
      await renderDetail('/images/docker-hosted/team/app')

      await user.click(await screen.findByRole('button', { name: 'Delete manifest 1111111111aa' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog).toHaveTextContent('Delete manifest 1111111111aa?')
      expect(dialog).toHaveTextContent('with its tag 1.36')
      expect(dialog).toHaveTextContent(
        'With it go the 2 manifests it lists and the 1 referrer (signatures, SBOMs, attestations) of it, unless a tag or another manifest still needs them.',
      )
      expect(within(dialog).queryByRole('alert')).toBeNull()
      await user.click(within(dialog).getByRole('button', { name: 'Delete manifest' }))

      await waitFor(() =>
        expect(screen.queryByRole('button', { name: 'Delete manifest 1111111111aa' })).toBeNull(),
      )
      expect(asked).toEqual([{ repo: 'docker-hosted', image: 'team/app', reference: INDEX }])
      expect(screen.getByRole('button', { name: 'Delete manifest 2222222222bb' })).toBeInTheDocument()
    })

    it('warns that an index lists the manifest, and shows a refusal', async () => {
      const asked = mockDelete(null, new Response('internal error', { status: 500 }))
      const user = userEvent.setup()
      await renderDetail('/images/docker-hosted/team/app')

      await user.click(await screen.findByRole('button', { name: 'Delete manifest 3333333333cc' }))
      const dialog = screen.getByRole('dialog')
      expect(within(dialog).getByRole('alert')).toHaveTextContent(
        'Index 1111111111aa lists this manifest: pulling linux/arm64/v8 through it fails once the manifest is gone.',
      )
      await user.click(within(dialog).getByRole('button', { name: 'Delete manifest' }))

      expect(await within(dialog).findByText('Could not delete')).toBeInTheDocument()
      expect(dialog).toHaveTextContent('internal error')
      expect(asked).toEqual([{ repo: 'docker-hosted', image: 'team/app', reference: ARM64 }])
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })

    it('deletes the whole image and returns to the repository', async () => {
      const asked = mockDelete(null, jsonResponse({ manifests: 4, tags: 2 }))
      const user = userEvent.setup()
      const router = await renderDetail('/images/docker-hosted/team/app')

      await user.click(await screen.findByRole('button', { name: 'Delete image…' }))
      const dialog = screen.getByRole('dialog')
      expect(dialog).toHaveTextContent('Delete team/app?')
      expect(dialog).toHaveTextContent('2 tags and 4 manifests')
      await user.click(within(dialog).getByRole('button', { name: 'Delete image' }))

      await waitFor(() => expect(router.state.location.pathname).toBe('/repos/docker-hosted'))
      expect(asked).toEqual([{ repo: 'docker-hosted', image: 'team/app', reference: null }])
    })

    it('returns to the repository when the last manifest is gone', async () => {
      const only: ImageDetail = {
        ...hostedDetail,
        tags: [hostedDetail.tags[1]],
        manifests: [hostedDetail.manifests[1]],
      }
      let gone = false
      mockApi(
        () => (gone ? new Response('image not found', { status: 404 }) : jsonResponse(only)),
        undefined,
        {
          me: adminMe,
          deleteImage: () => {
            gone = true
            return jsonResponse({ manifests: 1, tags: 1 })
          },
        },
      )
      const user = userEvent.setup()
      const router = await renderDetail('/images/docker-hosted/team/app')

      await user.click(await screen.findByRole('button', { name: 'Delete manifest 2222222222bb' }))
      await user.click(
        within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete manifest' }),
      )

      await waitFor(() => expect(router.state.location.pathname).toBe('/repos/docker-hosted'))
    })
  })
})
