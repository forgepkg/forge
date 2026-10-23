import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { ImageDetail } from '~/api/images'
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

/** Route the mock: `/admin/me` -> identity, `/browse/images/{repo}/{image…}`. */
function mockApi(detail: (repo: string, image: string) => Response) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) {
      return Promise.resolve(jsonResponse(readerMe))
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
})
