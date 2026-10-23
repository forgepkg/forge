import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { clearSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { BrowseRepo, BrowseResult } from '~/api/packages'
import type { ImagesResult } from '~/api/images'
import { routeTree } from '~/routeTree.gen'
import { textContent } from '~/test/text'

/**
 * Folder-view browse: the root lists the readable repositories (with kind and
 * format, an offline one badged); a repository screen searches + paginates
 * that repo's packages and says when the repository is offline — or, for a
 * docker repository, lists its images, with the `docker login` / `pull`
 * snippets. Drives the real route tree + `useBrowseRepos` /
 * `usePackageSearch` / `useImageSearch`, so URL-search-param wiring is
 * exercised too.
 */

const readerMe: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const repos: BrowseRepo[] = [
  {
    id: 1,
    name: 'nuget',
    kind: 'proxy',
    online: true,
    format: 'nuget',
    url: 'https://forge.example.com/v3/nuget',
  },
  {
    id: 2,
    name: 'internal',
    kind: 'hosted',
    online: true,
    format: 'nuget',
    url: 'https://forge.example.com/v3/internal',
  },
  {
    id: 3,
    name: 'releases',
    kind: 'hosted',
    online: false,
    format: 'nuget',
    url: 'https://forge.example.com/v3/releases',
  },
  { id: 4, name: 'docker-hosted', kind: 'hosted', online: true, format: 'docker' },
  {
    id: 5,
    name: 'pkgs',
    kind: 'hosted',
    online: true,
    format: 'acme',
    url: 'https://forge.example.com/repository/pkgs',
  },
]

function page(total: number, ids: string[]): BrowseResult {
  return {
    total,
    items: ids.map((id) => ({
      repo: 'nuget',
      repo_kind: 'hosted',
      id: id.toLowerCase(),
      original_id: id,
      latest_version: '1.0.0',
      listed: true,
    })),
  }
}

const fetchMock = vi.fn()

function imagePage(total: number, images: string[]): ImagesResult {
  return {
    total,
    items: images.map((image) => ({
      image,
      tag_count: 3,
      manifest_count: 1,
      last_pushed_at: '2026-10-21T10:58:44Z',
    })),
    registry: 'forge.example.com',
    pull_prefix: 'forge.example.com/docker-hosted',
  }
}

/** Queries scoped to the page (the rail lists the repositories too). */
function main() {
  return within(screen.getByRole('main'))
}

/** The table row of an element (a repository's link). */
function rowOf(element: HTMLElement): HTMLElement {
  return element.closest('tr') as HTMLElement
}

/**
 * Route the mock by URL: `/admin/me` -> identity, `/browse/repos` -> repo list,
 * `/browse/packages` -> handler, `/browse/images` -> image handler.
 */
function mockApi(
  browse: (url: URL) => Response,
  images: (url: URL) => Response = () => jsonResponse(imagePage(0, [])),
) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.endsWith('/admin/me')) {
      return Promise.resolve(jsonResponse(readerMe))
    }
    if (url.pathname.endsWith('/browse/repos')) {
      return Promise.resolve(jsonResponse(repos))
    }
    if (url.pathname.endsWith('/browse/packages')) {
      return Promise.resolve(browse(url))
    }
    if (url.pathname.endsWith('/browse/images')) {
      return Promise.resolve(images(url))
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

/** The URLs of every request to `path` the app made so far. */
function requestsTo(path: string): URL[] {
  return fetchMock.mock.calls
    .map(([input]) => new URL(String(input), 'http://localhost'))
    .filter((u) => u.pathname.endsWith(path))
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

/** Mount the app at `initialPath`, or with a history stack (last = current). */
async function renderBrowse(initialPath: string | string[] = '/') {
  const queryClient = testQueryClient()
  const entries = Array.isArray(initialPath) ? initialPath : [initialPath]
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({
      initialEntries: entries,
      initialIndex: entries.length - 1,
    }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

describe('Browse root (repository folders)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists the readable repositories as folder links', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/')

    const nugetLink = await waitFor(() => main().getByRole('link', { name: /nuget/ }))
    expect(nugetLink).toHaveAttribute('href', '/repos/nuget')
    expect(main().getByRole('link', { name: /internal/ })).toBeInTheDocument()
  })

  it('badges an offline repository', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/')

    const releases = await waitFor(() => main().getByRole('link', { name: /releases/ }))
    expect(within(rowOf(releases)).getByText('offline')).toHaveAttribute(
      'title',
      'Offline for maintenance',
    )
    expect(
      within(rowOf(main().getByRole('link', { name: /internal/ }))).queryByText('offline'),
    ).toBeNull()
  })

  it('shows the kind and format of each repository', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/')

    const docker = await waitFor(() => main().getByRole('link', { name: /docker-hosted/ }))
    expect(docker).toHaveAttribute('href', '/repos/docker-hosted')
    expect(within(rowOf(docker)).getByText('Docker')).toBeInTheDocument()
    expect(within(rowOf(docker)).getByText('hosted')).toBeInTheDocument()
    const nuget = rowOf(main().getByRole('link', { name: /^nuget/ }))
    expect(within(nuget).getByText('NuGet')).toBeInTheDocument()
    expect(within(nuget).getByText('proxy')).toBeInTheDocument()
  })

  it('filters the repositories by format, in the URL', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const user = userEvent.setup()
    const router = await renderBrowse('/')

    const filter = await screen.findByRole('radiogroup', { name: 'Filter by format' })
    expect(
      within(filter)
        .getAllByRole('radio')
        .map((o) => o.textContent?.replace(/ \d+$/, '')),
    ).toEqual(['All', 'acme', 'Docker', 'NuGet'])
    expect(within(filter).getByRole('radio', { name: /^All/ })).toBeChecked()

    await user.click(within(filter).getByRole('radio', { name: /^acme/ }))

    await waitFor(() =>
      expect(router.state.location.search).toEqual({ format: 'acme' }),
    )
    expect(await main().findByRole('link', { name: /pkgs/ })).toBeInTheDocument()
    expect(main().queryByRole('link', { name: /internal/ })).toBeNull()
    expect(main().queryByRole('link', { name: /docker-hosted/ })).toBeNull()
    expect(within(filter).getByRole('radio', { name: /^acme/ })).toBeChecked()

    await user.click(within(filter).getByRole('radio', { name: /^All/ }))

    await waitFor(() => expect(router.state.location.search).toEqual({}))
    expect(await main().findByRole('link', { name: /internal/ })).toBeInTheDocument()
  })

  it('says when no readable repository has the filtered format', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/?format=npm')

    expect(await screen.findByText('No npm repositories')).toBeInTheDocument()
    expect(main().queryByRole('link', { name: /internal/ })).toBeNull()
  })

  it('navigates into a repository when its folder is clicked', async () => {
    mockApi(() => jsonResponse(page(1, ['Alpha'])))

    const user = userEvent.setup()
    const router = await renderBrowse('/')

    await user.click(await waitFor(() => main().getByRole('link', { name: /nuget/ })))

    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/repos/nuget'),
    )
    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()
  })
})

describe('RepoBrowse (per-repo search)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('scopes the search to the repository from the URL', async () => {
    mockApi(() => jsonResponse(page(2, ['Alpha', 'Beta'])))

    await renderBrowse('/repos/nuget')

    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Beta/ })).toBeInTheDocument()
    const pager = screen.getByRole('navigation', { name: 'Pagination' })
    expect(pager).toHaveTextContent('Showing 1–2 of 2')
    expect(pager).toHaveTextContent('Page 1 of 1')

    // Every package request carried the repo filter.
    const pkgCalls = fetchMock.mock.calls
      .map(([input]) =>
        new URL(String(input), 'http://localhost'),
      )
      .filter((u) => u.pathname.endsWith('/browse/packages'))
    expect(pkgCalls.length).toBeGreaterThan(0)
    for (const u of pkgCalls) {
      expect(u.searchParams.get('repo')).toBe('nuget')
    }
  })

  it('paginates: Next requests the next page and updates skip', async () => {
    // 25 total over a page size of 20 => two pages.
    mockApi((url) => {
      const skip = Number(url.searchParams.get('skip') ?? '0')
      if (skip === 0) return jsonResponse(page(25, ['Alpha']))
      return jsonResponse(page(25, ['Omega']))
    })

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/nuget')

    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Next page' }))

    expect(await screen.findByRole('link', { name: /Omega/ })).toBeInTheDocument()
    expect(router.state.location.search).toMatchObject({ skip: 20 })
  })

  it('shows an empty state when there are no results', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/repos/nuget')

    expect(await screen.findByText('No packages found')).toBeInTheDocument()
  })

  it('a page past the last result offers a way back instead of looking empty', async () => {
    // An old bookmark: 25 packages, but skip=40 is past the last page.
    mockApi((url) => {
      const skip = Number(url.searchParams.get('skip') ?? '0')
      return jsonResponse(skip === 0 ? page(25, ['Alpha']) : page(25, []))
    })

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/nuget?q=a&skip=40')

    expect(await screen.findByText('No packages on this page')).toBeInTheDocument()
    expect(
      screen.queryByText('This repository does not contain any packages yet.'),
    ).toBeNull()

    await user.click(screen.getByRole('link', { name: 'Back to page 1' }))

    expect(await screen.findByRole('link', { name: /Alpha/ })).toBeInTheDocument()
    expect(router.state.location.search).toEqual({ q: 'a' })
  })

  it('shows an error state with a retry on failure', async () => {
    mockApi(() => new Response('boom', { status: 500 }))

    await renderBrowse('/repos/nuget')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load packages')).toBeInTheDocument()
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('says the repository is offline on its 503', async () => {
    mockApi(
      () =>
        new Response('repository is offline', {
          status: 503,
          headers: { 'retry-after': '60' },
        }),
    )

    await renderBrowse('/repos/releases')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Repository offline')).toBeInTheDocument()
    expect(alert).toHaveTextContent(
      'This repository is offline for maintenance. Try again later.',
    )
    expect(within(alert).queryByText('Could not load packages')).toBeNull()
    expect(screen.queryByText('No packages found')).toBeNull()
  })

  it('debounces a typed query into the URL search param', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/nuget')

    await user.type(screen.getByLabelText('Search packages'), 'json')

    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ q: 'json' }),
    )
  })

  it('Back after typing a query leaves the search instead of getting stuck', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const user = userEvent.setup()
    const router = await renderBrowse(['/', '/repos/nuget'])

    await user.type(await screen.findByLabelText('Search packages'), 'json')
    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ q: 'json' }),
    )

    // The debounced query replaced the entry, so one Back leaves the repo.
    router.history.back()
    await waitFor(() => expect(router.state.location.pathname).toBe('/'))
    await new Promise((r) => setTimeout(r, 500))
    expect(router.state.location.pathname).toBe('/')
  })

  it('Back to an earlier search shows that query and stays there', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    const router = await renderBrowse([
      '/repos/nuget?q=alpha',
      '/repos/nuget?q=beta',
    ])
    const box = await screen.findByLabelText('Search packages')
    expect(box).toHaveValue('beta')

    router.history.back()

    await waitFor(() => expect(box).toHaveValue('alpha'))
    // The input no longer drags the URL back to the newer query.
    await new Promise((r) => setTimeout(r, 500))
    expect(router.state.location.search).toMatchObject({ q: 'alpha' })
    expect(box).toHaveValue('alpha')
  })
})

describe('RepoBrowse connect snippets of package repositories', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('shows the dotnet commands of a hosted NuGet repository', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/repos/internal')

    const connect = await screen.findByRole('region', { name: 'Connect' })
    expect(
      within(connect).getByText(
        textContent('dotnet nuget add source https://forge.example.com/v3/internal/index.json --name internal --username <username> --password <token> --store-password-in-clear-text'),
      ),
    ).toBeInTheDocument()
    expect(
      within(connect).getByText(
        textContent('dotnet nuget push <package>.nupkg --source internal --api-key <token>'),
      ),
    ).toBeInTheDocument()
    expect(within(connect).getByRole('link', { name: 'Your tokens' })).toHaveAttribute(
      'href',
      '/tokens',
    )
  })

  it('offers no push command for a proxy', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/repos/nuget')

    const connect = await screen.findByRole('region', { name: 'Connect' })
    expect(
      within(connect).getByRole('button', { name: 'Copy add-source command' }),
    ).toBeInTheDocument()
    expect(within(connect).queryByText(/dotnet nuget push/)).toBeNull()
  })

  it('shows the URL of a plugin format repository', async () => {
    mockApi(() => jsonResponse(page(0, [])))

    await renderBrowse('/repos/pkgs')

    const connect = await screen.findByRole('region', { name: 'Connect' })
    expect(
      within(connect).getByText(textContent('https://forge.example.com/repository/pkgs')),
    ).toBeInTheDocument()
    expect(
      within(connect).getByRole('button', { name: 'Copy repository URL' }),
    ).toBeInTheDocument()
  })
})

describe('RepoBrowse of a docker repository (images)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists the images instead of packages, each linking to its detail page', async () => {
    mockApi(
      () => jsonResponse(page(1, ['ShouldNotShow'])),
      () => jsonResponse(imagePage(2, ['alpine', 'team/app'])),
    )

    await renderBrowse('/repos/docker-hosted')

    const app = await screen.findByRole('link', { name: /team\/app/ })
    expect(app).toHaveAttribute('href', '/images/docker-hosted/team/app')
    const cells = within(rowOf(app)).getAllByRole('cell')
    expect(cells[1]).toHaveTextContent('3')
    expect(cells[2]).toHaveTextContent('1')
    expect(screen.getByRole('link', { name: /alpine/ })).toHaveAttribute(
      'href',
      '/images/docker-hosted/alpine',
    )
    expect(screen.getByRole('navigation', { name: 'Pagination' })).toHaveTextContent(
      'Showing 1–2 of 2',
    )
    expect(screen.getByLabelText('Search images')).toBeInTheDocument()
    // NuGet-only controls are absent, and no package search was made.
    expect(screen.queryByLabelText('Search packages')).toBeNull()
    expect(screen.queryByText('Include prerelease versions')).toBeNull()
    expect(requestsTo('/browse/packages')).toHaveLength(0)
    // Every image request named the repository.
    const imageCalls = requestsTo('/browse/images')
    expect(imageCalls.length).toBeGreaterThan(0)
    for (const u of imageCalls) {
      expect(u.searchParams.get('repo')).toBe('docker-hosted')
    }
  })

  it('says a docker repository is offline on its 503', async () => {
    mockApi(
      () => jsonResponse(page(0, [])),
      () =>
        new Response('repository is offline', {
          status: 503,
          headers: { 'retry-after': '60' },
        }),
    )

    await renderBrowse('/repos/docker-hosted')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Repository offline')).toBeInTheDocument()
    expect(within(alert).queryByText('Could not load images')).toBeNull()
  })

  it('shows the connect snippets with the registry and pull prefix', async () => {
    mockApi(
      () => jsonResponse(page(0, [])),
      () => jsonResponse(imagePage(1, ['alpine'])),
    )

    await renderBrowse('/repos/docker-hosted')

    const connect = await screen.findByRole('region', { name: 'Connect' })
    expect(
      within(connect).getByText('docker login forge.example.com'),
    ).toBeInTheDocument()
    expect(
      within(connect).getByText(
        textContent('docker pull forge.example.com/docker-hosted/<image>:<tag>'),
      ),
    ).toBeInTheDocument()
    // A hosted repository can be pushed to.
    expect(
      within(connect).getByText(
        textContent('docker push forge.example.com/docker-hosted/<image>:<tag>'),
      ),
    ).toBeInTheDocument()
    expect(
      within(connect).getByRole('button', { name: 'Copy login command' }),
    ).toBeInTheDocument()
    expect(within(connect).getByRole('link', { name: 'Your tokens' })).toHaveAttribute(
      'href',
      '/tokens',
    )
  })

  it('debounces a typed image query into the URL and the request', async () => {
    mockApi(
      () => jsonResponse(page(0, [])),
      () => jsonResponse(imagePage(0, [])),
    )

    const user = userEvent.setup()
    const router = await renderBrowse('/repos/docker-hosted')

    await user.type(await screen.findByLabelText('Search images'), 'team')

    await waitFor(() =>
      expect(router.state.location.search).toMatchObject({ q: 'team' }),
    )
    await waitFor(() =>
      expect(
        requestsTo('/browse/images').some((u) => u.searchParams.get('q') === 'team'),
      ).toBe(true),
    )
  })

  it('shows an empty state (and still how to connect) for an empty repository', async () => {
    mockApi(
      () => jsonResponse(page(0, [])),
      () => jsonResponse(imagePage(0, [])),
    )

    await renderBrowse('/repos/docker-hosted')

    expect(await screen.findByText('No images found')).toBeInTheDocument()
    expect(
      screen.getByText('This repository does not contain any images yet.'),
    ).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Connect' })).toBeInTheDocument()
  })

  it('refreshes a cached repository list that predates the repository', async () => {
    mockApi(
      () => jsonResponse(page(1, ['ShouldNotShow'])),
      () => jsonResponse(imagePage(1, ['alpine'])),
    )
    // The first list (e.g. cached before an admin created the repository)
    // lacks it; the screen re-reads the list instead of assuming NuGet.
    const base = fetchMock.getMockImplementation()!
    let listCalls = 0
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname.endsWith('/browse/repos') && listCalls++ === 0) {
        return Promise.resolve(jsonResponse(repos.slice(0, 2)))
      }
      return base(input, init)
    })

    await renderBrowse('/repos/docker-hosted')

    expect(await screen.findByRole('link', { name: /alpine/ })).toBeInTheDocument()
    expect(listCalls).toBeGreaterThanOrEqual(2)
    // The NuGet screen was never rendered for it, not even briefly.
    expect(requestsTo('/browse/packages')).toHaveLength(0)
  })

  it('shows an error state with a retry when the images fail to load', async () => {
    mockApi(
      () => jsonResponse(page(0, [])),
      () => new Response('boom', { status: 500 }),
    )

    await renderBrowse('/repos/docker-hosted')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByText('Could not load images')).toBeInTheDocument()
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})
