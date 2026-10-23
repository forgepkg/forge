import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { BrowseRepo } from '~/api/packages'
import type { RawListing } from '~/api/raw'
import { renderApp } from '~/test/renderApp'

/**
 * The tree browser of a raw repository (`/repos/<repo>?path=<dir>/`): the
 * directory's entries from `GET /raw/<repo>/<dir>/` (JSON), opening
 * directories (the path lives in the URL), a file's details with its URL and
 * `curl` commands, the upload into the directory and the delete of a file
 * through `/browse/raw/<repo>/files`, and, for administrators, the delete of
 * a directory through the admin API.
 */

const admin: Me = {
  user: { id: 1, username: 'admin', is_admin: true, active: true },
  is_admin: true,
  capabilities: [],
}
const reader: Me = {
  user: { id: 2, username: 'alice', is_admin: false, active: true },
  is_admin: false,
  capabilities: [],
}

function repo(kind: string): BrowseRepo {
  return {
    id: 7,
    name: 'binaries',
    kind,
    online: true,
    format: 'raw',
    url: 'https://forge.example.com/raw/binaries',
  } as BrowseRepo
}

const root: RawListing = {
  repository: 'binaries',
  path: '',
  entries: [{ name: 'pdfium/', path: 'pdfium/', type: 'directory' }],
  next: null,
}

const pdfium: RawListing = {
  repository: 'binaries',
  path: 'pdfium/',
  entries: [
    { name: '7350/', path: 'pdfium/7350/', type: 'directory' },
    {
      name: 'pdfium linux.tgz',
      path: 'pdfium/pdfium linux.tgz',
      type: 'file',
      size: 2048,
      content_type: 'application/gzip',
      sha256: 'ab'.repeat(32),
      last_modified: '2026-10-21T10:58:44Z',
    },
  ],
  next: 'pdfium linux.tgz',
}

const fetchMock = vi.fn()
const calls: { method: string; url: URL; body?: unknown }[] = []

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function mockApi(me: Me, kind: string, listings: Record<string, RawListing>) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input.toString(), 'http://localhost')
    const method = init?.method ?? 'GET'
    calls.push({ method, url, body: init?.body })
    if (url.pathname === '/admin/me') return Promise.resolve(json(me))
    if (url.pathname === '/browse/repos') return Promise.resolve(json([repo(kind)]))
    if (url.pathname.startsWith('/raw/binaries/')) {
      const dir = decodeURIComponent(url.pathname.slice('/raw/binaries/'.length))
      const listing = listings[dir]
      return Promise.resolve(listing ? json(listing) : new Response('not found', { status: 404 }))
    }
    if (url.pathname === '/browse/raw/binaries/files' && method === 'POST') {
      return Promise.resolve(
        json({ files: [{ path: 'pdfium/new.bin', size: 3, sha256: 'cd', status: 'created' }] }, 201),
      )
    }
    if (url.pathname === '/browse/raw/binaries/files' && method === 'DELETE') {
      return Promise.resolve(new Response(null, { status: 204 }))
    }
    if (url.pathname === '/admin/repositories/binaries/files' && method === 'DELETE') {
      return Promise.resolve(json({ deleted: 4 }))
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

describe('RawBrowse', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    calls.length = 0
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    clearSession()
  })

  it('lists a directory and opens subdirectories through the URL', async () => {
    mockApi(reader, 'hosted', { '': root, 'pdfium/': pdfium })
    const user = userEvent.setup()
    const router = await renderApp('/repos/binaries')

    const list = await screen.findByRole('list', { name: 'Contents of binaries/' })
    await user.click(within(list).getByRole('button', { name: /pdfium\// }))
    await waitFor(() =>
      expect(router.state.location.search).toEqual({ path: 'pdfium/' }),
    )
    const dir = await screen.findByRole('list', { name: 'Contents of binaries/pdfium/' })
    expect(within(dir).getByText('7350/')).toBeInTheDocument()
    expect(within(dir).getByText('2.0 KiB')).toBeInTheDocument()
    expect(
      calls.some((c) => c.url.pathname === '/raw/binaries/pdfium/' && c.url.searchParams.get('format') === 'json'),
    ).toBe(true)

    // A page further, and back up through the path.
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() =>
      expect(router.state.location.search).toEqual({
        path: 'pdfium/',
        after: 'pdfium linux.tgz',
      }),
    )
    await user.click(
      within(screen.getByRole('navigation', { name: 'Path' })).getByRole('button', {
        name: 'binaries',
      }),
    )
    await waitFor(() => expect(router.state.location.search).toEqual({}))
  })

  it('shows a file with its URL and commands, and deletes it', async () => {
    mockApi(reader, 'hosted', { 'pdfium/': pdfium })
    const user = userEvent.setup()
    await renderApp('/repos/binaries?path=pdfium/')

    await user.click(await screen.findByRole('button', { name: /pdfium linux\.tgz/ }))
    const details = screen.getByRole('region', { name: 'pdfium/pdfium linux.tgz' })
    expect(within(details).getByText('application/gzip')).toBeInTheDocument()
    expect(within(details).getByText('ab'.repeat(32))).toBeInTheDocument()
    expect(
      within(details).getByText(
        'https://forge.example.com/raw/binaries/pdfium/pdfium%20linux.tgz',
      ),
    ).toBeInTheDocument()
    expect(within(details).getByRole('link', { name: 'Download' })).toHaveAttribute(
      'href',
      '/raw/binaries/pdfium/pdfium%20linux.tgz',
    )

    await user.click(within(details).getByRole('button', { name: 'Delete…' }))
    await user.click(within(details).getByRole('button', { name: 'Delete file' }))
    await waitFor(() =>
      expect(
        calls.find((c) => c.method === 'DELETE')?.url.toString(),
      ).toBe('http://localhost/browse/raw/binaries/files?path=pdfium%2Fpdfium+linux.tgz'),
    )
    // A reader is no administrator: no directory delete.
    expect(screen.queryByRole('button', { name: 'Delete this directory…' })).toBeNull()
  })

  it('uploads files into the directory', async () => {
    mockApi(reader, 'hosted', { 'pdfium/': pdfium })
    const user = userEvent.setup()
    await renderApp('/repos/binaries?path=pdfium/')

    const form = await screen.findByRole('form', { name: 'Upload files' })
    const input = form.querySelector('input[type="file"]') as HTMLInputElement
    await user.upload(input, new File(['abc'], 'new.bin'))
    await user.click(within(form).getByRole('button', { name: 'Upload' }))
    expect(await within(form).findByRole('status')).toHaveTextContent('Uploaded 1 file.')
    const post = calls.find((c) => c.method === 'POST')
    expect(post?.url.pathname).toBe('/browse/raw/binaries/files')
    expect(post?.url.searchParams.get('directory')).toBe('pdfium/')
    const body = post?.body as FormData
    expect((body.get('file') as File).name).toBe('new.bin')
  })

  it('lets administrators delete a directory; proxies take no uploads', async () => {
    mockApi(admin, 'proxy', { '': root, 'pdfium/': pdfium })
    const user = userEvent.setup()
    const router = await renderApp('/repos/binaries?path=pdfium/')

    await screen.findByRole('list', { name: 'Contents of binaries/pdfium/' })
    expect(screen.queryByRole('form', { name: 'Upload files' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Delete this directory…' }))
    await user.click(screen.getByRole('button', { name: 'Delete directory' }))
    await waitFor(() => expect(router.state.location.search).toEqual({}))
    const del = calls.find((c) => c.method === 'DELETE')
    expect(del?.url.pathname).toBe('/admin/repositories/binaries/files')
    expect(del?.url.searchParams.get('path')).toBe('pdfium/')
  })

  it('says so when the directory does not exist', async () => {
    mockApi(reader, 'hosted', {})
    await renderApp('/repos/binaries?path=gone/')
    expect(await screen.findByText('No such directory')).toBeInTheDocument()
  })
})
