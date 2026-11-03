import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'

import { makeQueryClient } from '~/lib/queryClient'
import { clearSession, setSession } from '~/lib/auth'
import type { RepoView } from '~/api/repositories'
import { CachedFilesPanel } from './CachedFilesPanel'

/**
 * The cached files panel of an apt proxy: **Delete cached file** evicts the
 * path it names through the admin API (#760).
 */

const repo = { name: 'debian', format: 'apt', kind: 'proxy' } as RepoView
const fetchMock = vi.fn()

function renderPanel() {
  render(
    <QueryClientProvider client={makeQueryClient()}>
      <CachedFilesPanel repo={repo} />
    </QueryClientProvider>,
  )
}

describe('CachedFilesPanel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    clearSession()
    vi.unstubAllGlobals()
  })

  it('deletes the cached file it names', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ deleted: 1 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
    renderPanel()

    const button = screen.getByRole('button', { name: 'Delete cached file' })
    expect(button).toBeDisabled()
    await user.type(
      screen.getByLabelText(/File or directory/),
      'pool/main/h/hello/hello_2.10-3_amd64.deb',
    )
    await user.click(button)

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [input, init] = fetchMock.mock.calls[0]
    const url = new URL(String(input), 'http://localhost')
    expect((init as RequestInit).method).toBe('DELETE')
    expect(url.pathname).toBe('/admin/repositories/debian/files')
    expect(url.searchParams.get('path')).toBe('pool/main/h/hello/hello_2.10-3_amd64.deb')
    expect(
      await screen.findByText(/Deleted pool\/main\/h\/hello\/hello_2.10-3_amd64.deb/),
    ).toBeInTheDocument()
  })

  it('shows why a delete failed', async () => {
    const user = userEvent.setup()
    fetchMock.mockResolvedValue(new Response('file not found', { status: 404 }))
    renderPanel()

    await user.type(screen.getByLabelText(/File or directory/), 'pool/main/x/x/x_1_amd64.deb')
    await user.click(screen.getByRole('button', { name: 'Delete cached file' }))

    expect(await screen.findByText('Could not delete the cached file')).toBeInTheDocument()
  })
})
