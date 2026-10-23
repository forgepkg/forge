import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import { FakeRbacApi, repo } from '~/test/fakeRbacApi'
import { renderApp } from '~/test/renderApp'

/**
 * Admin content-selector screens, against the real route tree and a stateful
 * fake of the RBAC API:
 *  - the list shows each selector's patterns, an empty include list as
 *    matching every package;
 *  - creating a selector sends its include and exclude lists, warns while the
 *    include list is empty, and its test box asks the server whether a
 *    package name matches the unsaved patterns;
 *  - editing keeps the name fixed and saves both lists;
 *  - deleting first names the grants (role, action, repository) that go with
 *    the selector, in a confirmation dialog.
 */

let api: FakeRbacApi

describe('admin content selectors', () => {
  beforeEach(() => {
    api = new FakeRbacApi({
      repos: [repo({ id: 10, name: 'internal' })],
      selectors: [
        { id: 20, name: 'acme', description: 'Acme packages', includes: ['acme.*'], excludes: ['acme.internal.*'] },
        { id: 21, name: 'everything', description: '', includes: [], excludes: [] },
      ],
    })
    api.state.roles.push({ id: 7, name: 'ci-pushers', description: '', builtin: false })
    api.state.grants.push(
      { id: 30, role_id: 7, repository_id: 10, action: 'write', selector_id: 20 },
      { id: 31, role_id: 2, repository_id: null, action: 'read', selector_id: 20 },
      { id: 32, role_id: 7, repository_id: 10, action: 'read', selector_id: null },
    )
    vi.stubGlobal('fetch', vi.fn(api.fetch))
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('lists selectors with their patterns', async () => {
    await renderApp('/manage/content-selectors')

    const acme = (await screen.findByRole('link', { name: 'acme' })).closest('tr')!
    expect(within(acme).getByText('Acme packages')).toBeInTheDocument()
    expect(within(acme).getByText('acme.*')).toBeInTheDocument()
    expect(within(acme).getByText('acme.internal.*')).toBeInTheDocument()
    const all = screen.getByRole('link', { name: 'everything' }).closest('tr')!
    expect(within(all).getByText('every package')).toBeInTheDocument()
  })

  it('creates a selector, testing a package name against the unsaved patterns', async () => {
    const u = userEvent.setup()
    const router = await renderApp('/manage/content-selectors/new')

    await u.type(await screen.findByLabelText('Name'), 'contoso')
    // The single empty include row does not count: the warning shows.
    expect(screen.getByText(/An empty include list/)).toHaveTextContent(
      'An empty include list matches every package',
    )
    await u.type(screen.getByLabelText('Includes pattern 1'), 'contoso.*')
    expect(screen.queryByText(/An empty include list/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Add exclude pattern' }))
    await u.type(screen.getByLabelText('Excludes pattern 1'), 'contoso.secret*')

    const tester = screen.getByLabelText('Test a package name')
    await u.type(tester, 'Contoso.Core')
    expect(await screen.findByText('matches')).toBeInTheDocument()
    await u.clear(tester)
    await u.type(tester, 'contoso.secrets')
    expect(await screen.findByText('does not match')).toBeInTheDocument()
    const lastMatch = api.sent('POST', /\/content-selectors\/match$/).at(-1)!
    expect(lastMatch.body).toEqual({
      includes: ['contoso.*'],
      excludes: ['contoso.secret*'],
      name: 'contoso.secrets',
    })

    await u.click(screen.getByRole('button', { name: 'Create selector' }))
    await waitFor(() =>
      expect(router.state.location.pathname).toBe('/manage/content-selectors'),
    )
    expect(api.sent('POST', /\/content-selectors$/)[0].body).toEqual({
      name: 'contoso',
      description: '',
      includes: ['contoso.*'],
      excludes: ['contoso.secret*'],
    })
    expect(await screen.findByRole('link', { name: 'contoso' })).toBeInTheDocument()
  })

  it('shows an invalid pattern in the test box', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/content-selectors/new')

    // (`[[` types one `[`.)
    await u.type(await screen.findByLabelText('Includes pattern 1'), 'acme.[[x')
    await u.type(screen.getByLabelText('Test a package name'), 'acme.x')
    expect(
      await screen.findByText(/invalid content-selector glob/),
    ).toBeInTheDocument()
  })

  it('edits a selector without changing its name', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/content-selectors/20')

    expect(await screen.findByLabelText('Name')).toHaveAttribute('readonly')
    await u.click(screen.getByRole('button', { name: 'Remove includes pattern 1' }))
    // Emptying the include list warns that the selector now matches everything.
    expect(screen.getByText(/An empty include list/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', { name: 'Add include pattern' }))
    await u.type(screen.getByLabelText('Includes pattern 1'), 'acme.public.*')
    await u.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(api.sent('PATCH', /\/content-selectors\/20$/)[0]?.body).toEqual({
        description: 'Acme packages',
        includes: ['acme.public.*'],
        excludes: ['acme.internal.*'],
      }),
    )
    expect(await screen.findByText('Saved.')).toBeInTheDocument()
  })

  it('names the grants a selector takes along before deleting it', async () => {
    const u = userEvent.setup()
    await renderApp('/manage/content-selectors')

    await u.click(await screen.findByRole('button', { name: 'Delete acme' }))
    const confirm = await screen.findByRole('dialog', { name: 'Delete acme?' })
    expect(
      await within(confirm).findByText('ci-pushers: write on internal (packages of acme)'),
    ).toBeInTheDocument()
    expect(
      within(confirm).getByText('anonymous: read on all repositories (packages of acme)'),
    ).toBeInTheDocument()
    // The grant without the selector is not affected.
    expect(within(confirm).queryByText(/ci-pushers: read/)).toBeNull()

    await u.click(within(confirm).getByRole('button', { name: 'Delete selector' }))
    await waitFor(() =>
      expect(api.sent('DELETE', /\/content-selectors\/20$/)).toHaveLength(1),
    )
    await waitFor(() => expect(screen.queryByRole('link', { name: 'acme' })).toBeNull())
    expect(api.state.grants.map((g) => g.id)).toEqual([32])
  })
})
