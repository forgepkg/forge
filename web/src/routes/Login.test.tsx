import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import {
  RouterProvider,
  createMemoryHistory,
  createRouter,
} from '@tanstack/react-router'

import { makeQueryClient } from '~/lib/queryClient'
import { clearSession, getCsrfToken, isAuthenticated } from '~/lib/auth'
import { assignLocation } from '~/lib/navigation'
import type { LoginOptions } from '~/api/auth'
import type { Me } from '~/api/me'
import { routeTree } from '~/routeTree.gen'

// jsdom cannot perform real navigation; mock the one-line indirection the
// OIDC redirect uses so we can assert on the target URL.
vi.mock('~/lib/navigation', () => ({ assignLocation: vi.fn() }))

/**
 * Login behavior:
 *  - identifier-first renders two steps (username -> /auth/identify ->
 *    password -> /auth/login) and enters session mode on success;
 *  - an oidc_redirect decision leaves the SPA for the IdP, carrying the
 *    `redirect` target through as `redirect_to`;
 *  - combined mode renders username+password plus one button per OIDC entry;
 *  - a 401 from /auth/login shows the uniform inline error;
 *  - a failed OIDC callback (`?error=<code>`) shows a generic message per
 *    code, never the raw parameter, with a "Try again" link that clears it;
 *  - there is **no** registry-token sign-in: the UI always authenticates with
 *    username+password or via a realm.
 */

const readerMe: Me = {
  user: { id: 2, username: 'reader', is_admin: false, active: true },
  is_admin: false,
  capabilities: ['repo.read'],
}

const identifierFirst: LoginOptions = {
  mode: 'identifier_first',
  password: true,
  oidc: [],
}

const combined: LoginOptions = {
  mode: 'combined',
  password: true,
  oidc: [
    { name: 'corp', label: 'Corp SSO', login_url: '/auth/oidc/login?realm=corp' },
  ],
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

interface AuthHandlers {
  options?: LoginOptions
  onIdentify?: (body: unknown) => Response
  onLogin?: (body: unknown) => Response
  onMe?: () => Response
}

/** Route the mock by method + pathname against the auth + me endpoints. */
function mockAuthApi(h: AuthHandlers) {
  fetchMock.mockImplementation(
    (input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === 'string' ? input : input.toString()
      const url = new URL(raw, 'http://localhost')
      const method = (init?.method ?? 'GET').toUpperCase()
      const path = url.pathname
      const body = () => (init?.body ? JSON.parse(init.body as string) : {})

      if (path.endsWith('/auth/login-options') && method === 'GET') {
        return Promise.resolve(
          h.options ? json(h.options) : new Response('error', { status: 500 }),
        )
      }
      if (path.endsWith('/auth/identify') && method === 'POST') {
        return Promise.resolve(
          h.onIdentify
            ? h.onIdentify(body())
            : new Response('not found', { status: 404 }),
        )
      }
      if (path.endsWith('/auth/login') && method === 'POST') {
        return Promise.resolve(
          h.onLogin
            ? h.onLogin(body())
            : new Response('not found', { status: 404 }),
        )
      }
      if (path.endsWith('/admin/me') && method === 'GET') {
        return Promise.resolve(h.onMe ? h.onMe() : json(readerMe))
      }
      return Promise.resolve(new Response('not found', { status: 404 }))
    },
  )
}

async function renderLogin(
  initialPath = '/login',
  queryClient = makeQueryClient(),
) {
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  })
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  await waitFor(() => expect(router.state.status).toBe('idle'))
  return router
}

describe('Login', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    vi.mocked(assignLocation).mockReset()
    clearSession()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  describe('identifier-first mode', () => {
    it('walks username -> password steps, POSTs /auth/login, and enters session mode', async () => {
      const user = userEvent.setup()
      let identified: unknown = null
      let loggedIn: unknown = null
      mockAuthApi({
        options: identifierFirst,
        onIdentify: (body) => {
          identified = body
          return json({ mode: 'password', realm: 'local' })
        },
        onLogin: (body) => {
          loggedIn = body
          return json({
            user_id: 2,
            username: 'alice',
            is_admin: false,
            csrf_token: 'csrf-abc',
          })
        },
      })

      const router = await renderLogin()

      // Step 1: only the username is asked for.
      await user.type(await screen.findByLabelText('Username'), 'alice')
      expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Continue' }))

      await waitFor(() => expect(identified).toEqual({ username: 'alice' }))

      // Step 2: the username is shown (changeable) and the password asked for.
      expect(await screen.findByText('alice')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Change' })).toBeInTheDocument()
      await user.type(screen.getByLabelText('Password'), 'hunter2')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() =>
        expect(loggedIn).toEqual({ username: 'alice', password: 'hunter2' }),
      )
      await waitFor(() => expect(router.state.location.pathname).toBe('/'))
      // Session mode: the CSRF token is stored.
      expect(getCsrfToken()).toBe('csrf-abc')
    })

    it('shows the uniform inline error on a 401 from /auth/login', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: identifierFirst,
        onIdentify: () => json({ mode: 'password', realm: 'local' }),
        onLogin: () => new Response('unauthorized', { status: 401 }),
      })

      const router = await renderLogin()

      await user.type(await screen.findByLabelText('Username'), 'alice')
      await user.click(screen.getByRole('button', { name: 'Continue' }))
      await user.type(await screen.findByLabelText('Password'), 'wrong')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Invalid username or password',
      )
      expect(router.state.location.pathname).toBe('/login')
      expect(isAuthenticated()).toBe(false)
    })

    it('navigates the browser to the IdP on an oidc_redirect decision, carrying redirect_to', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: identifierFirst,
        onIdentify: () =>
          json({
            mode: 'oidc_redirect',
            realm: 'corp',
            login_url: '/auth/oidc/login?realm=corp',
          }),
      })

      await renderLogin('/login?redirect=%2Fmanage%2Frepositories')

      await user.type(await screen.findByLabelText('Username'), 'bob@example.com')
      await user.click(screen.getByRole('button', { name: 'Continue' }))

      await waitFor(() =>
        expect(assignLocation).toHaveBeenCalledWith(
          '/auth/oidc/login?realm=corp&redirect_to=%2Fmanage%2Frepositories',
        ),
      )
      // No password step was revealed.
      expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
      // The browser is leaving: Continue stays disabled, so a second click
      // cannot start another flow.
      expect(screen.getByRole('button', { name: 'Checking…' })).toBeDisabled()
      expect(assignLocation).toHaveBeenCalledTimes(1)
    })

    it('re-enables Continue when the identify request fails', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: identifierFirst,
        onIdentify: () => new Response('boom', { status: 500 }),
      })

      await renderLogin()

      await user.type(await screen.findByLabelText('Username'), 'bob')
      await user.click(screen.getByRole('button', { name: 'Continue' }))

      expect(await screen.findByRole('alert')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Continue' })).toBeEnabled()
      expect(assignLocation).not.toHaveBeenCalled()
    })
  })

  describe('lockout and return-to', () => {
    it('shows a lockout message (not "server unreachable") on a 429', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: identifierFirst,
        onIdentify: () => json({ mode: 'password', realm: 'local' }),
        onLogin: () =>
          new Response('too many failed sign-in attempts; try again later', {
            status: 429,
            headers: { 'retry-after': '300' },
          }),
      })

      const router = await renderLogin()

      await user.type(await screen.findByLabelText('Username'), 'alice')
      await user.click(screen.getByRole('button', { name: 'Continue' }))
      await user.type(await screen.findByLabelText('Password'), 'guess')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(/too many failed sign-in attempts/i)
      expect(alert).toHaveTextContent(/try again in 5 minutes/i)
      expect(alert).not.toHaveTextContent(/reachable/i)
      expect(router.state.location.pathname).toBe('/login')
      // The form can be used again once the lockout is over.
      expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled()
    })

    it('says "in a few minutes" when the server gives no Retry-After', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: combined,
        onLogin: () => new Response('too many', { status: 429 }),
      })
      await renderLogin()
      await user.type(await screen.findByLabelText('Username'), 'alice')
      await user.type(screen.getByLabelText('Password'), 'guess')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))
      expect(await screen.findByRole('alert')).toHaveTextContent(
        /try again in a few minutes/i,
      )
    })

    it('ignores an off-site return-to', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: combined,
        onLogin: () =>
          json({ user_id: 2, username: 'alice', is_admin: false, csrf_token: 'c' }),
      })

      const router = await renderLogin('/login?redirect=%2F%2Fevil.example%2Fx')

      await user.type(await screen.findByLabelText('Username'), 'alice')
      await user.type(screen.getByLabelText('Password'), 'pw')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() => expect(router.state.location.pathname).toBe('/'))
      expect(assignLocation).not.toHaveBeenCalled()
    })

    it('drops every cached query before entering the app (no previous user data)', async () => {
      const user = userEvent.setup()
      mockAuthApi({
        options: combined,
        onLogin: () =>
          json({ user_id: 2, username: 'reader', is_admin: false, csrf_token: 'c' }),
      })
      const queryClient = makeQueryClient()
      // Left behind by whoever used this browser before.
      queryClient.setQueryData(['repositories', 'list'], [{ name: 'secret' }])
      queryClient.setQueryData(['me'], {
        user: { id: 1, username: 'previous', is_admin: true, active: true },
        is_admin: true,
        capabilities: [],
      })

      const router = await renderLogin('/login', queryClient)

      await user.type(await screen.findByLabelText('Username'), 'reader')
      await user.type(screen.getByLabelText('Password'), 'pw')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() => expect(router.state.location.pathname).toBe('/'))
      expect(queryClient.getQueryData(['repositories', 'list'])).toBeUndefined()
      // The identity was fetched fresh for the new user.
      await waitFor(() =>
        expect(queryClient.getQueryData<Me>(['me'])?.user.username).toBe('reader'),
      )
    })
  })

  describe('combined mode', () => {
    it('renders username+password and one button per OIDC entry', async () => {
      const user = userEvent.setup()
      let loggedIn: unknown = null
      mockAuthApi({
        options: combined,
        onLogin: (body) => {
          loggedIn = body
          return json({
            user_id: 2,
            username: 'alice',
            is_admin: false,
            csrf_token: 'csrf-xyz',
          })
        },
      })

      const router = await renderLogin()

      // Both credential fields and the IdP button are visible at once.
      const username = await screen.findByLabelText('Username')
      const password = screen.getByLabelText('Password')
      const oidcButton = screen.getByRole('button', { name: 'Login with Corp SSO' })
      expect(oidcButton).toBeInTheDocument()

      await user.type(username, 'alice')
      await user.type(password, 'hunter2')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() =>
        expect(loggedIn).toEqual({ username: 'alice', password: 'hunter2' }),
      )
      await waitFor(() => expect(router.state.location.pathname).toBe('/'))
      expect(getCsrfToken()).toBe('csrf-xyz')
    })

    it('sends the browser to the IdP when the OIDC button is clicked', async () => {
      const user = userEvent.setup()
      mockAuthApi({ options: combined })

      await renderLogin()

      await user.click(
        await screen.findByRole('button', { name: 'Login with Corp SSO' }),
      )

      expect(assignLocation).toHaveBeenCalledWith('/auth/oidc/login?realm=corp')
    })
  })

  describe('no token sign-in', () => {
    it('never offers a registry-token form', async () => {
      mockAuthApi({ options: identifierFirst })

      await renderLogin()

      await screen.findByLabelText('Username')
      expect(screen.queryByLabelText('Registry token')).not.toBeInTheDocument()
      expect(
        screen.queryByRole('button', { name: 'Use a registry token instead' }),
      ).not.toBeInTheDocument()
    })

    it('falls back to password sign-in when login-options is unavailable', async () => {
      const user = userEvent.setup()
      let loggedIn: unknown = null
      mockAuthApi({
        options: undefined, // 500 from /auth/login-options
        onLogin: (body) => {
          loggedIn = body
          return json({
            user_id: 2,
            username: 'alice',
            is_admin: false,
            csrf_token: 'csrf-fallback',
          })
        },
      })

      const router = await renderLogin()

      expect(await screen.findByRole('status')).toHaveTextContent(
        /password sign-in is available/i,
      )
      await user.type(screen.getByLabelText('Username'), 'alice')
      await user.type(screen.getByLabelText('Password'), 'hunter2')
      await user.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() =>
        expect(loggedIn).toEqual({ username: 'alice', password: 'hunter2' }),
      )
      await waitFor(() => expect(router.state.location.pathname).toBe('/'))
      expect(getCsrfToken()).toBe('csrf-fallback')
      expect(screen.queryByLabelText('Registry token')).not.toBeInTheDocument()
    })
  })

  describe('OIDC callback errors', () => {
    it('says the identity provider sign-in did not complete (oidc_failed)', async () => {
      mockAuthApi({ options: combined })

      await renderLogin('/login?error=oidc_failed')

      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Sign-in with your identity provider did not complete. Try again; if it keeps failing, ask your administrator.',
      )
      // The sign-in form is still offered below the message.
      expect(
        await screen.findByRole('button', { name: 'Login with Corp SSO' }),
      ).toBeInTheDocument()
    })

    it('says the account is not permitted (not_permitted)', async () => {
      mockAuthApi({ options: combined })

      await renderLogin('/login?error=not_permitted')

      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Your account is not permitted to sign in to Forge. Ask your administrator for access.',
      )
    })

    it('says the identity provider sent no UPN and names the claim (username_not_upn)', async () => {
      mockAuthApi({ options: combined })

      await renderLogin('/login?error=username_not_upn&claim=preferred_username')

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(
        'Forge names new accounts by a UPN such as alice@example.com, and your identity provider did not send one.',
      )
      expect(alert).toHaveTextContent(
        'The username came from the preferred_username claim.',
      )
    })

    it('never shows a claim that does not look like a claim name', async () => {
      mockAuthApi({ options: combined })

      await renderLogin(
        '/login?error=username_not_upn&claim=' +
          encodeURIComponent('call +1 555 for help'),
      )

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('did not send one')
      expect(alert).not.toHaveTextContent(/came from|555/)
    })

    it('shows no message without an error parameter', async () => {
      mockAuthApi({ options: combined })

      await renderLogin()

      await screen.findByLabelText('Username')
      expect(screen.queryByRole('alert')).toBeNull()
      expect(screen.queryByRole('link', { name: 'Try again' })).toBeNull()
    })

    it('never echoes an unknown code', async () => {
      mockAuthApi({ options: combined })

      await renderLogin('/login?error=Upstream%20IdP%20said%20no')

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent('Sign-in did not complete.')
      expect(alert).not.toHaveTextContent(/Upstream|IdP said no/)
      expect(screen.queryByText(/IdP said no/)).toBeNull()
    })

    it('"Try again" clears the error and keeps the return-to', async () => {
      const user = userEvent.setup()
      mockAuthApi({ options: combined })

      const router = await renderLogin(
        '/login?error=oidc_failed&redirect=%2Ftokens',
      )

      await user.click(await screen.findByRole('link', { name: 'Try again' }))

      await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
      expect(router.state.location.pathname).toBe('/login')
      expect(router.state.location.search).not.toHaveProperty('error')
      expect(router.state.location.search).toMatchObject({ redirect: '/tokens' })
    })
  })
})
