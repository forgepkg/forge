import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import { assignLocation } from '~/lib/navigation'
import type { Me } from '~/api/me'
import type { EmailSettings, EmailSettingsView, SmtpOauthTransportView } from '~/api/email'
import { renderApp } from '~/test/renderApp'
import { graphFederatedSubject, seedEmailFormValues, toEmailSettingsInput } from './Email'

vi.mock('~/lib/navigation', () => ({ assignLocation: vi.fn() }))

/**
 * **Admin → Email** (`/manage/settings/email`), against the real route tree:
 *  - unconfigured, the form starts empty and a save PUTs the document;
 *  - stored settings seed the form without the password, a blank password
 *    is left out of the PUT (the server keeps the stored one), and the page
 *    shows the last failed send;
 *  - a test send shows the recipient, and a failed one the server's error;
 *  - removing the settings asks first (a dialog), then DELETEs them;
 *  - a Microsoft Graph app: its fields, the federated credential's values to
 *    register, and no secret sent for a federated app;
 *  - SMTP with OAuth: its fields, registering Forge, the authorization in
 *    this browser (to the authorization URL) and on another device (polled
 *    until authorized), the outcome the callback returns with, and a refused
 *    refresh.
 */

const adminMe: Me = {
  user: { id: 1, username: 'root@example.com', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

const stored: EmailSettingsView = {
  configured: true,
  enabled: true,
  from_address: 'forge@example.com',
  from_name: 'Forge',
  invitation_ttl_hours: 48,
  transport: {
    kind: 'smtp',
    host: 'smtp.example.com',
    tls: 'starttls',
    username: 'forge',
    password_set: true,
  },
  secrets_unreadable: false,
  last_failure: { at: '2026-10-23T08:00:00Z', error: 'connection refused' },
  last_success_at: null,
  updated_at: '2026-10-23T07:00:00Z',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

interface Handlers {
  settings: EmailSettings
  onPut?: (body: unknown) => Response
  onTest?: (body: unknown) => Response
  onDelete?: () => Response
  /** `/admin/settings/email/oauth/<rest>`. */
  onOauth?: (rest: string, method: string, body: unknown) => Response
}

function mockApi(h: Handlers) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = () => (init?.body ? JSON.parse(init.body as string) : {})
    if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
    const oauth = path.match(/\/admin\/settings\/email\/oauth\/(.+)$/)
    if (oauth && h.onOauth) return Promise.resolve(h.onOauth(oauth[1], method, body()))
    if (path.endsWith('/admin/settings/email/test') && method === 'POST') {
      return Promise.resolve(
        h.onTest ? h.onTest(body()) : json({ sent: true, to: 'root@example.com' }),
      )
    }
    if (path.endsWith('/admin/settings/email')) {
      if (method === 'GET') return Promise.resolve(json(h.settings))
      if (method === 'PUT') {
        return Promise.resolve(h.onPut ? h.onPut(body()) : json(stored))
      }
      if (method === 'DELETE') {
        return Promise.resolve(h.onDelete ? h.onDelete() : new Response(null, { status: 204 }))
      }
    }
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

function calls(method: string, suffix: string) {
  return fetchMock.mock.calls.filter(([input, init]) => {
    const raw = typeof input === 'string' ? input : input.toString()
    return (
      ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase() === method &&
      new URL(raw, 'http://localhost').pathname.endsWith(suffix)
    )
  })
}

describe('email settings form values', () => {
  it('round-trips stored settings, leaving the password out', () => {
    expect(toEmailSettingsInput(seedEmailFormValues(stored))).toEqual({
      enabled: true,
      from_address: 'forge@example.com',
      from_name: 'Forge',
      reply_to: undefined,
      invitation_ttl_hours: 48,
      transport: {
        kind: 'smtp',
        host: 'smtp.example.com',
        port: undefined,
        tls: 'starttls',
        username: 'forge',
        password: undefined,
      },
    })
  })

  it('trims, drops blank optional fields and defaults the lifetime', () => {
    const values = {
      ...seedEmailFormValues(),
      from_address: ' forge@example.com ',
      from_name: '  ',
      invitation_ttl_hours: '',
      host: ' localhost ',
      port: '2525',
      tls: 'none' as const,
    }
    expect(toEmailSettingsInput(values)).toMatchObject({
      from_address: 'forge@example.com',
      from_name: undefined,
      invitation_ttl_hours: 72,
      transport: { host: 'localhost', port: 2525, tls: 'none', username: undefined },
    })
  })
})

const graphStored: EmailSettingsView = {
  ...stored,
  last_failure: null,
  transport: {
    kind: 'microsoft_graph',
    tenant_id: 'contoso.onmicrosoft.com',
    client_id: 'app-id',
    client_authentication: 'federated_credential',
    client_secret_set: false,
  },
  federated_credential: {
    issuer: 'https://forge.example.com',
    subject: 'app-id@https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0',
    audience: 'api://AzureADTokenExchange',
  },
}

describe('graph form values', () => {
  it('round-trips a federated app and sends no secret', () => {
    const values = { ...seedEmailFormValues(graphStored), client_secret: 'typed before' }
    expect(toEmailSettingsInput(values).transport).toEqual({
      kind: 'microsoft_graph',
      tenant_id: 'contoso.onmicrosoft.com',
      client_id: 'app-id',
      sender: undefined,
      client_authentication: 'federated_credential',
      client_secret: undefined,
    })
  })

  it('derives the subject as the server does', () => {
    expect(graphFederatedSubject(' contoso.onmicrosoft.com ', ' app-id ')).toBe(
      'app-id@https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0',
    )
  })
})

describe('admin email settings screen', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('saves new settings', async () => {
    const user = userEvent.setup()
    const puts: unknown[] = []
    mockApi({
      settings: { configured: false },
      onPut: (body) => {
        puts.push(body)
        return json(stored)
      },
    })
    await renderApp('/manage/settings/email')

    await user.type(await screen.findByLabelText('From address'), 'forge@example.com')
    await user.type(screen.getByLabelText('Host'), 'smtp.example.com')
    await user.type(screen.getByLabelText('Username'), 'forge')
    await user.type(screen.getByLabelText(/^Password/), 's3cret')
    expect(screen.queryByRole('button', { name: /send test email/i })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Saved.')).toBeInTheDocument()
    expect(puts).toEqual([
      {
        enabled: true,
        from_address: 'forge@example.com',
        invitation_ttl_hours: 72,
        transport: {
          kind: 'smtp',
          host: 'smtp.example.com',
          tls: 'starttls',
          username: 'forge',
          password: 's3cret',
        },
      },
    ])
  })

  it('keeps the stored password and shows the last failure', async () => {
    const user = userEvent.setup()
    const puts: Record<string, unknown>[] = []
    mockApi({
      settings: stored,
      onPut: (body) => {
        puts.push(body as Record<string, unknown>)
        return json({ ...stored, last_failure: null, updated_at: '2026-10-23T09:00:00Z' })
      },
    })
    await renderApp('/manage/settings/email')

    expect(await screen.findByText(/The last send failed/)).toHaveTextContent(
      'connection refused',
    )
    expect(screen.getByLabelText('From address')).toHaveValue('forge@example.com')
    expect(screen.getByLabelText(/^Password/)).toHaveValue('')
    expect(screen.getByText(/A password is stored/)).toBeInTheDocument()
    expect(screen.getByText('set')).toBeInTheDocument()

    // Another host needs the password again.
    await user.clear(screen.getByLabelText('Host'))
    await user.type(screen.getByLabelText('Host'), 'mail.example.com')
    expect(screen.queryByText(/A password is stored/)).toBeNull()
    await user.clear(screen.getByLabelText('Host'))
    await user.type(screen.getByLabelText('Host'), 'smtp.example.com')

    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0].transport).not.toHaveProperty('password')
    await waitFor(() => expect(screen.queryByText(/The last send failed/)).toBeNull())
  })

  it('reports a test send and its failure', async () => {
    const user = userEvent.setup()
    let fail = false
    mockApi({
      settings: stored,
      onTest: (body) =>
        fail
          ? json({ sent: false, to: 'ops@example.com', error: 'authentication failed' }, 502)
          : json({ sent: true, to: (body as { to?: string }).to ?? 'root@example.com' }),
    })
    await renderApp('/manage/settings/email')

    await user.click(await screen.findByRole('button', { name: 'Send test email' }))
    expect(await screen.findByText('Sent to root@example.com.')).toBeInTheDocument()
    expect(calls('POST', '/admin/settings/email/test')[0][1]?.body).toBe('{}')

    fail = true
    await user.type(screen.getByLabelText('Recipient'), 'ops@example.com')
    await user.click(screen.getByRole('button', { name: 'Send test email' }))
    expect(
      await screen.findByText('Sending to ops@example.com failed: authentication failed'),
    ).toBeInTheDocument()
  })

  it('asks before removing the settings', async () => {
    const user = userEvent.setup()
    mockApi({ settings: stored })
    await renderApp('/manage/settings/email')

    await user.click(await screen.findByRole('button', { name: 'Remove email settings' }))
    expect(calls('DELETE', '/admin/settings/email')).toHaveLength(0)
    const dialog = screen.getByRole('dialog', { name: 'Remove the email settings?' })
    await user.click(within(dialog).getByRole('button', { name: 'Remove the email settings' }))
    await waitFor(() => expect(calls('DELETE', '/admin/settings/email')).toHaveLength(1))
  })

  it('configures a Graph app with a secret, then shows a federated one', async () => {
    const user = userEvent.setup()
    const puts: Record<string, unknown>[] = []
    mockApi({
      settings: { configured: false },
      onPut: (body) => {
        puts.push(body as Record<string, unknown>)
        return json(graphStored)
      },
    })
    await renderApp('/manage/settings/email')

    await user.type(await screen.findByLabelText('From address'), 'forge@contoso.com')
    await user.selectOptions(screen.getByLabelText('Send through'), 'microsoft_graph')
    expect(screen.queryByLabelText('Host')).toBeNull()
    await user.type(screen.getByLabelText('Tenant'), 'contoso.onmicrosoft.com')
    await user.type(screen.getByLabelText('Application (client) id'), 'app-id')
    await user.type(screen.getByLabelText(/^Client secret/), 's3cret')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0].transport).toEqual({
      kind: 'microsoft_graph',
      tenant_id: 'contoso.onmicrosoft.com',
      client_id: 'app-id',
      client_authentication: 'client_secret',
      client_secret: 's3cret',
    })

    // The stored federated app: the values to register on it, to copy.
    expect(await screen.findByLabelText('Issuer')).toHaveValue('https://forge.example.com')
    expect(screen.getByLabelText('Subject identifier')).toHaveValue(
      'app-id@https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0',
    )
    expect(screen.getByLabelText('Audience')).toHaveValue('api://AzureADTokenExchange')
    expect(screen.queryByLabelText(/^Client secret/)).toBeNull()
  })

  it('configures SMTP with OAuth and registers Forge', async () => {
    const user = userEvent.setup()
    const puts: Record<string, unknown>[] = []
    const registrations: unknown[] = []
    mockApi({
      settings: { configured: false },
      onPut: (body) => {
        puts.push(body as Record<string, unknown>)
        return json(oauthStored)
      },
      onOauth: (rest, method, body) => {
        if (rest === 'register' && method === 'POST') {
          registrations.push(body)
          return json(registeredStored)
        }
        if (rest === 'authorize' && method === 'POST') {
          return json({ authorization_url: 'https://mail.example.com/authorize?state=s' })
        }
        return new Response('unexpected', { status: 500 })
      },
    })
    await renderApp('/manage/settings/email')

    await user.type(await screen.findByLabelText('From address'), 'forge@example.com')
    await user.selectOptions(screen.getByLabelText('Send through'), 'smtp_oauth')
    await user.type(screen.getByLabelText('Host'), 'mail.example.com')
    await user.type(screen.getByLabelText('Mailbox'), 'forge@example.com')
    await user.type(screen.getByLabelText('Authorization server'), 'https://mail.example.com')
    expect(screen.queryByLabelText(/^Client secret/)).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0].transport).toEqual({
      kind: 'smtp_oauth',
      host: 'mail.example.com',
      tls: 'starttls',
      issuer: 'https://mail.example.com',
      username: 'forge@example.com',
    })

    // No client yet: register Forge, as an account of the mail server
    // (Stalwart's way).
    expect(await screen.findByText(/Forge has no client/)).toBeInTheDocument()
    expect(screen.getByLabelText('Redirect URI')).toHaveValue(
      'https://forge.example.com/admin/settings/email/oauth/callback',
    )
    await user.selectOptions(screen.getByLabelText('Register as'), 'account')
    await user.type(screen.getByLabelText('Account'), 'admin')
    await user.type(screen.getByLabelText('Account password'), 'adm1n-pw')
    await user.click(screen.getByRole('button', { name: 'Register Forge' }))
    await waitFor(() =>
      expect(registrations).toEqual([{ username: 'admin', password: 'adm1n-pw' }]),
    )
    expect(await screen.findByText('not authorized')).toBeInTheDocument()
    expect(screen.getByText(/registered by Forge/)).toBeInTheDocument()
    // The registered client is kept by the form without naming it.
    expect(screen.queryByLabelText('Client id')).toBeNull()

    // In this browser: off to the authorization server.
    await user.click(screen.getByRole('button', { name: 'Authorize in this browser' }))
    await waitFor(() =>
      expect(assignLocation).toHaveBeenCalledWith('https://mail.example.com/authorize?state=s'),
    )
  })

  it('authorizes on another device', async () => {
    const user = userEvent.setup()
    let polls = 0
    mockApi({
      settings: registeredStored,
      onOauth: (rest, method) => {
        if (rest === 'authorize' && method === 'POST') {
          return json({
            flow_id: 'flow-1',
            user_code: 'WDJB-MJHT',
            verification_uri: 'https://mail.example.com/device',
            verification_uri_complete: null,
            expires_in: 600,
            interval: 1,
          })
        }
        if (rest === 'device/flow-1' && method === 'POST') {
          polls += 1
          return polls < 2
            ? json({ status: 'pending' })
            : json({ status: 'authorized', settings: authorizedStored })
        }
        return new Response('unexpected', { status: 500 })
      },
    })
    await renderApp('/manage/settings/email')

    await user.click(await screen.findByRole('button', { name: 'Authorize on another device' }))
    expect(await screen.findByText('WDJB-MJHT')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'https://mail.example.com/device' })).toHaveAttribute(
      'href',
      'https://mail.example.com/device',
    )
    // Two polls a second apart, in real time.
    expect(
      await screen.findByText('The mailbox authorized Forge: it can send now.', undefined, {
        timeout: 10_000,
      }),
    ).toBeInTheDocument()
    expect(polls).toBe(2)
    expect(screen.getByText('authorized')).toBeInTheDocument()
    expect(screen.queryByText('WDJB-MJHT')).toBeNull()
  }, 20_000)

  it('shows how the authorization in the browser ended', async () => {
    mockApi({ settings: registeredStored })
    const router = await renderApp('/manage/settings/email?oauth=refused&error=access_denied')
    expect(await screen.findByText(/refused the authorization/)).toHaveTextContent(
      'access_denied',
    )
    await userEvent.setup().click(screen.getByRole('button', { name: 'Dismiss' }))
    await waitFor(() => expect(router.state.location.search).toEqual({}))
  })

  it('ignores free text in the outcome', async () => {
    mockApi({ settings: registeredStored })
    await renderApp('/manage/settings/email?oauth=evil&error=Call+us')
    expect(await screen.findByText(/Forge has registered|registered by Forge/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull()
  })

  it('asks for a new authorization after a refused refresh', async () => {
    mockApi({
      settings: {
        ...authorizedStored,
        transport: {
          ...(authorizedStored.transport as SmtpOauthTransportView),
          authorization_error: 'the token request was refused (400 invalid_grant)',
        },
      },
    })
    await renderApp('/manage/settings/email')
    expect(await screen.findByText(/must authorize Forge again/)).toHaveTextContent(
      'invalid_grant',
    )
    expect(screen.queryByText('authorized')).toBeNull()
  })
})

const oauthStored: EmailSettingsView = {
  ...stored,
  last_failure: null,
  transport: {
    kind: 'smtp_oauth',
    host: 'mail.example.com',
    tls: 'starttls',
    issuer: 'https://mail.example.com',
    username: 'forge@example.com',
    client_secret_set: false,
    registration_access_token_set: false,
    refresh_token_set: false,
  },
  oauth_redirect_uri: 'https://forge.example.com/admin/settings/email/oauth/callback',
}

const registeredStored: EmailSettingsView = {
  ...oauthStored,
  transport: {
    ...(oauthStored.transport as SmtpOauthTransportView),
    client_id: 'forge-client',
    client_secret_set: true,
    registered: true,
    registration_client_uri: 'https://mail.example.com/register/forge-client',
    registration_access_token_set: true,
  },
}

const authorizedStored: EmailSettingsView = {
  ...registeredStored,
  transport: {
    ...(registeredStored.transport as SmtpOauthTransportView),
    grant: 'refresh_token',
    refresh_token_set: true,
  },
}

describe('smtp oauth form values', () => {
  it('keeps a registered client without naming it, and names one entered by hand', () => {
    expect(toEmailSettingsInput(seedEmailFormValues(registeredStored)).transport).toEqual({
      kind: 'smtp_oauth',
      host: 'mail.example.com',
      port: undefined,
      tls: 'starttls',
      issuer: 'https://mail.example.com',
      username: 'forge@example.com',
      scope: undefined,
      client_id: undefined,
      client_secret: undefined,
    })
    const manual: EmailSettingsView = {
      ...registeredStored,
      transport: {
        ...(registeredStored.transport as SmtpOauthTransportView),
        registered: undefined,
        registration_client_uri: undefined,
        client_id: 'manual',
      },
    }
    const values = { ...seedEmailFormValues(manual), oauth_client_secret: 'new', scope: ' smtp ' }
    expect(toEmailSettingsInput(values).transport).toMatchObject({
      client_id: 'manual',
      client_secret: 'new',
      scope: 'smtp',
    })
  })
})
