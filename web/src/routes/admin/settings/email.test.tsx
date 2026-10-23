import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { EmailSettings, EmailSettingsView } from '~/api/email'
import { renderApp } from '~/test/renderApp'
import { seedEmailFormValues, toEmailSettingsInput } from './Email'

/**
 * **Admin → Email** (`/manage/settings/email`), against the real route tree:
 *  - unconfigured, the form starts empty and a save PUTs the document;
 *  - stored settings seed the form without the password, a blank password
 *    is left out of the PUT (the server keeps the stored one), and the page
 *    shows the last failed send;
 *  - a test send shows the recipient, and a failed one the server's error;
 *  - removing the settings asks first, then DELETEs them.
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
}

function mockApi(h: Handlers) {
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = () => (init?.body ? JSON.parse(init.body as string) : {})
    if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
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

    await user.click(await screen.findByRole('button', { name: 'Remove…' }))
    expect(calls('DELETE', '/admin/settings/email')).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Remove the email settings' }))
    await waitFor(() => expect(calls('DELETE', '/admin/settings/email')).toHaveLength(1))
  })
})
