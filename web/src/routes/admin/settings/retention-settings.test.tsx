import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { clearSession, setSession } from '~/lib/auth'
import type { Me } from '~/api/me'
import type { RetentionSettings } from '~/api/settings'
import { renderApp } from '~/test/renderApp'

/**
 * The retention settings screen (`/manage/settings/retention`): the switch
 * that stops every retention run and how long the audit log is kept, each
 * saved on its own (`PUT /admin/settings/retention` names only its field).
 */

const adminMe: Me = {
  user: { id: 1, username: 'root', is_admin: true, active: true },
  is_admin: true,
  capabilities: ['repo.read', 'repo.admin'],
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const fetchMock = vi.fn()

function mockApi(initial: RetentionSettings, onPut?: (body: unknown) => Response) {
  let settings = initial
  fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input.toString()
    const path = new URL(raw, 'http://localhost').pathname
    const method = (init?.method ?? 'GET').toUpperCase()
    if (path.endsWith('/admin/me')) return Promise.resolve(json(adminMe))
    if (path.endsWith('/admin/settings/retention')) {
      if (method === 'PUT') {
        const body = JSON.parse(init?.body as string)
        if (onPut) {
          const resp = onPut(body)
          if (!resp.ok) return Promise.resolve(resp)
        }
        settings = { ...settings, ...body }
      }
      return Promise.resolve(json(settings))
    }
    if (path.endsWith('/admin/repositories')) return Promise.resolve(json([]))
    return Promise.resolve(new Response('not found', { status: 404 }))
  })
}

function puts(): unknown[] {
  return fetchMock.mock.calls
    .filter(([, init]) => (init?.method ?? 'GET').toUpperCase() === 'PUT')
    .map(([, init]) => JSON.parse((init as RequestInit).body as string))
}

describe('retention settings', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    setSession('admin-csrf')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    clearSession()
  })

  it('is linked from the admin home', async () => {
    mockApi({ runs_enabled: true, audit_retention_seconds: 7776000 })
    await renderApp('/manage')
    const main = within(screen.getByRole('main'))
    expect(await main.findByRole('link', { name: /^Retention/ })).toHaveAttribute(
      'href',
      '/manage/settings/retention',
    )
  })

  it('switches retention runs off', async () => {
    mockApi({ runs_enabled: true, audit_retention_seconds: 7776000 })
    await renderApp('/manage/settings/retention')
    const runs = within(await screen.findByRole('form', { name: 'Runs' }))
    const toggle = runs.getByRole('switch', { name: 'Retention runs' })
    expect(toggle).toBeChecked()
    await userEvent.click(toggle)
    await userEvent.click(runs.getByRole('button', { name: 'Save runs' }))
    await waitFor(() => expect(puts()).toEqual([{ runs_enabled: false }]))
    expect(await runs.findByText(/Retention runs are switched off/)).toBeInTheDocument()
  })

  it('sets how long the audit log is kept, or keeps it all', async () => {
    mockApi({ runs_enabled: true, audit_retention_seconds: 7776000 }, (body) =>
      (body as RetentionSettings).audit_retention_seconds === 360 * 86400 * 1000
        ? new Response('audit_retention_seconds must be at most 3153600000 (100 years)', {
            status: 400,
          })
        : json({}),
    )
    await renderApp('/manage/settings/retention')
    const audit = within(await screen.findByRole('form', { name: 'Audit log' }))
    expect(audit.getByText(/Rows are kept for 90 days/)).toBeInTheDocument()
    const field = audit.getByLabelText('Keep audit rows for')
    expect(field).toHaveValue('90')
    expect(audit.getByLabelText('Unit')).toHaveValue('days')

    await userEvent.clear(field)
    await userEvent.type(field, '0')
    await userEvent.click(audit.getByRole('button', { name: 'Save audit log' }))
    expect(audit.getByText('Enter a whole number of at least 1.')).toBeInTheDocument()

    await userEvent.clear(field)
    await userEvent.type(field, '30')
    await userEvent.click(audit.getByRole('button', { name: 'Save audit log' }))
    await waitFor(() => expect(puts()).toEqual([{ audit_retention_seconds: 30 * 86400 }]))
    expect(await audit.findByText(/Rows are kept for 30 days/)).toBeInTheDocument()

    await userEvent.clear(field)
    await userEvent.type(field, String(360 * 1000))
    await userEvent.click(audit.getByRole('button', { name: 'Save audit log' }))
    expect(await audit.findByText(/at most 3153600000/)).toBeInTheDocument()

    await userEvent.click(audit.getByRole('checkbox', { name: 'Keep every audit row' }))
    expect(audit.queryByLabelText('Keep audit rows for')).not.toBeInTheDocument()
    await userEvent.click(audit.getByRole('button', { name: 'Save audit log' }))
    await waitFor(() => expect(puts().at(-1)).toEqual({ audit_retention_seconds: 0 }))
    expect(await audit.findByText(/Rows are kept forever/)).toBeInTheDocument()
  })
})
