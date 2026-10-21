import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { FormatView, RepoView } from '~/api/repositories'
import {
  NUGET_FORMAT,
  RepositoryForm,
  toCreateBody,
  toUpdateBody,
  validateRepoName,
  type RepoFormValues,
} from './RepositoryForm'

/**
 * RepositoryForm (plan §Phase 4 testing):
 *  - a create-hosted submission produces the right `CreateRepo` body (kind +
 *    hosted-only `allow_redeploy`, no proxy fields);
 *  - the proxy upstream password is **write-only**: never seeded from an
 *    existing repo's GET, and only sent when typed;
 *  - validation blocks an empty name and a proxy without a remote URL.
 */

const helm: FormatView = {
  id: 'helm',
  name: 'Helm charts',
  builtin: false,
  kinds: ['hosted', 'group'],
  mount: '/repository',
  version: '0.1.0',
  description: 'Helm chart repositories.',
}

function lastValues(onSubmit: ReturnType<typeof vi.fn>): RepoFormValues {
  return onSubmit.mock.calls.at(-1)![0] as RepoFormValues
}

describe('RepositoryForm', () => {
  it('builds a hosted CreateRepo body with allow_redeploy and no proxy fields', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )

    await user.type(screen.getByLabelText('Name'), 'my-hosted')
    // kind defaults to hosted; toggle allow_redeploy on.
    await user.click(
      screen.getByLabelText(/Allow redeploy/),
    )
    await user.click(screen.getByRole('button', { name: 'Create repository' }))

    expect(onSubmit).toHaveBeenCalledTimes(1)
    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toMatchObject({
      name: 'my-hosted',
      kind: 'hosted',
      allow_redeploy: true,
    })
    expect(body).not.toHaveProperty('remote_url')
    expect(body).not.toHaveProperty('upstream_password')
    // NuGet is the server's default format: not sent.
    expect(body).not.toHaveProperty('format')
  })

  it('creates a repository of a plugin format, offering only its kinds', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        formats={[NUGET_FORMAT, helm]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )

    // NuGet first: proxies are offered, the feed is a V3 index.
    expect(screen.getByRole('option', { name: 'proxy' })).toBeInTheDocument()
    expect(screen.getByText('/v3/<name>/index.json')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    await user.selectOptions(screen.getByLabelText('Format'), 'helm')
    // A plugin format has no proxies; the kind falls back to hosted.
    expect(screen.queryByRole('option', { name: 'proxy' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Kind')).toHaveValue('hosted')
    expect(screen.getByText('/repository/<name>/')).toBeInTheDocument()
    expect(screen.getByText(helm.description!)).toBeInTheDocument()

    await user.type(screen.getByLabelText('Name'), 'charts')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      name: 'charts',
      kind: 'hosted',
      format: 'helm',
    })
  })

  it('shows a stored format read-only on edit', () => {
    renderEdit({ ...storedProxy, kind: 'hosted', format: 'helm' })
    expect(screen.getByLabelText('Format')).toHaveValue('helm')
    expect(screen.getByLabelText('Format')).toHaveAttribute('readonly')
    expect(screen.getByText('/repository/<name>/')).toBeInTheDocument()
  })

  it('sends prefer_hosted for groups (on by default)', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    await user.type(screen.getByLabelText('Name'), 'my-group')
    await user.selectOptions(screen.getByLabelText('Kind'), 'group')
    expect(screen.getByLabelText(/Prefer hosted packages/)).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      kind: 'group',
      prefer_hosted: true,
    })
  })

  it('sends reserved prefixes for groups, split on commas and spaces', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    await user.type(screen.getByLabelText('Name'), 'my-group')
    await user.selectOptions(screen.getByLabelText('Kind'), 'group')
    await user.type(screen.getByLabelText('Reserved prefixes'), 'Acme., Contoso.Internal.')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      kind: 'group',
      reserved_prefixes: ['Acme.', 'Contoso.Internal.'],
    })
  })

  it('sends reserved prefixes on edit only when they change', async () => {
    const group: RepoView = {
      ...storedProxy,
      kind: 'group',
      remote_url: null,
      prefer_hosted: true,
      reserved_prefixes: ['acme.'],
    }
    const user = userEvent.setup()
    const onSubmit = renderEdit(group)
    await save(user)
    const values = lastValues(onSubmit)
    expect(values.reserved_prefixes).toBe('acme.')
    expect(toUpdateBody(values, group)).not.toHaveProperty('reserved_prefixes')
    expect(
      toUpdateBody({ ...values, reserved_prefixes: '' }, group),
    ).toMatchObject({ reserved_prefixes: [] })
  })

  it('blocks submit when the name is empty', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(
      screen.getByText('A repository name is required.'),
    ).toBeInTheDocument()
  })

  it('blocks a proxy without a remote URL', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    await user.type(screen.getByLabelText('Name'), 'my-proxy')
    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(
      screen.getByText('A proxy repository requires a remote URL.'),
    ).toBeInTheDocument()
  })

  it('never seeds the upstream password from an existing repo and omits it when blank', async () => {
    const existing: RepoView = {
      id: 1,
      name: 'upstream',
      format: 'nuget',
      kind: 'proxy',
      anonymous_read: false,
      online: true,
      remote_url: 'https://api.nuget.org/v3/index.json',
      package_delay_seconds: 0,
      upstream_username: 'svc',
      has_upstream_password: true,
      metadata_ttl_seconds: null,
      not_found_ttl_seconds: null,
      allow_redeploy: false,
      prefer_hosted: false,
      reserved_prefixes: [],
    }
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="edit"
        existing={existing}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )

    // The password field is empty even though a secret is stored (write-only).
    const pwd = screen.getByLabelText('Upstream password') as HTMLInputElement
    expect(pwd.value).toBe('')
    // The hint advertises that a stored secret is kept when left blank.
    expect(
      screen.getByText(/A password is stored\. Leave blank to keep it/),
    ).toBeInTheDocument()

    // Kind is locked in edit mode.
    const kind = screen.getByLabelText('Kind') as HTMLInputElement
    expect(kind.readOnly).toBe(true)

    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    // Submitted values carry an empty password (caller omits it from the PUT).
    expect(lastValues(onSubmit).upstream_password).toBe('')
  })

  it('includes the upstream password only once typed', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    await user.type(screen.getByLabelText('Name'), 'p')
    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    await user.type(
      screen.getByLabelText('Remote URL'),
      'https://example.test/v3/index.json',
    )
    await user.type(screen.getByLabelText('Upstream password'), 's3cret')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))

    const body = toCreateBody(lastValues(onSubmit))
    expect(body.upstream_password).toBe('s3cret')
    expect(body.remote_url).toBe('https://example.test/v3/index.json')
  })
})

/** A stored proxy with credentials and explicit TTLs. */
const storedProxy: RepoView = {
  id: 7,
  name: 'private-feed',
  format: 'nuget',
  kind: 'proxy',
  anonymous_read: false,
  online: true,
  remote_url: 'https://pkgs.example.com/feed/v3/index.json',
  package_delay_seconds: 0,
  upstream_username: 'svc',
  has_upstream_password: true,
  metadata_ttl_seconds: 600,
  not_found_ttl_seconds: 120,
  allow_redeploy: false,
  prefer_hosted: false,
  reserved_prefixes: [],
}

function renderEdit(existing: RepoView = storedProxy) {
  const onSubmit = vi.fn()
  render(
    <RepositoryForm
      mode="edit"
      existing={existing}
      submitting={false}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  )
  return onSubmit
}

async function save(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Save changes' }))
}

describe('repository names (M18)', () => {
  it('accepts the server rule and rejects everything else', () => {
    for (const ok of ['nuget', 'my.repo_1-x', 'A', 'a'.repeat(64), '0day']) {
      expect(validateRepoName(ok)).toBeNull()
    }
    expect(validateRepoName('')).toMatch(/required/)
    expect(validateRepoName('Team Packages')).toMatch(/letters, digits/)
    expect(validateRepoName('-leading')).toMatch(/starting with a letter or digit/)
    expect(validateRepoName('.hidden')).toMatch(/starting with a letter or digit/)
    expect(validateRepoName('a/b')).toMatch(/letters, digits/)
    expect(validateRepoName('a'.repeat(65))).toMatch(/at most 64/)
    for (const reserved of ['new', 'NEW', 'New']) {
      expect(validateRepoName(reserved)).toMatch(/"new" is reserved/)
    }
  })

  it('blocks an invalid name inline on create', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )

    await user.type(screen.getByLabelText('Name'), 'Team Packages')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent(/no spaces/)
    expect(screen.getByLabelText('Name')).toHaveAttribute('data-invalid')

    await user.clear(screen.getByLabelText('Name'))
    await user.type(screen.getByLabelText('Name'), 'new')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent(/"new" is reserved/)

    await user.clear(screen.getByLabelText('Name'))
    await user.type(screen.getByLabelText('Name'), 'team-packages')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('on edit, keeps a legacy name editable but validates a rename', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit({ ...storedProxy, name: 'Team Packages' })

    await save(user)
    expect(onSubmit).toHaveBeenCalledTimes(1)

    await user.clear(screen.getByLabelText('Name'))
    await user.type(screen.getByLabelText('Name'), 'still bad')
    await save(user)
    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('alert')).toHaveTextContent(/no spaces/)
  })
})

describe('repository update body (M2)', () => {
  it('omits every untouched field — no nulls that would clear stored values', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit()
    await save(user)

    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({})
  })

  it('sends null for an explicitly emptied TTL and the value for a changed one', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit()

    await user.clear(screen.getByLabelText('Metadata TTL (seconds)'))
    const nf = screen.getByLabelText('Not-found TTL (seconds)')
    await user.clear(nf)
    await user.type(nf, '30')
    await save(user)

    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({
      metadata_ttl_seconds: null,
      not_found_ttl_seconds: 30,
    })
  })

  it('"Remove stored credentials" sends both username and password as null', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit()

    await user.click(screen.getByRole('button', { name: 'Remove stored credentials' }))
    expect(screen.getByLabelText('Upstream username')).toBeDisabled()
    expect(screen.getByLabelText('Upstream password')).toBeDisabled()
    expect(screen.getByText(/will be removed when you save/)).toBeInTheDocument()
    await save(user)

    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({
      upstream_username: null,
      upstream_password: null,
    })

    // Undo: the username is back and nothing about the credentials is sent.
    await user.click(screen.getByRole('button', { name: 'Keep them' }))
    expect(screen.getByLabelText('Upstream username')).toHaveValue('svc')
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({})
  })

  it('does not offer to remove credentials when none are stored', () => {
    renderEdit({ ...storedProxy, upstream_username: null, has_upstream_password: false })
    expect(
      screen.queryByRole('button', { name: 'Remove stored credentials' }),
    ).toBeNull()
  })

  it('sends a changed username, null for an emptied one, and a typed password', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit()

    const username = screen.getByLabelText('Upstream username')
    await user.clear(username)
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({
      upstream_username: null,
    })

    await user.type(username, 'svc2')
    await user.type(screen.getByLabelText('Upstream password'), 'pat-2')
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({
      upstream_username: 'svc2',
      upstream_password: 'pat-2',
    })
  })

  it('warns that credentials are dropped when the remote URL moves to another origin', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit()
    const remote = screen.getByLabelText('Remote URL')

    // Same origin, different path: credentials stay, no warning.
    await user.clear(remote)
    await user.type(remote, 'https://pkgs.example.com/other/v3/index.json')
    expect(screen.queryByText(/credentials will be dropped/)).toBeNull()

    // Different origin without a new password: warn.
    await user.clear(remote)
    await user.type(remote, 'https://api.nuget.org/v3/index.json')
    expect(screen.getByRole('status')).toHaveTextContent(
      /stored upstream credentials will be dropped/,
    )
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedProxy)).toEqual({
      remote_url: 'https://api.nuget.org/v3/index.json',
    })

    // A new password for the new host keeps (replaces) the credentials.
    await user.type(screen.getByLabelText('Upstream password'), 'new-pat')
    expect(screen.queryByText(/credentials will be dropped/)).toBeNull()
  })
})
