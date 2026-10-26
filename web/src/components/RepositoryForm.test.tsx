import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { FormatView, RepoView } from '~/api/repositories'
import {
  DOCKER_FORMAT,
  NPM_FORMAT,
  NUGET_FORMAT,
  RAW_FORMAT,
  RepositoryForm,
  bytesToMib,
  mibToBytes,
  toCreateBody,
  toUpdateBody,
  validateDockerHost,
  validateRepoName,
  type RepoFormValues,
} from './RepositoryForm'

/**
 * RepositoryForm:
 *  - a create-hosted submission produces the right `CreateRepo` body (kind +
 *    hosted-only `deployment_policy`, no proxy fields);
 *  - the proxy upstream password is **write-only**: never seeded from an
 *    existing repo's GET, and only sent when typed;
 *  - validation blocks an empty name and a proxy without a remote URL;
 *  - docker repositories: the format is chosen on create (read-only on edit),
 *    the NuGet-only fields are hidden and never sent, the docker options are
 *    sent only for docker (and only the ones the kind takes), and an edit
 *    diffs them (an emptied host / writable member clears it with `null`).
 */

const example: FormatView = {
  id: 'example',
  name: 'Example packages',
  kinds: ['hosted', 'group'],
  version: '0.1.0',
  description: 'Example package repositories.',
}

function lastValues(onSubmit: ReturnType<typeof vi.fn>): RepoFormValues {
  return onSubmit.mock.calls.at(-1)![0] as RepoFormValues
}

describe('RepositoryForm', () => {
  it('builds a hosted CreateRepo body with a deployment policy and no proxy fields', async () => {
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
    // kind defaults to hosted; let versions be pushed again.
    await user.selectOptions(screen.getByLabelText('Deployment policy'), 'allow_redeploy')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))

    expect(onSubmit).toHaveBeenCalledTimes(1)
    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toMatchObject({
      name: 'my-hosted',
      kind: 'hosted',
      deployment_policy: 'allow_redeploy',
    })
    expect(body).not.toHaveProperty('allow_redeploy')
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
        formats={[NUGET_FORMAT, example]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )

    // NuGet first: proxies are offered, the feed is a service index.
    expect(screen.getByRole('option', { name: 'proxy' })).toBeInTheDocument()
    expect(screen.getByText('/repository/<name>/index.json')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    await user.selectOptions(screen.getByLabelText('Format'), 'example')
    // A plugin format has no proxies; the kind falls back to hosted.
    expect(screen.queryByRole('option', { name: 'proxy' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Kind')).toHaveValue('hosted')
    expect(screen.getByText('/repository/<name>/')).toBeInTheDocument()
    expect(screen.getByText(example.description!)).toBeInTheDocument()

    await user.type(screen.getByLabelText('Name'), 'pkgs')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      name: 'pkgs',
      kind: 'hosted',
      format: 'example',
    })
  })

  it('shows a stored format read-only on edit', () => {
    renderEdit({ ...storedProxy, kind: 'hosted', format: 'example' })
    expect(screen.getByLabelText('Format')).toHaveValue('example')
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
      host: null,
      immutable_tags: false,
      latest_mutable: false,
      writable_member: null,
      max_upload_bytes: null,
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
  host: null,
  immutable_tags: false,
  latest_mutable: false,
  writable_member: null,
  max_upload_bytes: null,
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
    expect(screen.getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true')

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

/** The docker options an untouched NuGet body must never carry. */
const DOCKER_FIELDS = ['host', 'immutable_tags', 'latest_mutable', 'writable_member']

function renderCreate() {
  const onSubmit = vi.fn()
  render(
    <RepositoryForm
      mode="create"
      formats={[NUGET_FORMAT, DOCKER_FORMAT]}
      submitting={false}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  )
  return onSubmit
}

async function create(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Create repository' }))
}

describe('docker repositories: create', () => {
  it('a NuGet body sends no format and no docker fields', async () => {
    const user = userEvent.setup()
    const onSubmit = renderCreate()

    await user.type(screen.getByLabelText('Name'), 'feed')
    // A host typed while "Docker" was selected is dropped when switching back.
    await user.selectOptions(screen.getByLabelText('Format'), 'docker')
    await user.type(screen.getByLabelText('Host'), 'docker.example.com')
    await user.selectOptions(screen.getByLabelText('Format'), 'nuget')
    expect(screen.queryByLabelText('Host')).toBeNull()
    await create(user)

    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toMatchObject({ name: 'feed', kind: 'hosted' })
    // NuGet is the server's default format: not sent.
    expect(body).not.toHaveProperty('format')
    for (const field of DOCKER_FIELDS) expect(body).not.toHaveProperty(field)
  })

  it('hosted docker: hides allow_redeploy, sends host + immutable tags + latest_mutable', async () => {
    const user = userEvent.setup()
    const onSubmit = renderCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'docker')
    expect(screen.queryByLabelText(/Allow redeploy/)).toBeNull()
    await user.type(screen.getByLabelText('Name'), 'docker-hosted')
    await user.type(screen.getByLabelText('Host'), 'docker.example.com')

    // "Allow moving latest" is only available with immutable tags.
    const latest = screen.getByLabelText(/Allow moving latest/)
    expect(latest).toBeDisabled()
    await user.click(screen.getByLabelText(/Immutable tags/))
    expect(latest).toBeEnabled()
    await user.click(latest)
    await create(user)

    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toEqual({
      name: 'docker-hosted',
      kind: 'hosted',
      format: 'docker',
      anonymous_read: false,
      online: true,
      host: 'docker.example.com',
      immutable_tags: true,
      latest_mutable: true,
    })
  })

  it('unticking immutable tags also clears latest_mutable', async () => {
    const user = userEvent.setup()
    const onSubmit = renderCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'docker')
    await user.type(screen.getByLabelText('Name'), 'docker-hosted')
    await user.click(screen.getByLabelText(/Immutable tags/))
    await user.click(screen.getByLabelText(/Allow moving latest/))
    await user.click(screen.getByLabelText(/Immutable tags/))
    expect(screen.getByLabelText(/Allow moving latest/)).not.toBeChecked()
    await create(user)

    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      immutable_tags: false,
      latest_mutable: false,
    })
  })

  it('docker proxy: registry URL placeholder, no package delay, no empty host', async () => {
    const user = userEvent.setup()
    const onSubmit = renderCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'docker')
    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    expect(screen.queryByLabelText('Package delay (seconds)')).toBeNull()
    const remote = screen.getByLabelText('Remote URL')
    expect(remote).toHaveAttribute('placeholder', 'https://registry-1.docker.io')
    await user.type(screen.getByLabelText('Name'), 'docker-hub')
    await user.type(remote, 'https://registry-1.docker.io')
    await create(user)

    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toMatchObject({
      name: 'docker-hub',
      kind: 'proxy',
      format: 'docker',
      remote_url: 'https://registry-1.docker.io',
    })
    expect(body).not.toHaveProperty('package_delay_seconds')
    expect(body).not.toHaveProperty('allow_redeploy')
    for (const field of DOCKER_FIELDS) expect(body).not.toHaveProperty(field)
  })

  it('docker group: namespace prefixes and the writable member', async () => {
    const user = userEvent.setup()
    const onSubmit = renderCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'docker')
    await user.selectOptions(screen.getByLabelText('Kind'), 'group')
    expect(screen.getByText(/namespaces such as/)).toHaveTextContent('acme/')
    expect(screen.queryByLabelText(/Immutable tags/)).toBeNull()
    await user.type(screen.getByLabelText('Name'), 'docker-group')
    await user.type(screen.getByLabelText('Reserved prefixes'), 'acme/')
    await user.type(screen.getByLabelText('Writable member'), 'docker-hosted')
    await create(user)

    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toMatchObject({
      kind: 'group',
      format: 'docker',
      prefer_hosted: true,
      reserved_prefixes: ['acme/'],
      writable_member: 'docker-hosted',
    })
    expect(body).not.toHaveProperty('immutable_tags')
    expect(body).not.toHaveProperty('host')
  })

  it('blocks an uppercase docker name and an invalid host inline', async () => {
    const user = userEvent.setup()
    const onSubmit = renderCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'docker')
    await user.type(screen.getByLabelText('Name'), 'Docker-Hosted')
    await user.type(screen.getByLabelText('Host'), 'https://docker.example.com')
    await create(user)

    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.getByText(/must be lowercase/)).toBeInTheDocument()
    expect(screen.getByText(/Give a DNS name/)).toBeInTheDocument()
  })
})

describe('docker repository names and hosts', () => {
  it('requires a lowercase OCI name component for docker only', () => {
    for (const ok of ['docker-hosted', 'a', 'my.repo', 'a__b', 'a--b', '0day']) {
      expect(validateRepoName(ok, 'docker')).toBeNull()
    }
    expect(validateRepoName('Docker', 'docker')).toMatch(/lowercase/)
    expect(validateRepoName('a..b', 'docker')).toMatch(/separators/)
    expect(validateRepoName('a___b', 'docker')).toMatch(/separators/)
    expect(validateRepoName('trailing-', 'docker')).toMatch(/separators/)
    expect(validateRepoName('new', 'docker')).toMatch(/"new" is reserved/)
    // NuGet keeps its own (case-insensitive) rule.
    expect(validateRepoName('Docker')).toBeNull()
  })

  it('accepts a DNS name as host and rejects schemes, ports and bare names', () => {
    expect(validateDockerHost('')).toBeNull()
    expect(validateDockerHost('docker.example.com')).toBeNull()
    for (const bad of [
      'https://docker.example.com',
      'docker.example.com:5000',
      'docker.example.com/path',
      'localhost',
      '-bad.example.com',
    ]) {
      expect(validateDockerHost(bad)).toMatch(/DNS name/)
    }
  })
})

/** A stored hosted docker repository with a host. */
const storedDocker: RepoView = {
  ...storedProxy,
  id: 9,
  name: 'docker-hosted',
  format: 'docker',
  kind: 'hosted',
  remote_url: null,
  upstream_username: null,
  has_upstream_password: false,
  metadata_ttl_seconds: null,
  not_found_ttl_seconds: null,
  host: 'docker.example.com',
  immutable_tags: false,
  latest_mutable: false,
}

describe('docker repositories: update body', () => {
  it('shows the format read-only and sends nothing when untouched', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit(storedDocker)

    const format = screen.getByLabelText('Format') as HTMLInputElement
    expect(format.readOnly).toBe(true)
    expect(format).toHaveValue('Docker / OCI')
    expect(screen.getByLabelText('Host')).toHaveValue('docker.example.com')
    await save(user)

    expect(toUpdateBody(lastValues(onSubmit), storedDocker)).toEqual({})
  })

  it('an emptied host is sent as null; a changed one as the value', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit(storedDocker)
    const host = screen.getByLabelText('Host')

    await user.clear(host)
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedDocker)).toEqual({ host: null })

    await user.type(host, 'registry.example.com')
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedDocker)).toEqual({
      host: 'registry.example.com',
    })
  })

  it('diffs immutable_tags / latest_mutable', async () => {
    const user = userEvent.setup()
    const onSubmit = renderEdit(storedDocker)

    await user.click(screen.getByLabelText(/Immutable tags/))
    await user.click(screen.getByLabelText(/Allow moving latest/))
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedDocker)).toEqual({
      immutable_tags: true,
      latest_mutable: true,
    })

    const immutable = { ...storedDocker, immutable_tags: true, latest_mutable: true }
    expect(
      toUpdateBody({ ...lastValues(onSubmit), immutable_tags: false }, immutable),
    ).toEqual({ immutable_tags: false, latest_mutable: false })
  })

  it('a docker group sets and clears its writable member', async () => {
    const group: RepoView = {
      ...storedDocker,
      name: 'docker-group',
      kind: 'group',
      host: null,
      prefer_hosted: true,
      writable_member: 'docker-hosted',
    }
    const user = userEvent.setup()
    const onSubmit = renderEdit(group)
    const member = screen.getByLabelText('Writable member')
    expect(member).toHaveValue('docker-hosted')

    await user.clear(member)
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), group)).toEqual({
      writable_member: null,
    })

    await user.type(member, 'docker-releases')
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), group)).toEqual({
      writable_member: 'docker-releases',
    })
  })

  it('never sends NuGet-only or docker-only fields across formats', () => {
    // A docker proxy: changing the hidden delay value sends nothing.
    const dockerProxy: RepoView = {
      ...storedDocker,
      kind: 'proxy',
      remote_url: 'https://ghcr.io',
      host: null,
    }
    const values = {
      ...lastValuesOf(dockerProxy),
      package_delay_seconds: '3600',
      deployment_policy: 'allow_redeploy' as const,
    }
    expect(toUpdateBody(values, dockerProxy)).toEqual({})

    // A NuGet repository: docker values never reach the body.
    expect(
      toUpdateBody(
        {
          ...lastValuesOf(storedProxy),
          host: 'docker.example.com',
          writable_member: 'x',
          immutable_tags: true,
        },
        storedProxy,
      ),
    ).toEqual({})
  })
})

/** The values an untouched edit of `existing` submits. */
function lastValuesOf(existing: RepoView): RepoFormValues {
  const onSubmit = vi.fn()
  const { unmount } = render(
    <RepositoryForm
      mode="edit"
      existing={existing}
      submitting={false}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
  unmount()
  return lastValues(onSubmit)
}

describe('repository upload limit', () => {
  const nuget: FormatView = {
    ...NUGET_FORMAT,
    default_max_upload_bytes: 512 * 1024 * 1024,
    max_upload_bytes_limit: 4 * 1024 * 1024 * 1024,
  }
  const storedHosted: RepoView = {
    ...storedProxy,
    name: 'packages',
    kind: 'hosted',
    remote_url: null,
    upstream_username: null,
    has_upstream_password: false,
    metadata_ttl_seconds: null,
    not_found_ttl_seconds: null,
    max_upload_bytes: 100 * 1024 * 1024,
  }

  it('converts between bytes and MiB', () => {
    expect(bytesToMib(512 * 1024 * 1024)).toBe('512')
    expect(bytesToMib(1536 * 1024)).toBe('1.5')
    expect(mibToBytes('1.5')).toBe(1536 * 1024)
    expect(mibToBytes(' ')).toBeNull()
    expect(mibToBytes('lots')).toBeNull()
  })

  it('shows the default and sends a typed limit in bytes on create', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        formats={[nuget]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    const field = screen.getByLabelText('Maximum upload size (MiB)')
    expect(field).toHaveAttribute('placeholder', 'Default: 512')
    await user.type(screen.getByLabelText('Name'), 'big-packages')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(toCreateBody(lastValues(onSubmit))).not.toHaveProperty('max_upload_bytes')

    await user.type(field, '2048')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      max_upload_bytes: 2048 * 1024 * 1024,
    })
  })

  it('refuses a limit above what the server can stage, and a non-positive one', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        formats={[nuget]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    await user.type(screen.getByLabelText('Name'), 'too-big')
    const field = screen.getByLabelText('Maximum upload size (MiB)')
    await user.type(field, '8192')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('At most 4096 MiB')

    await user.clear(field)
    await user.type(field, '0')
    await user.click(screen.getByRole('button', { name: 'Create repository' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('positive number')
  })

  it('on edit, sends a changed limit, null for an emptied one, nothing when untouched', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="edit"
        existing={storedHosted}
        formats={[nuget]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    const field = screen.getByLabelText('Maximum upload size (MiB)')
    expect(field).toHaveValue(100)
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedHosted)).toEqual({})

    await user.clear(field)
    await user.type(field, '250')
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedHosted)).toEqual({
      max_upload_bytes: 250 * 1024 * 1024,
    })

    await user.clear(field)
    await save(user)
    expect(toUpdateBody(lastValues(onSubmit), storedHosted)).toEqual({
      max_upload_bytes: null,
    })
  })

  it('is not offered for proxies and groups', () => {
    render(
      <RepositoryForm
        mode="edit"
        existing={storedProxy}
        formats={[nuget]}
        submitting={false}
        onSubmit={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.queryByLabelText('Maximum upload size (MiB)')).toBeNull()
  })
})

describe('raw repositories', () => {
  function renderRawCreate() {
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        formats={[NUGET_FORMAT, DOCKER_FORMAT, RAW_FORMAT]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    return onSubmit
  }

  it('hosted: a deployment policy instead of allow_redeploy, and inline display', async () => {
    const user = userEvent.setup()
    const onSubmit = renderRawCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'raw')
    expect(screen.queryByLabelText(/Allow redeploy \(re-push/)).toBeNull()
    await user.type(screen.getByLabelText('Name'), 'binaries')
    await user.selectOptions(screen.getByLabelText('Deployment policy'), 'allow_redeploy')
    await user.click(screen.getByLabelText(/Display files in the browser/))
    await create(user)

    expect(toCreateBody(lastValues(onSubmit))).toEqual({
      name: 'binaries',
      kind: 'hosted',
      format: 'raw',
      anonymous_read: false,
      online: true,
      deployment_policy: 'allow_redeploy',
      content_disposition: 'inline',
    })
  })

  it('proxy: a maximum age instead of the package delay and metadata TTL', async () => {
    const user = userEvent.setup()
    const onSubmit = renderRawCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'raw')
    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    expect(screen.queryByLabelText('Package delay (seconds)')).toBeNull()
    expect(screen.queryByLabelText('Metadata TTL (seconds)')).toBeNull()
    await user.type(screen.getByLabelText('Name'), 'pdfium')
    await user.type(
      screen.getByLabelText('Remote URL'),
      'https://github.com/bblanchon/pdfium-binaries/releases/download/',
    )
    await user.type(screen.getByLabelText('Maximum age (seconds)'), '0')
    await create(user)

    const body = toCreateBody(lastValues(onSubmit))
    expect(body).toMatchObject({
      kind: 'proxy',
      format: 'raw',
      remote_url: 'https://github.com/bblanchon/pdfium-binaries/releases/download/',
      max_age_seconds: 0,
    })
    expect(body).not.toHaveProperty('package_delay_seconds')
    expect(body).not.toHaveProperty('metadata_ttl_seconds')
    expect(body).not.toHaveProperty('content_disposition')
  })

  it('group: no dependency-confusion options', async () => {
    const user = userEvent.setup()
    const onSubmit = renderRawCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'raw')
    await user.selectOptions(screen.getByLabelText('Kind'), 'group')
    expect(screen.queryByLabelText(/Prefer hosted/)).toBeNull()
    expect(screen.queryByLabelText('Reserved prefixes')).toBeNull()
    await user.type(screen.getByLabelText('Name'), 'all-files')
    await create(user)

    const body = toCreateBody(lastValues(onSubmit))
    expect(body).not.toHaveProperty('prefer_hosted')
    expect(body).not.toHaveProperty('reserved_prefixes')
  })

  it('on edit, diffs the raw options and clears an emptied maximum age', () => {
    const storedRaw: RepoView = {
      ...storedProxy,
      name: 'pdfium',
      format: 'raw',
      metadata_ttl_seconds: null,
      max_age_seconds: 600,
      content_disposition: 'attachment',
    }
    const untouched = lastValuesOf(storedRaw)
    expect(untouched.max_age_seconds).toBe('600')
    expect(toUpdateBody(untouched, storedRaw)).toEqual({})
    expect(
      toUpdateBody(
        { ...untouched, max_age_seconds: '', inline_content: true, package_delay_seconds: '9' },
        storedRaw,
      ),
    ).toEqual({ max_age_seconds: null, content_disposition: 'inline' })

    const hosted: RepoView = {
      ...storedRaw,
      kind: 'hosted',
      remote_url: null,
      max_age_seconds: null,
      deployment_policy: 'disable_redeploy',
    }
    const values = lastValuesOf(hosted)
    expect(
      toUpdateBody({ ...values, deployment_policy: 'read_only' }, hosted),
    ).toEqual({ deployment_policy: 'read_only' })
  })
})

describe('npm repositories', () => {
  function renderNpmCreate() {
    const onSubmit = vi.fn()
    render(
      <RepositoryForm
        mode="create"
        formats={[NUGET_FORMAT, NPM_FORMAT]}
        submitting={false}
        onSubmit={onSubmit}
        onCancel={() => {}}
      />,
    )
    return onSubmit
  }

  it('hosted: a deployment policy instead of allow_redeploy', async () => {
    const user = userEvent.setup()
    const onSubmit = renderNpmCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'npm')
    expect(screen.queryByLabelText(/Allow redeploy \(re-push/)).toBeNull()
    await user.type(screen.getByLabelText('Name'), 'npm-hosted')
    await user.selectOptions(screen.getByLabelText('Deployment policy'), 'read_only')
    await create(user)

    expect(toCreateBody(lastValues(onSubmit))).toEqual({
      name: 'npm-hosted',
      kind: 'hosted',
      format: 'npm',
      anonymous_read: false,
      online: true,
      deployment_policy: 'read_only',
    })
  })

  it('proxy: the public registry as placeholder, with a package delay', async () => {
    const user = userEvent.setup()
    const onSubmit = renderNpmCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'npm')
    await user.selectOptions(screen.getByLabelText('Kind'), 'proxy')
    expect(screen.getByLabelText('Remote URL')).toHaveAttribute(
      'placeholder',
      'https://registry.npmjs.org',
    )
    await user.type(screen.getByLabelText('Name'), 'npmjs')
    await user.type(screen.getByLabelText('Remote URL'), 'https://registry.npmjs.org')
    await user.clear(screen.getByLabelText('Package delay (seconds)'))
    await user.type(screen.getByLabelText('Package delay (seconds)'), '86400')
    await create(user)

    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      kind: 'proxy',
      format: 'npm',
      remote_url: 'https://registry.npmjs.org',
      package_delay_seconds: 86400,
    })
  })

  it('group: reserved scopes and the writable member publishes go to', async () => {
    const user = userEvent.setup()
    const onSubmit = renderNpmCreate()

    await user.selectOptions(screen.getByLabelText('Format'), 'npm')
    await user.selectOptions(screen.getByLabelText('Kind'), 'group')
    await user.type(screen.getByLabelText('Name'), 'npm-all')
    await user.type(screen.getByLabelText('Reserved prefixes'), '@acme, @acme-internal')
    await user.type(screen.getByLabelText('Writable member'), 'npm-hosted')
    await create(user)

    expect(toCreateBody(lastValues(onSubmit))).toMatchObject({
      kind: 'group',
      format: 'npm',
      prefer_hosted: true,
      reserved_prefixes: ['@acme', '@acme-internal'],
      writable_member: 'npm-hosted',
    })
  })

  it('on edit, diffs the deployment policy and the writable member', () => {
    const hosted: RepoView = {
      ...storedProxy,
      name: 'npm-hosted',
      format: 'npm',
      kind: 'hosted',
      remote_url: null,
      deployment_policy: 'disable_redeploy',
    }
    const values = lastValuesOf(hosted)
    expect(toUpdateBody(values, hosted)).toEqual({})
    expect(
      toUpdateBody({ ...values, deployment_policy: 'allow_redeploy' }, hosted),
    ).toEqual({ deployment_policy: 'allow_redeploy' })

    const group: RepoView = {
      ...storedProxy,
      name: 'npm-all',
      format: 'npm',
      kind: 'group',
      remote_url: null,
      writable_member: 'npm-hosted',
    }
    expect(toUpdateBody({ ...lastValuesOf(group), writable_member: '' }, group)).toEqual({
      writable_member: null,
    })
  })
})
