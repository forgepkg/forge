import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { RepoView } from '~/api/repositories'
import {
  RepositoryForm,
  toCreateBody,
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
