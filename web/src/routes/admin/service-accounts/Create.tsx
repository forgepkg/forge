import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { AccessLevel } from '~/api/rbac'
import { upnError, type CreatedUser } from '~/api/users'
import { useCreateUser } from '~/queries/useUsers'
import { useRealms } from '~/queries/useRealms'
import { AccessLevelFields, SERVICE_ACCOUNT_LEVELS } from '~/components/AccessLevelFields'
import {
  Button,
  Columns,
  FormActions,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  TextareaField,
  TextField,
} from '~/components/ui'

export const Route = createFileRoute('/_app/manage/service-accounts/new')({
  component: CreateServiceAccountPage,
})

/**
 * Create a service account (#508): its name (a UPN, like every account's),
 * what it is for and who owns it, optionally the trusted-header realm whose
 * proxy names it, and its built-in access level (reader or writer: a service
 * account is never an admin). It gets no password, invitation or email; its
 * API tokens are issued on its page, where the create leads.
 */
function CreateServiceAccountPage() {
  const create = useCreateUser()
  const realms = useRealms()
  const trustedHeaderRealms = (realms.data ?? []).filter((r) => r.kind === 'trusted_header')
  const [username, setUsername] = useState('')
  const [usernameTouched, setUsernameTouched] = useState(false)
  const [description, setDescription] = useState('')
  // '' = no realm: only its tokens authenticate it.
  const [realm, setRealm] = useState('')
  const [level, setLevel] = useState<AccessLevel>('reader')
  const [created, setCreated] = useState<CreatedUser | null>(null)

  const usernameError = username.trim() ? upnError(username) : null
  const showUsernameError = usernameTouched && usernameError !== null

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!username.trim() || usernameError) {
      setUsernameTouched(true)
      return
    }
    create.mutate(
      {
        username: username.trim(),
        kind: 'service',
        description: description.trim() || undefined,
        role: level,
        realm: realm || undefined,
      },
      { onSuccess: setCreated },
    )
  }

  function another() {
    setCreated(null)
    setUsername('')
    setUsernameTouched(false)
    setDescription('')
    setRealm('')
    setLevel('reader')
    create.reset()
  }

  return (
    <Page>
      <PageHeader
        title="New service account"
        crumbs={[
          { label: 'Service accounts', to: '/manage/service-accounts' },
          { label: 'New service account' },
        ]}
        description="An account for a machine or a network that nobody signs in to. It authenticates with the API tokens you issue on its page, or through the trusted-header realm whose proxy names it."
      />

      {created ? (
        <Panel
          title={`Created ${created.username}`}
          footer={
            <>
              <Button onClick={another}>Create another</Button>
              <Button
                variant="primary"
                href={`/manage/service-accounts/${created.id}`}
                aria-label={`Go to ${created.username}`}
              >
                {`Go to ${created.username}`}
              </Button>
            </>
          }
        >
          <Notice tone="ok">
            {created.realm
              ? `Created ${created.username}: the proxy of ${created.realm} names it. Its page issues its API tokens.`
              : `Created ${created.username}. Issue its API tokens on its page.`}
          </Notice>
        </Panel>
      ) : (
        <Columns
          aside={
            <Panel title="Signing in">
              <p className="fg-text">
                Nobody signs in to a service account: it has no password and
                no email, and no identity provider is linked to it. Its API
                tokens authenticate it, and so does the trusted-header realm
                it belongs to; no other realm may name it. Deactivating it
                stops both.
              </p>
            </Panel>
          }
          asideLabel="About service accounts"
        >
          <form
            onSubmit={submit}
            className="flex flex-col gap-6"
            aria-label="New service account"
          >
            <Panel title="Service account">
              <div className="fg-form">
                <TextField
                  label="Name"
                  type="text"
                  autoComplete="off"
                  mono
                  placeholder="ci-runners@example.com"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onBlur={() => setUsernameTouched(true)}
                  error={showUsernameError ? usernameError : undefined}
                  description="A UPN, in the name space every account shares."
                />
                <TextareaField
                  label="Description"
                  optional
                  rows={3}
                  placeholder="The build agents of the platform team; owner: platform@example.com"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  description="What it is for and who owns it."
                />
                <SelectField
                  label="Trusted-header realm"
                  value={realm}
                  onChange={(e) => setRealm(e.target.value)}
                  description={
                    realm
                      ? 'The proxy in front of Forge names the account in this realm’s header; no other realm may.'
                      : trustedHeaderRealms.length === 0
                        ? 'No trusted-header realm exists: only its API tokens authenticate it.'
                        : 'Only its API tokens authenticate it.'
                  }
                >
                  <option value="">None (API tokens only)</option>
                  {trustedHeaderRealms.map((r) => (
                    <option key={r.id} value={r.name}>
                      {r.name}
                    </option>
                  ))}
                </SelectField>
              </div>
            </Panel>
            <Panel title="Access">
              <AccessLevelFields
                value={level}
                onChange={setLevel}
                levels={SERVICE_ACCOUNT_LEVELS}
              />
              <p className="fg-text fg-text--small">
                A service account is never an admin: for admin automation,
                issue an administrator a token with the admin scope.{' '}
                <Link to="/manage/roles" className="fg-link">
                  Roles
                </Link>{' '}
                assigned on its page add to this level.
              </p>
            </Panel>
            {create.isError && (
              <Notice tone="danger">{create.error.body || create.error.message}</Notice>
            )}
            <FormActions>
              <Button variant="ghost" href="/manage/service-accounts">
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                icon="Plus"
                disabled={create.isPending || !username.trim() || !!usernameError}
              >
                {create.isPending ? 'Creating…' : 'Create service account'}
              </Button>
            </FormActions>
          </form>
        </Columns>
      )}
    </Page>
  )
}
