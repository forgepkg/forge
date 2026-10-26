import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { AccessLevel } from '~/api/rbac'
import type { RealmKind } from '~/api/realms'
import { canonicalUsername, upnError, type CreatedUser } from '~/api/users'
import { useCreateUser } from '~/queries/useUsers'
import { useRealms } from '~/queries/useRealms'
import { useEmailSettings } from '~/queries/useEmail'
import { formatDateTime } from '~/lib/oci'
import { AccessLevelFields } from '~/components/AccessLevelFields'
import { REALM_KINDS } from '~/components/RealmForm'
import { ShowOnceSecret } from '~/components/ShowOnceSecret'
import {
  Button,
  Columns,
  FormActions,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  TextField,
} from '~/components/ui'

export const Route = createFileRoute('/_app/manage/users/new')({
  component: CreateUserPage,
})

/** A loose check of an address: something@something, without spaces. */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/

/** The realm kinds whose accounts an administrator creates here. */
const ACCOUNT_REALM_KINDS: RealmKind[] = ['credential_forwarding', 'trusted_header']

/**
 * Create a user (#322). A local account gets no password here: Forge emails
 * its user an invitation to choose one (to the username, or the address
 * entered), or, without an email service, shows the link once to pass on.
 * An account of a credential-forwarding realm signs in with the upstream's
 * password instead, and one of a trusted-header realm is named by the
 * headers of its proxy. Either way the admin picks the built-in access level.
 */
function CreateUserPage() {
  const create = useCreateUser()
  const realms = useRealms()
  const email = useEmailSettings()
  const accountRealms = (realms.data ?? []).filter((r) => ACCOUNT_REALM_KINDS.includes(r.kind))
  const [username, setUsername] = useState('')
  const [usernameTouched, setUsernameTouched] = useState(false)
  // Blank: the username.
  const [address, setAddress] = useState('')
  // '' = invited (a Forge password); otherwise the account realm's name.
  const [realm, setRealm] = useState('')
  const realmKind = accountRealms.find((r) => r.name === realm)?.kind
  const [level, setLevel] = useState<AccessLevel>('reader')
  const [created, setCreated] = useState<{
    user: CreatedUser
    realmKind?: RealmKind
  } | null>(null)

  const usernameError = username.trim() ? upnError(username) : null
  const showUsernameError = usernameTouched && usernameError !== null
  const addressError =
    address.trim() !== '' && !EMAIL_SHAPE.test(address.trim())
      ? 'Enter an email address.'
      : null
  const noEmailService =
    email.data !== undefined && (!email.data.configured || !email.data.enabled)

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!username.trim() || usernameError || addressError) {
      setUsernameTouched(true)
      return
    }
    create.mutate(
      {
        username: username.trim(),
        email: address.trim() || undefined,
        role: level,
        realm: realm || undefined,
      },
      { onSuccess: (user) => setCreated({ user, realmKind }) },
    )
  }

  function another() {
    setCreated(null)
    setUsername('')
    setUsernameTouched(false)
    setAddress('')
    setRealm('')
    setLevel('reader')
    create.reset()
  }

  return (
    <Page>
      <PageHeader
        title="New user"
        crumbs={[{ label: 'Users', to: '/manage/users' }, { label: 'New user' }]}
        description="A local account is invited to choose its own password; an account of a credential-forwarding realm signs in with the upstream's, and one of a trusted-header realm is named by its proxy."
      />

      {created ? (
        <Created user={created.user} realmKind={created.realmKind} onAnother={another} />
      ) : (
        <Columns
          aside={
            <Panel title="Invitations">
              <p className="fg-text">
                The invitation link works once, until it expires; the user
                page can send a new one or hand over a link while the user
                has not chosen a password.
              </p>
            </Panel>
          }
          asideLabel="About invitations"
        >
          <form onSubmit={submit} className="flex flex-col gap-6" aria-label="New user">
            {!realm && noEmailService && (
              <Notice
                tone="warn"
                role="status"
                action={
                  <Link to="/manage/settings/email" className="fg-notice-action">
                    Set up email
                  </Link>
                }
              >
                No email service is configured, so no invitation can be sent:
                the account is created and its invitation link is shown here
                once, to pass on yourself.
              </Notice>
            )}
            <Panel title="Account">
              <div className="fg-form">
                <TextField
                  label="Username"
                  type="text"
                  autoComplete="off"
                  mono
                  placeholder="alice@example.com"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onBlur={() => setUsernameTouched(true)}
                  error={showUsernameError ? usernameError : undefined}
                />
                {accountRealms.length > 0 && (
                  <SelectField
                    label="Sign-in"
                    value={realm}
                    onChange={(e) => setRealm(e.target.value)}
                    description={
                      realmKind === 'credential_forwarding'
                        ? 'Signs in with the upstream’s password, which gets the part of the username before the @.'
                        : realmKind === 'trusted_header'
                          ? 'The proxy in front of Forge names the account in its header; it has no password. Its API tokens are issued on its user page.'
                          : 'The user is invited to choose a password.'
                    }
                  >
                    <option value="">Forge password (invitation)</option>
                    {accountRealms.map((r) => (
                      <option key={r.id} value={r.name}>
                        {REALM_KINDS[r.kind].label}: {r.name}
                      </option>
                    ))}
                  </SelectField>
                )}
                <TextField
                  label="Email address"
                  type="email"
                  autoComplete="off"
                  placeholder={canonicalUsername(username) || 'the username'}
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  error={addressError ?? undefined}
                  description={
                    realm
                      ? 'Optional: where Forge writes to the user.'
                      : 'Where the invitation goes. Blank: the username, when it is a mailbox.'
                  }
                />
              </div>
            </Panel>
            <Panel title="Access">
              <AccessLevelFields value={level} onChange={setLevel} />
            </Panel>
            {create.isError && (
              <Notice tone="danger">{create.error.body || create.error.message}</Notice>
            )}
            <FormActions>
              <Button variant="ghost" href="/manage/users">
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                icon={realm ? 'Plus' : 'Mail'}
                disabled={
                  create.isPending || !username.trim() || !!usernameError || !!addressError
                }
              >
                {create.isPending ? 'Creating…' : realm ? 'Create user' : 'Create and invite'}
              </Button>
            </FormActions>
          </form>
        </Columns>
      )}
    </Page>
  )
}

/** What the create did: the invitation sent, or its link to pass on. */
function Created({
  user,
  realmKind,
  onAnother,
}: {
  user: CreatedUser
  realmKind?: RealmKind
  onAnother: () => void
}) {
  const invitation = user.invitation
  const until = invitation ? formatDateTime(invitation.expires_at) : ''
  return (
    <Panel
      title={`Created ${user.username}`}
      footer={
        <>
          <Button onClick={onAnother}>Create another</Button>
          <Button
            variant="primary"
            href={`/manage/users/${user.id}`}
            aria-label={`Go to ${user.username}`}
          >
            {`Go to ${user.username}`}
          </Button>
        </>
      }
    >
      {invitation?.email_sent ? (
        <Notice tone="ok">
          Created {user.username} and sent the invitation to {invitation.email}.
          The link works once, until {until}.
        </Notice>
      ) : invitation ? (
        <>
          <p className="fg-text">
            Created {user.username}.{' '}
            {invitation.error === 'no email service is configured'
              ? 'No email service is configured,'
              : `The invitation email was not sent (${invitation.error ?? 'unknown error'}),`}{' '}
            so give the user this link to choose a password. It works once,
            until {until}.
          </p>
          {invitation.link && (
            <ShowOnceSecret secret={invitation.link} label="Invitation link" />
          )}
        </>
      ) : realmKind === 'trusted_header' ? (
        <Notice tone="ok">
          Created {user.username}: the headers of its realm&apos;s proxy name it.
        </Notice>
      ) : (
        <Notice tone="ok">
          Created {user.username}: it signs in with its upstream password.
        </Notice>
      )}
    </Panel>
  )
}
