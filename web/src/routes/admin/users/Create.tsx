import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { AccessLevel } from '~/api/rbac'
import { canonicalUsername, upnError, type CreatedUser } from '~/api/users'
import { useCreateUser } from '~/queries/useUsers'
import { useRealms } from '~/queries/useRealms'
import { useEmailSettings } from '~/queries/useEmail'
import { AccessLevelFields } from '~/components/AccessLevelFields'
import { Button } from '~/components/catalyst/button'
import {
  Description,
  ErrorMessage,
  Field,
  FieldGroup,
  Label,
} from '~/components/catalyst/fieldset'
import { Heading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'
import { Text } from '~/components/catalyst/text'
import { ShowOnceSecret } from '~/components/ShowOnceSecret'

export const Route = createFileRoute('/_app/manage/users/new')({
  component: CreateUserPage,
})

/** A loose check of an address: something@something, without spaces. */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/

/**
 * Create a user (#322). A local account gets no password here: Forge emails
 * its user an invitation to choose one (to the username, or the address
 * entered), or, without an email service, shows the link once to pass on.
 * An account of a credential-forwarding realm signs in with the upstream's
 * password instead. Either way the admin picks the built-in access level.
 */
function CreateUserPage() {
  const create = useCreateUser()
  const realms = useRealms()
  const email = useEmailSettings()
  const forwarding = (realms.data ?? []).filter((r) => r.kind === 'credential_forwarding')
  const [username, setUsername] = useState('')
  const [usernameTouched, setUsernameTouched] = useState(false)
  // Blank: the username.
  const [address, setAddress] = useState('')
  // '' = invited (a Forge password); otherwise the forwarding realm's name.
  const [realm, setRealm] = useState('')
  const [level, setLevel] = useState<AccessLevel>('reader')
  const [created, setCreated] = useState<CreatedUser | null>(null)

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
      { onSuccess: (user) => setCreated(user) },
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
    <section className="space-y-6">
      <div>
        <Link
          to="/manage/users"
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Users
        </Link>
        <Heading className="mt-1">New user</Heading>
      </div>

      {created ? (
        <Created user={created} onAnother={another} />
      ) : (
        <form onSubmit={submit} className="space-y-8" aria-label="New user">
          {!realm && noEmailService && (
            <p
              role="status"
              className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-sm/6 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400"
            >
              No email service is configured, so no invitation can be sent:
              the account is created and its invitation link is shown here
              once, to pass on yourself.{' '}
              <Link
                to="/manage/settings/email"
                className="font-medium underline hover:no-underline"
              >
                Set up email
              </Link>
            </p>
          )}
          <FieldGroup>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Username</Label>
                <Input
                  type="text"
                  autoComplete="off"
                  placeholder="alice@example.com"
                  value={username}
                  invalid={showUsernameError}
                  onChange={(e) => setUsername(e.target.value)}
                  onBlur={() => setUsernameTouched(true)}
                />
                {showUsernameError && <ErrorMessage>{usernameError}</ErrorMessage>}
              </Field>
              {forwarding.length > 0 && (
                <Field>
                  <Label>Sign-in</Label>
                  <Select value={realm} onChange={(e) => setRealm(e.target.value)}>
                    <option value="">Forge password (invitation)</option>
                    {forwarding.map((r) => (
                      <option key={r.id} value={r.name}>
                        Credential forwarding: {r.name}
                      </option>
                    ))}
                  </Select>
                  <Description>
                    {realm
                      ? 'Signs in with the upstream’s password, which gets the part of the username before the @.'
                      : 'The user is invited to choose a password.'}
                  </Description>
                </Field>
              )}
              <Field>
                <Label>Email address</Label>
                <Input
                  type="email"
                  autoComplete="off"
                  placeholder={canonicalUsername(username) || 'the username'}
                  value={address}
                  invalid={addressError !== null}
                  onChange={(e) => setAddress(e.target.value)}
                />
                {addressError ? (
                  <ErrorMessage>{addressError}</ErrorMessage>
                ) : (
                  <Description>
                    {realm
                      ? 'Optional: where Forge writes to the user.'
                      : 'Where the invitation goes. Blank: the username, when it is a mailbox.'}
                  </Description>
                )}
              </Field>
            </div>
            <AccessLevelFields value={level} onChange={setLevel} />
          </FieldGroup>
          {create.isError && (
            <p
              role="alert"
              className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
            >
              {create.error.body || create.error.message}
            </p>
          )}
          <Button
            type="submit"
            disabled={create.isPending || !username.trim() || !!usernameError || !!addressError}
          >
            {create.isPending ? 'Creating…' : realm ? 'Create user' : 'Create and invite'}
          </Button>
        </form>
      )}
    </section>
  )
}

/** What the create did: the invitation sent, or its link to pass on. */
function Created({ user, onAnother }: { user: CreatedUser; onAnother: () => void }) {
  const invitation = user.invitation
  return (
    <div className="space-y-4">
      {invitation?.email_sent ? (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Created {user.username} and sent the invitation to {invitation.email}.
          The link works once, until {new Date(invitation.expires_at).toLocaleString()}.
        </p>
      ) : invitation ? (
        <>
          <Text>
            Created {user.username}.{' '}
            {invitation.error === 'no email service is configured'
              ? 'No email service is configured,'
              : `The invitation email was not sent (${invitation.error ?? 'unknown error'}),`}{' '}
            so give the user this link to choose a password. It works once,
            until {new Date(invitation.expires_at).toLocaleString()}.
          </Text>
          {invitation.link && (
            <ShowOnceSecret secret={invitation.link} label="Invitation link" />
          )}
        </>
      ) : (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Created {user.username}: it signs in with its upstream password.
        </p>
      )}
      <div className="flex flex-wrap gap-3">
        <Link
          to="/manage/users/$userId"
          params={{ userId: String(user.id) }}
          className="inline-flex items-center rounded-lg bg-zinc-900 px-3 py-1.5 text-sm/6 font-semibold text-white hover:bg-zinc-700 dark:bg-white dark:text-zinc-900"
        >
          Go to {user.username}
        </Link>
        <Button outline onClick={onAnother}>
          Create another
        </Button>
      </div>
    </div>
  )
}
