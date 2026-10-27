import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { CreatedToken, TokenView } from '~/api/tokens'
import {
  ACCESS_ROLES,
  accessLevel,
  ADMIN_ROLE,
  WRITER_ROLE,
  type AccessLevel,
} from '~/api/rbac'
import { ApiError } from '~/lib/httpClient'
import {
  authSourceLabel,
  isServiceAccount,
  isTrustedHeaderAccount,
  type IssuedInvitation,
  type UserView,
} from '~/api/users'
import {
  useConvertUserToLocal,
  useInviteUser,
  useReauthUser,
  useRevokeInvitation,
  useSetUserActive,
  useUsers,
} from '~/queries/useUsers'
import { useMe } from '~/queries/useMe'
import {
  useCreateToken,
  useRevokeToken,
  useSetTokenScope,
  useTokens,
} from '~/queries/useTokens'
import { useRepositories } from '~/queries/useRepositories'
import {
  useAssignRole,
  useRoles,
  useSelectors,
  useUnassignRole,
  useUserEffective,
  useUserRoles,
} from '~/queries/useRbac'
import {
  Button,
  CellActions,
  Code,
  Columns,
  Dialog,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/ui'
import { AccessBadge } from '~/components/AccessBadge'
import { UserStatusBadge } from './List'
import { AccessLevelFields, SERVICE_ACCOUNT_LEVELS } from '~/components/AccessLevelFields'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  byId,
  InlineError,
  LevelBadge,
  RepositoryLabel,
  repoNames,
  SelectorLabel,
} from '~/components/RbacLabels'
import { ShowOnceSecret } from '~/components/ShowOnceSecret'
import { TokenCreateForm } from '~/components/TokenCreateForm'
import {
  formatTokenExpiry,
  TokenScopeBadges,
  TokenStatusBadge,
  tokenStatus,
} from '~/components/TokenBadges'
import {
  draftFromScope,
  draftProblem,
  scopeFromDraft,
  TokenScopeFields,
  type ScopeDraft,
} from '~/components/TokenScopeFields'

export const Route = createFileRoute('/_app/manage/users/$userId')({
  component: UserPage,
})

/**
 * The add form at the top of a flush panel, above its table (a role):
 * padded like the panel body, ruled off from the table.
 */
const ADD_STRIP = 'grid gap-4 border-b border-line px-5 py-4'

/**
 * One user: their built-in access level (reader, writer or admin), which
 * admins switch here (in the side column); the roles they hold, which admins
 * assign and remove here (taking `admin` from the last active administrator
 * is refused with the server's reason); their effective access, the union of
 * those roles' grants with repository and selector names; and their tokens.
 * Tokens are listed as metadata only (the secret is never returned), issued
 * with an optional scope (the plaintext is shown **once** via
 * `ShowOnceSecret`, held in transient component state and never written into
 * a query cache), re-scoped and revoked (after a confirmation dialog). The
 * header says how the user signs in, so a role or token does not go to a
 * look-alike account by mistake. A credential-forwarding account whose realm
 * kept its password hash can be switched to a local account with that
 * password from here. An invited account (its user has not chosen a password
 * yet) shows its invitation, which can be resent, copied as a link (shown
 * once) or revoked. The account section on top deactivates, reactivates and
 * signs the user out everywhere.
 */
function UserPage() {
  const { userId } = Route.useParams()
  const id = Number(userId)

  // The username comes from the cached users list (there is no per-user GET).
  const users = useUsers()
  const user = users.data?.find((u) => u.id === id)
  const name = user ? user.username : `User #${id}`
  const trustedHeader = user ? isTrustedHeaderAccount(user) : false

  if (user && isServiceAccount(user)) {
    return (
      <Page>
        <PageHeader
          title={name}
          crumbs={[{ label: 'Users', to: '/manage/users' }, { label: name }]}
        />
        <EmptyState title="A service account" icon="Terminal">
          Nobody signs in to {user.username}: manage it under{' '}
          <Link
            to="/manage/service-accounts/$userId"
            params={{ userId: String(user.id) }}
            className="fg-link"
          >
            Service accounts
          </Link>
          .
        </EmptyState>
      </Page>
    )
  }

  return (
    <Page>
      <PageHeader
        title={name}
        crumbs={[{ label: 'Users', to: '/manage/users' }, { label: name }]}
        meta={
          user
            ? [
                <>
                  Sign-in:{' '}
                  <span className="fg-strong">{authSourceLabel(user.auth_source)}</span>
                </>,
              ]
            : undefined
        }
      >
        {user && <UserStatusBadge status={user.status} />}
      </PageHeader>

      {user && <UserAccount user={user} />}
      {user && (user.status === 'invited' || user.status === 'invitation_expired') && (
        <UserInvitation user={user} />
      )}
      {user?.captured_password_at && <KeptPassword user={user} />}

      <Columns
        asideLabel="Access"
        aside={<UserAccess userId={id} trustedHeader={trustedHeader} />}
      >
        <UserRoles
          userId={id}
          legacyAdmin={user?.is_admin ?? false}
          trustedHeader={trustedHeader}
        />
        <EffectiveAccess userId={id} />
        <UserTokens userId={id} inactive={user?.active === false} />
      </Columns>
    </Page>
  )
}

/**
 * The user's built-in access level: reader (no built-in role), writer (the
 * `writer` role) or admin (the `admin` role), switched through
 * `/admin/users/{id}/roles`. A switch assigns the new level's role first and
 * then takes the other one, so a refused step (the last active
 * administrator keeps `admin`: 409, with the server's reason) never leaves
 * the user with less access than before. A service account
 * (`serviceAccount`) or an account of a trusted-header realm
 * (`trustedHeader`) is a reader or a writer, never an admin.
 */
export function UserAccess({
  userId,
  serviceAccount = false,
  trustedHeader = false,
}: {
  userId: number
  serviceAccount?: boolean
  trustedHeader?: boolean
}) {
  const held = useUserRoles(userId)
  const roles = useRoles()
  const assign = useAssignRole()
  const unassign = useUnassignRole()
  const current = accessLevel((held.data ?? []).map((r) => r.name))
  const [choice, setChoice] = useState<AccessLevel | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const chosen = choice ?? current

  async function save() {
    if (chosen === current) return
    setSaving(true)
    setError(null)
    try {
      if (chosen !== 'reader') {
        const name = ACCESS_ROLES[chosen]
        const role = (roles.data ?? []).find((r) => r.name === name)
        if (!role) throw new Error(`The built-in role ${name} is missing.`)
        await assign.mutateAsync({ userId, roleId: role.id })
      }
      for (const role of held.data ?? []) {
        const level = role.name === ADMIN_ROLE || role.name === WRITER_ROLE
        if (level && (chosen === 'reader' || role.name !== ACCESS_ROLES[chosen])) {
          await unassign.mutateAsync({ userId, roleId: role.id })
        }
      }
      setChoice(null)
    } catch (e) {
      setError(
        e instanceof ApiError ? e.body || e.message : (e as Error).message,
      )
    } finally {
      setSaving(false)
    }
  }

  const loaded = !held.isError && !roles.isError && !held.isLoading && !roles.isLoading

  return (
    <Panel
      title="Access"
      description={
        serviceAccount
          ? 'The service account’s built-in role: a service account is never an admin. Its other roles add to it.'
          : trustedHeader
            ? "The user's built-in role: the headers of a trusted-header realm never make anyone an admin. Their other roles add to it."
            : "The user's built-in role. Their other roles add to it."
      }
      actions={
        loaded && (
          <span className="flex items-center gap-2 text-ink-muted">
            Now: <AccessBadge level={current} />
          </span>
        )
      }
    >
      {held.isError || roles.isError ? (
        <ErrorState
          title="Could not load the user's access"
          message={(held.error ?? roles.error)?.message}
          onRetry={() => {
            void held.refetch()
            void roles.refetch()
          }}
        />
      ) : held.isLoading || roles.isLoading ? (
        <Skeleton lines={3} label="Loading access…" />
      ) : (
        <form
          aria-label="Change access"
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
          className="grid gap-4"
        >
          <AccessLevelFields
            value={chosen}
            onChange={setChoice}
            disabled={saving}
            levels={serviceAccount || trustedHeader ? SERVICE_ACCOUNT_LEVELS : undefined}
          />
          {error && <InlineError>{error}</InlineError>}
          <div>
            <Button type="submit" disabled={saving || chosen === current}>
              {saving ? 'Saving…' : 'Change access'}
            </Button>
          </div>
        </form>
      )}
    </Panel>
  )
}

/**
 * The roles the user holds; admins assign and remove them here. A service
 * account (`serviceAccount`) or an account of a trusted-header realm
 * (`trustedHeader`) is never offered `admin`.
 */
export function UserRoles({
  userId,
  legacyAdmin,
  serviceAccount = false,
  trustedHeader = false,
}: {
  userId: number
  legacyAdmin: boolean
  serviceAccount?: boolean
  trustedHeader?: boolean
}) {
  const held = useUserRoles(userId)
  const roles = useRoles()
  const assign = useAssignRole()
  const unassign = useUnassignRole()
  const [roleId, setRoleId] = useState('')

  const heldIds = new Set((held.data ?? []).map((r) => r.id))
  const candidates = (roles.data ?? []).filter(
    (r) => !heldIds.has(r.id) && !((serviceAccount || trustedHeader) && r.name === ADMIN_ROLE),
  )
  const holdsAdmin = (held.data ?? []).some((r) => r.name === ADMIN_ROLE)

  return (
    <Panel
      title="Roles"
      count={held.data?.length}
      description={
        serviceAccount
          ? 'What the service account may do follows from the roles it holds.'
          : 'What the user may do follows from the roles they hold.'
      }
      flush
    >
      <form
        aria-label="Assign role"
        onSubmit={(e) => {
          e.preventDefault()
          if (roleId === '') return
          assign.mutate(
            { userId, roleId: Number(roleId) },
            { onSuccess: () => setRoleId('') },
          )
        }}
        className={ADD_STRIP}
      >
        {legacyAdmin && held.data && !holdsAdmin && (
          <Notice>
            The user is an administrator through the legacy <Code>is_admin</Code>{' '}
            flag, without the admin role.
          </Notice>
        )}
        <div className="flex flex-wrap items-end gap-3">
          <SelectField
            label="Role"
            className="min-w-0 flex-[1_1_240px]"
            value={roleId}
            onChange={(e) => setRoleId(e.target.value)}
          >
            <option value="">Choose a role…</option>
            {candidates.map((r) => (
              <option key={r.id} value={String(r.id)}>
                {r.name}
              </option>
            ))}
          </SelectField>
          <Button type="submit" icon="Plus" disabled={assign.isPending || roleId === ''}>
            {assign.isPending ? 'Assigning…' : 'Assign role'}
          </Button>
        </div>
        {assign.isError && (
          <InlineError>{assign.error.body || assign.error.message}</InlineError>
        )}
        {unassign.isError && (
          <InlineError>{unassign.error.body || unassign.error.message}</InlineError>
        )}
      </form>

      {held.isError ? (
        <ErrorState
          title="Could not load the user's roles"
          message={held.error?.message}
          onRetry={() => void held.refetch()}
        />
      ) : held.isLoading ? (
        <Skeleton lines={3} label="Loading roles…" />
      ) : (held.data?.length ?? 0) === 0 ? (
        <EmptyState title="The user holds no role" icon="Lock" bordered={false} />
      ) : (
        <Table caption="Roles the user holds">
          <TableHead>
            <TableHeader>Role</TableHeader>
            <TableHeader>Description</TableHeader>
            <TableHeader align="right" width="96px">
              <span className="fg-sr">Actions</span>
            </TableHeader>
          </TableHead>
          <TableBody>
            {held.data!.map((r) => (
              <TableRow key={r.id}>
                <TableCell lead>
                  <Link
                    to="/manage/roles/$roleId"
                    params={{ roleId: String(r.id) }}
                    className="fg-link-strong"
                  >
                    {r.name}
                  </Link>
                </TableCell>
                <TableCell>{r.description || '—'}</TableCell>
                <TableCell align="right">
                  <CellActions>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={unassign.isPending}
                      aria-label={`Remove role ${r.name}`}
                      onClick={() => unassign.mutate({ userId, roleId: r.id })}
                    >
                      Remove
                    </Button>
                  </CellActions>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  )
}

/**
 * The user's effective access (`/admin/users/{id}/effective`): every grant of
 * every role they hold, with repository and selector names. Reads of what
 * anonymous callers may read, and token scopes, are not part of it.
 */
export function EffectiveAccess({ userId }: { userId: number }) {
  const effective = useUserEffective(userId)
  const repos = useRepositories()
  const selectors = useSelectors()
  const names = repoNames(repos.data)
  const selectorMap = byId(selectors.data)

  return (
    <Panel
      title="Effective access"
      description="The grants of all the user's roles together. Signed-in users can also read what anonymous callers may read; a token can narrow this further."
      flush
    >
      {effective.isError ? (
        <ErrorState
          title="Could not load the user's access"
          message={effective.error?.message}
          onRetry={() => void effective.refetch()}
        />
      ) : effective.isLoading || !effective.data ? (
        <Skeleton lines={3} label="Loading access…" />
      ) : (
        <>
          {effective.data.is_admin && (
            <Notice>
              <StatusBadge tone="heat">administrator</StatusBadge> May do
              everything, on every repository, whatever the grants below say.
            </Notice>
          )}
          {effective.data.grants.length === 0 ? (
            !effective.data.is_admin && (
              <EmptyState title="The user may do nothing" icon="Lock" bordered={false} />
            )
          ) : (
            <Table caption="Effective grants">
              <TableHead>
                <TableHeader>Repository</TableHeader>
                <TableHeader width="120px">Level</TableHeader>
                <TableHeader>Packages</TableHeader>
              </TableHead>
              <TableBody>
                {effective.data.grants.map((g, i) => (
                  <TableRow key={i}>
                    <TableCell lead>
                      <RepositoryLabel id={g.repository_id} names={names} />
                    </TableCell>
                    <TableCell>
                      <LevelBadge level={g.level} />
                    </TableCell>
                    <TableCell>
                      <SelectorLabel
                        id={g.selector_id}
                        selectors={selectorMap}
                        includes={g.includes}
                        excludes={g.excludes}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </>
      )}
    </Panel>
  )
}

/**
 * The user's tokens: the New token panel (issue, with a scope), the scope
 * editor of the token being re-scoped, and the Tokens table (re-scope and
 * revoke, after a confirmation dialog). While the account is inactive its
 * tokens are refused but not revoked, which the table says.
 */
export function UserTokens({ userId, inactive }: { userId: number; inactive: boolean }) {
  const tokens = useTokens(userId)
  const create = useCreateToken(userId)
  const revoke = useRevokeToken(userId)
  const repos = useRepositories()

  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<number | null>(null)
  const [editing, setEditing] = useState<TokenView | null>(null)
  const revoking = tokens.data?.find((t) => t.id === pendingRevoke)

  function confirmRevoke(tokenId: number) {
    revoke.mutate(tokenId, { onSettled: () => setPendingRevoke(null) })
  }

  return (
    <>
      {created && (
        <>
          <ShowOnceSecret
            secret={created.token}
            label="Token"
            onDismiss={() => setCreated(null)}
          />
          <p className="fg-text fg-text--small">
            {created.expires_at === null
              ? 'This token never expires; it stays valid until revoked.'
              : `This token expires ${formatTokenExpiry(created.expires_at)}.`}
          </p>
        </>
      )}

      <TokenCreateForm
        repositories={repos.data ?? []}
        submitting={create.isPending}
        placeholder="e.g. ci-pipeline"
        onSubmit={(body, reset) =>
          create.mutate(body, {
            onSuccess: (token) => {
              setCreated(token)
              reset()
            },
          })
        }
      />

      {create.isError && (
        <InlineError>{create.error.body || create.error.message}</InlineError>
      )}
      {revoke.isError && (
        <InlineError>{revoke.error.body || revoke.error.message}</InlineError>
      )}

      {editing && (
        <ScopeEditor
          key={editing.id}
          userId={userId}
          token={editing}
          repositories={repos.data ?? []}
          onDone={() => setEditing(null)}
        />
      )}

      {revoking && (
        <Dialog
          open
          onClose={() => setPendingRevoke(null)}
          icon="Trash"
          tone="danger"
          title={`Revoke ${revoking.name}?`}
          description="Clients that use it can no longer authenticate until they are given a new token. This cannot be undone."
          confirmLabel={revoke.isPending ? 'Revoking…' : 'Revoke token'}
          confirmVariant="danger-solid"
          confirmDisabled={revoke.isPending}
          onConfirm={() => confirmRevoke(revoking.id)}
        />
      )}

      <Panel
        title="Tokens"
        count={tokens.data?.length}
        description="API tokens authenticate this user against the registry. The secret is shown only at creation time."
        flush
      >
        {inactive && (
          <Notice tone="warn" role="status">
            The account is inactive: its tokens are refused until it is
            reactivated. Revoke a token to stop it for good.
          </Notice>
        )}
        {tokens.isError ? (
          <ErrorState
            title="Could not load tokens"
            message={tokens.error?.message}
            onRetry={() => void tokens.refetch()}
          />
        ) : tokens.isLoading ? (
          <Skeleton lines={3} label="Loading tokens…" />
        ) : (tokens.data?.length ?? 0) === 0 ? (
          <EmptyState title="No tokens yet" icon="Key" bordered={false}>
            Create a token above to let this user authenticate.
          </EmptyState>
        ) : (
          <Table caption="Tokens of the user">
            <TableHead>
              <TableHeader>Name</TableHeader>
              <TableHeader>Created</TableHeader>
              <TableHeader>Expires</TableHeader>
              <TableHeader>Last used</TableHeader>
              <TableHeader>Scope</TableHeader>
              <TableHeader width="100px">Status</TableHeader>
              <TableHeader align="right">
                <span className="fg-sr">Actions</span>
              </TableHeader>
            </TableHead>
            <TableBody>
              {tokens.data!.map((token) => (
                <TokenRow
                  key={token.id}
                  token={token}
                  onEditScope={() => setEditing(token)}
                  onRequestRevoke={() => setPendingRevoke(token.id)}
                />
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
    </>
  )
}

/**
 * Change a token's scope, in a panel above the tokens table. The next
 * request with the token reads it; there is no cache to wait for.
 */
function ScopeEditor({
  userId,
  token,
  repositories,
  onDone,
}: {
  userId: number
  token: TokenView
  repositories: ReadonlyArray<{ id: number; name: string }>
  onDone: () => void
}) {
  const save = useSetTokenScope(userId)
  const [draft, setDraft] = useState<ScopeDraft>(() =>
    draftFromScope(token.scope),
  )
  const problem = draftProblem(draft)

  return (
    <Panel
      as="form"
      onSubmit={(e) => {
        e.preventDefault()
        if (problem) return
        save.mutate(
          { id: token.id, scope: scopeFromDraft(draft) },
          { onSuccess: onDone },
        )
      }}
      title={
        <>
          Scope of <span className="font-mono">{token.name}</span>
        </>
      }
      description="The next request with the token uses the new scope."
      footer={
        <>
          {problem && <p className="fg-field-desc mr-auto self-center">{problem}</p>}
          <Button variant="ghost" onClick={onDone}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={save.isPending || !!problem}>
            {save.isPending ? 'Saving…' : 'Save scope'}
          </Button>
        </>
      }
    >
      <TokenScopeFields value={draft} onChange={setDraft} repositories={repositories} />
      {save.isError && (
        <InlineError>{save.error.body || save.error.message}</InlineError>
      )}
    </Panel>
  )
}

/**
 * An invited account's invitation: where it went and until when, sending a
 * new one (the old link stops working), making a link to copy instead (shown
 * once, like a token), and revoking it.
 */
function UserInvitation({ user }: { user: UserView }) {
  const invite = useInviteUser()
  const revoke = useRevokeInvitation()
  // The answer of the last resend or copy: its link is shown once, held
  // here and never cached.
  const [issued, setIssued] = useState<IssuedInvitation | null>(null)
  const invitation = user.invitation
  const live = user.status === 'invited'

  function make(sendEmail: boolean) {
    setIssued(null)
    invite.mutate(
      { id: user.id, send_email: sendEmail },
      { onSuccess: (made) => setIssued(made) },
    )
  }

  return (
    <Panel
      title="Invitation"
      description={
        live && invitation
          ? `${user.username} has not chosen a password yet. The invitation ${
              invitation.sent_at ? `went to ${invitation.email}` : 'link was handed over'
            } and works until ${formatTs(invitation.expires_at)}.`
          : `${user.username} has not chosen a password yet, and no invitation link works: send a new one.`
      }
      footer={
        <>
          {live && (
            <Button
              variant="ghost"
              disabled={revoke.isPending}
              onClick={() => {
                setIssued(null)
                revoke.mutate(user.id)
              }}
            >
              Revoke invitation
            </Button>
          )}
          <Button icon="Copy" disabled={invite.isPending} onClick={() => make(false)}>
            Copy invitation link
          </Button>
          <Button
            variant="primary"
            icon="Mail"
            disabled={invite.isPending}
            onClick={() => make(true)}
          >
            Resend invitation
          </Button>
        </>
      }
    >
      {(invite.isError || revoke.isError) && (
        <InlineError>
          {invite.error?.body || invite.error?.message || revoke.error?.body || revoke.error?.message}
        </InlineError>
      )}
      {issued?.email_sent && (
        <Notice tone="ok">
          Sent a new invitation to {issued.email}; the previous link no longer works.
        </Notice>
      )}
      {issued && !issued.email_sent && issued.link && (
        <>
          {issued.error && (
            <p className="fg-text">
              {issued.error === 'no email service is configured'
                ? 'No email service is configured,'
                : `The invitation email was not sent (${issued.error}),`}{' '}
              so give the user this link.
            </p>
          )}
          <ShowOnceSecret
            secret={issued.link}
            label="Invitation link"
            onDismiss={() => setIssued(null)}
          />
        </>
      )}
      {!issued && !invite.isError && !revoke.isError && (
        <p className="fg-text fg-text--small">
          Resending makes a new link; the one sent before stops working.
        </p>
      )}
    </Panel>
  )
}

type AccountAction = 'deactivate' | 'reactivate' | 'reauth'

/**
 * The account's state and what changes it without deleting it, each after a
 * confirmation that says what happens:
 *
 * - **Deactivate** (`PATCH {"active": false}`): every sign-in is refused, the
 *   user's sessions end, an invitation is revoked, and their tokens are
 *   refused but not revoked. The last active administrator's is refused
 *   (409), and the server's reason shows here.
 * - **Reactivate** (`{"active": true}`): only the flag; the user's unrevoked
 *   tokens work again, so the confirmation counts them.
 * - **Sign out everywhere** (`POST …/reauth`): ends the user's browser
 *   sessions; for a credential-forwarding account the password is checked
 *   against the upstream again, and the tokens minted from a forwarded
 *   sign-in are revoked.
 */
function UserAccount({ user }: { user: UserView }) {
  const me = useMe()
  const tokens = useTokens(user.id)
  const setActive = useSetUserActive()
  const reauth = useReauthUser()
  const [confirming, setConfirming] = useState<AccountAction | null>(null)
  const [done, setDone] = useState<string | null>(null)
  const self = me.data?.user.id === user.id
  const invited = user.status === 'invited' || user.status === 'invitation_expired'
  const forwarded = user.auth_source === 'upstream-basic'
  const error = setActive.error ?? reauth.error
  const pending = setActive.isPending || reauth.isPending
  const liveTokens = tokens.data?.filter((t) => tokenStatus(t) === 'active').length
  const ownAccount = self ? ' This is your own account: you are signed out too.' : ''

  function ask(action: AccountAction) {
    setActive.reset()
    reauth.reset()
    setDone(null)
    setConfirming(action)
  }

  function confirm() {
    const close = { onSettled: () => setConfirming(null) }
    if (confirming === 'reauth') {
      reauth.mutate(user.id, {
        ...close,
        onSuccess: () => setDone(`Signed ${user.username} out everywhere.`),
      })
    } else if (confirming) {
      const active = confirming === 'reactivate'
      setActive.mutate(
        { id: user.id, active },
        {
          ...close,
          onSuccess: () =>
            setDone(
              active
                ? `Reactivated ${user.username}.`
                : `Deactivated ${user.username}: their sessions have ended.`,
            ),
        },
      )
    }
  }

  return (
    <Panel
      title="Account"
      description={
        !user.active
          ? `${user.username} is inactive: every sign-in is refused, and their tokens are suspended, not revoked.`
          : invited
            ? `${user.username} is active but has not chosen a password yet, so they cannot sign in.`
            : `${user.username} is active and can sign in.`
      }
      footer={
        user.active ? (
          <>
            {!invited && (
              <Button icon="LogOut" disabled={pending} onClick={() => ask('reauth')}>
                Sign out everywhere…
              </Button>
            )}
            <Button
              variant="danger"
              icon="Lock"
              disabled={pending}
              onClick={() => ask('deactivate')}
            >
              Deactivate…
            </Button>
          </>
        ) : (
          <Button variant="primary" disabled={pending} onClick={() => ask('reactivate')}>
            Reactivate…
          </Button>
        )
      }
    >
      {error ? (
        <InlineError>{error.body || error.message}</InlineError>
      ) : done ? (
        <Notice tone="ok">{done}</Notice>
      ) : (
        <p className="fg-text fg-text--small">
          {!user.active
            ? 'Reactivating lets the user sign in again, and their unrevoked tokens work again.'
            : invited
              ? 'Deactivating revokes the invitation and keeps the account and its roles; it can be undone.'
              : "Deactivating refuses every sign-in but keeps the account, its roles and its tokens; it can be undone. Signing out everywhere ends the user's sessions and leaves the account active."}
        </p>
      )}

      <Dialog
        open={confirming === 'deactivate'}
        onClose={() => setConfirming(null)}
        icon="Lock"
        tone="warn"
        title={`Deactivate ${user.username}?`}
        description={`Every sign-in is refused: password, browser, identity provider, credential forwarding and API tokens. Their browser sessions end now.${
          invited ? ' Their invitation is revoked.' : ''
        } Their tokens are suspended, not revoked: they work again if the account is reactivated.${ownAccount}`}
        confirmLabel={setActive.isPending ? 'Deactivating…' : 'Deactivate user'}
        confirmVariant="danger"
        confirmDisabled={pending}
        onConfirm={confirm}
      />
      <Dialog
        open={confirming === 'reactivate'}
        onClose={() => setConfirming(null)}
        icon="Refresh"
        title={`Reactivate ${user.username}?`}
        description={reactivateConsequence(liveTokens)}
        confirmLabel={setActive.isPending ? 'Reactivating…' : 'Reactivate user'}
        confirmDisabled={pending}
        onConfirm={confirm}
      />
      <Dialog
        open={confirming === 'reauth'}
        onClose={() => setConfirming(null)}
        icon="LogOut"
        title={`Sign ${user.username} out everywhere?`}
        description={`Their browser sessions end, so they have to sign in again.${
          forwarded
            ? ' Their password is checked against the upstream again at the next sign-in or password request, and the tokens they minted from a forwarded sign-in are revoked; tokens an administrator issued keep working.'
            : ' Their API tokens keep working: revoke them under Tokens to stop them.'
        }${ownAccount}`}
        confirmLabel={reauth.isPending ? 'Signing out…' : 'Sign out everywhere'}
        confirmDisabled={pending}
        onConfirm={confirm}
      />
    </Panel>
  )
}

/**
 * What reactivating does to the user's tokens: the ones neither revoked nor
 * expired (`live`, unknown while the list loads) work again.
 */
function reactivateConsequence(live: number | undefined): string {
  if (live === 0) return 'The user can sign in again. They have no token that would work again.'
  const tokens =
    live === undefined
      ? 'their unrevoked tokens work'
      : live === 1
        ? 'their 1 unrevoked token works'
        : `their ${live} unrevoked tokens work`
  return `The user can sign in again, and ${tokens} again. Revoke any that should not under Tokens before you reactivate.`
}

/**
 * A credential-forwarding account's kept password hash, and the switch of the
 * account to a local one with that password (asks for a confirmation first,
 * in a dialog).
 */
function KeptPassword({ user }: { user: UserView }) {
  const convert = useConvertUserToLocal()
  const [confirming, setConfirming] = useState(false)
  return (
    <>
      <Notice
        action={
          <Button size="sm" onClick={() => setConfirming(true)}>
            Switch to a local account…
          </Button>
        }
      >
        Password kept {formatTs(user.captured_password_at)}: the last password
        the upstream accepted for this user. Switching to a local account makes
        it the user&apos;s Forge password; the upstream is never asked about
        this user again.
      </Notice>
      {convert.isError && (
        <InlineError>{convert.error.body || convert.error.message}</InlineError>
      )}
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        icon="Key"
        title={`Switch ${user.username} to a local account?`}
        description="The kept password becomes the user's Forge password, and the upstream is never asked about this user again."
        confirmLabel={convert.isPending ? 'Switching…' : 'Switch to a local account'}
        confirmDisabled={convert.isPending}
        onConfirm={() =>
          convert.mutate(user.id, { onSettled: () => setConfirming(false) })
        }
      />
    </>
  )
}

function formatTs(ts: string | null): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}

function TokenRow({
  token,
  onEditScope,
  onRequestRevoke,
}: {
  token: TokenView
  onEditScope: () => void
  onRequestRevoke: () => void
}) {
  const revoked = token.revoked_at != null
  return (
    <TableRow>
      <TableCell lead className="font-mono">
        {token.name}
      </TableCell>
      <TableCell nowrap>{formatTs(token.created_at)}</TableCell>
      <TableCell nowrap>{formatTokenExpiry(token.expires_at)}</TableCell>
      <TableCell nowrap>{formatTs(token.last_used_at)}</TableCell>
      <TableCell>
        <TokenScopeBadges scope={token.scope} />
      </TableCell>
      <TableCell>
        <TokenStatusBadge token={token} />
      </TableCell>
      <TableCell align="right" nowrap>
        {revoked ? (
          <span className="text-ink-faint">—</span>
        ) : (
          <CellActions>
            <Button
              size="sm"
              variant="ghost"
              icon="Pencil"
              aria-label={`Edit scope of ${token.name}`}
              onClick={onEditScope}
            >
              Edit scope
            </Button>
            <Button size="sm" variant="ghost" icon="Trash" onClick={onRequestRevoke}>
              Revoke
            </Button>
          </CellActions>
        )}
      </TableCell>
    </TableRow>
  )
}
