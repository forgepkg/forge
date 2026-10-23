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
import { authSourceLabel, type UserView } from '~/api/users'
import { useConvertUserToLocal, useUsers } from '~/queries/useUsers'
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
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Field, Label } from '~/components/catalyst/fieldset'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Select } from '~/components/catalyst/select'
import { Text } from '~/components/catalyst/text'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/catalyst/table'
import { AccessBadge } from '~/components/AccessBadge'
import { AccessLevelFields } from '~/components/AccessLevelFields'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  ActionBadge,
  byId,
  RepositoryLabel,
  repoNames,
  SelectorLabel,
} from '~/components/RbacLabels'
import { ShowOnceSecret } from '~/components/ShowOnceSecret'
import { TokenCreateForm } from '~/components/TokenCreateForm'
import { TokenScopeBadges, TokenStatusBadge } from '~/components/TokenBadges'
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
 * One user: their built-in access level (reader, writer or admin), which
 * admins switch here; the roles they hold, which admins assign and remove
 * here (taking `admin` from the last active administrator is refused with
 * the server's reason); their effective access, the union of those roles'
 * grants with repository and selector names; and their tokens. Tokens are
 * listed as metadata only (the secret is never returned), issued with an
 * optional scope (the plaintext is shown **once** via `ShowOnceSecret`, held
 * in transient component state and never written into a query cache),
 * re-scoped and revoked. The header says how the user signs in, so a role or
 * token does not go to a look-alike account by mistake. A
 * credential-forwarding account whose realm kept its password hash can be
 * switched to a local account with that password from here.
 */
function UserPage() {
  const { userId } = Route.useParams()
  const id = Number(userId)

  // The username comes from the cached users list (there is no per-user GET).
  const users = useUsers()
  const user = users.data?.find((u) => u.id === id)

  return (
    <section className="space-y-8">
      <div>
        <Link
          to="/manage/users"
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          ← Users
        </Link>
        <Heading className="mt-1">{user ? user.username : `User #${id}`}</Heading>
        {user && (
          <Text className="mt-1">
            Sign-in:{' '}
            <span className="font-medium text-zinc-950 dark:text-white">
              {authSourceLabel(user.auth_source)}
            </span>
          </Text>
        )}
      </div>

      {user?.captured_password_at && <KeptPassword user={user} />}

      <UserAccess userId={id} />
      <UserRoles userId={id} legacyAdmin={user?.is_admin ?? false} />
      <EffectiveAccess userId={id} />
      <UserTokens userId={id} />
    </section>
  )
}

/**
 * The user's built-in access level: reader (no built-in role), writer (the
 * `writer` role) or admin (the `admin` role), switched through
 * `/admin/users/{id}/roles`. A switch assigns the new level's role first and
 * then takes the other one, so a refused step (the last active
 * administrator keeps `admin`: 409, with the server's reason) never leaves
 * the user with less access than before.
 */
function UserAccess({ userId }: { userId: number }) {
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

  return (
    <div className="space-y-4">
      <div>
        <Subheading>Access</Subheading>
        <Text className="mt-1">
          The user&apos;s built-in role. Their other roles below add to it.
        </Text>
      </div>
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
        <Text>Loading access…</Text>
      ) : (
        <form
          aria-label="Change access"
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
          className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
        >
          <Text>
            Now: <AccessBadge level={current} />
          </Text>
          <AccessLevelFields
            value={chosen}
            onChange={setChoice}
            disabled={saving}
          />
          {error && <InlineError>{error}</InlineError>}
          <Button type="submit" disabled={saving || chosen === current}>
            {saving ? 'Saving…' : 'Change access'}
          </Button>
        </form>
      )}
    </div>
  )
}

/** The roles the user holds; admins assign and remove them here. */
function UserRoles({
  userId,
  legacyAdmin,
}: {
  userId: number
  legacyAdmin: boolean
}) {
  const held = useUserRoles(userId)
  const roles = useRoles()
  const assign = useAssignRole()
  const unassign = useUnassignRole()
  const [roleId, setRoleId] = useState('')

  const heldIds = new Set((held.data ?? []).map((r) => r.id))
  const candidates = (roles.data ?? []).filter((r) => !heldIds.has(r.id))
  const holdsAdmin = (held.data ?? []).some((r) => r.name === ADMIN_ROLE)

  return (
    <div className="space-y-4">
      <div>
        <Subheading>Roles</Subheading>
        <Text className="mt-1">
          What the user may do follows from the roles they hold.
        </Text>
      </div>

      {legacyAdmin && held.data && !holdsAdmin && (
        <Text>
          The user is an administrator through the legacy <code>is_admin</code>{' '}
          flag, without the admin role.
        </Text>
      )}

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
        className="flex items-end gap-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
      >
        <Field className="flex-1">
          <Label>Role</Label>
          <Select value={roleId} onChange={(e) => setRoleId(e.target.value)}>
            <option value="">Choose a role…</option>
            {candidates.map((r) => (
              <option key={r.id} value={String(r.id)}>
                {r.name}
              </option>
            ))}
          </Select>
        </Field>
        <Button type="submit" disabled={assign.isPending || roleId === ''}>
          {assign.isPending ? 'Assigning…' : 'Assign role'}
        </Button>
      </form>

      {assign.isError && (
        <InlineError>{assign.error.body || assign.error.message}</InlineError>
      )}
      {unassign.isError && (
        <InlineError>{unassign.error.body || unassign.error.message}</InlineError>
      )}

      {held.isError ? (
        <ErrorState
          title="Could not load the user's roles"
          message={held.error?.message}
          onRetry={() => void held.refetch()}
        />
      ) : held.isLoading ? (
        <Text>Loading roles…</Text>
      ) : (held.data?.length ?? 0) === 0 ? (
        <Text>The user holds no role.</Text>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Role</TableHeader>
              <TableHeader>Description</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {held.data!.map((r) => (
              <TableRow key={r.id}>
                <TableCell>
                  <Link
                    to="/manage/roles/$roleId"
                    params={{ roleId: String(r.id) }}
                    className="font-medium text-sky-600 hover:underline dark:text-sky-400"
                  >
                    {r.name}
                  </Link>
                </TableCell>
                <TableCell className="whitespace-normal text-zinc-500 dark:text-zinc-400">
                  {r.description || '—'}
                </TableCell>
                <TableCell>
                  <button
                    type="button"
                    disabled={unassign.isPending}
                    onClick={() => unassign.mutate({ userId, roleId: r.id })}
                    className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
                    aria-label={`Remove role ${r.name}`}
                  >
                    Remove
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}

/**
 * The user's effective access (`/admin/users/{id}/effective`): every grant of
 * every role they hold, with repository and selector names. Reads of what
 * anonymous callers may read, and token scopes, are not part of it.
 */
function EffectiveAccess({ userId }: { userId: number }) {
  const effective = useUserEffective(userId)
  const repos = useRepositories()
  const selectors = useSelectors()
  const names = repoNames(repos.data)
  const selectorMap = byId(selectors.data)

  return (
    <div className="space-y-4">
      <div>
        <Subheading>Effective access</Subheading>
        <Text className="mt-1">
          The grants of all the user&apos;s roles together. Signed-in users
          can also read what anonymous callers may read; a token can narrow
          this further.
        </Text>
      </div>
      {effective.isError ? (
        <ErrorState
          title="Could not load the user's access"
          message={effective.error?.message}
          onRetry={() => void effective.refetch()}
        />
      ) : effective.isLoading || !effective.data ? (
        <Text>Loading access…</Text>
      ) : (
        <>
          {effective.data.is_admin && (
            <p className="flex items-center gap-2 text-sm/6 text-zinc-950 dark:text-white">
              <Badge color="red">administrator</Badge>
              May do everything, on every repository, whatever the grants
              below say.
            </p>
          )}
          {effective.data.grants.length === 0 ? (
            !effective.data.is_admin && <Text>The user may do nothing.</Text>
          ) : (
            <Table striped>
              <TableHead>
                <TableRow>
                  <TableHeader>Repository</TableHeader>
                  <TableHeader>Action</TableHeader>
                  <TableHeader>Packages</TableHeader>
                </TableRow>
              </TableHead>
              <TableBody>
                {effective.data.grants.map((g, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <RepositoryLabel id={g.repository_id} names={names} />
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={g.action} />
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
    </div>
  )
}

/** The user's tokens: issue (with a scope), re-scope and revoke. */
function UserTokens({ userId }: { userId: number }) {
  const tokens = useTokens(userId)
  const create = useCreateToken(userId)
  const revoke = useRevokeToken(userId)
  const repos = useRepositories()

  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<number | null>(null)
  const [editing, setEditing] = useState<TokenView | null>(null)

  function confirmRevoke(tokenId: number) {
    revoke.mutate(tokenId, { onSettled: () => setPendingRevoke(null) })
  }

  return (
    <div className="space-y-4">
      <div>
        <Subheading>Tokens</Subheading>
        <Text className="mt-1">
          API tokens authenticate this user against the registry. The secret is
          shown only at creation time.
        </Text>
      </div>

      {created && (
        <ShowOnceSecret
          secret={created.token}
          label="Token"
          onDismiss={() => setCreated(null)}
        />
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

      {tokens.isError ? (
        <ErrorState
          title="Could not load tokens"
          message={tokens.error?.message}
          onRetry={() => void tokens.refetch()}
        />
      ) : tokens.isLoading ? (
        <Text>Loading tokens…</Text>
      ) : (tokens.data?.length ?? 0) === 0 ? (
        <EmptyState title="No tokens yet">
          Create a token above to let this user authenticate.
        </EmptyState>
      ) : (
        <Table striped>
          <TableHead>
            <TableRow>
              <TableHeader>Name</TableHeader>
              <TableHeader>Created</TableHeader>
              <TableHeader>Last used</TableHeader>
              <TableHeader>Scope</TableHeader>
              <TableHeader>Status</TableHeader>
              <TableHeader>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {tokens.data!.map((token) => (
              <TokenRow
                key={token.id}
                token={token}
                isRevoking={revoke.isPending && pendingRevoke === token.id}
                pendingRevoke={pendingRevoke === token.id}
                onEditScope={() => setEditing(token)}
                onRequestRevoke={() => setPendingRevoke(token.id)}
                onCancelRevoke={() => setPendingRevoke(null)}
                onConfirmRevoke={() => confirmRevoke(token.id)}
              />
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}

/**
 * Change a token's scope. The next request with the token reads it; there is
 * no cache to wait for.
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
    <form
      aria-label={`Scope of ${token.name}`}
      onSubmit={(e) => {
        e.preventDefault()
        if (problem) return
        save.mutate(
          { id: token.id, scope: scopeFromDraft(draft) },
          { onSuccess: onDone },
        )
      }}
      className="space-y-6 rounded-xl p-4 ring-1 ring-sky-500/30"
    >
      <Text>
        Scope of the token{' '}
        <span className="font-medium text-zinc-950 dark:text-white">
          {token.name}
        </span>
      </Text>
      <TokenScopeFields
        value={draft}
        onChange={setDraft}
        repositories={repositories}
      />
      {problem && <Text>{problem}</Text>}
      {save.isError && (
        <InlineError>{save.error.body || save.error.message}</InlineError>
      )}
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={save.isPending || !!problem}>
          {save.isPending ? 'Saving…' : 'Save scope'}
        </Button>
        <Button type="button" plain onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  )
}

/**
 * A credential-forwarding account's kept password hash, and the switch of the
 * account to a local one with that password (asks for a confirmation first).
 */
function KeptPassword({ user }: { user: UserView }) {
  const convert = useConvertUserToLocal()
  const [confirming, setConfirming] = useState(false)
  return (
    <div className="space-y-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <Text>
        Password kept {formatTs(user.captured_password_at)}: the last password
        the upstream accepted for this user. Switching to a local account makes
        it the user&apos;s Forge password; the upstream is never asked about
        this user again.
      </Text>
      {convert.isError && (
        <InlineError>{convert.error.body || convert.error.message}</InlineError>
      )}
      {confirming ? (
        <div className="flex items-center gap-3">
          <Button
            color="red"
            disabled={convert.isPending}
            onClick={() =>
              convert.mutate(user.id, { onSettled: () => setConfirming(false) })
            }
          >
            {convert.isPending ? 'Switching…' : 'Switch to a local account'}
          </Button>
          <Button plain onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </div>
      ) : (
        <Button outline onClick={() => setConfirming(true)}>
          Switch to a local account…
        </Button>
      )}
    </div>
  )
}

function InlineError({ children }: { children: React.ReactNode }) {
  return (
    <p
      role="alert"
      className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
    >
      {children}
    </p>
  )
}

function formatTs(ts: string | null): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}

function TokenRow({
  token,
  isRevoking,
  pendingRevoke,
  onEditScope,
  onRequestRevoke,
  onCancelRevoke,
  onConfirmRevoke,
}: {
  token: TokenView
  isRevoking: boolean
  pendingRevoke: boolean
  onEditScope: () => void
  onRequestRevoke: () => void
  onCancelRevoke: () => void
  onConfirmRevoke: () => void
}) {
  const revoked = token.revoked_at != null
  return (
    <TableRow>
      <TableCell className="font-medium">{token.name}</TableCell>
      <TableCell className="text-zinc-500 dark:text-zinc-400">
        {formatTs(token.created_at)}
      </TableCell>
      <TableCell className="text-zinc-500 dark:text-zinc-400">
        {formatTs(token.last_used_at)}
      </TableCell>
      <TableCell>
        <TokenScopeBadges scope={token.scope} />
      </TableCell>
      <TableCell>
        <TokenStatusBadge token={token} />
      </TableCell>
      <TableCell>
        {revoked ? (
          <span className="text-zinc-400 dark:text-zinc-500">—</span>
        ) : pendingRevoke ? (
          <span className="flex items-center gap-2">
            <button
              type="button"
              onClick={onConfirmRevoke}
              disabled={isRevoking}
              className="font-medium text-red-600 hover:underline disabled:opacity-60 dark:text-red-400"
            >
              {isRevoking ? 'Revoking…' : 'Confirm'}
            </button>
            <button
              type="button"
              onClick={onCancelRevoke}
              className="text-zinc-500 hover:underline dark:text-zinc-400"
            >
              Cancel
            </button>
          </span>
        ) : (
          <span className="flex items-center gap-3">
            <button
              type="button"
              onClick={onEditScope}
              className="font-medium text-sky-600 hover:underline dark:text-sky-400"
              aria-label={`Edit scope of ${token.name}`}
            >
              Edit scope
            </button>
            <button
              type="button"
              onClick={onRequestRevoke}
              className="font-medium text-red-600 hover:underline dark:text-red-400"
            >
              Revoke
            </button>
          </span>
        )}
      </TableCell>
    </TableRow>
  )
}
