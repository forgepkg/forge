import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { CreatedToken, TokenView } from '~/api/tokens'
import { authSourceLabel } from '~/api/users'
import { useUsers } from '~/queries/useUsers'
import {
  useCreateToken,
  useRevokeToken,
  useTokens,
} from '~/queries/useTokens'
import { Button } from '~/components/catalyst/button'
import { Field, Label } from '~/components/catalyst/fieldset'
import { Heading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Text } from '~/components/catalyst/text'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/catalyst/table'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { ShowOnceSecret } from '~/components/ShowOnceSecret'
import { TokenScopeBadges, TokenStatusBadge } from '~/components/TokenBadges'

export const Route = createFileRoute('/_app/manage/users/$userId')({
  component: UserTokens,
})

/**
 * Per-user token management (plan §Phase 5). Slice 1 scopes tokens to a user
 * (`/admin/users/{id}/tokens`), so this is the user's "edit" screen: it lists
 * the user's tokens (metadata only — the secret is never returned), issues new
 * tokens (the plaintext is shown **once** via `ShowOnceSecret`), and revokes
 * existing ones. The plaintext is held in transient component state and never
 * written into a query cache. The header says how the user signs in, so a
 * token is not issued to a look-alike account by mistake.
 */
function UserTokens() {
  const { userId } = Route.useParams()
  const id = Number(userId)

  // The username comes from the cached users list (no per-user GET in slice 1).
  const users = useUsers()
  const user = users.data?.find((u) => u.id === id)

  const tokens = useTokens(id)
  const create = useCreateToken(id)
  const revoke = useRevokeToken(id)

  const [name, setName] = useState('')
  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<number | null>(null)

  function issue(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    create.mutate(
      { name: name.trim() },
      {
        onSuccess: (token) => {
          setCreated(token)
          setName('')
        },
      },
    )
  }

  function confirmRevoke(tokenId: number) {
    revoke.mutate(tokenId, { onSettled: () => setPendingRevoke(null) })
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
        <Heading className="mt-1">
          Tokens{user ? ` — ${user.username}` : ''}
        </Heading>
        {user && (
          <Text className="mt-1">
            Sign-in:{' '}
            <span className="font-medium text-zinc-950 dark:text-white">
              {authSourceLabel(user.auth_source)}
            </span>
          </Text>
        )}
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

      <form
        onSubmit={issue}
        className="flex items-end gap-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
      >
        <Field className="flex-1">
          <Label>Token name</Label>
          <Input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. ci-pipeline"
          />
        </Field>
        <Button type="submit" disabled={create.isPending || !name.trim()}>
          {create.isPending ? 'Creating…' : 'Create token'}
        </Button>
      </form>

      {create.isError && (
        <InlineError>{create.error.body || create.error.message}</InlineError>
      )}
      {revoke.isError && (
        <InlineError>{revoke.error.body || revoke.error.message}</InlineError>
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
                onRequestRevoke={() => setPendingRevoke(token.id)}
                onCancelRevoke={() => setPendingRevoke(null)}
                onConfirmRevoke={() => confirmRevoke(token.id)}
              />
            ))}
          </TableBody>
        </Table>
      )}
    </section>
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
  onRequestRevoke,
  onCancelRevoke,
  onConfirmRevoke,
}: {
  token: TokenView
  isRevoking: boolean
  pendingRevoke: boolean
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
          <button
            type="button"
            onClick={onRequestRevoke}
            className="font-medium text-red-600 hover:underline dark:text-red-400"
          >
            Revoke
          </button>
        )}
      </TableCell>
    </TableRow>
  )
}
