import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { CreatedToken, TokenView } from '~/api/tokens'
import {
  useCreateMyToken,
  useMyTokens,
  useRevokeMyToken,
} from '~/queries/useTokens'
import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { Code, Text } from '~/components/catalyst/text'
import { Heading } from '~/components/catalyst/heading'
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
import { TokenCreateForm } from '~/components/TokenCreateForm'
import { TokenScopeBadges, TokenStatusBadge } from '~/components/TokenBadges'

export const Route = createFileRoute('/_app/tokens')({
  component: MyTokens,
})

/**
 * Self-service token management: every signed-in user can mint, list, and
 * revoke their **own** registry tokens here (`/admin/me/tokens` — not
 * admin-gated). Tokens authenticate NuGet clients against the feed and Docker
 * clients against the registry (`docker login`, the token as the password);
 * they cannot be used to sign in to this UI. A token can be scoped to some
 * actions and to some of the repositories the user can read. The plaintext is
 * shown **once** via `ShowOnceSecret`, held in transient component state, and
 * never written into a query cache.
 */
function MyTokens() {
  const tokens = useMyTokens()
  const create = useCreateMyToken()
  const revoke = useRevokeMyToken()
  const repos = useBrowseRepos()

  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<number | null>(null)

  function confirmRevoke(tokenId: number) {
    revoke.mutate(tokenId, { onSettled: () => setPendingRevoke(null) })
  }

  return (
    <section className="space-y-6">
      <div>
        <Heading>Your tokens</Heading>
        <Text className="mt-1">
          Registry tokens authenticate NuGet clients (e.g.{' '}
          <Code>dotnet restore</Code> / <Code>push</Code>) against the feed,
          and Docker clients: use one as the password of{' '}
          <Code>docker login</Code>. They cannot be used to sign in here. The
          secret is shown only at creation time.
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
        placeholder="e.g. my-laptop"
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
          Create a token above to authenticate your NuGet or Docker client.
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
