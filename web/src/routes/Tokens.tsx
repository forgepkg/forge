import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { CreatedToken, TokenView } from '~/api/tokens'
import {
  useCreateMyToken,
  useMyTokens,
  useRevokeMyToken,
} from '~/queries/useTokens'
import { useBrowseRepos } from '~/queries/useBrowseRepos'
import {
  Button,
  CellActions,
  Code,
  Dialog,
  Notice,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/ui'
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
  const [pendingRevoke, setPendingRevoke] = useState<TokenView | null>(null)

  function confirmRevoke(tokenId: number) {
    revoke.mutate(tokenId, { onSettled: () => setPendingRevoke(null) })
  }

  return (
    <Page>
      <PageHeader
        title="Your tokens"
        description={
          <>
            Registry tokens authenticate NuGet clients (<Code>dotnet restore</Code>,{' '}
            <Code>push</Code>), Docker and Helm clients as you: use one as the
            password of <Code>docker login</Code> or{' '}
            <Code>helm registry login</Code> with your username. They
            cannot be used to sign in here. The secret is shown only at
            creation time.
          </>
        }
      />

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
        placeholder="e.g. build-agent-04"
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
        <Notice tone="danger">{create.error.body || create.error.message}</Notice>
      )}
      {revoke.isError && (
        <Notice tone="danger">{revoke.error.body || revoke.error.message}</Notice>
      )}

      {tokens.isError ? (
        <ErrorState
          title="Could not load tokens"
          message={tokens.error?.message}
          onRetry={() => void tokens.refetch()}
        />
      ) : (
        <Panel
          title="Tokens"
          count={tokens.data?.length}
          flush
          description="A token stops working when you revoke it or when it expires."
        >
          {tokens.isLoading ? (
            <Skeleton variant="table" label="Loading tokens…" />
          ) : (tokens.data?.length ?? 0) === 0 ? (
            <EmptyState title="No tokens yet" icon="Key" bordered={false}>
              Create a token above to authenticate your NuGet, Helm or Docker client.
            </EmptyState>
          ) : (
            <Table caption="Your registry tokens">
              <TableHead>
                <TableHeader>Name</TableHeader>
                <TableHeader>Created</TableHeader>
                <TableHeader>Last used</TableHeader>
                <TableHeader>Scope</TableHeader>
                <TableHeader>Status</TableHeader>
                <TableHeader align="right">
                  <span className="fg-sr">Actions</span>
                </TableHeader>
              </TableHead>
              <TableBody>
                {tokens.data!.map((token) => (
                  <TokenRow
                    key={token.id}
                    token={token}
                    onRequestRevoke={() => setPendingRevoke(token)}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
      )}

      <Dialog
        open={pendingRevoke !== null}
        onClose={() => setPendingRevoke(null)}
        icon="Key"
        tone="danger"
        title={`Revoke ${pendingRevoke?.name ?? 'token'}?`}
        description="Clients that use it can no longer pull or push. This cannot be undone."
        confirmLabel={revoke.isPending ? 'Revoking…' : 'Revoke token'}
        confirmVariant="danger-solid"
        confirmDisabled={revoke.isPending}
        onConfirm={() => pendingRevoke && confirmRevoke(pendingRevoke.id)}
      />
    </Page>
  )
}

function formatTs(ts: string | null): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime())
    ? ts
    : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function TokenRow({
  token,
  onRequestRevoke,
}: {
  token: TokenView
  onRequestRevoke: () => void
}) {
  const revoked = token.revoked_at != null
  return (
    <TableRow>
      <TableCell lead className="font-mono text-[13px] font-semibold">
        {token.name}
      </TableCell>
      <TableCell nowrap>{formatTs(token.created_at)}</TableCell>
      <TableCell nowrap>{formatTs(token.last_used_at)}</TableCell>
      <TableCell>
        <TokenScopeBadges scope={token.scope} />
      </TableCell>
      <TableCell>
        <TokenStatusBadge token={token} />
      </TableCell>
      <TableCell align="right">
        {revoked ? (
          <span className="text-ink-faint">—</span>
        ) : (
          <CellActions>
            <Button size="sm" variant="ghost" icon="Trash" onClick={onRequestRevoke}>
              Revoke
            </Button>
          </CellActions>
        )}
      </TableCell>
    </TableRow>
  )
}
