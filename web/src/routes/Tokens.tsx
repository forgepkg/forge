import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { CreatedToken, TokenView } from '~/api/tokens'
import {
  useCreateMyToken,
  useMyTokens,
  useRevokeMyToken,
} from '~/queries/useTokens'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { ShowOnceSecret } from '~/components/ShowOnceSecret'

export const Route = createFileRoute('/_app/tokens')({
  component: MyTokens,
})

/**
 * Self-service token management: every signed-in user can mint, list, and
 * revoke their **own** registry tokens here (`/admin/me/tokens` — not
 * admin-gated). Tokens authenticate NuGet clients against the feed; they
 * cannot be used to sign in to this UI. The plaintext is shown **once** via
 * `ShowOnceSecret`, held in transient component state, and never written into
 * a query cache.
 */
function MyTokens() {
  const tokens = useMyTokens()
  const create = useCreateMyToken()
  const revoke = useRevokeMyToken()

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
        <h1 className="text-2xl font-semibold">Your tokens</h1>
        <p className="mt-1 text-slate-600">
          Registry tokens authenticate NuGet clients (e.g.{' '}
          <span className="font-mono">dotnet restore</span> /{' '}
          <span className="font-mono">push</span>) against the feed. They
          cannot be used to sign in here. The secret is shown only at creation
          time.
        </p>
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
        className="flex items-end gap-3 rounded-lg border border-slate-200 bg-white p-4"
      >
        <label className="block flex-1 text-sm">
          <span className="mb-1 block font-medium text-slate-700">
            Token name
          </span>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. my-laptop"
            className="w-full rounded border border-slate-300 px-3 py-2"
          />
        </label>
        <button
          type="submit"
          disabled={create.isPending || !name.trim()}
          className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-60"
        >
          {create.isPending ? 'Creating…' : 'Create token'}
        </button>
      </form>

      {create.isError && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          {create.error.body || create.error.message}
        </p>
      )}
      {revoke.isError && (
        <p
          role="alert"
          className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
        >
          {revoke.error.body || revoke.error.message}
        </p>
      )}

      {tokens.isError ? (
        <ErrorState
          title="Could not load tokens"
          message={tokens.error?.message}
          onRetry={() => void tokens.refetch()}
        />
      ) : tokens.isLoading ? (
        <p className="text-slate-500">Loading tokens…</p>
      ) : (tokens.data?.length ?? 0) === 0 ? (
        <EmptyState title="No tokens yet">
          Create a token above to authenticate your NuGet client.
        </EmptyState>
      ) : (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-left text-slate-500">
              <th className="py-2 pr-4 font-medium">Name</th>
              <th className="py-2 pr-4 font-medium">Created</th>
              <th className="py-2 pr-4 font-medium">Last used</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-4 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
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
          </tbody>
        </table>
      )}
    </section>
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
    <tr className="border-b border-slate-100 last:border-0">
      <td className="py-2 pr-4 font-medium text-slate-900">{token.name}</td>
      <td className="py-2 pr-4 text-slate-600">{formatTs(token.created_at)}</td>
      <td className="py-2 pr-4 text-slate-600">
        {formatTs(token.last_used_at)}
      </td>
      <td className="py-2 pr-4">
        {revoked ? (
          <span className="text-slate-400">revoked</span>
        ) : (
          <span className="text-emerald-700">active</span>
        )}
      </td>
      <td className="py-2 pr-4">
        {revoked ? (
          <span className="text-slate-400">—</span>
        ) : pendingRevoke ? (
          <span className="flex items-center gap-2">
            <button
              type="button"
              onClick={onConfirmRevoke}
              disabled={isRevoking}
              className="text-red-700 hover:underline disabled:opacity-60"
            >
              {isRevoking ? 'Revoking…' : 'Confirm'}
            </button>
            <button
              type="button"
              onClick={onCancelRevoke}
              className="text-slate-500 hover:underline"
            >
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            onClick={onRequestRevoke}
            className="text-red-700 hover:underline"
          >
            Revoke
          </button>
        )}
      </td>
    </tr>
  )
}
