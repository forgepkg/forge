import { createFileRoute } from '@tanstack/react-router'

import { ApiError } from '~/lib/httpClient'
import { useMe } from '~/queries/useMe'

export const Route = createFileRoute('/_app/')({
  component: Browse,
})

/**
 * Browse landing (placeholder until Phase 3, which adds cross-repo search + a
 * paginated package table). For now it confirms the single-origin round-trip by
 * rendering the resolved identity from `GET /admin/me`, including the
 * unauthenticated state. Reachable by any reader; no admin gate.
 */
function Browse() {
  const me = useMe()

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Browse</h1>
        <p className="mt-1 text-slate-600">
          Search and browse packages across repositories. (Coming in Phase 3.)
        </p>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white p-5">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-500">
          Identity (GET /admin/me)
        </h2>

        {me.isLoading && <p className="mt-3 text-slate-500">Checking session…</p>}

        {me.isError &&
          (me.error instanceof ApiError && me.error.status === 401 ? (
            <p className="mt-3 text-slate-700">
              Browsing anonymously. Sign in with a registry token to manage the
              registry.
            </p>
          ) : (
            <p className="mt-3 text-red-600">
              Could not load identity:{' '}
              {String(me.error?.message ?? 'unknown error')}
            </p>
          ))}

        {me.data && (
          <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
            <dt className="text-slate-500">Username</dt>
            <dd className="font-medium">{me.data.user.username}</dd>
            <dt className="text-slate-500">Role</dt>
            <dd>{me.data.is_admin ? 'admin' : 'reader'}</dd>
            <dt className="text-slate-500">Capabilities</dt>
            <dd className="font-mono text-xs">{me.data.capabilities.join(', ')}</dd>
          </dl>
        )}
      </div>
    </section>
  )
}
