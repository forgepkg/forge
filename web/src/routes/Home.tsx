import { createFileRoute } from '@tanstack/react-router'
import clsx from 'clsx'

import { useMe } from '~/queries/useMe'
import { ApiError } from '~/lib/httpClient'

export const Route = createFileRoute('/')({
  component: Home,
})

/**
 * Placeholder home route (Phase 1). Proves the single-origin serving model end
 * to end: it calls `GET /admin/me` through the shared `httpClient` and renders
 * the resolved identity, the unauthenticated state, or an error. Browse + admin
 * screens replace this in later phases.
 */
function Home() {
  const me = useMe()

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Welcome</h1>
        <p className="mt-1 text-slate-600">
          envisia forge serves this SPA and its API from a single origin.
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
              Not signed in. Paste a registry token on the login screen
              (available in a later phase) to manage the registry.
            </p>
          ) : (
            <p className="mt-3 text-red-600">
              Could not load identity: {String(me.error?.message ?? 'unknown error')}
            </p>
          ))}

        {me.data && (
          <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
            <dt className="text-slate-500">Username</dt>
            <dd className="font-medium">{me.data.user.username}</dd>
            <dt className="text-slate-500">Role</dt>
            <dd>
              <span
                className={clsx(
                  'rounded px-2 py-0.5 text-xs font-medium',
                  me.data.is_admin
                    ? 'bg-emerald-100 text-emerald-800'
                    : 'bg-slate-100 text-slate-700',
                )}
              >
                {me.data.is_admin ? 'admin' : 'reader'}
              </span>
            </dd>
            <dt className="text-slate-500">Capabilities</dt>
            <dd className="font-mono text-xs">{me.data.capabilities.join(', ')}</dd>
          </dl>
        )}
      </div>
    </section>
  )
}
