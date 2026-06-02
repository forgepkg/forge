import type { QueryClient } from '@tanstack/react-query'
import { createRootRouteWithContext, Link, Outlet } from '@tanstack/react-router'

/** Router context made available to every route (loaders, beforeLoad). */
export interface RouterContext {
  queryClient: QueryClient
}

/**
 * Root route: the app shell (header nav + main outlet). Future phases add the
 * auth context and the admin-gated layout beneath this; Phase 1 keeps it to a
 * minimal shell so the single-origin serving + `/admin/me` round-trip is
 * verifiable.
 */
export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
})

function RootLayout() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center gap-4 px-6 py-4">
          <Link to="/" className="text-lg font-semibold text-slate-900">
            envisia&nbsp;forge
          </Link>
          <span className="text-sm text-slate-500">package registry</span>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
