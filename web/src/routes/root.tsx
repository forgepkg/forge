import type { QueryClient } from '@tanstack/react-query'
import { createRootRouteWithContext, Outlet } from '@tanstack/react-router'

/** Router context made available to every route (loaders, beforeLoad). */
export interface RouterContext {
  queryClient: QueryClient
}

/**
 * Root route. It only provides the router context and a page background; it does
 * **not** render the app navigation, so the `/login` screen can stand on its own
 * outside the authenticated shell. The nav + current-user live in `AppLayout`,
 * which wraps every authenticated screen.
 */
export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
})

function RootLayout() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <Outlet />
    </div>
  )
}
