import { createFileRoute, Outlet, redirect } from '@tanstack/react-router'

import { meQueryOptions } from '~/api/me'
import { ApiError } from '~/lib/httpClient'

export const Route = createFileRoute('/_app/manage')({
  /**
   * Hard admin gate (plan §5). Runs before any `/manage/*` screen loads:
   *   - no/invalid credential (401/403) -> /login (with an "expired" notice and
   *     a redirect back to the attempted admin URL),
   *   - authenticated but not an admin   -> Browse (`/`), readers have no admin
   *     screens.
   * The cosmetic half (hiding the Admin nav link) lives in `AppLayout`; this is
   * the enforcement that a non-admin can never reach an admin route by URL.
   */
  beforeLoad: async ({ context, location }) => {
    try {
      const me = await context.queryClient.ensureQueryData(meQueryOptions)
      if (!me.is_admin) {
        throw redirect({ to: '/' })
      }
    } catch (error) {
      if (error instanceof ApiError && error.isAuthError) {
        throw redirect({
          to: '/login',
          search: { redirect: location.href, expired: true },
        })
      }
      throw error
    }
  },
  component: AdminLayout,
})

function AdminLayout() {
  return <Outlet />
}
