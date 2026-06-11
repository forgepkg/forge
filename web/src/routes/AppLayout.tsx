import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  createFileRoute,
  Link,
  Outlet,
  redirect,
  useRouter,
} from '@tanstack/react-router'
import clsx from 'clsx'

import { meKeys, meQueryOptions } from '~/api/me'
import { logout } from '~/api/auth'
import { ApiError } from '~/lib/httpClient'
import { clearSession, onAuthChange } from '~/lib/auth'
import { useMe } from '~/queries/useMe'

export const Route = createFileRoute('/_app')({
  /**
   * Login gate for the whole app: browsing (and everything else under the
   * shell) is for signed-in users only. An unauthenticated caller is sent to
   * /login with a redirect back to the attempted URL; the server enforces the
   * same rule (401 on /browse/*), this is the navigation half.
   */
  beforeLoad: async ({ context, location }) => {
    try {
      await context.queryClient.ensureQueryData(meQueryOptions)
    } catch (error) {
      if (error instanceof ApiError && error.isAuthError) {
        throw redirect({
          to: '/login',
          search: { redirect: location.href },
        })
      }
      throw error
    }
  },
  component: AppLayout,
})

/**
 * The authenticated app shell: top nav + current-user widget wrapping every
 * non-login screen. The admin nav link is rendered **only** when `is_admin` is
 * true (the route guard in `AdminLayout` is the hard enforcement; this is the
 * cosmetic half — readers never see the link).
 */
function AppLayout() {
  const me = useMe()
  const queryClient = useQueryClient()
  const router = useRouter()

  // Keep the `me` query in sync with same-tab and cross-tab credential changes.
  // This is a genuine external-system subscription (localStorage + the auth
  // module's in-tab notifier), so an effect is the right tool; it returns a
  // cleanup and invalidates the cached identity whenever the credential moves.
  useEffect(() => {
    return onAuthChange(() => {
      void queryClient.invalidateQueries({ queryKey: meKeys.self() })
    })
  }, [queryClient])

  const isAdmin = me.data?.is_admin === true

  async function signOut() {
    // Only the server can invalidate the httpOnly cookie, so POST /auth/logout
    // (CSRF-guarded) before clearing local state.
    try {
      await logout()
    } catch {
      /* clear local state regardless; the cookie may already be dead */
    }
    clearSession()
    void router.navigate({ to: '/login' })
  }

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center gap-6 px-6 py-4">
          <Link to="/" className="text-lg font-semibold text-slate-900">
            envisia&nbsp;forge
          </Link>
          <nav className="flex items-center gap-4 text-sm">
            <NavLink to="/">Browse</NavLink>
            <NavLink to="/tokens">Tokens</NavLink>
            {isAdmin && <NavLink to="/admin">Admin</NavLink>}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <CurrentUser
              username={me.data?.user.username ?? null}
              isAdmin={isAdmin}
              onSignOut={signOut}
            />
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <Link
      to={to}
      className="text-slate-600 hover:text-slate-900 [&.active]:font-medium [&.active]:text-slate-900"
      activeOptions={{ exact: to === '/' }}
    >
      {children}
    </Link>
  )
}

function CurrentUser({
  username,
  isAdmin,
  onSignOut,
}: {
  username: string | null
  isAdmin: boolean
  onSignOut: () => void
}) {
  if (!username) {
    return (
      <Link
        to="/login"
        className="rounded bg-slate-900 px-3 py-1.5 font-medium text-white hover:bg-slate-700"
      >
        Sign in
      </Link>
    )
  }
  return (
    <>
      <span className="text-slate-600">
        {username}
        <span
          className={clsx(
            'ml-2 rounded px-1.5 py-0.5 text-xs font-medium',
            isAdmin
              ? 'bg-emerald-100 text-emerald-800'
              : 'bg-slate-100 text-slate-700',
          )}
        >
          {isAdmin ? 'admin' : 'reader'}
        </span>
      </span>
      <button
        type="button"
        onClick={onSignOut}
        className="rounded border border-slate-300 px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100"
      >
        Sign out
      </button>
    </>
  )
}
