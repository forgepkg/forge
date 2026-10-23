import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  createFileRoute,
  Link,
  Outlet,
  redirect,
  useRouter,
  useRouterState,
} from '@tanstack/react-router'

import { meKeys, meQueryOptions } from '~/api/me'
import { authKeys, authSessionQueryOptions, logout } from '~/api/auth'
import { ApiError, onUnauthorized } from '~/lib/httpClient'
import { clearSession, onAuthChange } from '~/lib/auth'
import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { useMe } from '~/queries/useMe'
import { AppRail } from '~/components/AppRail'
import { Icon, Logo, ToastProvider } from '~/components/ui'

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
      // Bootstrap the CSRF token from the live session (an OIDC redirect
      // only sets the cookie); once per load, best-effort.
      await context.queryClient.ensureQueryData(authSessionQueryOptions)
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
 * The authenticated app shell: the navigation rail on the left (the places,
 * Administration, the readable repositories, the current user with the theme
 * switch and Sign out) and the content column. Below 900px the rail is a
 * drawer behind the menu button of a top bar. The Administration section is
 * rendered **only** when `is_admin` is true (the route guard in `AdminLayout`
 * is the hard enforcement; this is the cosmetic half — readers never see the
 * links).
 */
function AppLayout() {
  const me = useMe()
  const queryClient = useQueryClient()
  const router = useRouter()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const repos = useBrowseRepos()
  // The phone drawer; closed again by every navigation.
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerPath, setDrawerPath] = useState(pathname)
  if (drawerPath !== pathname) {
    setDrawerPath(pathname)
    setDrawerOpen(false)
  }

  // Set while a deliberate sign-out runs: its own 401s (an already-expired
  // session) must not be reported as "session expired".
  const signingOut = useRef(false)
  // Set once a 401 has sent us to login, so a burst of failing requests
  // navigates once.
  const expiredHandled = useRef(false)

  // Keep the `me` query in sync with same-tab and cross-tab credential changes.
  // This is a genuine external-system subscription (localStorage + the auth
  // module's in-tab notifier), so an effect is the right tool; it returns a
  // cleanup and invalidates the cached identity whenever the credential moves.
  // (`clearSession` only notifies when a token was stored, so a 401 reaches
  // this at most once.)
  useEffect(() => {
    return onAuthChange(() => {
      void queryClient.invalidateQueries({ queryKey: meKeys.self() })
    })
  }, [queryClient])

  // A 401 from any API call means the session is gone (idle timeout, revoked,
  // signed out in another tab). *Remove* the cached identity and session sync
  // — invalidating would keep the stale `me`, which the route guards'
  // `ensureQueryData` keeps resolving, so the user would never reach login —
  // and route to /login with a return-to and the "expired" notice. The
  // return-to is the latest location, i.e. the attempted one when the 401
  // came from a route guard mid-navigation.
  useEffect(() => {
    return onUnauthorized(() => {
      if (signingOut.current || expiredHandled.current) return
      queryClient.removeQueries({ queryKey: meKeys.self() })
      queryClient.removeQueries({ queryKey: authKeys.session() })
      const location = router.latestLocation
      if (location.pathname === '/login') return
      expiredHandled.current = true
      void router.navigate({
        to: '/login',
        search: { redirect: location.href, expired: true },
        replace: true,
      })
    })
  }, [queryClient, router])

  // Escape closes the phone drawer (a document-level key listener while open).
  useEffect(() => {
    if (!drawerOpen) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setDrawerOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [drawerOpen])

  // `is_admin` is the server's effective RBAC verdict (admin role or legacy
  // flag), not the raw column.
  const isAdmin = me.data?.is_admin === true
  const username = me.data?.user.username ?? null

  async function signOut() {
    // Only the server can invalidate the httpOnly cookie, so POST /auth/logout
    // (CSRF-guarded) before clearing local state. A failure is surfaced on the
    // login screen: the server session may still be alive, and silently
    // pretending otherwise would leave it usable. Local state is cleared and
    // the user is sent to login either way.
    signingOut.current = true
    let logoutFailed = false
    try {
      await logout()
    } catch (error) {
      // A 401 means the session is already gone — that is a successful logout.
      logoutFailed = !(error instanceof ApiError && error.status === 401)
    }
    // Drop *every* cached query, not just the identity: the next person to
    // sign in on this browser must never see the previous user's data. Done
    // before `clearSession` so its notification finds nothing to refetch.
    queryClient.clear()
    clearSession()
    void router.navigate({
      to: '/login',
      search: logoutFailed ? { logout_failed: true } : {},
    })
  }

  return (
    <ToastProvider>
      <div className="fg-app">
        <header className="fg-topbar">
          <button
            type="button"
            className="fg-topbar-btn"
            aria-label="Open navigation"
            aria-expanded={drawerOpen}
            onClick={() => setDrawerOpen(true)}
          >
            <Icon name="Menu" size={20} />
          </button>
          <Link to="/" className="fg-topbar-home" aria-label="Forge home">
            <Logo size={22} />
          </Link>
        </header>
        {drawerOpen && (
          <div className="fg-drawer-scrim" aria-hidden="true" onClick={() => setDrawerOpen(false)} />
        )}
        <div className={drawerOpen ? 'fg-app-rail is-open' : 'fg-app-rail'}>
          <AppRail
            pathname={pathname}
            isAdmin={isAdmin}
            username={username}
            repos={Array.isArray(repos.data) ? repos.data : []}
            onSignOut={() => void signOut()}
            onClose={() => setDrawerOpen(false)}
          />
        </div>
        <main className="fg-app-main">
          <div className="fg-app-content">
            <Outlet />
          </div>
        </main>
      </div>
    </ToastProvider>
  )
}
