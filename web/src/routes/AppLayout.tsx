import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  createFileRoute,
  Outlet,
  redirect,
  useRouter,
  useRouterState,
} from '@tanstack/react-router'

import { meKeys, meQueryOptions } from '~/api/me'
import { authKeys, authSessionQueryOptions, logout } from '~/api/auth'
import { ApiError } from '~/lib/httpClient'
import { clearSession, onAuthChange } from '~/lib/auth'
import { useMe } from '~/queries/useMe'
import { Badge } from '~/components/catalyst/badge'
import {
  Navbar,
  NavbarDivider,
  NavbarItem,
  NavbarLabel,
  NavbarSection,
  NavbarSpacer,
} from '~/components/catalyst/navbar'
import {
  Sidebar,
  SidebarBody,
  SidebarHeader,
  SidebarItem,
  SidebarLabel,
  SidebarSection,
} from '~/components/catalyst/sidebar'
import { StackedLayout } from '~/components/catalyst/stacked-layout'
import { ThemeToggle } from '~/components/ThemeToggle'

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

const NAV_ITEMS = [
  { label: 'Browse', to: '/', adminOnly: false },
  { label: 'Tokens', to: '/tokens', adminOnly: false },
  { label: 'Admin', to: '/admin', adminOnly: true },
] as const

/** Whether a nav target is the current location (Browse only matches exactly). */
function isCurrent(pathname: string, to: string): boolean {
  if (to === '/') return pathname === '/'
  return pathname === to || pathname.startsWith(`${to}/`)
}

/**
 * The authenticated app shell: Catalyst stacked layout with the top navbar
 * (collapsing into a sidebar drawer on mobile), theme switcher, and the
 * current-user widget. The Admin nav item is rendered **only** when
 * `is_admin` is true (the route guard in `AdminLayout` is the hard
 * enforcement; this is the cosmetic half — readers never see the link).
 */
function AppLayout() {
  const me = useMe()
  const queryClient = useQueryClient()
  const router = useRouter()
  const pathname = useRouterState({ select: (s) => s.location.pathname })

  // Keep the `me` query in sync with same-tab and cross-tab credential changes.
  // This is a genuine external-system subscription (localStorage + the auth
  // module's in-tab notifier), so an effect is the right tool; it returns a
  // cleanup and invalidates the cached identity whenever the credential moves.
  useEffect(() => {
    return onAuthChange(() => {
      void queryClient.invalidateQueries({ queryKey: meKeys.self() })
    })
  }, [queryClient])

  // `is_admin` is the server's effective RBAC verdict (admin role or legacy
  // flag), not the raw column.
  const isAdmin = me.data?.is_admin === true
  const username = me.data?.user.username ?? null
  const items = NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin)

  async function signOut() {
    // Only the server can invalidate the httpOnly cookie, so POST /auth/logout
    // (CSRF-guarded) before clearing local state. A failure is surfaced on the
    // login screen: the server session may still be alive, and silently
    // pretending otherwise would leave it usable. Local state is cleared and
    // the user is sent to login either way.
    let logoutFailed = false
    try {
      await logout()
    } catch (error) {
      // A 401 means the session is already gone — that is a successful logout.
      logoutFailed = !(error instanceof ApiError && error.status === 401)
    }
    clearSession()
    queryClient.removeQueries({ queryKey: authKeys.session() })
    queryClient.removeQueries({ queryKey: meKeys.self() })
    void router.navigate({
      to: '/login',
      search: logoutFailed ? { logout_failed: true } : {},
    })
  }

  return (
    <StackedLayout
      navbar={
        <Navbar>
          <NavbarItem href="/" aria-label="envisia forge home">
            <BrandMark />
            <NavbarLabel className="font-semibold tracking-tight">
              envisia&nbsp;forge
            </NavbarLabel>
          </NavbarItem>
          <NavbarDivider className="max-lg:hidden" />
          <NavbarSection className="max-lg:hidden">
            {items.map((item) => (
              <NavbarItem
                key={item.to}
                href={item.to}
                current={isCurrent(pathname, item.to)}
              >
                {item.label}
              </NavbarItem>
            ))}
          </NavbarSection>
          <NavbarSpacer />
          <NavbarSection>
            <ThemeToggle />
            {username && (
              <>
                <span className="flex items-center gap-2 px-2 text-sm/6 text-zinc-950 max-sm:hidden dark:text-white">
                  {username}
                  <Badge color={isAdmin ? 'emerald' : 'zinc'}>
                    {isAdmin ? 'admin' : 'reader'}
                  </Badge>
                </span>
                <NavbarItem onClick={() => void signOut()}>Sign out</NavbarItem>
              </>
            )}
          </NavbarSection>
        </Navbar>
      }
      sidebar={
        <Sidebar>
          <SidebarHeader>
            <span className="flex items-center gap-2 px-2 py-1 font-semibold tracking-tight">
              <BrandMark />
              envisia&nbsp;forge
            </span>
          </SidebarHeader>
          <SidebarBody>
            <SidebarSection>
              {items.map((item) => (
                <SidebarItem
                  key={item.to}
                  href={item.to}
                  current={isCurrent(pathname, item.to)}
                >
                  <SidebarLabel>{item.label}</SidebarLabel>
                </SidebarItem>
              ))}
            </SidebarSection>
          </SidebarBody>
        </Sidebar>
      }
    >
      <Outlet />
    </StackedLayout>
  )
}

/** Small gradient brand square so the navbar has a visual anchor. */
function BrandMark() {
  return (
    <span
      aria-hidden="true"
      className="grid size-6 shrink-0 place-items-center rounded-md bg-gradient-to-br from-sky-500 to-indigo-600 text-[11px] font-bold text-white"
    >
      ef
    </span>
  )
}
