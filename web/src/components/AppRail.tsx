import { useSyncExternalStore } from 'react'
import { Link } from '@tanstack/react-router'
import clsx from 'clsx'

import type { BrowseRepo } from '~/api/packages'
import { Avatar, Icon, Logo, Menu, formatLabel, type IconName } from '~/components/ui'
import { getTheme, onThemeChange, resolveTheme, setTheme, THEMES } from '~/lib/theme'

interface RailLink {
  label: string
  to: string
  icon: IconName
}

const PLACES: RailLink[] = [
  { label: 'Browse', to: '/', icon: 'Grid' },
  { label: 'Your tokens', to: '/tokens', icon: 'Key' },
]

const ADMINISTRATION: RailLink[] = [
  { label: 'Overview', to: '/manage', icon: 'Overview' },
  { label: 'Repositories', to: '/manage/repositories', icon: 'Repository' },
  { label: 'Users', to: '/manage/users', icon: 'Users' },
  { label: 'Service accounts', to: '/manage/service-accounts', icon: 'Terminal' },
  { label: 'Roles', to: '/manage/roles', icon: 'Lock' },
  { label: 'Content selectors', to: '/manage/content-selectors', icon: 'Filter' },
  { label: 'Authentication', to: '/manage/realms', icon: 'Shield' },
  { label: 'Settings', to: '/manage/settings', icon: 'Sliders' },
  { label: 'Email', to: '/manage/settings/email', icon: 'Mail' },
  { label: 'Retention', to: '/manage/settings/retention', icon: 'Clock' },
  { label: 'Traffic', to: '/manage/traffic', icon: 'Activity' },
  { label: 'System', to: '/manage/system', icon: 'Database' },
]

/**
 * The rail item the location belongs to: the longest `to` the path is or
 * starts with (Settings on `/manage/settings`, Email on its sub-page),
 * Browse only on `/` itself.
 */
function currentLink(pathname: string, links: RailLink[]): string | undefined {
  let best: string | undefined
  for (const { to } of links) {
    const hit =
      to === '/' ? pathname === '/' : pathname === to || pathname.startsWith(`${to}/`)
    if (hit && (!best || to.length > best.length)) best = to
  }
  return best
}

/** The repository a browse location shows (`/repos/x`, `/packages/x/…`, `/images/x/…`). */
function currentRepo(pathname: string): string | undefined {
  const m = /^\/(?:repos|packages|images)\/([^/]+)/.exec(pathname)
  return m ? decodeURIComponent(m[1]) : undefined
}

/**
 * The navigation rail: the lockup, the places (Browse, Your tokens),
 * Administration for admins, the repositories the user can read with their
 * kind dot and format, and the signed-in user with the theme switch and Sign
 * out. On phones it is the drawer behind the top bar's menu button
 * (`AppLayout`), with a close button of its own.
 */
export function AppRail({
  pathname,
  isAdmin,
  username,
  repos,
  onSignOut,
  onClose,
}: {
  pathname: string
  isAdmin: boolean
  username: string | null
  repos: BrowseRepo[]
  onSignOut: () => void
  /** Closes the phone drawer. */
  onClose: () => void
}) {
  const links = isAdmin ? [...PLACES, ...ADMINISTRATION] : PLACES
  const current = currentLink(pathname, links)
  const repo = currentRepo(pathname)

  return (
    <nav className="fg-rail" aria-label="Main">
      <div className="fg-rail-brand">
        <Link to="/" className="fg-rail-home" aria-label="Forge home">
          <Logo size={24} />
        </Link>
        <button
          type="button"
          className="fg-rail-icon fg-rail-close"
          aria-label="Close navigation"
          onClick={onClose}
        >
          <Icon name="X" size={16} />
        </button>
      </div>
      <div className="fg-rail-sections">
        <RailSection links={PLACES} current={current} />
        {isAdmin && (
          <RailSection title="Administration" links={ADMINISTRATION} current={current} />
        )}
        {repos.length > 0 && (
          <div className="fg-rail-section">
            <div className="fg-rail-title">Repositories</div>
            <ul className="fg-rail-list">
              {repos.map((r) => (
                <li key={r.name}>
                  <Link
                    to="/repos/$repo"
                    params={{ repo: r.name }}
                    className={clsx('fg-rail-item', repo === r.name && 'is-current')}
                    aria-current={repo === r.name ? 'page' : undefined}
                  >
                    <span
                      className={`fg-rail-kind fg-rail-kind--${r.kind}`}
                      aria-hidden="true"
                    />
                    <span className="fg-rail-label">
                      {r.name}
                      <span className="fg-sr">{`, ${r.kind}`}</span>
                    </span>
                    <span className="fg-rail-meta">{formatLabel(r.format)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      {username && (
        <div className="fg-rail-user">
          <Avatar name={username} size={30} decorative />
          <span className="fg-rail-who">
            <span className="fg-rail-name">{username}</span>
            <span className="fg-rail-role">{isAdmin ? 'Administrator' : 'User'}</span>
          </span>
          <ThemeMenu />
          <button
            type="button"
            className="fg-rail-icon"
            aria-label="Sign out"
            title="Sign out"
            onClick={onSignOut}
          >
            <Icon name="LogOut" size={16} />
          </button>
        </div>
      )}
    </nav>
  )
}

function RailSection({
  title,
  links,
  current,
}: {
  title?: string
  links: RailLink[]
  current: string | undefined
}) {
  return (
    <div className="fg-rail-section">
      {title && <div className="fg-rail-title">{title}</div>}
      <ul className="fg-rail-list">
        {links.map((l) => (
          <li key={l.to}>
            <Link
              to={l.to}
              className={clsx('fg-rail-item', current === l.to && 'is-current')}
              aria-current={current === l.to ? 'page' : undefined}
            >
              <Icon name={l.icon} size={16} />
              <span className="fg-rail-label">{l.label}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * The theme switch: System (follows the OS between Light and Dark), Light,
 * Light with dark rail, Dark. The preference lives in `lib/theme.ts`, an
 * external store (localStorage + `data-theme`), read with
 * `useSyncExternalStore` so it survives reloads and follows other tabs.
 */
function ThemeMenu() {
  const theme = useSyncExternalStore(onThemeChange, getTheme, getTheme)
  const shown = resolveTheme(theme)
  return (
    <Menu
      label="Change theme"
      iconOnly
      icon={shown === 'dark' ? 'Moon' : 'Sun'}
      direction="up"
      align="end"
      buttonClassName="fg-rail-icon"
      items={THEMES.map((t) => ({
        label: t.label,
        checked: theme === t.value,
        onSelect: () => setTheme(t.value),
      }))}
    />
  )
}
