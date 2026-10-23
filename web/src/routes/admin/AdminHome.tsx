import { createFileRoute, Link } from '@tanstack/react-router'

import { Code, Icon, Page, PageHeader, type IconName } from '~/components/ui'

export const Route = createFileRoute('/_app/manage/')({
  component: AdminHome,
})

/** The admin screens, each with the icon the rail shows for it. */
const SECTIONS = [
  {
    to: '/manage/repositories',
    title: 'Repositories',
    icon: 'Repository',
    description: 'Hosted, proxy, and group repositories; group members and owners.',
  },
  {
    to: '/manage/users',
    title: 'Users & tokens',
    icon: 'Users',
    description:
      'Create and delete accounts; assign their roles; issue, scope and revoke their registry tokens.',
  },
  {
    to: '/manage/roles',
    title: 'Roles',
    icon: 'Lock',
    description: 'Roles, the grants they carry on repositories, and their members.',
  },
  {
    to: '/manage/content-selectors',
    title: 'Content selectors',
    icon: 'Filter',
    description: 'Package-name patterns that narrow a grant to some packages.',
  },
  {
    to: '/manage/realms',
    title: 'Authentication',
    icon: 'Shield',
    description: 'Login realms: local passwords, OIDC, credential forwarding.',
  },
  {
    to: '/manage/settings',
    title: 'Settings',
    icon: 'Sliders',
    description:
      'Anonymous access, the login screen, password Basic, session lifetimes and the lockout.',
  },
  {
    to: '/manage/settings/email',
    title: 'Email',
    icon: 'Mail',
    description: 'The service Forge sends invitations and notifications through.',
  },
  {
    to: '/manage/system',
    title: 'System',
    icon: 'Database',
    description: 'The keys of the secret encryption and their rotation; the local blob cache.',
  },
] as const satisfies ReadonlyArray<{
  to: string
  title: string
  icon: IconName
  description: string
}>

/**
 * Admin landing. Only reachable once the `AdminLayout` guard has confirmed
 * `is_admin`. A card per admin screen, with the rail's icon for it: the
 * repositories, users (incl. per-user tokens and roles), roles, content
 * selectors, authentication-realm, settings, email-service and system
 * screens; the header names what only the `/admin` API manages (CHANGELOG
 * "Known limitations").
 */
function AdminHome() {
  return (
    <Page>
      <PageHeader
        title="Administration"
        description={
          <>
            Manage repositories, users and their API tokens, roles and their
            grants, content selectors, authentication realms, the sign-in
            and anonymous-access settings, the email service, and the
            secret encryption and blob cache. Retention and user
            deactivation have no screen yet; use the <Code>/admin</Code> API.
          </>
        }
      />
      <ul className="m-0 flex list-none flex-wrap gap-4 p-0">
        {SECTIONS.map((section) => (
          <li key={section.to} className="flex min-w-0 flex-[1_1_280px]">
            <Link
              to={section.to}
              className="fg-panel group flex w-full items-start gap-4 p-5 text-ink no-underline transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--focus)]"
            >
              <span className="fg-choice-icon flex-none group-hover:text-heat">
                <Icon name={section.icon} size={18} />
              </span>
              <span className="grid min-w-0 gap-1">
                <span className="fg-strong group-hover:text-heat-strong">
                  {section.title}
                </span>
                <span className="text-[13px] leading-5 text-ink-muted">
                  {section.description}
                </span>
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </Page>
  )
}
