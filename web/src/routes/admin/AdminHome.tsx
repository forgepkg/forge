import { createFileRoute, Link } from '@tanstack/react-router'

import { Heading } from '~/components/catalyst/heading'
import { Code, Text } from '~/components/catalyst/text'

export const Route = createFileRoute('/_app/manage/')({
  component: AdminHome,
})

const SECTIONS = [
  {
    to: '/manage/repositories',
    title: 'Repositories',
    description: 'Hosted, proxy, and group repositories; group members and owners.',
  },
  {
    to: '/manage/users',
    title: 'Users & tokens',
    description: 'Create and delete accounts; issue and revoke their registry tokens.',
  },
  {
    to: '/manage/realms',
    title: 'Authentication',
    description: 'Login realms: local passwords, OIDC, credential forwarding.',
  },
] as const

/**
 * Admin landing. Only reachable once the `AdminLayout` guard has confirmed
 * `is_admin`. Links to the repositories, users (incl. per-user tokens), and
 * authentication-realm management screens, and names what only the `/admin`
 * API manages (CHANGELOG "Known limitations").
 */
function AdminHome() {
  return (
    <section className="space-y-6">
      <div>
        <Heading>Administration</Heading>
        <Text className="mt-1">
          Manage repositories, users and their API tokens, and authentication
          realms. Retention, RBAC roles and grants, user deactivation and key
          rotation have no screen yet; use the <Code>/admin</Code> API.
        </Text>
      </div>
      <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {SECTIONS.map((section) => (
          <li key={section.to}>
            <Link
              to={section.to}
              className="group block h-full rounded-xl p-5 ring-1 ring-zinc-950/5 transition hover:bg-zinc-950/[2.5%] hover:ring-zinc-950/10 dark:ring-white/10 dark:hover:bg-white/[2.5%] dark:hover:ring-white/20"
            >
              <span className="font-medium text-zinc-950 group-hover:text-sky-700 dark:text-white dark:group-hover:text-sky-400">
                {section.title}
              </span>
              <Text className="mt-1 !text-sm">{section.description}</Text>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  )
}
