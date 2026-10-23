import { Link } from '@tanstack/react-router'

import { ANONYMOUS_ROLE } from '~/api/rbac'
import type { RepoView } from '~/api/repositories'
import type { AnonymousMode } from '~/api/settings'
import { useRoleGrants, useRoles, useSelectors } from '~/queries/useRbac'
import { useAuthSettings } from '~/queries/useSettings'
import { Badge } from '~/components/catalyst/badge'
import { Subheading } from '~/components/catalyst/heading'
import { Text } from '~/components/catalyst/text'
import { ActionBadge, byId, SelectorLabel } from '~/components/RbacLabels'

const MODE_LABELS: Record<AnonymousMode, string> = {
  off: 'off',
  allowlist: 'IP allowlist',
  all: 'everyone',
}

/**
 * A repository's anonymous access, read-only: its `anonymous_read` flag (set
 * in the form) together with the grants of the built-in `anonymous` role that
 * cover it, on this repository or on every repository. Either opens the
 * repository to callers who do not sign in, as far as the server's anonymous
 * mode (Settings, which this links to) lets them in at all; the grants are
 * changed on the role's page, which this links to too.
 */
export function AnonymousAccessPanel({ repo }: { repo: RepoView }) {
  const settings = useAuthSettings()
  const roles = useRoles()
  const role = roles.data?.find((r) => r.name === ANONYMOUS_ROLE)
  const grants = useRoleGrants(role?.id ?? 0, role != null)
  const selectors = useSelectors()
  const selectorMap = byId(selectors.data)

  const covering = (grants.data ?? []).filter(
    (g) => g.repository_id == null || g.repository_id === repo.id,
  )

  return (
    <div
      role="region"
      aria-label="Anonymous access"
      className="space-y-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <Subheading>Anonymous access</Subheading>
      <Text>
        Server-wide anonymous access:{' '}
        {settings.data == null ? (
          '…'
        ) : settings.data.anonymous_mode === 'off' ? (
          <Badge color="zinc">off</Badge>
        ) : (
          <Badge color="amber">{MODE_LABELS[settings.data.anonymous_mode]}</Badge>
        )}{' '}
        <Link
          to="/manage/settings"
          className="text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
        >
          Settings →
        </Link>
      </Text>
      {settings.data?.anonymous_mode === 'off' && (
        <Text>
          Nobody reads without signing in while it is off, whatever this
          repository allows.
        </Text>
      )}
      <Text>
        Allow anonymous read:{' '}
        {repo.anonymous_read ? (
          <Badge color="amber">on</Badge>
        ) : (
          <Badge color="zinc">off</Badge>
        )}
      </Text>
      {roles.isError || grants.isError ? (
        <Text>Could not load the anonymous role&apos;s grants.</Text>
      ) : roles.isLoading || (role != null && grants.isLoading) ? (
        <Text>Loading the anonymous role&apos;s grants…</Text>
      ) : role == null ? (
        <Text>There is no anonymous role.</Text>
      ) : (
        <>
          {covering.length === 0 ? (
            <Text>The anonymous role grants nothing on this repository.</Text>
          ) : (
            <div>
              <Text>The anonymous role grants on this repository:</Text>
              <ul className="mt-1 space-y-1 text-sm/6 text-zinc-950 dark:text-white">
                {covering.map((g) => (
                  <li key={g.id} className="flex flex-wrap items-center gap-2">
                    <ActionBadge action={g.action} />
                    <span>
                      {g.repository_id == null
                        ? 'on all repositories'
                        : 'on this repository'}
                      ,
                    </span>
                    <SelectorLabel id={g.selector_id} selectors={selectorMap} />
                  </li>
                ))}
              </ul>
            </div>
          )}
          <Link
            to="/manage/roles/$roleId"
            params={{ roleId: String(role.id) }}
            className="inline-block text-sm/6 text-sky-600 hover:underline dark:text-sky-400"
          >
            Change the anonymous role&apos;s grants →
          </Link>
        </>
      )}
    </div>
  )
}
