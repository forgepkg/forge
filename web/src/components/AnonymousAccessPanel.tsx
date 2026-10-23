import { Link } from '@tanstack/react-router'

import { ANONYMOUS_ROLE } from '~/api/rbac'
import type { RepoView } from '~/api/repositories'
import type { AnonymousMode } from '~/api/settings'
import { useRoleGrants, useRoles, useSelectors } from '~/queries/useRbac'
import { useAuthSettings } from '~/queries/useSettings'
import { FactList, Panel, Skeleton, StatusBadge } from '~/components/ui'
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
 * changed on the role's page, which this links to too. A panel of the edit
 * screen's side column (a region named "Anonymous access").
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
    <Panel
      title="Anonymous access"
      description="Who may read this repository without signing in."
    >
      <FactList
        items={[
          {
            term: 'Server-wide',
            value: (
              <span className="inline-flex flex-wrap items-center gap-2">
                {settings.data == null ? (
                  '…'
                ) : settings.data.anonymous_mode === 'off' ? (
                  <StatusBadge>off</StatusBadge>
                ) : (
                  <StatusBadge tone="warn">
                    {MODE_LABELS[settings.data.anonymous_mode]}
                  </StatusBadge>
                )}
                <Link to="/manage/settings" className="fg-link">
                  Settings →
                </Link>
              </span>
            ),
          },
          {
            term: 'Allow anonymous read',
            value: repo.anonymous_read ? (
              <StatusBadge tone="warn">on</StatusBadge>
            ) : (
              <StatusBadge>off</StatusBadge>
            ),
          },
        ]}
      />
      {settings.data?.anonymous_mode === 'off' && (
        <p className="fg-text">
          Nobody reads without signing in while it is off, whatever this
          repository allows.
        </p>
      )}
      {roles.isError || grants.isError ? (
        <p className="fg-text">Could not load the anonymous role&apos;s grants.</p>
      ) : roles.isLoading || (role != null && grants.isLoading) ? (
        <Skeleton lines={2} label="Loading the anonymous role's grants…" />
      ) : role == null ? (
        <p className="fg-text">There is no anonymous role.</p>
      ) : (
        <>
          {covering.length === 0 ? (
            <p className="fg-text">
              The anonymous role grants nothing on this repository.
            </p>
          ) : (
            <div className="grid gap-2">
              <p className="fg-text">The anonymous role grants on this repository:</p>
              <ul className="m-0 grid list-none gap-2 p-0 text-ink">
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
          <p className="m-0">
            <Link
              to="/manage/roles/$roleId"
              params={{ roleId: String(role.id) }}
              className="fg-link"
            >
              Change the anonymous role&apos;s grants →
            </Link>
          </p>
        </>
      )}
    </Panel>
  )
}
