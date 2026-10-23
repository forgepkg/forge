import type { RoleView } from '~/api/rbac'
import { useRepositories } from '~/queries/useRepositories'
import {
  useDeleteRole,
  useRoleGrants,
  useRoleMembers,
  useSelectors,
} from '~/queries/useRbac'
import { Button } from '~/components/catalyst/button'
import { Text } from '~/components/catalyst/text'
import {
  byId,
  grantText,
  InlineError,
  repoNames,
} from '~/components/RbacLabels'

/**
 * The confirmation before a role is deleted: deleting it unassigns its users
 * and removes its grants (both cascade on the server), so it names them first
 * and deletes only once both lists have loaded.
 */
export function RoleDeleteConfirm({
  role,
  onCancel,
  onDeleted,
}: {
  role: RoleView
  onCancel: () => void
  onDeleted: () => void
}) {
  const members = useRoleMembers(role.id)
  const grants = useRoleGrants(role.id)
  const repos = useRepositories()
  const selectors = useSelectors()
  const del = useDeleteRole()

  const names = repoNames(repos.data)
  const selectorMap = byId(selectors.data)
  const loading = members.isLoading || grants.isLoading
  const loadError = members.error ?? grants.error

  return (
    <div
      role="region"
      aria-label={`Delete role ${role.name}`}
      className="space-y-3 rounded-xl border border-red-500/25 bg-red-500/5 p-4 dark:bg-red-500/10"
    >
      <Text>
        Delete the role{' '}
        <span className="font-medium text-zinc-950 dark:text-white">
          {role.name}
        </span>
        ?
      </Text>
      {loadError ? (
        <InlineError>
          Could not load what the role holds: {loadError.body || loadError.message}
        </InlineError>
      ) : loading ? (
        <Text>Loading the role&apos;s users and grants…</Text>
      ) : (
        <>
          {(members.data?.length ?? 0) === 0 ? (
            <Text>No user holds it.</Text>
          ) : (
            <div>
              <Text>
                It is taken from {members.data!.length === 1 ? 'this user' : `these ${members.data!.length} users`}:
              </Text>
              <ul className="mt-1 list-inside list-disc text-sm/6 text-zinc-950 dark:text-white">
                {members.data!.map((m) => (
                  <li key={m.id}>{m.username}</li>
                ))}
              </ul>
            </div>
          )}
          {(grants.data?.length ?? 0) === 0 ? (
            <Text>It has no grants.</Text>
          ) : (
            <div>
              <Text>
                {grants.data!.length === 1 ? 'This grant is' : `These ${grants.data!.length} grants are`}{' '}
                removed:
              </Text>
              <ul className="mt-1 list-inside list-disc text-sm/6 text-zinc-950 dark:text-white">
                {grants.data!.map((g) => (
                  <li key={g.id}>{grantText(g, names, selectorMap)}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      {del.isError && <InlineError>{del.error.body || del.error.message}</InlineError>}
      <div className="flex items-center gap-3">
        <Button
          color="red"
          disabled={loading || loadError != null || del.isPending}
          onClick={() => del.mutate(role.id, { onSuccess: onDeleted })}
        >
          {del.isPending ? 'Deleting…' : 'Delete role'}
        </Button>
        <Button plain onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  )
}
