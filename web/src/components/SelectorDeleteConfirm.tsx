import type { SelectorView } from '~/api/rbac'
import { useRepositories } from '~/queries/useRepositories'
import {
  useDeleteSelector,
  useRoles,
  useSelectorGrants,
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
 * The confirmation before a content selector is deleted: the server deletes
 * the grants scoped by it along with it (rather than leaving them to cover
 * every package), so this names them, role by role, first.
 */
export function SelectorDeleteConfirm({
  selector,
  onCancel,
  onDeleted,
}: {
  selector: SelectorView
  onCancel: () => void
  onDeleted: () => void
}) {
  const grants = useSelectorGrants(selector.id)
  const roles = useRoles()
  const repos = useRepositories()
  const del = useDeleteSelector()

  const roleMap = byId(roles.data)
  const names = repoNames(repos.data)
  const selectors = new Map([[selector.id, selector]])

  return (
    <div
      role="region"
      aria-label={`Delete selector ${selector.name}`}
      className="space-y-3 rounded-xl border border-red-500/25 bg-red-500/5 p-4 dark:bg-red-500/10"
    >
      <Text>
        Delete the content selector{' '}
        <span className="font-medium text-zinc-950 dark:text-white">
          {selector.name}
        </span>
        ?
      </Text>
      {grants.isError ? (
        <InlineError>
          Could not load the grants it scopes:{' '}
          {grants.error.body || grants.error.message}
        </InlineError>
      ) : grants.isLoading ? (
        <Text>Loading the grants it scopes…</Text>
      ) : (grants.data?.length ?? 0) === 0 ? (
        <Text>No grant uses it.</Text>
      ) : (
        <div>
          <Text>
            {grants.data!.length === 1
              ? 'This grant is'
              : `These ${grants.data!.length} grants are`}{' '}
            deleted with it:
          </Text>
          <ul className="mt-1 list-inside list-disc text-sm/6 text-zinc-950 dark:text-white">
            {grants.data!.map((g) => (
              <li key={g.id}>
                {roleMap.get(g.role_id)?.name ?? `role #${g.role_id}`}:{' '}
                {grantText(g, names, selectors)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {del.isError && (
        <InlineError>{del.error.body || del.error.message}</InlineError>
      )}
      <div className="flex items-center gap-3">
        <Button
          color="red"
          disabled={grants.isLoading || grants.isError || del.isPending}
          onClick={() => del.mutate(selector.id, { onSuccess: onDeleted })}
        >
          {del.isPending ? 'Deleting…' : 'Delete selector'}
        </Button>
        <Button plain onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  )
}
