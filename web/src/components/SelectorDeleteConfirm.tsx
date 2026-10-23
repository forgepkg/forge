import type { SelectorView } from '~/api/rbac'
import { useRepositories } from '~/queries/useRepositories'
import {
  useDeleteSelector,
  useRoles,
  useSelectorGrants,
} from '~/queries/useRbac'
import { Dialog } from '~/components/ui'
import {
  byId,
  grantText,
  InlineError,
  repoNames,
} from '~/components/RbacLabels'

/**
 * The confirmation before a content selector is deleted, as a dialog open
 * while it is mounted: the server deletes the grants scoped by it along with
 * it (rather than leaving them to cover every package), so this names them,
 * role by role, first. Cancel, Escape and the close button call `onCancel`.
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
    <Dialog
      open
      onClose={onCancel}
      icon="Trash"
      tone="danger"
      title={`Delete ${selector.name}?`}
      description="The grants it scopes are deleted with it, so they never cover every package. This cannot be undone."
      confirmLabel={del.isPending ? 'Deleting…' : 'Delete selector'}
      confirmVariant="danger-solid"
      confirmDisabled={grants.isLoading || grants.isError || del.isPending}
      onConfirm={() => del.mutate(selector.id, { onSuccess: onDeleted })}
    >
      {grants.isError ? (
        <InlineError>
          Could not load the grants it scopes:{' '}
          {grants.error.body || grants.error.message}
        </InlineError>
      ) : grants.isLoading ? (
        <p className="fg-text">Loading the grants it scopes…</p>
      ) : (grants.data?.length ?? 0) === 0 ? (
        <p className="fg-text">No grant uses it.</p>
      ) : (
        <div className="grid gap-1">
          <p className="fg-text">
            {grants.data!.length === 1
              ? 'This grant is'
              : `These ${grants.data!.length} grants are`}{' '}
            deleted with it:
          </p>
          <ul className="fg-list text-ink">
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
    </Dialog>
  )
}
