import type { RoleView } from '~/api/rbac'
import { useRepositories } from '~/queries/useRepositories'
import {
  useDeleteRole,
  useRoleGrants,
  useRoleMembers,
  useSelectors,
} from '~/queries/useRbac'
import { Dialog } from '~/components/ui'
import {
  byId,
  grantText,
  InlineError,
  repoNames,
} from '~/components/RbacLabels'

/**
 * The confirmation before a role is deleted, as a dialog open while it is
 * mounted: deleting the role unassigns its users and removes its grants
 * (both cascade on the server), so it names them first and deletes only once
 * both lists have loaded. Cancel, Escape and the close button call
 * `onCancel`.
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
    <Dialog
      open
      onClose={onCancel}
      icon="Trash"
      tone="danger"
      title={`Delete ${role.name}?`}
      description="Its users lose the role and its grants are removed. This cannot be undone."
      confirmLabel={del.isPending ? 'Deleting…' : 'Delete role'}
      confirmVariant="danger-solid"
      confirmDisabled={loading || loadError != null || del.isPending}
      onConfirm={() => del.mutate(role.id, { onSuccess: onDeleted })}
    >
      {loadError ? (
        <InlineError>
          Could not load what the role holds: {loadError.body || loadError.message}
        </InlineError>
      ) : loading ? (
        <p className="fg-text">Loading the role&apos;s users and grants…</p>
      ) : (
        <>
          {(members.data?.length ?? 0) === 0 ? (
            <p className="fg-text">No user holds it.</p>
          ) : (
            <div className="grid gap-1">
              <p className="fg-text">
                It is taken from{' '}
                {members.data!.length === 1
                  ? 'this user'
                  : `these ${members.data!.length} users`}
                :
              </p>
              <ul className="fg-list text-ink">
                {members.data!.map((m) => (
                  <li key={m.id}>{m.username}</li>
                ))}
              </ul>
            </div>
          )}
          {(grants.data?.length ?? 0) === 0 ? (
            <p className="fg-text">It has no grants.</p>
          ) : (
            <div className="grid gap-1">
              <p className="fg-text">
                {grants.data!.length === 1
                  ? 'This grant is'
                  : `These ${grants.data!.length} grants are`}{' '}
                removed:
              </p>
              <ul className="fg-list text-ink">
                {grants.data!.map((g) => (
                  <li key={g.id}>{grantText(g, names, selectorMap)}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      {del.isError && <InlineError>{del.error.body || del.error.message}</InlineError>}
    </Dialog>
  )
}
