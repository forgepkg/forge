import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { ApiError } from '~/lib/httpClient'
import { realmKeys } from '~/api/realms'
import { ADMIN_ROLE, assignRole, roleKeys, type RoleView } from '~/api/rbac'
import {
  convertUserToLocal,
  createUser,
  deleteUser,
  fetchUsers,
  userKeys,
  type CreateUser,
  type UserView,
} from '~/api/users'

/**
 * TanStack Query hooks for the admin user resource. Reads use `useQuery`;
 * mutations invalidate the user list on success so the UI re-fetches the
 * authoritative server state. Auth failures are not retried by the shared
 * query-client policy.
 */

/** List all users (`GET /admin/users`). */
export function useUsers() {
  return useQuery<UserView[], ApiError>({
    queryKey: userKeys.list(),
    queryFn: ({ signal }) => fetchUsers(signal),
  })
}

/** A create whose user exists although one of its roles could not be given. */
export class PartialCreate extends Error {
  constructor(
    public readonly created: UserView,
    message: string,
  ) {
    super(message)
  }
}

/**
 * Create a user, then give it the chosen roles. `admin` goes with the create
 * (`is_admin`, which also assigns the role); the others are assigned one by
 * one afterwards, and a failed assignment is a {@link PartialCreate} that
 * names the role while the user stays created. Invalidates the user list and
 * the roles (their counts) either way.
 */
export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation<
    UserView,
    Error,
    { body: Omit<CreateUser, 'is_admin'>; roles: RoleView[] }
  >({
    mutationFn: async ({ body, roles }) => {
      const created = await createUser({
        ...body,
        is_admin: roles.some((r) => r.name === ADMIN_ROLE),
      })
      for (const role of roles) {
        if (role.name === ADMIN_ROLE) continue
        try {
          await assignRole(created.id, role.id)
        } catch (e) {
          const reason = e instanceof ApiError ? e.body || e.message : String(e)
          throw new PartialCreate(
            created,
            `Created ${created.username}, but could not give it the role ${role.name}: ${reason}`,
          )
        }
      }
      return created
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
      void queryClient.invalidateQueries({ queryKey: roleKeys.all() })
    },
  })
}

/** Delete a user; invalidates the list on success. */
export function useDeleteUser() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => deleteUser(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

/**
 * Switch a credential-forwarding account to a local one with its kept
 * password; invalidates the list (and realm counts) on success.
 */
export function useConvertUserToLocal() {
  const queryClient = useQueryClient()
  return useMutation<UserView, ApiError, number>({
    mutationFn: (id) => convertUserToLocal(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
      void queryClient.invalidateQueries({ queryKey: realmKeys.all() })
    },
  })
}
