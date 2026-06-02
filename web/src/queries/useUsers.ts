import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
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

/** Create a user; invalidates the list on success. */
export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation<UserView, ApiError, CreateUser>({
    mutationFn: (body) => createUser(body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
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
