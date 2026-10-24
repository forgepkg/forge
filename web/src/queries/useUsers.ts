import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { ApiError } from '~/lib/httpClient'
import { realmKeys } from '~/api/realms'
import { roleKeys } from '~/api/rbac'
import { tokenKeys } from '~/api/tokens'
import {
  convertUserToLocal,
  createUser,
  deleteUser,
  fetchUsers,
  inviteUser,
  reauthUser,
  revokeInvitation,
  setUserActive,
  userKeys,
  type CreateUser,
  type CreatedUser,
  type IssuedInvitation,
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

/**
 * Create a user (`POST /admin/users`) with its built-in access level; a
 * local one is invited. Invalidates the user list and the roles (their
 * counts).
 */
export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation<CreatedUser, ApiError, CreateUser>({
    mutationFn: (body) => createUser(body),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
      void queryClient.invalidateQueries({ queryKey: roleKeys.all() })
    },
  })
}

/**
 * Make a new invitation for `id` (sent, or as a link to copy); invalidates
 * the list (its status) on success.
 */
export function useInviteUser() {
  const queryClient = useQueryClient()
  return useMutation<
    IssuedInvitation,
    ApiError,
    { id: number; send_email: boolean; email?: string }
  >({
    mutationFn: ({ id, ...body }) => inviteUser(id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

/** Revoke `id`'s invitation; invalidates the list on success. */
export function useRevokeInvitation() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => revokeInvitation(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

/**
 * Deactivate or reactivate a user. The answer replaces the user in the
 * cached list at once (the list and the user page show the new status), and
 * the list is re-fetched.
 */
export function useSetUserActive() {
  const queryClient = useQueryClient()
  return useMutation<UserView, ApiError, { id: number; active: boolean }>({
    mutationFn: ({ id, active }) => setUserActive(id, active),
    onSuccess: (updated) => {
      queryClient.setQueryData<UserView[]>(userKeys.list(), (users) =>
        users?.map((u) => (u.id === updated.id ? updated : u)),
      )
      void queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

/**
 * Sign a user out everywhere; invalidates their token list on success (the
 * tokens they minted from a forwarded sign-in are revoked).
 */
export function useReauthUser() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => reauthUser(id),
    onSuccess: (_, id) => {
      void queryClient.invalidateQueries({ queryKey: tokenKeys.list(id) })
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
