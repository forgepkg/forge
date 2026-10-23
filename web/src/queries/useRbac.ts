import { useEffect, useState } from 'react'
import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import { userKeys } from '~/api/users'
import {
  addGrant,
  assignRole,
  createRole,
  createSelector,
  deleteRole,
  deleteSelector,
  fetchGrants,
  fetchRole,
  fetchRoleMembers,
  fetchRoles,
  fetchSelectorGrants,
  fetchSelectors,
  fetchUserEffective,
  fetchUserRoles,
  matchSelector,
  removeGrant,
  roleKeys,
  selectorKeys,
  unassignRole,
  updateRole,
  updateSelector,
  userRoleKeys,
  type AddGrant,
  type CreateRole,
  type CreateSelector,
  type EffectiveView,
  type GrantView,
  type RoleMember,
  type RoleView,
  type SelectorView,
  type UpdateSelector,
} from '~/api/rbac'

/**
 * TanStack Query hooks for the RBAC admin screens. A role, grant, selector or
 * assignment change shows up in several views at once (role counts, the user
 * list's roles, a user's effective access, a selector's grants), so every
 * mutation invalidates all of them rather than tracking which one changed.
 */
function invalidateRbac(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: roleKeys.all() })
  void queryClient.invalidateQueries({ queryKey: selectorKeys.all() })
  void queryClient.invalidateQueries({ queryKey: userRoleKeys.all() })
  void queryClient.invalidateQueries({ queryKey: userKeys.all() })
}

/** Every role (`GET /admin/roles`). */
export function useRoles() {
  return useQuery<RoleView[], ApiError>({
    queryKey: roleKeys.list(),
    queryFn: ({ signal }) => fetchRoles(signal),
  })
}

/** One role (`GET /admin/roles/{id}`). */
export function useRole(id: number) {
  return useQuery<RoleView, ApiError>({
    queryKey: roleKeys.detail(id),
    queryFn: ({ signal }) => fetchRole(id, signal),
  })
}

/** A role's grants; `enabled: false` defers the load (e.g. until a delete is asked for). */
export function useRoleGrants(id: number, enabled = true) {
  return useQuery<GrantView[], ApiError>({
    queryKey: roleKeys.grants(id),
    queryFn: ({ signal }) => fetchGrants(id, signal),
    enabled,
  })
}

/** A role's members; `enabled: false` defers the load. */
export function useRoleMembers(id: number, enabled = true) {
  return useQuery<RoleMember[], ApiError>({
    queryKey: roleKeys.members(id),
    queryFn: ({ signal }) => fetchRoleMembers(id, signal),
    enabled,
  })
}

export function useCreateRole() {
  const queryClient = useQueryClient()
  return useMutation<RoleView, ApiError, CreateRole>({
    mutationFn: (body) => createRole(body),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

export function useUpdateRole(id: number) {
  const queryClient = useQueryClient()
  return useMutation<RoleView, ApiError, string>({
    mutationFn: (description) => updateRole(id, description),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

export function useDeleteRole() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => deleteRole(id),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

export function useAddGrant(roleId: number) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, AddGrant>({
    mutationFn: (body) => addGrant(roleId, body),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

export function useRemoveGrant(roleId: number) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (grantId) => removeGrant(roleId, grantId),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

/** The roles a user holds (`GET /admin/users/{id}/roles`). */
export function useUserRoles(userId: number) {
  return useQuery<RoleView[], ApiError>({
    queryKey: userRoleKeys.roles(userId),
    queryFn: ({ signal }) => fetchUserRoles(userId, signal),
  })
}

/** Assign a role to a user: `{ userId, roleId }`. */
export function useAssignRole() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, { userId: number; roleId: number }>({
    mutationFn: ({ userId, roleId }) => assignRole(userId, roleId),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

/** Take a role from a user; 409 for the last administrator's `admin`. */
export function useUnassignRole() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, { userId: number; roleId: number }>({
    mutationFn: ({ userId, roleId }) => unassignRole(userId, roleId),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

/** A user's effective access (`GET /admin/users/{id}/effective`). */
export function useUserEffective(userId: number) {
  return useQuery<EffectiveView, ApiError>({
    queryKey: userRoleKeys.effective(userId),
    queryFn: ({ signal }) => fetchUserEffective(userId, signal),
  })
}

/** Every content selector (`GET /admin/content-selectors`). */
export function useSelectors() {
  return useQuery<SelectorView[], ApiError>({
    queryKey: selectorKeys.list(),
    queryFn: ({ signal }) => fetchSelectors(signal),
  })
}

/** The grants a selector scopes; `enabled: false` defers the load. */
export function useSelectorGrants(id: number, enabled = true) {
  return useQuery<GrantView[], ApiError>({
    queryKey: selectorKeys.grants(id),
    queryFn: ({ signal }) => fetchSelectorGrants(id, signal),
    enabled,
  })
}

export function useCreateSelector() {
  const queryClient = useQueryClient()
  return useMutation<SelectorView, ApiError, CreateSelector>({
    mutationFn: (body) => createSelector(body),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

export function useUpdateSelector(id: number) {
  const queryClient = useQueryClient()
  return useMutation<SelectorView, ApiError, UpdateSelector>({
    mutationFn: (body) => updateSelector(id, body),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

export function useDeleteSelector() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => deleteSelector(id),
    onSuccess: () => invalidateRbac(queryClient),
  })
}

/**
 * Whether `name` matches the (unsaved) patterns, asked of the server a moment
 * after the last keystroke so its globs, not a copy of them, decide.
 */
export function useSelectorMatch(
  includes: string[],
  excludes: string[],
  name: string,
) {
  const input = useDebounced({ includes, excludes, name: name.trim() })
  return useQuery<{ matches: boolean }, ApiError>({
    queryKey: ['content-selectors', 'match', input],
    queryFn: ({ signal }) => matchSelector(input, signal),
    enabled: input.name !== '',
    staleTime: Infinity,
    retry: false,
  })
}

function useDebounced<T>(value: T, ms = 250): T {
  const key = JSON.stringify(value)
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(timer)
    // `key` stands for `value`: a new array of the same patterns is no change.
  }, [key, ms])
  return settled
}
