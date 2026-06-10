import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  createRealm,
  deleteRealm,
  fetchRealm,
  fetchRealms,
  realmKeys,
  reorderRealms,
  updateRealm,
  type CreateRealm,
  type RealmView,
  type UpdateRealm,
} from '~/api/realms'

/**
 * TanStack Query hooks for the admin auth-realm resource (§12.7). Reads use
 * `useQuery`; mutations invalidate the realm queries on success so the UI
 * re-fetches the authoritative server state (order, redacted config, ...).
 */

/** List all realms in priority order (`GET /admin/realms`). */
export function useRealms() {
  return useQuery<RealmView[], ApiError>({
    queryKey: realmKeys.list(),
    queryFn: ({ signal }) => fetchRealms(signal),
  })
}

/** One realm by id (`GET /admin/realms/{id}`). */
export function useRealm(id: number) {
  return useQuery<RealmView, ApiError>({
    queryKey: realmKeys.detail(id),
    queryFn: ({ signal }) => fetchRealm(id, signal),
  })
}

/** Create a realm; invalidates the list on success. */
export function useCreateRealm() {
  const queryClient = useQueryClient()
  return useMutation<RealmView, ApiError, CreateRealm>({
    mutationFn: (body) => createRealm(body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: realmKeys.all() })
    },
  })
}

/** Patch a realm; invalidates list + detail on success. */
export function useUpdateRealm(id: number) {
  const queryClient = useQueryClient()
  return useMutation<RealmView, ApiError, UpdateRealm>({
    mutationFn: (body) => updateRealm(id, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: realmKeys.all() })
    },
  })
}

/** Delete a realm; invalidates the list on success. */
export function useDeleteRealm() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => deleteRealm(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: realmKeys.all() })
    },
  })
}

/** PUT the full new id order; invalidates the list on success. */
export function useReorderRealms() {
  const queryClient = useQueryClient()
  return useMutation<RealmView[], ApiError, number[]>({
    mutationFn: (order) => reorderRealms(order),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: realmKeys.all() })
    },
  })
}
