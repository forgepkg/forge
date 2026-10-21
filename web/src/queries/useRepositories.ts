import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  addMember,
  createRepository,
  deleteRepository,
  fetchMembers,
  fetchRepositories,
  fetchRepository,
  removeMember,
  repoKeys,
  updateMember,
  updateRepository,
  type AddMember,
  type CreateRepo,
  type MemberView,
  type RepoView,
  type UpdateRepo,
} from '~/api/repositories'

/**
 * TanStack Query hooks for the admin repository resource. Reads use `useQuery`;
 * mutations invalidate the relevant list / detail / members keys on success so
 * the UI re-fetches the authoritative server state (rather than optimistically
 * mutating a redacted view). Auth failures are not retried by the shared
 * query-client policy.
 */

/** List all repositories (`GET /admin/repositories`). */
export function useRepositories() {
  return useQuery<RepoView[], ApiError>({
    queryKey: repoKeys.list(),
    queryFn: ({ signal }) => fetchRepositories(signal),
  })
}

/** One repository's detail (`GET /admin/repositories/{name}`). */
export function useRepository(name: string) {
  return useQuery<RepoView, ApiError>({
    queryKey: repoKeys.detail(name),
    queryFn: ({ signal }) => fetchRepository(name, signal),
  })
}

/** Create a repository; invalidates the list on success. */
export function useCreateRepository() {
  const queryClient = useQueryClient()
  return useMutation<RepoView, ApiError, CreateRepo>({
    mutationFn: (body) => createRepository(body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.list() })
    },
  })
}

/** Update a repository; invalidates the list + that repo's detail on success. */
export function useUpdateRepository(name: string) {
  const queryClient = useQueryClient()
  return useMutation<RepoView, ApiError, UpdateRepo>({
    mutationFn: (body) => updateRepository(name, body),
    onSuccess: (updated) => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.list() })
      // The name may have changed; invalidate both the old and new detail keys.
      void queryClient.invalidateQueries({ queryKey: repoKeys.detail(name) })
      if (updated.name !== name) {
        void queryClient.invalidateQueries({
          queryKey: repoKeys.detail(updated.name),
        })
      }
    },
  })
}

/** Delete a repository; invalidates the list on success. */
export function useDeleteRepository() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, string>({
    mutationFn: (name) => deleteRepository(name),
    onSuccess: (_void, name) => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.list() })
      void queryClient.removeQueries({ queryKey: repoKeys.detail(name) })
    },
  })
}

/** A group's ordered members (`GET /admin/repositories/{name}/members`). */
export function useMembers(name: string) {
  return useQuery<MemberView[], ApiError>({
    queryKey: repoKeys.members(name),
    queryFn: ({ signal }) => fetchMembers(name, signal),
  })
}

/** Add a member to a group; invalidates that group's member list on success. */
export function useAddMember(name: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, AddMember>({
    mutationFn: (body) => addMember(name, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.members(name) })
    },
  })
}

/** Remove a member from a group; invalidates that group's member list. */
export function useRemoveMember(name: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, string>({
    mutationFn: (member) => removeMember(name, member),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.members(name) })
    },
  })
}

/** Flag or unflag a member as owner; invalidates that group's member list. */
export function useUpdateMember(name: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, { member: string; owner: boolean }>({
    mutationFn: ({ member, owner }) => updateMember(name, member, { owner }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.members(name) })
    },
  })
}
