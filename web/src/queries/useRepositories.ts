import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import { imageKeys } from '~/api/images'
import { pkgKeys } from '~/api/packages'
import { rawKeys } from '~/api/raw'
import {
  addMember,
  createTrustedPublisher,
  createRepository,
  deleteTrustedPublisher,
  deleteRepository,
  fetchFormats,
  fetchMembers,
  fetchRepositories,
  fetchRepository,
  fetchTrustedPublishers,
  formatKeys,
  invalidateProxyCache,
  removeMember,
  repoKeys,
  updateMember,
  updateRepository,
  updateTrustedPublisher,
  type AddMember,
  type CreateRepo,
  type FormatView,
  type InvalidateProxyCache,
  type MemberView,
  type ProxyCacheInvalidated,
  type RepoView,
  type UpdateRepo,
  type TrustedPublisherBody,
  type TrustedPublisherView,
} from '~/api/repositories'

/**
 * TanStack Query hooks for the admin repository resource. Reads use `useQuery`;
 * mutations invalidate the relevant list / detail / members keys on success so
 * the UI re-fetches the authoritative server state (rather than optimistically
 * mutating a redacted view). Auth failures are not retried by the shared
 * query-client policy.
 *
 * A change to a repository or a group's members also invalidates what the
 * Browse screens cached ({@link invalidateBrowse}).
 */

/**
 * Mark everything the Browse screens show as stale: the repository list
 * (`GET /browse/repos`), package and image searches and details, and raw
 * listings. Creating, renaming, deleting or taking a repository offline, and
 * changing a group's members, change what they list.
 */
function invalidateBrowse(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: pkgKeys.all() })
  void queryClient.invalidateQueries({ queryKey: imageKeys.all() })
  void queryClient.invalidateQueries({ queryKey: rawKeys.all })
}

/** List all repositories (`GET /admin/repositories`). */
export function useRepositories() {
  return useQuery<RepoView[], ApiError>({
    queryKey: repoKeys.list(),
    queryFn: ({ signal }) => fetchRepositories(signal),
  })
}

/** The installed package formats (`GET /admin/formats`). */
export function useFormats() {
  return useQuery<FormatView[], ApiError>({
    queryKey: formatKeys.list(),
    queryFn: ({ signal }) => fetchFormats(signal),
    // Formats change only when the server restarts with other plugins.
    staleTime: 5 * 60 * 1000,
  })
}

/** One repository's detail (`GET /admin/repositories/{name}`). */
export function useRepository(name: string) {
  return useQuery<RepoView, ApiError>({
    queryKey: repoKeys.detail(name),
    queryFn: ({ signal }) => fetchRepository(name, signal),
  })
}

/** Create a repository; invalidates the list and Browse on success. */
export function useCreateRepository() {
  const queryClient = useQueryClient()
  return useMutation<RepoView, ApiError, CreateRepo>({
    mutationFn: (body) => createRepository(body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.list() })
      invalidateBrowse(queryClient)
    },
  })
}

/**
 * Update a repository; invalidates the list, that repo's detail and Browse on
 * success.
 */
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
      invalidateBrowse(queryClient)
    },
  })
}

/** Delete a repository; invalidates the list and Browse on success. */
export function useDeleteRepository() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, string>({
    mutationFn: (name) => deleteRepository(name),
    onSuccess: (_void, name) => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.list() })
      void queryClient.removeQueries({ queryKey: repoKeys.detail(name) })
      invalidateBrowse(queryClient)
    },
  })
}

/**
 * Invalidate a proxy's cache. Nothing to re-fetch: the repository's view does
 * not change.
 */
export function useInvalidateProxyCache(name: string) {
  return useMutation<ProxyCacheInvalidated, ApiError, InvalidateProxyCache>({
    mutationFn: (body) => invalidateProxyCache(name, body),
  })
}

/** A group's ordered members (`GET /admin/repositories/{name}/members`). */
export function useMembers(name: string) {
  return useQuery<MemberView[], ApiError>({
    queryKey: repoKeys.members(name),
    queryFn: ({ signal }) => fetchMembers(name, signal),
  })
}

/**
 * Add a member to a group; invalidates that group's member list and Browse on
 * success.
 */
export function useAddMember(name: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, AddMember>({
    mutationFn: (body) => addMember(name, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.members(name) })
      invalidateBrowse(queryClient)
    },
  })
}

/** Remove a member from a group; invalidates its member list and Browse. */
export function useRemoveMember(name: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, string>({
    mutationFn: (member) => removeMember(name, member),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.members(name) })
      invalidateBrowse(queryClient)
    },
  })
}

/**
 * Flag or unflag a member as owner (which decides what the group serves);
 * invalidates that group's member list and Browse.
 */
export function useUpdateMember(name: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, { member: string; owner: boolean }>({
    mutationFn: ({ member, owner }) => updateMember(name, member, { owner }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: repoKeys.members(name) })
      invalidateBrowse(queryClient)
    },
  })
}

export function useTrustedPublishers(name: string) {
  return useQuery<TrustedPublisherView[], ApiError>({
    queryKey: repoKeys.trustedPublishers(name),
    queryFn: ({ signal }) => fetchTrustedPublishers(name, signal),
  })
}

function useTrustedPublisherMutation<TVariables>(
  name: string,
  mutationFn: (variables: TVariables) => Promise<unknown>,
) {
  const queryClient = useQueryClient()
  return useMutation<unknown, ApiError, TVariables>({
    mutationFn,
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: repoKeys.trustedPublishers(name),
      })
    },
  })
}

export function useCreateTrustedPublisher(name: string) {
  return useTrustedPublisherMutation(name, (body: TrustedPublisherBody) =>
    createTrustedPublisher(name, body),
  )
}

export function useUpdateTrustedPublisher(name: string) {
  return useTrustedPublisherMutation(
    name,
    ({ id, body }: { id: number; body: TrustedPublisherBody }) =>
      updateTrustedPublisher(name, id, body),
  )
}

export function useDeleteTrustedPublisher(name: string) {
  return useTrustedPublisherMutation(name, (id: number) =>
    deleteTrustedPublisher(name, id),
  )
}
