import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  cancelImport,
  createImport,
  deleteImport,
  fetchImportItems,
  fetchImports,
  importKeys,
  isActive,
  resumeImport,
  type CreateImport,
  type ImportItem,
  type ImportView,
  type ItemState,
  type ResumeImport,
} from '~/api/imports'

/** How often a repository's imports are re-read while one is active. */
const ACTIVE_REFRESH_MS = 2000

/**
 * A repository's imports, newest first. Re-read every two seconds while one
 * is queued or running, so its progress moves on screen.
 */
export function useImports(repo: string) {
  return useQuery<ImportView[], ApiError>({
    queryKey: importKeys.all(repo),
    queryFn: ({ signal }) => fetchImports(repo, signal),
    refetchInterval: (query) =>
      (query.state.data ?? []).some(isActive) ? ACTIVE_REFRESH_MS : false,
  })
}

/** An import's items, optionally of one state. */
export function useImportItems(
  repo: string,
  id: number,
  state: ItemState | undefined,
  enabled: boolean,
) {
  return useQuery<ImportItem[], ApiError>({
    queryKey: importKeys.items(repo, id, state ?? 'all'),
    queryFn: ({ signal }) => fetchImportItems(repo, id, state, signal),
    enabled,
  })
}

/** After any change, read the repository's imports (and items) again. */
function useRefresh(repo: string) {
  const queryClient = useQueryClient()
  return () => {
    void queryClient.invalidateQueries({ queryKey: importKeys.all(repo) })
  }
}

export function useCreateImport(repo: string) {
  const refresh = useRefresh(repo)
  return useMutation<ImportView, ApiError, CreateImport>({
    mutationFn: (body) => createImport(repo, body),
    onSuccess: refresh,
  })
}

export function useCancelImport(repo: string) {
  const refresh = useRefresh(repo)
  return useMutation<ImportView, ApiError, number>({
    mutationFn: (id) => cancelImport(repo, id),
    onSuccess: refresh,
  })
}

export function useResumeImport(repo: string) {
  const refresh = useRefresh(repo)
  return useMutation<ImportView, ApiError, { id: number; body: ResumeImport }>(
    {
      mutationFn: ({ id, body }) => resumeImport(repo, id, body),
      onSuccess: refresh,
    },
  )
}

export function useDeleteImport(repo: string) {
  const refresh = useRefresh(repo)
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => deleteImport(repo, id),
    onSuccess: refresh,
  })
}
