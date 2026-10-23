import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  deleteRetention,
  fetchRetention,
  fetchRetentionAudit,
  previewRetention,
  retentionKeys,
  runRetention,
  saveRetention,
  type AuditQuery,
  type AuditRecord,
  type PreviewView,
  type RetentionPolicy,
  type RetentionView,
} from '~/api/retention'

/** How often the policy's run state is re-read while a run is awaited. */
const RUN_REFRESH_MS = 3000

/**
 * A repository's retention policy and run ledger. Re-read every few seconds
 * while a run is running, or while `poll` says so of the last answer (a run
 * was asked for and the ledger does not show it finished yet).
 */
export function useRetention(
  repo: string,
  poll?: (view: RetentionView | undefined) => boolean,
) {
  return useQuery<RetentionView, ApiError>({
    queryKey: retentionKeys.view(repo),
    queryFn: ({ signal }) => fetchRetention(repo, signal),
    refetchInterval: (query) =>
      query.state.data?.last_run?.state === 'running' || poll?.(query.state.data)
        ? RUN_REFRESH_MS
        : false,
  })
}

/** A page of the audit log; the previous page stays on screen while paging. */
export function useRetentionAudit(repo: string, q: AuditQuery) {
  return useQuery<{ items: AuditRecord[] }, ApiError>({
    queryKey: retentionKeys.audit(repo, q),
    queryFn: ({ signal }) => fetchRetentionAudit(repo, q, signal),
    placeholderData: keepPreviousData,
  })
}

/** Store a policy; the stored (canonical) policy comes back. */
export function useSaveRetention(repo: string) {
  const queryClient = useQueryClient()
  return useMutation<RetentionView, ApiError, RetentionPolicy>({
    mutationFn: (policy) => saveRetention(repo, policy),
    onSuccess: (view) => {
      queryClient.setQueryData(retentionKeys.view(repo), view)
    },
  })
}

/** Remove the policy; the run ledger stays (the server keeps it). */
export function useDeleteRetention(repo: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, void>({
    mutationFn: () => deleteRetention(repo),
    onSuccess: () => {
      queryClient.setQueryData<RetentionView>(retentionKeys.view(repo), (old) =>
        old ? { ...old, policy: null } : old,
      )
      void queryClient.invalidateQueries({ queryKey: retentionKeys.view(repo) })
    },
  })
}

/** Dry-run a draft policy (or, without one, the stored policy). */
export function usePreviewRetention(repo: string) {
  return useMutation<PreviewView, ApiError, RetentionPolicy | undefined>({
    mutationFn: (policy) => previewRetention(repo, policy),
  })
}

export function useRunRetention(repo: string) {
  const queryClient = useQueryClient()
  return useMutation<{ scheduled: boolean }, ApiError, void>({
    mutationFn: () => runRetention(repo),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: retentionKeys.view(repo) })
    },
  })
}
