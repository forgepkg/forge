import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchAuthSettings,
  fetchRetentionSettings,
  settingsKeys,
  updateAuthSettings,
  updateRetentionSettings,
  type AuthSettings,
  type AuthSettingsUpdate,
  type RetentionSettings,
  type RetentionSettingsUpdate,
} from '~/api/settings'

/** The sign-in and anonymous-access settings (`GET /admin/settings/auth`). */
export function useAuthSettings() {
  return useQuery<AuthSettings, ApiError>({
    queryKey: settingsKeys.auth(),
    queryFn: ({ signal }) => fetchAuthSettings(signal),
  })
}

/** Change the settings; the answer replaces the cached ones. */
export function useUpdateAuthSettings() {
  const queryClient = useQueryClient()
  return useMutation<AuthSettings, ApiError, AuthSettingsUpdate>({
    mutationFn: (body) => updateAuthSettings(body),
    onSuccess: (saved) => {
      queryClient.setQueryData(settingsKeys.auth(), saved)
    },
  })
}

/** Whether retention runs, and how long its audit log is kept. */
export function useRetentionSettings() {
  return useQuery<RetentionSettings, ApiError>({
    queryKey: settingsKeys.retention(),
    queryFn: ({ signal }) => fetchRetentionSettings(signal),
  })
}

/**
 * Change the retention settings; the answer replaces the cached ones, and the
 * repositories' retention views (which say whether runs are on) are re-read.
 */
export function useUpdateRetentionSettings() {
  const queryClient = useQueryClient()
  return useMutation<RetentionSettings, ApiError, RetentionSettingsUpdate>({
    mutationFn: (body) => updateRetentionSettings(body),
    onSuccess: (saved) => {
      queryClient.setQueryData(settingsKeys.retention(), saved)
      void queryClient.invalidateQueries({ queryKey: ['retention'] })
    },
  })
}
