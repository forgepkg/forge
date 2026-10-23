import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchAuthSettings,
  settingsKeys,
  updateAuthSettings,
  type AuthSettings,
  type AuthSettingsUpdate,
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
