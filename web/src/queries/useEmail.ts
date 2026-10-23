import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  deleteEmailSettings,
  emailKeys,
  fetchEmailSettings,
  putEmailSettings,
  sendTestEmail,
  type EmailSettings,
  type EmailSettingsInput,
  type EmailSettingsView,
  type TestEmailResult,
} from '~/api/email'

/**
 * TanStack Query hooks for the email-service settings. Every mutation
 * refetches the settings: a send records its outcome there, and a save
 * clears it.
 */

/** The stored settings (`GET /admin/settings/email`). */
export function useEmailSettings() {
  return useQuery<EmailSettings, ApiError>({
    queryKey: emailKeys.settings(),
    queryFn: ({ signal }) => fetchEmailSettings(signal),
  })
}

/** Store the settings (`PUT`). */
export function useSaveEmailSettings() {
  const queryClient = useQueryClient()
  return useMutation<EmailSettingsView, ApiError, EmailSettingsInput>({
    mutationFn: (body) => putEmailSettings(body),
    onSuccess: (view) => {
      queryClient.setQueryData(emailKeys.settings(), view)
    },
  })
}

/** Remove the settings (`DELETE`). */
export function useDeleteEmailSettings() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, void>({
    mutationFn: () => deleteEmailSettings(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: emailKeys.settings() })
    },
  })
}

/** Send a test message (`POST /test`), to `to` or the calling admin. */
export function useSendTestEmail() {
  const queryClient = useQueryClient()
  return useMutation<TestEmailResult, ApiError, string | undefined>({
    mutationFn: (to) => sendTestEmail(to),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: emailKeys.settings() })
    },
  })
}
