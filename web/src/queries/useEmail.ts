import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  authorizeEmailOauthClientCredentials,
  deleteEmailSettings,
  emailKeys,
  fetchEmailSettings,
  forgetEmailOauthClient,
  putEmailSettings,
  registerEmailOauthClient,
  sendTestEmail,
  startEmailOauthCodeFlow,
  startEmailOauthDeviceFlow,
  type DeviceAuthorization,
  type EmailSettings,
  type EmailSettingsInput,
  type EmailSettingsView,
  type EmailSettingsWithWarning,
  type RegistrationAuth,
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
  return useMutation<EmailSettingsWithWarning, ApiError, EmailSettingsInput>({
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

/** Register Forge with the authorization server (`POST /oauth/register`). */
export function useRegisterEmailOauthClient() {
  const queryClient = useQueryClient()
  return useMutation<EmailSettingsWithWarning, ApiError, RegistrationAuth>({
    mutationFn: (auth) => registerEmailOauthClient(auth),
    onSuccess: (view) => {
      queryClient.setQueryData(emailKeys.settings(), view)
    },
  })
}

/** Forget the OAuth client and its authorization (`DELETE /oauth/client`). */
export function useForgetEmailOauthClient() {
  const queryClient = useQueryClient()
  return useMutation<EmailSettingsWithWarning, ApiError, void>({
    mutationFn: () => forgetEmailOauthClient(),
    onSuccess: (view) => {
      queryClient.setQueryData(emailKeys.settings(), view)
    },
  })
}

/** Start the code flow: the authorization URL to send the browser to. */
export function useStartEmailOauthCodeFlow() {
  return useMutation<{ authorization_url: string }, ApiError, void>({
    mutationFn: () => startEmailOauthCodeFlow(),
  })
}

/** Start a device authorization. */
export function useStartEmailOauthDeviceFlow() {
  return useMutation<DeviceAuthorization, ApiError, void>({
    mutationFn: () => startEmailOauthDeviceFlow(),
  })
}

/** Use the client credentials grant: no mailbox authorizes Forge. */
export function useEmailOauthClientCredentials() {
  const queryClient = useQueryClient()
  return useMutation<{ settings: EmailSettingsView }, ApiError, void>({
    mutationFn: () => authorizeEmailOauthClientCredentials(),
    onSuccess: ({ settings }) => {
      queryClient.setQueryData(emailKeys.settings(), settings)
    },
  })
}
