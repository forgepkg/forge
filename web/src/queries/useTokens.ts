import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  createMyToken,
  createToken,
  fetchMyTokens,
  fetchTokens,
  revokeMyToken,
  revokeToken,
  tokenKeys,
  type CreatedToken,
  type CreateToken,
  type TokenView,
} from '~/api/tokens'

/**
 * TanStack Query hooks for the per-user token resource. The create mutation
 * returns the one-time plaintext `CreatedToken`; the caller renders it via
 * `ShowOnceSecret` and it is **never** written into a query cache (the list
 * cache holds only `TokenView` metadata). Mutations invalidate that user's
 * token list so the new/revoked token's metadata is re-fetched.
 */

/** List a user's tokens (`GET /admin/users/{id}/tokens`). */
export function useTokens(userId: number) {
  return useQuery<TokenView[], ApiError>({
    queryKey: tokenKeys.list(userId),
    queryFn: ({ signal }) => fetchTokens(userId, signal),
  })
}

/** Issue a token for a user; invalidates that user's token list on success. */
export function useCreateToken(userId: number) {
  const queryClient = useQueryClient()
  return useMutation<CreatedToken, ApiError, CreateToken>({
    mutationFn: (body) => createToken(userId, body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: tokenKeys.list(userId) })
    },
  })
}

/** Revoke a token; invalidates the owning user's token list on success. */
export function useRevokeToken(userId: number) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => revokeToken(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: tokenKeys.list(userId) })
    },
  })
}

/** List the signed-in user's own tokens (`GET /admin/me/tokens`). */
export function useMyTokens() {
  return useQuery<TokenView[], ApiError>({
    queryKey: tokenKeys.mine(),
    queryFn: ({ signal }) => fetchMyTokens(signal),
  })
}

/** Issue a token for the signed-in user; invalidates the own-token list. */
export function useCreateMyToken() {
  const queryClient = useQueryClient()
  return useMutation<CreatedToken, ApiError, CreateToken>({
    mutationFn: (body) => createMyToken(body),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: tokenKeys.mine() })
    },
  })
}

/** Revoke one of the signed-in user's tokens; invalidates the own-token list. */
export function useRevokeMyToken() {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, number>({
    mutationFn: (id) => revokeMyToken(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: tokenKeys.mine() })
    },
  })
}
