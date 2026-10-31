import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchAddresses,
  fetchBlobCache,
  fetchCryptoKeys,
  rotateKeys,
  systemKeys,
  type BlobCacheStats,
  type CryptoKeys,
  type RotationLayer,
  type RotationResult,
  type ServerAddresses,
} from '~/api/system'

/** The secret encryption's key metadata (`GET /admin/crypto/keys`). */
export function useCryptoKeys() {
  return useQuery<CryptoKeys, ApiError>({
    queryKey: systemKeys.cryptoKeys(),
    queryFn: ({ signal }) => fetchCryptoKeys(signal),
  })
}

/** Rotate one key layer; the key list is read again afterwards, whatever the outcome. */
export function useRotateKeys() {
  const queryClient = useQueryClient()
  return useMutation<RotationResult, ApiError, RotationLayer>({
    mutationFn: (layer) => rotateKeys(layer),
    onSettled: () => queryClient.invalidateQueries({ queryKey: systemKeys.cryptoKeys() }),
  })
}

/** The answering instance's local blob cache (`GET /admin/blob-cache`). */
export function useBlobCache() {
  return useQuery<BlobCacheStats, ApiError>({
    queryKey: systemKeys.blobCache(),
    queryFn: ({ signal }) => fetchBlobCache(signal),
  })
}

/** The public and alias base URLs (`GET /admin/addresses`); they change only with a restart. */
export function useAddresses() {
  return useQuery<ServerAddresses, ApiError>({
    queryKey: systemKeys.addresses(),
    queryFn: ({ signal }) => fetchAddresses(signal),
    staleTime: Infinity,
  })
}
