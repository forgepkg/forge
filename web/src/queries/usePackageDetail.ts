import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchPackageDetail,
  deletePackageVersion,
  pkgKeys,
  refreshPackage,
  type PackageDetail,
} from '~/api/packages'

/** How often a page whose refresh runs in the background looks again. */
export const REFRESH_POLL_MS = 2000

/**
 * Package detail (`GET /browse/packages/{repo}/{id}`): visible versions with
 * per-version metadata + dependency groups. A 404 (package not found) surfaces
 * as an `ApiError(404)` the route renders as an empty/not-found state. While
 * the server refreshes the package from its upstream in the background
 * (`refreshing`), it is asked again every {@link REFRESH_POLL_MS}.
 */
export function usePackageDetail(repo: string, id: string) {
  return useQuery<PackageDetail, ApiError>({
    queryKey: pkgKeys.detail(repo, id),
    queryFn: ({ signal }) => fetchPackageDetail(repo, id, signal),
    refetchInterval: (query) => (query.state.data?.refreshing ? REFRESH_POLL_MS : false),
  })
}

/**
 * **Refresh from upstream** (`POST /browse/packages/{repo}/{id}/refresh`):
 * the refreshed detail replaces the page's, and the repository's package
 * list is read again, which may now have the package.
 */
export function useRefreshPackage(repo: string, id: string) {
  const queryClient = useQueryClient()
  return useMutation<PackageDetail, ApiError, void>({
    mutationFn: () => refreshPackage(repo, id),
    onSuccess: (detail) => {
      queryClient.setQueryData(pkgKeys.detail(repo, id), detail)
      void queryClient.invalidateQueries({ queryKey: [...pkgKeys.all(), 'search'] })
    },
  })
}

export function useDeletePackageVersion(repo: string, id: string) {
  const queryClient = useQueryClient()
  return useMutation<void, ApiError, string>({
    mutationFn: (version) => deletePackageVersion(repo, id, version),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: pkgKeys.all() })
    },
  })
}
