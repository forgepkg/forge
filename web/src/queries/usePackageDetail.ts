import { useQuery } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchPackageDetail,
  pkgKeys,
  type PackageDetail,
} from '~/api/packages'

/**
 * Package detail (`GET /browse/packages/{repo}/{id}`): visible versions with
 * per-version metadata + dependency groups. A 404 (package not found) surfaces
 * as an `ApiError(404)` the route renders as an empty/not-found state.
 */
export function usePackageDetail(repo: string, id: string) {
  return useQuery<PackageDetail, ApiError>({
    queryKey: pkgKeys.detail(repo, id),
    queryFn: ({ signal }) => fetchPackageDetail(repo, id, signal),
  })
}
