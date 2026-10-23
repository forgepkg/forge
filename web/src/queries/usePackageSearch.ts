import { keepPreviousData, useQuery } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchPackages,
  pkgKeys,
  type BrowseResult,
  type SearchParams,
} from '~/api/packages'

/**
 * Cross-repository package search (`GET /browse/packages`).
 *
 * Uses `keepPreviousData` so paging / typing keeps the previous page visible
 * while the next loads (no flicker). Auth failures are not retried (the shared
 * query-client policy); browsing requires a signed-in user, so a 401 here means
 * the session has ended.
 */
export function usePackageSearch(params: SearchParams) {
  return useQuery<BrowseResult, ApiError>({
    queryKey: pkgKeys.search(params),
    queryFn: ({ signal }) => fetchPackages(params, signal),
    placeholderData: keepPreviousData,
  })
}
