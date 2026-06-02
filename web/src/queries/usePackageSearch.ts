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
 * while the next loads (no flicker, plan §7). Auth failures are not retried
 * (the shared query-client policy); browse itself works anonymously, so a 401
 * here only happens when a stale token is attached.
 */
export function usePackageSearch(params: SearchParams) {
  return useQuery<BrowseResult, ApiError>({
    queryKey: pkgKeys.search(params),
    queryFn: ({ signal }) => fetchPackages(params, signal),
    placeholderData: keepPreviousData,
  })
}
