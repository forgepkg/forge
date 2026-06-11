import { useQuery } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import { fetchBrowseRepos, pkgKeys, type BrowseRepo } from '~/api/packages'

/**
 * The repositories the signed-in user may browse (`GET /browse/repos`) — the
 * root of the folder view. Requires a session; the `_app` login gate runs
 * before any consumer renders.
 */
export function useBrowseRepos() {
  return useQuery<BrowseRepo[], ApiError>({
    queryKey: pkgKeys.repos(),
    queryFn: ({ signal }) => fetchBrowseRepos(signal),
  })
}
