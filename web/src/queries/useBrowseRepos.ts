import { useQuery } from '@tanstack/react-query'

import { browseReposQueryOptions } from '~/api/packages'

/**
 * The repositories the signed-in user may browse (`GET /browse/repos`) — the
 * root of the folder view, each with its kind and format. Requires a session;
 * the `_app` login gate runs before any consumer renders.
 */
export function useBrowseRepos() {
  return useQuery(browseReposQueryOptions)
}
