import { keepPreviousData, useQuery } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchImages,
  imageKeys,
  type ImageSearchParams,
  type ImagesResult,
} from '~/api/images'

/**
 * One docker repository's images (`GET /browse/images?repo=…`), with the
 * registry host and pull prefix for the connect snippets.
 *
 * Uses `keepPreviousData` like `usePackageSearch`, so paging / typing keeps
 * the previous page visible while the next loads. Auth failures are not
 * retried (the shared query-client policy).
 */
export function useImageSearch(params: ImageSearchParams) {
  return useQuery<ImagesResult, ApiError>({
    queryKey: imageKeys.search(params),
    queryFn: ({ signal }) => fetchImages(params, signal),
    placeholderData: keepPreviousData,
  })
}
