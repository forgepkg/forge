import { useQuery } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import { fetchImageDetail, imageKeys, type ImageDetail } from '~/api/images'

/**
 * Image detail (`GET /browse/images/{repo}/{image…}`): the image's tags and
 * manifests plus its `docker pull` name. A 404 (image not found / nothing
 * visible) surfaces as an `ApiError(404)` the route renders as a not-found
 * state.
 */
export function useImageDetail(repo: string, image: string) {
  return useQuery<ImageDetail, ApiError>({
    queryKey: imageKeys.detail(repo, image),
    queryFn: ({ signal }) => fetchImageDetail(repo, image, signal),
    enabled: image !== '',
  })
}
