import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  deleteImage,
  fetchImageDetail,
  imageKeys,
  type ImageDeleted,
  type ImageDetail,
} from '~/api/images'

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

/**
 * Delete a tag or a manifest (the reference) of a hosted repository's image,
 * or (no reference) the whole image; refreshes every image query after.
 */
export function useDeleteImage(repo: string, image: string) {
  const queryClient = useQueryClient()
  return useMutation<ImageDeleted, ApiError, string | undefined>({
    mutationFn: (reference) => deleteImage(repo, image, reference),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: imageKeys.all() })
    },
  })
}
