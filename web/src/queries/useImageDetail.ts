import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  deleteImage,
  fetchImageDeletePreview,
  fetchImageDetail,
  imageKeys,
  type ImageDeleted,
  type ImageDeletePreview,
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
 * What deleting the manifest `digest` would remove (the confirmation's
 * wording): asked afresh each time a confirmation opens, never from a cache,
 * and not at all without a digest.
 */
export function useImageDeletePreview(repo: string, image: string, digest: string | undefined) {
  return useQuery<ImageDeletePreview, ApiError>({
    queryKey: imageKeys.deletePreview(repo, image, digest ?? ''),
    queryFn: ({ signal }) => fetchImageDeletePreview(repo, image, digest ?? '', signal),
    enabled: digest !== undefined,
    staleTime: 0,
    gcTime: 0,
    retry: false,
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
