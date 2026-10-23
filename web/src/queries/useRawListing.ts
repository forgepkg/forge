import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'

import { ApiError } from '~/lib/httpClient'
import {
  deleteRawDirectory,
  deleteRawFile,
  fetchRawListing,
  rawKeys,
  uploadRawFiles,
  type RawListing,
} from '~/api/raw'

/**
 * A page of a raw repository's directory (`GET /raw/<repo>/<path>`). Keeps
 * the previous page visible while the next loads, like the package search.
 * A directory that does not exist (404) is an answer, not retried.
 */
export function useRawListing(repo: string, path: string, after?: string) {
  return useQuery<RawListing, ApiError>({
    queryKey: rawKeys.listing(repo, path, after),
    queryFn: ({ signal }) => fetchRawListing(repo, path, after, signal),
    placeholderData: keepPreviousData,
    retry: (failureCount, error) =>
      !(error instanceof ApiError && [401, 403, 404].includes(error.status)) &&
      failureCount < 2,
  })
}

/** Upload files into a directory; every listing of the repository refetches. */
export function useRawUpload(repo: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ directory, files }: { directory: string; files: File[] }) =>
      uploadRawFiles(repo, directory, files),
    onSettled: () => queryClient.invalidateQueries({ queryKey: rawKeys.repo(repo) }),
  })
}

/** Delete a file, or (admins) a directory with everything below it. */
export function useRawDelete(repo: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (path: string) => {
      if (path.endsWith('/')) {
        await deleteRawDirectory(repo, path)
      } else {
        await deleteRawFile(repo, path)
      }
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: rawKeys.repo(repo) }),
  })
}
