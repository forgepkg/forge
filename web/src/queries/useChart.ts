import { useQuery } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import { fetchChart, imageKeys, type ChartDetail } from '~/api/images'

/**
 * A Helm chart of an image (`GET /browse/chart`): the `Chart.yaml` metadata,
 * README and default values of the manifest `digest`. Disabled until a
 * digest is known.
 */
export function useChart(repo: string, image: string, digest: string | undefined) {
  return useQuery<ChartDetail, ApiError>({
    queryKey: imageKeys.chart(repo, image, digest ?? ''),
    queryFn: ({ signal }) => fetchChart(repo, image, digest ?? '', signal),
    enabled: !!digest,
  })
}
