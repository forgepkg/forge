import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  fetchTrafficClient,
  fetchTrafficOverview,
  fetchTrafficSettings,
  trafficKeys,
  updateTrafficSettings,
  type TrafficClientDetail,
  type TrafficOverview,
  type TrafficQuery,
  type TrafficSettings,
  type TrafficSettingsUpdate,
} from '~/api/traffic'

/** How often an open traffic view is read again: the files change every minute. */
const REFRESH_MS = 60_000

/**
 * The traffic of a range (`GET /admin/traffic`). While another range or
 * instance loads, the previous answer stays on screen.
 */
export function useTrafficOverview(q: TrafficQuery) {
  return useQuery<TrafficOverview, ApiError>({
    queryKey: trafficKeys.overview(q),
    queryFn: ({ signal }) => fetchTrafficOverview(q, signal),
    placeholderData: keepPreviousData,
    refetchInterval: REFRESH_MS,
  })
}

/** One client network's traffic and request log (`GET /admin/traffic/client`). */
export function useTrafficClient(network: string, q: TrafficQuery) {
  return useQuery<TrafficClientDetail, ApiError>({
    queryKey: trafficKeys.client(network, q),
    queryFn: ({ signal }) => fetchTrafficClient(network, q, signal),
    placeholderData: keepPreviousData,
    refetchInterval: REFRESH_MS,
    enabled: network.length > 0,
  })
}

/** What is recorded and how long it is kept (`GET /admin/settings/traffic`). */
export function useTrafficSettings() {
  return useQuery<TrafficSettings, ApiError>({
    queryKey: trafficKeys.settings(),
    queryFn: ({ signal }) => fetchTrafficSettings(signal),
  })
}

/**
 * Change the traffic settings; the answer replaces the cached ones, and the
 * traffic views (which say what is recorded) are read again.
 */
export function useUpdateTrafficSettings() {
  const queryClient = useQueryClient()
  return useMutation<TrafficSettings, ApiError, TrafficSettingsUpdate>({
    mutationFn: (body) => updateTrafficSettings(body),
    onSuccess: (saved) => {
      queryClient.setQueryData(trafficKeys.settings(), saved)
      void queryClient.invalidateQueries({ queryKey: trafficKeys.all })
    },
  })
}
