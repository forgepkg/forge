import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { ApiError } from '~/lib/httpClient'
import {
  downloadGeoip,
  fetchGeoip,
  fetchTrafficOverview,
  fetchTrafficSettings,
  removeGeoip,
  trafficKeys,
  updateGeoip,
  updateTrafficSettings,
  type GeoipStatus,
  type TrafficOverview,
  type TrafficQuery,
  type TrafficSettings,
  type TrafficSettingsUpdate,
} from '~/api/traffic'

/** How often an open traffic view is read again: today's files change every minute. */
const REFRESH_MS = 60_000

/**
 * The requests of a range (`GET /admin/traffic`). While another range or
 * filter loads, the previous answer stays on screen.
 */
export function useTrafficOverview(q: TrafficQuery) {
  return useQuery<TrafficOverview, ApiError>({
    queryKey: trafficKeys.overview(q),
    queryFn: ({ signal }) => fetchTrafficOverview(q, signal),
    placeholderData: keepPreviousData,
    refetchInterval: REFRESH_MS,
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

/** The geolocation databases and the MaxMind download (`GET /admin/traffic/geoip`). */
export function useGeoip() {
  return useQuery<GeoipStatus, ApiError>({
    queryKey: trafficKeys.geoip(),
    queryFn: ({ signal }) => fetchGeoip(signal),
  })
}

/** Answers that replace the geolocation status, and make the traffic views be read again. */
function useGeoipMutation<V>(fn: (v: V) => Promise<GeoipStatus | void>) {
  const queryClient = useQueryClient()
  return useMutation<GeoipStatus | void, ApiError, V>({
    mutationFn: fn,
    onSuccess: (status) => {
      if (status) queryClient.setQueryData(trafficKeys.geoip(), status)
      void queryClient.invalidateQueries({ queryKey: trafficKeys.all })
    },
  })
}

/** Set the MaxMind account ID and license key. */
export function useUpdateGeoip() {
  return useGeoipMutation((body: { account_id: string; license_key?: string }) =>
    updateGeoip(body),
  )
}

/** Download the databases now. */
export function useDownloadGeoip() {
  return useGeoipMutation((_: void) => downloadGeoip())
}

/** Forget the MaxMind account and delete the databases. */
export function useRemoveGeoip() {
  return useGeoipMutation((_: void) => removeGeoip())
}
