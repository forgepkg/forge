import { httpClient } from '~/lib/httpClient'

/**
 * Admin traffic API: the traffic statistics every instance writes to the
 * object store (`crates/server/src/admin/traffic.rs`, `crates/traffic`).
 *
 *  - `GET /admin/traffic` answers the requests of a range of days over every
 *    instance (or the one `instance` names), by day, repository, country,
 *    autonomous system and client network, narrowed by the filters given.
 *  - `GET` / `PUT /admin/settings/traffic`: what is recorded and how long it
 *    is kept; `PUT` changes the fields it names.
 *  - `/admin/traffic/geoip`: the geolocation databases and the MaxMind
 *    download (`PUT` the account, `DELETE` it and the databases, `POST
 *    …/update` to download now).
 */

/** The ranges the screen offers, in days up to today. */
export type TrafficRange = 'today' | '7d' | '30d' | '90d' | '365d'

export const TRAFFIC_RANGES: { id: TrafficRange; label: string }[] = [
  { id: 'today', label: 'Today' },
  { id: '7d', label: '7 days' },
  { id: '30d', label: '30 days' },
  { id: '90d', label: '90 days' },
  { id: '365d', label: '1 year' },
]

export function isTrafficRange(value: unknown): value is TrafficRange {
  return TRAFFIC_RANGES.some((r) => r.id === value)
}

/** What a filter value says for "none": no repository, no known country. */
export const NONE = '-'

/** An instance whose files the range holds. */
export interface TrafficInstance {
  id: string
  host: string
  started_at: string | null
}

/** A day of the range. */
export interface TrafficDay {
  /** `YYYY-MM-DD`, UTC. */
  day: string
  requests: number
  bytes: number
  /** The client networks that made requests that day. */
  clients: number
}

/** A share of the range. */
export interface TrafficShare {
  requests: number
  bytes: number
  clients: number
}

/** A client network's requests. */
export interface TrafficClient {
  network: string
  address: string
  /** ISO 3166-1 alpha-2; `""` unknown. */
  country: string
  /** `0` unknown. */
  asn: number
  as_org: string
  requests: number
  bytes: number
  /** The repositories it made the most requests to (`""`: none). */
  repositories: string[]
  days: number
  first_day: string | null
  last_day: string | null
}

/** `GET /admin/traffic`. */
export interface TrafficOverview {
  from: string
  to: string
  instances: TrafficInstance[]
  totals: {
    requests: number
    bytes: number
    clients: number
    countries: number
    asns: number
  }
  days: TrafficDay[]
  /** `""` names the requests that addressed no repository. */
  repositories: ({ name: string } & TrafficShare)[]
  countries: ({ country: string } & TrafficShare)[]
  asns: ({ asn: number; org: string } & TrafficShare)[]
  clients: TrafficClient[]
  recording: {
    enabled: boolean
    client_addresses: boolean
    /** Whether a country database is loaded. */
    countries: boolean
    /** Whether an autonomous system database is loaded. */
    asns: boolean
  }
}

/** `GET /admin/settings/traffic`. */
export interface TrafficSettings {
  enabled: boolean
  client_addresses: boolean
  retention_days: number
}

/** `PUT /admin/settings/traffic` body: the fields to change. */
export type TrafficSettingsUpdate = Partial<TrafficSettings>

/** A loaded geolocation database. */
export interface GeoDatabase {
  database_type: string
  built_at: string | null
  size: number
}

/** `GET /admin/traffic/geoip`. */
export interface GeoipStatus {
  country: GeoDatabase | null
  asn: GeoDatabase | null
  maxmind: {
    account_id: string | null
    license_key_set: boolean
    last_attempt: string | null
    last_success: string | null
    last_error: string | null
    url: string
    editions: string[]
  }
}

/** What the screen asks for: a range and the filters. */
export interface TrafficQuery {
  range: TrafficRange
  instance?: string
  repository?: string
  network?: string
  country?: string
  asn?: string
}

export const trafficKeys = {
  all: ['traffic'] as const,
  overview: (q: TrafficQuery) => ['traffic', 'overview', q] as const,
  settings: () => ['settings', 'traffic'] as const,
  geoip: () => ['traffic', 'geoip'] as const,
}

/** `GET /admin/traffic`. */
export function fetchTrafficOverview(
  q: TrafficQuery,
  signal?: AbortSignal,
): Promise<TrafficOverview> {
  return httpClient.get<TrafficOverview>('/admin/traffic', {
    signal,
    query: {
      range: q.range,
      instance: q.instance,
      repository: q.repository,
      network: q.network,
      country: q.country,
      asn: q.asn,
    },
  })
}

/** `GET /admin/settings/traffic`. */
export function fetchTrafficSettings(signal?: AbortSignal): Promise<TrafficSettings> {
  return httpClient.get<TrafficSettings>('/admin/settings/traffic', { signal })
}

/** `PUT /admin/settings/traffic`. */
export function updateTrafficSettings(body: TrafficSettingsUpdate): Promise<TrafficSettings> {
  return httpClient.put<TrafficSettings>('/admin/settings/traffic', body)
}

/** `GET /admin/traffic/geoip`. */
export function fetchGeoip(signal?: AbortSignal): Promise<GeoipStatus> {
  return httpClient.get<GeoipStatus>('/admin/traffic/geoip', { signal })
}

/** `PUT /admin/traffic/geoip`: the license key left out keeps the stored one. */
export function updateGeoip(body: {
  account_id: string
  license_key?: string
}): Promise<GeoipStatus> {
  return httpClient.put<GeoipStatus>('/admin/traffic/geoip', body)
}

/** `POST /admin/traffic/geoip/update`. */
export function downloadGeoip(): Promise<GeoipStatus> {
  return httpClient.post<GeoipStatus>('/admin/traffic/geoip/update')
}

/** `DELETE /admin/traffic/geoip`. */
export function removeGeoip(): Promise<void> {
  return httpClient.delete<void>('/admin/traffic/geoip')
}
