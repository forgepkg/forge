import { httpClient } from '~/lib/httpClient'

/**
 * Admin traffic API: the traffic statistics every instance writes to the
 * object store (`crates/server/src/admin/traffic.rs`, `crates/traffic`).
 *
 *  - `GET /admin/traffic` answers the traffic of a range over every instance
 *    (or the one `instance` names): counts by time bucket, surface,
 *    repository and status, latency, and the top 20 client networks.
 *  - `GET /admin/traffic/client` answers one client network's counts and
 *    its requests in the request log (the last 24 hours of the range at
 *    most, the newest 500).
 *  - `GET` / `PUT /admin/settings/traffic`: what is recorded and how long
 *    it is kept; `PUT` changes the fields it names.
 */

/** The ranges the views offer. */
export type TrafficRange = '1h' | '6h' | '24h' | '7d' | '30d' | '90d'

export const TRAFFIC_RANGES: { id: TrafficRange; label: string }[] = [
  { id: '1h', label: '1 hour' },
  { id: '6h', label: '6 hours' },
  { id: '24h', label: '24 hours' },
  { id: '7d', label: '7 days' },
  { id: '30d', label: '30 days' },
  { id: '90d', label: '90 days' },
]

export function isTrafficRange(value: unknown): value is TrafficRange {
  return TRAFFIC_RANGES.some((r) => r.id === value)
}

/** An instance whose files the range holds. */
export interface TrafficInstance {
  id: string
  host: string
  started_at: string | null
}

/** A point of a series: the counts of one step. */
export interface TrafficPoint {
  start: string
  requests: number
  bytes: number
  client_errors: number
  server_errors: number
}

/** What is recorded now (the settings), so a view can say why data is missing. */
export interface TrafficRecording {
  enabled: boolean
  client_addresses: boolean
  request_log: boolean
}

/** The span a view covers. */
interface TrafficSpan {
  from: string
  to: string
  step_seconds: number
  /** What the files read count by. */
  resolution: 'minute' | 'hour'
}

export interface TrafficTotals {
  requests: number
  bytes: number
  /** 4xx answers (the next three included). */
  client_errors: number
  /** 401 and 403 answers. */
  denied: number
  not_found: number
  /** 429 answers. */
  throttled: number
  /** 5xx answers. */
  server_errors: number
  mean_ms: number | null
  /** The latency bound half, 95 % and 99 % of the requests stayed within. */
  p50_ms: number | null
  p95_ms: number | null
  p99_ms: number | null
}

/** A client network's counts. */
export interface TrafficClient {
  network: string
  address: string
  requests: number
  bytes: number
  client_errors: number
  denied: number
  not_found: number
  throttled: number
  server_errors: number
  user_agent: string | null
  account: string | null
  user_id: number | null
  username: string | null
  hosts: string[]
  first_seen: string | null
  last_seen: string | null
}

/** `GET /admin/traffic`. */
export interface TrafficOverview extends TrafficSpan {
  instances: TrafficInstance[]
  totals: TrafficTotals
  series: TrafficPoint[]
  surfaces: { surface: string; requests: number; bytes: number }[]
  repositories: {
    name: string
    requests: number
    bytes: number
    client_errors: number
    server_errors: number
  }[]
  statuses: { status: number; requests: number }[]
  clients: TrafficClient[]
  recording: TrafficRecording
}

/** A request of the request log. */
export interface TrafficLogEntry {
  time: string
  address: string
  method: string
  path: string
  surface: string
  repository: string | null
  status: number
  bytes: number
  duration_ms: number
  user_agent: string | null
  account: string | null
  user_id: number | null
  username: string | null
  host: string
}

/** How often a value occurs in a client's log. */
export interface TrafficTally {
  value: string
  requests: number
}

/** How often an account occurs in a client's log. */
export interface TrafficAccountTally {
  account: string | null
  user_id: number | null
  username: string | null
  requests: number
}

/** `GET /admin/traffic/client`. */
export interface TrafficClientDetail extends TrafficSpan {
  network: string
  instances: TrafficInstance[]
  /** Its counts in the time buckets it was among the top clients of. */
  totals: TrafficClient | null
  series: TrafficPoint[]
  log: {
    from: string
    to: string
    matched: number
    entries: TrafficLogEntry[]
    paths: TrafficTally[]
    user_agents: TrafficTally[]
    accounts: TrafficAccountTally[]
    statuses: TrafficTally[]
  }
  recording: TrafficRecording
}

/** `GET /admin/settings/traffic`. */
export interface TrafficSettings {
  enabled: boolean
  client_addresses: boolean
  request_log: boolean
  /** Days the counts by hour are kept; `0` keeps them. */
  statistics_retention_days: number
  client_retention_days: number
  request_log_retention_days: number
}

/** `PUT /admin/settings/traffic` body: the fields to change. */
export type TrafficSettingsUpdate = Partial<TrafficSettings>

/** What a view asks for. */
export interface TrafficQuery {
  range: TrafficRange
  instance?: string
  repository?: string
}

export const trafficKeys = {
  all: ['traffic'] as const,
  overview: (q: TrafficQuery) => ['traffic', 'overview', q] as const,
  client: (network: string, q: TrafficQuery) => ['traffic', 'client', network, q] as const,
  settings: () => ['settings', 'traffic'] as const,
}

/** `GET /admin/traffic`. */
export function fetchTrafficOverview(
  q: TrafficQuery,
  signal?: AbortSignal,
): Promise<TrafficOverview> {
  return httpClient.get<TrafficOverview>('/admin/traffic', {
    signal,
    query: { range: q.range, instance: q.instance, repository: q.repository },
  })
}

/** `GET /admin/traffic/client`. */
export function fetchTrafficClient(
  network: string,
  q: TrafficQuery,
  signal?: AbortSignal,
): Promise<TrafficClientDetail> {
  return httpClient.get<TrafficClientDetail>('/admin/traffic/client', {
    signal,
    query: { network, range: q.range, instance: q.instance },
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
