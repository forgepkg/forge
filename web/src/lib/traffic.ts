import type { Tone } from '~/components/ui'

/**
 * How the traffic views name what the statistics count: surfaces, accounts,
 * statuses, instances.
 */

const SURFACES: Record<string, string> = {
  oci: 'Docker registry',
  nuget: 'NuGet',
  plugin_npm: 'npm',
  plugin_raw: 'Raw',
  plugin_other: 'Other formats',
  repository: 'Unknown repositories',
  admin: 'Admin API',
  browse: 'Browse API',
  auth: 'Sign-in and tokens',
  ui: 'Web UI',
}

/** A surface as people call it (`plugin_npm` → npm). */
export function surfaceLabel(surface: string): string {
  return SURFACES[surface] ?? surface
}

const ACCOUNT_KINDS: Record<string, string> = {
  anonymous: 'anonymous',
  session: 'web session',
  token: 'API token',
  password: 'password',
  trusted_header: 'trusted proxy',
  workload: 'workload identity',
}

/** Who a request ran as: `alice (API token)`, `anonymous`. */
export function accountLabel(
  account: string | null,
  username: string | null,
  userId: number | null,
): string {
  const kind = account ? (ACCOUNT_KINDS[account] ?? account) : null
  const who = username ?? (userId != null ? `user ${userId}` : null)
  if (who && kind) return `${who} (${kind})`
  return who ?? kind ?? '—'
}

/** The tone of a status: 2xx ok, 3xx neutral, 4xx warn, 5xx danger. */
export function statusTone(status: number): Tone {
  if (status >= 500) return 'danger'
  if (status >= 400) return 'warn'
  if (status >= 300) return 'neutral'
  return 'ok'
}

/** What the series' points are: "per minute", "per 5 minutes", "per day". */
export function stepLabel(seconds: number): string {
  if (seconds % 86_400 === 0) return seconds === 86_400 ? 'per day' : `per ${seconds / 86_400} days`
  if (seconds % 3_600 === 0) return seconds === 3_600 ? 'per hour' : `per ${seconds / 3_600} hours`
  return seconds === 60 ? 'per minute' : `per ${seconds / 60} minutes`
}

const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 })

/** `part` of `whole` as a percentage; an em dash without a whole. */
export function share(part: number, whole: number): string {
  return whole > 0 ? percent.format(part / whole) : '—'
}

function bound(ms: number): string {
  return ms >= 1_000 ? `${ms / 1_000} s` : `${ms} ms`
}

/**
 * How fast the requests were answered, from the latency histogram's bounds:
 * `95 % answered within 250 ms, half within 10 ms`; `null` without requests.
 */
export function latencySummary(totals: {
  requests: number
  p50_ms: number | null
  p95_ms: number | null
}): string | null {
  if (totals.requests === 0) return null
  const p95 = totals.p95_ms == null ? '5 % took over 60 s' : `95 % answered within ${bound(totals.p95_ms)}`
  const p50 = totals.p50_ms == null ? 'half took over 60 s' : `half within ${bound(totals.p50_ms)}`
  return `${p95}, ${p50}`
}
