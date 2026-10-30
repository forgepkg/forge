/**
 * How the traffic views name what the statistics count: countries,
 * autonomous systems, repositories, shares.
 */

const regions = (() => {
  try {
    return new Intl.DisplayNames(undefined, { type: 'region' })
  } catch {
    return null
  }
})()

/** A country's name from its ISO code (`DE` → Germany); `Unknown` for none. */
export function countryName(code: string): string {
  if (!code) return 'Unknown'
  try {
    return regions?.of(code) ?? code
  } catch {
    return code
  }
}

/** An autonomous system: `AS3320 Deutsche Telekom AG`; `Unknown` for none. */
export function asnLabel(asn: number, org: string): string {
  if (!asn) return 'Unknown'
  return org ? `AS${asn} ${org}` : `AS${asn}`
}

/** A repository's name; what `""` stands for: requests to no repository. */
export function repositoryLabel(name: string): string {
  return name || 'No repository (web UI, APIs, sign-in)'
}

const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 })

/** `part` of `whole` as a percentage; an em dash without a whole. */
export function share(part: number, whole: number): string {
  return whole > 0 ? percent.format(part / whole) : '—'
}

/** A `YYYY-MM-DD` day as the locale writes a date (`Oct 30, 2026`). */
export function dayLabel(day: string | null | undefined): string {
  if (!day) return '—'
  const d = new Date(`${day}T00:00:00Z`)
  return Number.isNaN(d.getTime())
    ? day
    : d.toLocaleDateString(undefined, { dateStyle: 'medium', timeZone: 'UTC' })
}
