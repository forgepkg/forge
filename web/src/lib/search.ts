/**
 * How the router reads and writes a URL's query string (#403).
 *
 * TanStack Router's default turns every value that looks like a number, a
 * boolean or JSON into one: `?tag=1.36` became the number `1.36`, `?tag=1.10`
 * the number `1.1`, `?q=true` the boolean `true`. The routes keep strings
 * only, so a hand-written or tool-built link with such a value lost it.
 *
 * Here every value stays the string it was in the URL. The one exception is a
 * JSON string literal (`?tag=%221.36%22`, which the default wrote for a string
 * that would otherwise have parsed as a number): it reads as the string inside,
 * so links written before keep working. A string that would read that way
 * itself is written as a JSON literal, so it reads back unchanged.
 *
 * The routes' `validateSearch` therefore get strings from a URL. A value the
 * app passes to `navigate` reaches them as given, so a route expecting a
 * number or a boolean takes both ({@link searchInt}, {@link searchFlag}).
 */

/** One query value as the routes see it. */
function parseValue(raw: string): string {
  if (raw.startsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(raw)
      if (typeof parsed === 'string') return parsed
    } catch {
      // Not a JSON string literal: the text itself.
    }
  }
  return raw
}

/**
 * The router's `parseSearch`: every key's value as a string. A key given more
 * than once keeps its first value.
 */
export function parseSearch(searchStr: string): Record<string, unknown> {
  const params = new URLSearchParams(
    searchStr.startsWith('?') ? searchStr.slice(1) : searchStr,
  )
  const search: Record<string, unknown> = {}
  for (const [key, value] of params) {
    if (!(key in search)) search[key] = parseValue(value)
  }
  return search
}

/**
 * The router's `stringifySearch`: a string as it is, unless {@link parseSearch}
 * would read it as another string; anything else as JSON (`20`, `true`).
 * Undefined values are left out.
 */
export function stringifySearch(search: Record<string, unknown>): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(search)) {
    if (value === undefined) continue
    if (typeof value === 'string') {
      params.set(key, parseValue(value) === value ? value : JSON.stringify(value))
    } else {
      params.set(key, JSON.stringify(value))
    }
  }
  const searchStr = params.toString()
  return searchStr ? `?${searchStr}` : ''
}

/** The router options that make it use the functions above. */
export const searchOptions = { parseSearch, stringifySearch }

/** A non-negative integer from the URL (`"20"`) or from `navigate` (`20`). */
export function searchInt(value: unknown): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) && value >= 0 ? Math.floor(value) : undefined
  }
  if (typeof value === 'string' && /^\d{1,15}$/.test(value)) return Number(value)
  return undefined
}

/** `true` from the URL (`"true"`) or from `navigate`. */
export function searchFlag(value: unknown): boolean {
  return value === true || value === 'true'
}
