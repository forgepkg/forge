/**
 * How long ago `iso` was, the way a page says how old its data is: "just
 * now", "5 min ago", "3 h ago", "2 d ago". `null` when `iso` does not parse.
 * A time in the future (a clock ahead of this one) is "just now".
 */
export function formatAge(iso: string, now: number = Date.now()): string | null {
  const at = new Date(iso).getTime()
  if (Number.isNaN(at)) return null
  const seconds = Math.max(0, Math.floor((now - at) / 1000))
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.floor(hours / 24)} d ago`
}
