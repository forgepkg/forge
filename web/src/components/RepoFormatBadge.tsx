import { FormatTag, formatLabel } from '~/components/ui'

export { formatLabel }

/**
 * The repository format (`nuget` | `docker` | `npm` | `raw` | `apt`) with its
 * display name and glyph. An id the UI does not know shows as it is, like
 * `RepoKindBadge`.
 */
export function RepoFormatBadge({ format }: { format: string }) {
  return <FormatTag format={format} />
}
