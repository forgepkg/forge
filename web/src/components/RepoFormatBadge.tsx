import { FormatTag, formatLabel } from '~/components/ui'

export { formatLabel }

/**
 * The repository format (`nuget` | `docker` | `raw`) with its display
 * name and a generic glyph. Other formats (WebAssembly plugins) show their
 * raw id, like `RepoKindBadge`.
 */
export function RepoFormatBadge({ format }: { format: string }) {
  return <FormatTag format={format} />
}
