import { Badge } from '~/components/catalyst/badge'

/**
 * Badge for a repository format (`nuget` | `docker` | `helm`), with the
 * format's display name. Other formats (WebAssembly plugins) fall back to
 * their raw id in a neutral style, like `RepoKindBadge`.
 */
const FORMATS: Record<
  string,
  { label: string; color: React.ComponentProps<typeof Badge>['color'] }
> = {
  nuget: { label: 'NuGet', color: 'indigo' },
  docker: { label: 'Docker', color: 'cyan' },
  helm: { label: 'Helm', color: 'sky' },
}

/** Display name of a repository format (`NuGet`, `Docker`, `Helm`). */
export function formatLabel(format: string): string {
  return FORMATS[format]?.label ?? format
}

export function RepoFormatBadge({ format }: { format: string }) {
  return (
    <Badge color={FORMATS[format]?.color ?? 'zinc'}>{formatLabel(format)}</Badge>
  )
}
