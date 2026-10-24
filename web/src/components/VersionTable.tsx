import type { DetailVersion } from '~/api/packages'
import {
  Button,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Version,
} from '~/components/ui'
import { DelayBadge } from './DelayBadge'
import { RetentionBadge } from './RetentionBadge'

/**
 * Per-version table for the package-detail view. Columns: version, published
 * time, size, and the listed / proxy delay / retention badges. Download
 * counts are intentionally absent — the browse API does not expose them (see
 * `src/api/packages.ts`).
 *
 * `published_at` is when the version reached Forge. On a proxy that is when
 * Forge first downloaded it from the upstream, not when it was published
 * there (and unknown for versions not downloaded yet), so the column is
 * labelled "Cached" for a proxy repository.
 *
 * An npm package's versions also show the dist-tags that point at them and
 * whether they are deprecated (the message in the badge's title).
 */
export function VersionTable({
  versions,
  repoKind,
  caption,
<<<<<<< HEAD
  onDelete,
  deletePending,
=======
  distTags,
  deprecated,
>>>>>>> origin/main
}: {
  versions: DetailVersion[]
  /** The package's repository kind: `hosted` | `proxy` | `group`. */
  repoKind: string
  caption?: string
<<<<<<< HEAD
  onDelete?: (version: DetailVersion) => void
  deletePending?: boolean
=======
  /** npm: tag → version. */
  distTags?: Record<string, string>
  /** npm: version → deprecation message. */
  deprecated?: Record<string, string>
>>>>>>> origin/main
}) {
  const tagsOf = (version: string) =>
    Object.entries(distTags ?? {})
      .filter(([, v]) => v === version)
      .map(([tag]) => tag)
  return (
    <Table caption={caption}>
      <TableHead>
        <TableHeader>Version</TableHeader>
        {repoKind === 'proxy' ? (
          <TableHeader hint="When Forge first downloaded this version from the upstream">
            Cached
          </TableHeader>
        ) : (
          <TableHeader>Published</TableHeader>
        )}
        <TableHeader align="right" width="110px">
          Size
        </TableHeader>
        <TableHeader>Status</TableHeader>
        {onDelete && <TableHeader align="right">Actions</TableHeader>}
      </TableHead>
      <TableBody>
        {versions.map((v) => (
          <TableRow key={v.version}>
            <TableCell lead>
              <Version value={v.version_original} listed={v.listed} />
            </TableCell>
            <TableCell nowrap>{formatDate(v.published_at)}</TableCell>
            <TableCell align="right" nowrap>
              {formatSize(v.size)}
            </TableCell>
            <TableCell>
              <span className="fg-cell-badges">
                {tagsOf(v.version).map((tag) => (
                  <StatusBadge key={tag} tone="ok" dot={false} title={`dist-tag ${tag}`}>
                    {tag}
                  </StatusBadge>
                ))}
                {deprecated?.[v.version] != null && (
                  <StatusBadge tone="warn" title={deprecated[v.version]}>
                    deprecated
                  </StatusBadge>
                )}
                {!v.listed && <StatusBadge>unlisted</StatusBadge>}
                <DelayBadge status={v.delay_status} delayedUntil={v.delayed_until} />
                <RetentionBadge status={v.retention_status} />
              </span>
            </TableCell>
            {onDelete && (
              <TableCell align="right">
                <Button
                  size="sm"
                  variant="danger"
                  disabled={deletePending}
                  onClick={() => onDelete(v)}
                >
                  Delete
                </Button>
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? '—'
    : d.toLocaleDateString(undefined, { dateStyle: 'medium' })
}

/** Binary units with one decimal (`4.2 MiB`), as the design system writes sizes. */
function formatSize(bytes: number | null): string {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  const kib = bytes / 1024
  if (kib < 1024) return `${kib.toFixed(1)} KiB`
  return `${(kib / 1024).toFixed(1)} MiB`
}
