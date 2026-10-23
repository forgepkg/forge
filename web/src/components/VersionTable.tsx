import clsx from 'clsx'

import type { DetailVersion } from '~/api/packages'
import { Badge } from '~/components/catalyst/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/catalyst/table'
import { DelayBadge } from './DelayBadge'
import { RetentionBadge } from './RetentionBadge'

/**
 * Per-version table for the package-detail view. Columns: version, published
 * time, size, listed/unlisted, and proxy delay + retention badges. Download
 * counts are intentionally absent — the browse API does not expose them (see
 * `src/api/packages.ts`).
 *
 * `published_at` is when the version reached Forge. On a proxy that is when
 * Forge first downloaded it from the upstream, not when it was published
 * there (and unknown for versions not downloaded yet), so the column is
 * labelled "Cached" for a proxy repository.
 */
export function VersionTable({
  versions,
  repoKind,
}: {
  versions: DetailVersion[]
  /** The package's repository kind: `hosted` | `proxy` | `group`. */
  repoKind: string
}) {
  return (
    <Table striped>
      <TableHead>
        <TableRow>
          <TableHeader>Version</TableHeader>
          {repoKind === 'proxy' ? (
            <TableHeader title="When Forge first downloaded this version from the upstream">
              Cached
            </TableHeader>
          ) : (
            <TableHeader>Published</TableHeader>
          )}
          <TableHeader>Size</TableHeader>
          <TableHeader>Status</TableHeader>
        </TableRow>
      </TableHead>
      <TableBody>
        {versions.map((v) => (
          <TableRow key={v.version}>
            <TableCell className="font-mono">
              <span className={clsx(!v.listed && 'text-zinc-400 dark:text-zinc-500')}>
                {v.version_original}
              </span>
            </TableCell>
            <TableCell className="text-zinc-500 dark:text-zinc-400">
              {formatDate(v.published_at)}
            </TableCell>
            <TableCell className="text-zinc-500 dark:text-zinc-400">
              {formatSize(v.size)}
            </TableCell>
            <TableCell>
              <span className="flex flex-wrap items-center gap-1.5">
                {!v.listed && <Badge color="zinc">unlisted</Badge>}
                <DelayBadge status={v.delay_status} delayedUntil={v.delayed_until} />
                <RetentionBadge status={v.retention_status} />
              </span>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

function formatSize(bytes: number | null): string {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  const kb = bytes / 1024
  if (kb < 1024) return `${kb.toFixed(1)} KB`
  return `${(kb / 1024).toFixed(1)} MB`
}
