import { useQuery } from '@tanstack/react-query'

import type { ImageManifest, ImageTag } from '~/api/images'
import { browseReposQueryOptions } from '~/api/packages'
import {
  formatBytes,
  formatDateTime,
  manifestKind,
  referrerKind,
  shortDigest,
  type ManifestKind,
} from '~/lib/oci'
import {
  Button,
  Chip,
  CopyButton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  type IconName,
} from '~/components/ui'

/**
 * The image-detail tables: an image's **tags** (what each points at, its size
 * and platforms) and its **manifests** (every stored manifest — images,
 * indexes / manifest lists, and artifacts such as signatures or SBOMs that
 * refer to another manifest). Digests are shown Docker-style (12 hex chars)
 * with the full digest in a tooltip and a copy button. Sizes are the
 * compressed layer sizes the server reports ("—" when unknown).
 *
 * With `onDelete` (administrators, hosted repositories), each row ends in a
 * Delete button that asks the page to confirm the delete of its tag or
 * manifest.
 *
 * A manifest's `created_at` is when it reached Forge. On a proxy that is when
 * Forge first cached it from the upstream, not when it was pushed there, so
 * the column is labelled "Cached" for a proxy repository (as package
 * versions are, #110).
 *
 * A group's manifests come from its members (`source`), and each row's time
 * is what its member's is: cached for a proxy member, pushed for a hosted one
 * (#562). The members' kinds come from the readable repositories
 * (`/browse/repos`), which list every member a group serves the reader. When
 * every row has the same kind the column is labelled for it; when the rows
 * mix kinds, or a row's member is not known, the column is "Pushed / cached"
 * and each row of a known member says which its time is.
 */

/** A short digest with its full value as tooltip, plus a copy button. */
export function Digest({ digest, label }: { digest: string; label: string }) {
  return (
    <span className="fg-digest">
      <span className="fg-digest-short" title={digest}>
        {shortDigest(digest)}
      </span>
      <CopyButton value={digest} label={label} />
    </span>
  )
}

/** Chips (platforms, tags); an em dash when there are none. */
function Chips({ values }: { values: string[] }) {
  if (values.length === 0) {
    return <span className="text-ink-faint">—</span>
  }
  return (
    <span className="fg-cell-badges">
      {values.map((v) => (
        <Chip key={v}>{v}</Chip>
      ))}
    </span>
  )
}

/** A row's Delete button. */
function DeleteCell({
  label,
  disabled,
  onClick,
}: {
  label: string
  disabled?: boolean
  onClick: () => void
}) {
  return (
    <TableCell align="right">
      <Button size="sm" variant="danger" aria-label={label} disabled={disabled} onClick={onClick}>
        Delete
      </Button>
    </TableCell>
  )
}

export function TagTable({
  tags,
  noun = 'tag',
  onDelete,
  deletePending,
}: {
  tags: ImageTag[]
  /** What a tag is to the reader: a `tag`, or a chart's `version`. */
  noun?: string
  onDelete?: (tag: ImageTag) => void
  deletePending?: boolean
}) {
  return (
    <Table caption="Tags">
      <TableHead>
        <TableHeader width="160px">Tag</TableHeader>
        <TableHeader>Digest</TableHeader>
        <TableHeader align="right" width="110px">
          Size
        </TableHeader>
        <TableHeader>Platforms</TableHeader>
        {onDelete && <TableHeader align="right">Actions</TableHeader>}
      </TableHead>
      <TableBody>
        {tags.map((t) => (
          <TableRow key={t.tag}>
            <TableCell lead>
              <span className="fg-mono font-semibold">{t.tag}</span>
            </TableCell>
            <TableCell>
              <Digest digest={t.digest} label={`Copy digest of ${t.tag}`} />
            </TableCell>
            <TableCell align="right" nowrap>
              {formatBytes(t.size)}
            </TableCell>
            <TableCell>
              <Chips values={t.platforms} />
            </TableCell>
            {onDelete && (
              <DeleteCell
                label={`Delete ${noun} ${t.tag}`}
                disabled={deletePending}
                onClick={() => onDelete(t)}
              />
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

/** What a manifest's `created_at` is: when it was pushed, or first cached. */
type TimeKind = 'pushed' | 'cached'

/** The time kind of a repository (or a group's member) of `kind`. */
function timeKindOf(kind: string | undefined): TimeKind | undefined {
  if (kind === 'proxy') return 'cached'
  if (kind === 'hosted') return 'pushed'
  return undefined
}

const TIME_HEADERS: Record<TimeKind | 'mixed', { label: string; hint?: string }> = {
  pushed: { label: 'Pushed' },
  cached: {
    label: 'Cached',
    hint: 'When Forge first cached this manifest from the upstream',
  },
  mixed: {
    label: 'Pushed / cached',
    hint: 'When the manifest was pushed to a hosted member, or first cached from the upstream by a proxy member',
  },
}

/**
 * The kind of the member each manifest of a group comes from, by member
 * name; empty for any other repository (no request is made).
 */
function useMemberKinds(repoKind: string): Map<string, string> {
  const repos = useQuery({ ...browseReposQueryOptions, enabled: repoKind === 'group' })
  return new Map((repoKind === 'group' ? (repos.data ?? []) : []).map((r) => [r.name, r.kind]))
}

const KIND_ICONS: Record<ManifestKind, IconName> = {
  Image: 'Package',
  Index: 'Layers',
  Artifact: 'Shield',
}

export function ManifestTable({
  manifests,
  repoKind,
  onDelete,
  deletePending,
}: {
  manifests: ImageManifest[]
  /**
   * The image's repository kind: `hosted` | `proxy` | `group`. A group shows
   * which member each manifest comes from.
   */
  repoKind: string
  onDelete?: (manifest: ImageManifest) => void
  deletePending?: boolean
}) {
  // Referrers name their subject by digest; show the subject's tags too.
  const tagsByDigest = new Map(manifests.map((m) => [m.digest, m.tags]))
  const showSource = repoKind === 'group'
  const memberKinds = useMemberKinds(repoKind)
  const rowTimeKind = (m: ImageManifest): TimeKind | undefined =>
    timeKindOf(showSource ? m.source && memberKinds.get(m.source) : repoKind)
  const rowKinds = new Set(manifests.map(rowTimeKind))
  // One kind for every row labels the column for it; a mix (or a member of
  // unknown kind) gets the neutral heading and a per-row label.
  const single: TimeKind | undefined = showSource
    ? rowKinds.size === 1
      ? [...rowKinds][0]
      : undefined
    : (timeKindOf(repoKind) ?? 'pushed')
  const timeHeader = TIME_HEADERS[single ?? 'mixed']

  return (
    <Table caption="Manifests">
      <TableHead>
        <TableHeader>Digest</TableHeader>
        <TableHeader>Kind</TableHeader>
        <TableHeader align="right">Size</TableHeader>
        <TableHeader>Platforms</TableHeader>
        <TableHeader>Tags</TableHeader>
        <TableHeader hint={timeHeader.hint}>{timeHeader.label}</TableHeader>
        <TableHeader>Last pulled</TableHeader>
        {showSource && <TableHeader>Source</TableHeader>}
        {onDelete && <TableHeader align="right">Actions</TableHeader>}
      </TableHead>
      <TableBody>
        {manifests.map((m) => (
          <TableRow key={m.digest}>
            <TableCell lead>
              <Digest digest={m.digest} label={`Copy digest ${shortDigest(m.digest)}`} />
            </TableCell>
            <TableCell>
              <ManifestKindCell manifest={m} subjectTags={tagsByDigest} />
            </TableCell>
            <TableCell align="right" nowrap title={`Manifest: ${m.manifest_size} B`}>
              {formatBytes(m.size)}
            </TableCell>
            <TableCell>
              <Chips values={m.platforms} />
            </TableCell>
            <TableCell>
              <Chips values={m.tags} />
            </TableCell>
            <TableCell nowrap title={m.created_at}>
              <TimeCell manifest={m} label={single ? undefined : rowTimeKind(m)} />
            </TableCell>
            <TableCell nowrap title={m.last_pulled_at ?? undefined}>
              {formatDateTime(m.last_pulled_at)}
            </TableCell>
            {showSource && (
              <TableCell>
                <span className="fg-mono">{m.source ?? '—'}</span>
              </TableCell>
            )}
            {onDelete && (
              <DeleteCell
                label={`Delete manifest ${shortDigest(m.digest)}`}
                disabled={deletePending}
                onClick={() => onDelete(m)}
              />
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

/**
 * A manifest's `created_at`; in a column of mixed kinds, with whether the
 * row's time is a push or a cache.
 */
function TimeCell({ manifest, label }: { manifest: ImageManifest; label?: TimeKind }) {
  if (!label) return <>{formatDateTime(manifest.created_at)}</>
  return (
    <span className="flex flex-col items-start gap-0.5">
      <span>{formatDateTime(manifest.created_at)}</span>
      <span className="fg-cell-sub">{label === 'cached' ? 'Cached' : 'Pushed'}</span>
    </span>
  )
}

/**
 * The manifest's kind badge (media / artifact type as tooltip); an index
 * adds how many manifests it lists, a referrer (signature, attestation, SBOM,
 * …) which manifest it refers to.
 */
function ManifestKindCell({
  manifest,
  subjectTags,
}: {
  manifest: ImageManifest
  subjectTags: Map<string, string[]>
}) {
  const kind = manifestKind(manifest)
  const subject = manifest.subject_digest
  const tags = subject ? (subjectTags.get(subject) ?? []) : []
  return (
    <span className="flex flex-col items-start gap-0.5">
      <StatusBadge
        icon={KIND_ICONS[kind]}
        title={manifest.artifact_type ?? manifest.media_type}
      >
        {kind}
      </StatusBadge>
      {manifest.children.length > 0 && (
        <span className="fg-cell-sub">
          lists {manifest.children.length}{' '}
          {manifest.children.length === 1 ? 'manifest' : 'manifests'}
        </span>
      )}
      {subject && (
        <span className="fg-cell-sub">
          {referrerKind(manifest.artifact_type) ?? 'Referrer'} · refers to{' '}
          <span className="font-mono" title={subject}>
            {shortDigest(subject)}
          </span>
          {tags.length > 0 && <> ({tags.join(', ')})</>}
        </span>
      )}
    </span>
  )
}
