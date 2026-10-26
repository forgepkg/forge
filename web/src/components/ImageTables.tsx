import type { ImageManifest, ImageTag } from '~/api/images'
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

const KIND_ICONS: Record<ManifestKind, IconName> = {
  Image: 'Package',
  Index: 'Layers',
  Artifact: 'Shield',
}

export function ManifestTable({
  manifests,
  showSource,
  onDelete,
  deletePending,
}: {
  manifests: ImageManifest[]
  /** Group repositories: show which member each manifest comes from. */
  showSource: boolean
  onDelete?: (manifest: ImageManifest) => void
  deletePending?: boolean
}) {
  // Referrers name their subject by digest; show the subject's tags too.
  const tagsByDigest = new Map(manifests.map((m) => [m.digest, m.tags]))

  return (
    <Table caption="Manifests">
      <TableHead>
        <TableHeader>Digest</TableHeader>
        <TableHeader>Kind</TableHeader>
        <TableHeader align="right">Size</TableHeader>
        <TableHeader>Platforms</TableHeader>
        <TableHeader>Tags</TableHeader>
        <TableHeader>Pushed</TableHeader>
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
              {formatDateTime(m.created_at)}
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
