import type { ImageManifest, ImageTag } from '~/api/images'
import {
  formatBytes,
  formatDateTime,
  manifestKind,
  referrerKind,
  shortDigest,
  type ManifestKind,
} from '~/lib/oci'
import { Badge } from '~/components/catalyst/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/catalyst/table'
import { CopyButton } from '~/components/CopyButton'

/**
 * The image-detail tables: an image's **tags** (what each points at, its size
 * and platforms) and its **manifests** (every stored manifest — images,
 * indexes / manifest lists, and artifacts such as signatures or SBOMs that
 * refer to another manifest). Digests are shown Docker-style (12 hex chars)
 * with the full digest in a tooltip and a copy button. Sizes are the
 * compressed layer sizes the server reports ("—" when unknown).
 */

/** A short digest with its full value as tooltip, plus a copy button. */
export function Digest({ digest, label }: { digest: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="font-mono" title={digest}>
        {shortDigest(digest)}
      </span>
      <CopyButton value={digest} label={label} />
    </span>
  )
}

/** Platforms (`linux/amd64`, …) as chips; an em dash when none are known. */
function Platforms({ platforms }: { platforms: string[] }) {
  if (platforms.length === 0) {
    return <span className="text-zinc-400 dark:text-zinc-500">—</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {platforms.map((p) => (
        <Badge key={p} color="zinc" className="font-mono">
          {p}
        </Badge>
      ))}
    </span>
  )
}

export function TagTable({ tags }: { tags: ImageTag[] }) {
  return (
    <Table striped>
      <TableHead>
        <TableRow>
          <TableHeader>Tag</TableHeader>
          <TableHeader>Digest</TableHeader>
          <TableHeader>Size</TableHeader>
          <TableHeader>Platforms</TableHeader>
        </TableRow>
      </TableHead>
      <TableBody>
        {tags.map((t) => (
          <TableRow key={t.tag}>
            <TableCell className="font-mono font-medium">{t.tag}</TableCell>
            <TableCell>
              <Digest digest={t.digest} label={`Copy digest of ${t.tag}`} />
            </TableCell>
            <TableCell className="text-zinc-500 dark:text-zinc-400">
              {formatBytes(t.size)}
            </TableCell>
            <TableCell>
              <Platforms platforms={t.platforms} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

const KIND_COLORS: Record<ManifestKind, React.ComponentProps<typeof Badge>['color']> = {
  Image: 'sky',
  Index: 'purple',
  Artifact: 'amber',
}

export function ManifestTable({
  manifests,
  showSource,
}: {
  manifests: ImageManifest[]
  /** Group repositories: show which member each manifest comes from. */
  showSource: boolean
}) {
  // Referrers name their subject by digest; show the subject's tags too.
  const tagsByDigest = new Map(manifests.map((m) => [m.digest, m.tags]))

  return (
    <Table striped>
      <TableHead>
        <TableRow>
          <TableHeader>Digest</TableHeader>
          <TableHeader>Kind</TableHeader>
          <TableHeader>Size</TableHeader>
          <TableHeader>Platforms</TableHeader>
          <TableHeader>Tags</TableHeader>
          <TableHeader>Pushed</TableHeader>
          <TableHeader>Last pulled</TableHeader>
          {showSource && <TableHeader>Source</TableHeader>}
        </TableRow>
      </TableHead>
      <TableBody>
        {manifests.map((m) => (
          <TableRow key={m.digest}>
            <TableCell>
              <Digest digest={m.digest} label={`Copy digest ${shortDigest(m.digest)}`} />
            </TableCell>
            <TableCell>
              <ManifestKindCell manifest={m} subjectTags={tagsByDigest} />
            </TableCell>
            <TableCell
              className="text-zinc-500 dark:text-zinc-400"
              title={`Manifest: ${m.manifest_size} B`}
            >
              {formatBytes(m.size)}
            </TableCell>
            <TableCell>
              <Platforms platforms={m.platforms} />
            </TableCell>
            <TableCell>
              {m.tags.length === 0 ? (
                <span className="text-zinc-400 dark:text-zinc-500">—</span>
              ) : (
                <span className="flex flex-wrap gap-1">
                  {m.tags.map((tag) => (
                    <Badge key={tag} color="zinc" className="font-mono">
                      {tag}
                    </Badge>
                  ))}
                </span>
              )}
            </TableCell>
            <TableCell
              className="text-zinc-500 dark:text-zinc-400"
              title={m.created_at}
            >
              {formatDateTime(m.created_at)}
            </TableCell>
            <TableCell
              className="text-zinc-500 dark:text-zinc-400"
              title={m.last_pulled_at ?? undefined}
            >
              {formatDateTime(m.last_pulled_at)}
            </TableCell>
            {showSource && (
              <TableCell className="font-mono text-zinc-500 dark:text-zinc-400">
                {m.source ?? '—'}
              </TableCell>
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
      <span title={manifest.artifact_type ?? manifest.media_type}>
        <Badge color={KIND_COLORS[kind]}>{kind}</Badge>
      </span>
      {manifest.children.length > 0 && (
        <span className="text-xs text-zinc-500 dark:text-zinc-400">
          lists {manifest.children.length}{' '}
          {manifest.children.length === 1 ? 'manifest' : 'manifests'}
        </span>
      )}
      {subject && (
        <span className="text-xs text-zinc-500 dark:text-zinc-400">
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
