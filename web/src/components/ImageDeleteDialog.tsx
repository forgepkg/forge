import type { ReactNode } from 'react'
import type { UseMutationResult } from '@tanstack/react-query'

import type {
  ImageDeleted,
  ImageDeletePreview,
  ImageDetail,
  ImageManifest,
  ImageTag,
} from '~/api/images'
import type { ApiError } from '~/lib/httpClient'
import { chartVersion, isChartImage, shortDigest } from '~/lib/oci'
import { useImageDeletePreview } from '~/queries/useImageDetail'
import { Code, Dialog, Notice } from '~/components/ui'

/** What the image page asks an administrator to confirm the delete of. */
export type ImageDeleteTarget =
  | { kind: 'image' }
  | { kind: 'tag'; tag: ImageTag }
  | { kind: 'manifest'; manifest: ImageManifest }
  /** A Helm chart's version: the manifest its tag points at. */
  | { kind: 'version'; tag: ImageTag }

/** The `reference` the admin API deletes for `target` (none: the image). */
function referenceOf(target: ImageDeleteTarget): string | undefined {
  switch (target.kind) {
    case 'image':
      return undefined
    case 'tag':
      return target.tag.tag
    case 'manifest':
      return target.manifest.digest
    case 'version':
      return target.tag.digest
  }
}

/** The manifest a delete of `target` deletes, when it deletes one. */
function manifestOf(target: ImageDeleteTarget | null): string | undefined {
  return target?.kind === 'manifest' || target?.kind === 'version'
    ? referenceOf(target)
    : undefined
}

function count(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`
}

/** `names` as code, and how many of `total` they leave out. */
function Names({ names, total }: { names: string[]; total: number }) {
  return (
    <>
      <Code>{names.join(', ')}</Code>
      {total > names.length && ` and ${(total - names.length).toLocaleString()} more`}
    </>
  )
}

/** What goes with a manifest, by the server's count: `''` when nothing does. */
function takenAlong(preview: ImageDeletePreview): string {
  const along = [
    preview.listed > 0 && `the ${count(preview.listed, 'manifest', 'manifests')} it lists`,
    preview.referrers > 0 &&
      `${count(preview.referrers, 'referrer', 'referrers')} (signatures, SBOMs, attestations)`,
  ].filter((part): part is string => !!part)
  return along.length > 0
    ? `With it go ${along.join(' and ')}; what a tag or another manifest still needs stays. `
    : ''
}

/**
 * The confirmation of an image page's delete (administrators, hosted
 * repositories): the whole image, a tag, a manifest with what only it kept,
 * or a Helm chart's version. It says what goes along and runs the delete
 * through `del` ({@link useDeleteImage}); `onDeleted` closes it.
 *
 * The page lists at most 1,000 tags and 1,000 manifests of an image, so the
 * wording never counts its rows (#546): the whole image is counted by the
 * page's totals, and what a manifest's delete takes (every tag on it, the
 * manifests it lists, its referrers) and which indexes list it is asked of
 * the server ({@link useImageDeletePreview}). Until that answers, the delete
 * cannot be confirmed; when it fails, the dialog says what the server does
 * in general instead.
 */
export function ImageDeleteDialog({
  detail,
  target,
  del,
  onClose,
  onDeleted,
}: {
  detail: ImageDetail
  target: ImageDeleteTarget | null
  del: UseMutationResult<ImageDeleted, ApiError, string | undefined>
  onClose: () => void
  onDeleted: (target: ImageDeleteTarget) => void
}) {
  const manifest = manifestOf(target)
  const asked = useImageDeletePreview(detail.repo, detail.image, manifest)
  // An answer still being asked again is not the server's current one.
  const preview = manifest !== undefined && !asked.isFetching ? asked.data : undefined
  const checking = manifest !== undefined && (asked.isFetching || (!preview && !asked.isError))

  let title = ''
  let description: ReactNode = null
  let warning: ReactNode = null
  let confirm = 'Delete'
  const image = <Code>{detail.image}</Code>

  if (target?.kind === 'image') {
    const chart = isChartImage(detail.manifests)
    const tags = detail.tags_total ?? detail.tags.length
    const manifests = detail.manifests_total ?? detail.manifests.length
    const partial = tags > detail.tags.length || manifests > detail.manifests.length
    title = `Delete ${detail.image}?`
    confirm = chart ? 'Delete chart' : 'Delete image'
    description = (
      <>
        Permanently delete {chart ? 'chart' : 'image'} {image} from repository{' '}
        <Code>{detail.repo}</Code>:{' '}
        {chart ? count(tags, 'version', 'versions') : count(tags, 'tag', 'tags')} and{' '}
        {count(manifests, 'manifest', 'manifests')}
        {partial && ', not only the newest this page lists'}. Clients that pull it start failing;
        those that already pulled it keep their copy. This cannot be undone.
      </>
    )
  } else if (target?.kind === 'tag') {
    const { tag, digest } = target.tag
    title = `Delete tag ${tag}?`
    confirm = 'Delete tag'
    description = (
      <>
        Remove the tag <Code>{tag}</Code> from {image}. The manifest it points at,{' '}
        <Code>{shortDigest(digest)}</Code>, stays and can still be pulled by digest; delete it
        under Manifests to remove it too.
      </>
    )
  } else if (target?.kind === 'manifest') {
    const m = target.manifest
    title = `Delete manifest ${shortDigest(m.digest)}?`
    confirm = 'Delete manifest'
    description = (
      <>
        Permanently delete the manifest <Code>{shortDigest(m.digest)}</Code> of {image}
        {preview && preview.tags_total > 0 && (
          <>
            {' '}
            with its {preview.tags_total === 1 ? 'tag' : 'tags'}{' '}
            <Names names={preview.tags} total={preview.tags_total} />
          </>
        )}
        . {preview && takenAlong(preview)}This cannot be undone.
      </>
    )
  } else if (target?.kind === 'version') {
    const version = chartVersion(target.tag.tag)
    // The version's own tag is what is asked for; the others go unasked.
    const others = preview?.tags.filter((tag) => tag !== target.tag.tag) ?? []
    // Its own tag is among the tags, named or (past the bound) only counted.
    const own =
      preview && (others.length < preview.tags.length || preview.tags_total > preview.tags.length)
    const othersTotal = preview ? preview.tags_total - (own ? 1 : 0) : 0
    title = `Delete ${detail.image} ${version}?`
    confirm = 'Delete version'
    description = (
      <>
        Permanently delete version <Code>{version}</Code> of chart {image} from repository{' '}
        <Code>{detail.repo}</Code>
        {othersTotal > 0 && (
          <>
            , and with it the {othersTotal === 1 ? 'tag' : 'tags'}{' '}
            <Names names={others} total={othersTotal} /> of the same manifest
          </>
        )}
        . {preview && takenAlong(preview)}Clients that already pulled it keep their copy. This
        cannot be undone.
      </>
    )
  }

  if (manifest !== undefined && checking) {
    warning = <Notice tone="info">Checking what this delete takes along…</Notice>
  } else if (manifest !== undefined && !preview) {
    warning = (
      <Notice tone="warn" title="Could not check what this delete takes along">
        The manifest goes with every tag on it, also tags this page does not list, and with the
        manifests it lists and its referrers (signatures, SBOMs, attestations) unless a tag or
        another manifest still needs them. An index that lists it can no longer pull its
        platform. ({asked.error?.body || asked.error?.message})
      </Notice>
    )
  } else if (preview && preview.indexes_total > 0) {
    const one = preview.indexes_total === 1
    const platforms = target?.kind === 'manifest' ? target.manifest.platforms : []
    warning = (
      <Notice tone="warn">
        {one ? 'Index ' : 'Indexes '}
        {preview.indexes.map((digest, i) => (
          <span key={digest}>
            {i > 0 && ', '}
            <Code>{shortDigest(digest)}</Code>
          </span>
        ))}
        {preview.indexes_total > preview.indexes.length &&
          ` and ${(preview.indexes_total - preview.indexes.length).toLocaleString()} more`}{' '}
        {one ? 'lists' : 'list'} this manifest: pulling{' '}
        {platforms.length > 0 ? platforms.join(', ') : 'its platform'} through{' '}
        {one ? 'it' : 'them'} fails once the manifest is gone.
      </Notice>
    )
  }

  return (
    <Dialog
      open={target !== null}
      onClose={() => {
        if (!del.isPending) onClose()
      }}
      title={title}
      description={description}
      icon="Trash"
      tone="danger"
      confirmLabel={del.isPending ? 'Deleting…' : confirm}
      confirmVariant="danger-solid"
      confirmDisabled={del.isPending || checking}
      onConfirm={() =>
        target &&
        del.mutate(referenceOf(target), {
          onSuccess: () => onDeleted(target),
        })
      }
    >
      {warning}
      {target && target.kind !== 'tag' && (
        <Notice>
          The config and layers no other manifest of {image} uses can still be pulled by digest
          until the registry releases them: with the default settings, up to a day after they were
          last pushed. Pulling them does not prolong that.
        </Notice>
      )}
      {del.isError && (
        <Notice tone="danger" title="Could not delete">
          {del.error.body || del.error.message}
        </Notice>
      )}
    </Dialog>
  )
}
