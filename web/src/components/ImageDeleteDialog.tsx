import type { ReactNode } from 'react'
import type { UseMutationResult } from '@tanstack/react-query'

import type { ImageDeleted, ImageDetail, ImageManifest, ImageTag } from '~/api/images'
import type { ApiError } from '~/lib/httpClient'
import { chartVersion, isChartImage, shortDigest } from '~/lib/oci'
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

function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

/**
 * The confirmation of an image page's delete (administrators, hosted
 * repositories): the whole image, a tag, a manifest with what only it kept,
 * or a Helm chart's version. It says what goes along and runs the delete
 * through `del` ({@link useDeleteImage}); `onDeleted` closes it.
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
  let title = ''
  let description: ReactNode = null
  let warning: ReactNode = null
  let confirm = 'Delete'
  const image = <Code>{detail.image}</Code>

  if (target?.kind === 'image') {
    const chart = isChartImage(detail.manifests)
    title = `Delete ${detail.image}?`
    confirm = chart ? 'Delete chart' : 'Delete image'
    description = (
      <>
        Permanently delete {chart ? 'chart' : 'image'} {image} from repository{' '}
        <Code>{detail.repo}</Code>:{' '}
        {chart
          ? count(detail.tags.length, 'version', 'versions')
          : count(detail.tags.length, 'tag', 'tags')}{' '}
        and {count(detail.manifests.length, 'manifest', 'manifests')}. Clients that pull it start
        failing; those that already pulled it keep their copy. This cannot be undone.
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
    const referrers = detail.manifests.filter((r) => r.subject_digest === m.digest).length
    const along = [
      m.children.length > 0 &&
        `the ${count(m.children.length, 'manifest', 'manifests')} it lists`,
      referrers > 0 &&
        `the ${count(referrers, 'referrer', 'referrers')} (signatures, SBOMs, attestations) of it`,
    ].filter((part): part is string => !!part)
    const parents = detail.manifests.filter((p) => p.children.includes(m.digest))
    title = `Delete manifest ${shortDigest(m.digest)}?`
    confirm = 'Delete manifest'
    description = (
      <>
        Permanently delete the manifest <Code>{shortDigest(m.digest)}</Code> of {image}
        {m.tags.length > 0 && (
          <>
            {' '}
            with its {m.tags.length === 1 ? 'tag' : 'tags'} <Code>{m.tags.join(', ')}</Code>
          </>
        )}
        .{' '}
        {along.length > 0 &&
          `With it go ${along.join(' and ')}, unless a tag or another manifest still needs them. `}
        This cannot be undone.
      </>
    )
    if (parents.length > 0) {
      warning = (
        <Notice tone="warn">
          {parents.length === 1 ? 'Index ' : 'Indexes '}
          {parents.map((p, i) => (
            <span key={p.digest}>
              {i > 0 && ', '}
              <Code>{shortDigest(p.digest)}</Code>
            </span>
          ))}{' '}
          {parents.length === 1 ? 'lists' : 'list'} this manifest: pulling{' '}
          {m.platforms.length > 0 ? m.platforms.join(', ') : 'its platform'} through{' '}
          {parents.length === 1 ? 'it' : 'them'} fails once the manifest is gone.
        </Notice>
      )
    }
  } else if (target?.kind === 'version') {
    const version = chartVersion(target.tag.tag)
    const signed = detail.manifests.some((r) => r.subject_digest === target.tag.digest)
    title = `Delete ${detail.image} ${version}?`
    confirm = 'Delete version'
    description = (
      <>
        Permanently delete version <Code>{version}</Code> of chart {image} from repository{' '}
        <Code>{detail.repo}</Code>
        {signed && ', with its signatures and other referrers'}. Clients that already pulled it
        keep their copy. This cannot be undone.
      </>
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
      confirmDisabled={del.isPending}
      onConfirm={() =>
        target &&
        del.mutate(referenceOf(target), {
          onSuccess: () => onDeleted(target),
        })
      }
    >
      {warning}
      {del.isError && (
        <Notice tone="danger" title="Could not delete">
          {del.error.body || del.error.message}
        </Notice>
      )}
    </Dialog>
  )
}
