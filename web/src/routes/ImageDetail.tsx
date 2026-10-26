import { useState, type ReactNode } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { ImageDetail } from '~/api/images'
import { isRepositoryOffline } from '~/api/packages'
import { ApiError } from '~/lib/httpClient'
import { cappedNote, defaultPullTag, formatDateTime, isChartImage } from '~/lib/oci'
import { useDeleteImage, useImageDetail } from '~/queries/useImageDetail'
import { useMe } from '~/queries/useMe'
import { ChartView } from '~/components/ChartView'
import { ManifestTable, TagTable } from '~/components/ImageTables'
import { ImageDeleteDialog, type ImageDeleteTarget } from '~/components/ImageDeleteDialog'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  Button,
  Code,
  CommandSnippet,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
} from '~/components/ui'

/** `?tag=` — the tag the pull commands use (deep-linkable). */
interface ImageDetailSearch {
  tag?: string
}

/**
 * `/images/$repo/<image…>`: the image name is the splat (`_splat`), since an
 * OCI image name may contain `/` (`team/app`).
 */
export const Route = createFileRoute('/_app/images/$repo/$')({
  validateSearch: (search: Record<string, unknown>): ImageDetailSearch =>
    typeof search.tag === 'string' && search.tag.length > 0
      ? { tag: search.tag }
      : {},
  component: ImageDetailRoute,
})

/** One page per image, so nothing (a pending delete) outlives a navigation. */
function ImageDetailRoute() {
  const { repo, _splat } = Route.useParams()
  return <ImageDetailPage key={JSON.stringify([repo, _splat ?? ''])} />
}

/**
 * Image-detail view of a docker repository: the pull commands (by tag and by
 * digest), the image's tags, and every manifest it holds — images, indexes
 * and referrers such as signatures — with sizes, platforms and timestamps.
 * An image of Helm charts (`helm push`) shows its charts instead
 * ({@link ChartView}). Loading / not-found / error states mirror the
 * package-detail screen. Administrators delete, in a hosted repository, the
 * image, a tag, a manifest or a chart's version ({@link ImageDeleteDialog}).
 */
function ImageDetailPage() {
  const { repo, _splat } = Route.useParams()
  const image = _splat ?? ''
  const { tag } = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const detail = useImageDetail(repo, image)
  const me = useMe()
  const del = useDeleteImage(repo, image)
  const [pendingDelete, setPendingDelete] = useState<ImageDeleteTarget | null>(null)

  const crumbs = [
    { label: 'Repositories', to: '/' },
    { label: repo, to: '/repos/$repo', params: { repo } },
    { label: image },
  ]
  const shell = (body: ReactNode) => (
    <Page>
      <PageHeader title={image || repo} icon="Layers" crumbs={crumbs} />
      {body}
    </Page>
  )
  const notFound = (
    <EmptyState title="Image not found" icon="Layers">
      No readable image <Code>{image}</Code> in repository <Code>{repo}</Code>.
    </EmptyState>
  )

  if (image === '') return shell(notFound)

  if (detail.isLoading) {
    return shell(<Skeleton variant="table" label="Loading image…" />)
  }

  if (detail.isError) {
    // A 404 means the image (or repo) is not visible / does not exist; render
    // it as a not-found empty state rather than a scary error panel.
    if (detail.error instanceof ApiError && detail.error.status === 404) {
      return shell(notFound)
    }
    if (isRepositoryOffline(detail.error)) {
      return shell(<RepositoryOfflineState onRetry={() => void detail.refetch()} />)
    }
    return shell(
      <ErrorState
        title="Could not load image"
        message={detail.error?.message}
        onRetry={() => void detail.refetch()}
      />,
    )
  }

  const img = detail.data
  if (!img) return null
  const lastPushed = img.manifests
    .map((m) => m.created_at)
    .filter((t): t is string => !!t)
    .sort()
    .at(-1)
  const chart = isChartImage(img.manifests)
  // The server lists at most 1,000 of each, and counts them all.
  const tagCount = img.tags_total ?? img.tags.length
  const manifestCount = img.manifests_total ?? img.manifests.length
  const selectTag = (next: string) =>
    void navigate({ search: { tag: next }, replace: true })
  const canDelete = me.data?.is_admin === true && img.repo_kind === 'hosted'
  const askDelete = canDelete
    ? (target: ImageDeleteTarget) => {
        del.reset()
        setPendingDelete(target)
      }
    : undefined
  const toRepository = () => void navigate({ to: '/repos/$repo', params: { repo } })
  const deleteDialog = (
    <ImageDeleteDialog
      detail={img}
      target={pendingDelete}
      del={del}
      onClose={() => setPendingDelete(null)}
      onDeleted={async (target) => {
        setPendingDelete(null)
        if (target.kind === 'image') return toRepository()
        // The last manifest gone, the image is too.
        const remaining = await detail.refetch({ cancelRefetch: false })
        if (remaining.error instanceof ApiError && remaining.error.status === 404) {
          toRepository()
        }
      }}
    />
  )
  const header = (
    <PageHeader
      title={img.image}
      icon={chart ? 'Wheel' : 'Layers'}
      crumbs={[
        { label: 'Repositories', to: '/' },
        { label: img.repo, to: '/repos/$repo', params: { repo: img.repo } },
        { label: img.image },
      ]}
      kind={img.repo_kind}
      format="docker"
      meta={[
        chart && 'Helm chart',
        chart
          ? tagCount === 1
            ? '1 version'
            : `${tagCount.toLocaleString()} versions`
          : tagCount === 1
            ? '1 tag'
            : `${tagCount.toLocaleString()} tags`,
        manifestCount === 1 ? '1 manifest' : `${manifestCount.toLocaleString()} manifests`,
        // A proxy's manifests carry their cache time, not a push (#248).
        img.repo_kind === 'hosted' && lastPushed && `Pushed ${formatDateTime(lastPushed)}`,
      ]}
      actions={
        askDelete && (
          <Button
            variant="danger"
            size="sm"
            icon="Trash"
            disabled={del.isPending}
            onClick={() => askDelete({ kind: 'image' })}
          >
            {chart ? 'Delete chart…' : 'Delete image…'}
          </Button>
        )
      }
    />
  )

  if (chart) {
    return (
      <Page>
        {header}
        <ChartView
          detail={img}
          selectedTag={tag}
          onSelectTag={selectTag}
          onDeleteVersion={askDelete && ((t) => askDelete({ kind: 'version', tag: t }))}
          onDeleteManifest={askDelete && ((m) => askDelete({ kind: 'manifest', manifest: m }))}
          deletePending={del.isPending}
        />
        {deleteDialog}
      </Page>
    )
  }

  return (
    <Page>
      {header}

      <PullPanel detail={img} selectedTag={tag} onSelectTag={selectTag} />

      <Panel
        title="Tags"
        count={tagCount}
        flush
        description={[
          cappedNote(img.tags.length, img.tags_total, 'tags'),
          'A tag on an index pulls the platform that matches the client.',
        ]
          .filter(Boolean)
          .join(' ')}
      >
        {img.tags.length === 0 ? (
          <EmptyState title="No tags" icon="Layers" bordered={false}>
            This image has only untagged manifests; pull one by digest.
          </EmptyState>
        ) : (
          <TagTable
            tags={img.tags}
            onDelete={askDelete && ((t) => askDelete({ kind: 'tag', tag: t }))}
            deletePending={del.isPending}
          />
        )}
      </Panel>

      <Panel
        title="Manifests"
        count={manifestCount}
        flush
        description={[
          cappedNote(img.manifests.length, img.manifests_total, 'manifests'),
          'Indexes, the platform images they list, and referrers such as signatures and SBOMs.',
        ]
          .filter(Boolean)
          .join(' ')}
      >
        <ManifestTable
          manifests={img.manifests}
          repoKind={img.repo_kind}
          onDelete={askDelete && ((m) => askDelete({ kind: 'manifest', manifest: m }))}
          deletePending={del.isPending}
        />
      </Panel>
      {deleteDialog}
    </Page>
  )
}

/**
 * `docker pull` by tag (the selected one, else {@link defaultPullTag}:
 * `latest` or the newest image tag) and by digest. An image with no tag at
 * all is pulled by the digest of a top-level manifest (not an index's child,
 * not a referrer).
 */
function PullPanel({
  detail,
  selectedTag,
  onSelectTag,
}: {
  detail: ImageDetail
  selectedTag: string | undefined
  onSelectTag: (tag: string) => void
}) {
  const current =
    detail.tags.find((t) => t.tag === selectedTag) ??
    defaultPullTag(detail.tags, detail.manifests)
  const children = new Set(detail.manifests.flatMap((m) => m.children))
  const digest =
    current?.digest ??
    (
      detail.manifests.find(
        (m) => !m.subject_digest && !children.has(m.digest),
      ) ?? detail.manifests[0]
    )?.digest

  return (
    <Panel
      title="Pull"
      description={
        <>
          Log in first with <Code>docker login {detail.registry}</Code>, using
          an API token from{' '}
          <Link to="/tokens" className="fg-link">
            Your tokens
          </Link>{' '}
          as the password.
        </>
      }
    >
      <div className="flex flex-wrap items-end gap-4">
        {detail.tags.length > 1 && current && (
          <SelectField
            label="Tag"
            className="w-48"
            value={current.tag}
            onChange={(e) => onSelectTag(e.target.value)}
          >
            {detail.tags.map((t) => (
              <option key={t.tag} value={t.tag}>
                {t.tag}
              </option>
            ))}
          </SelectField>
        )}
        {current && (
          <CommandSnippet
            label="By tag"
            className="min-w-0 flex-[1_1_420px]"
            command={`docker pull ${detail.pull_name}:${current.tag}`}
            copyLabel="Copy pull command"
          />
        )}
      </div>
      {digest && (
        <CommandSnippet
          label="By digest"
          command={`docker pull ${detail.pull_name}@${digest}`}
          copyLabel="Copy pull-by-digest command"
        />
      )}
    </Panel>
  )
}
