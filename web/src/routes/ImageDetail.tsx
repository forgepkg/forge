import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import type { ImageDetail } from '~/api/images'
import { isRepositoryOffline } from '~/api/packages'
import { ApiError } from '~/lib/httpClient'
import { defaultPullTag } from '~/lib/oci'
import { useImageDetail } from '~/queries/useImageDetail'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Code, Text } from '~/components/catalyst/text'
import { Divider } from '~/components/catalyst/divider'
import { Field, Label } from '~/components/catalyst/fieldset'
import { Select } from '~/components/catalyst/select'
import { RepoKindBadge } from '~/components/RepoKindBadge'
import { CommandSnippet } from '~/components/CopyButton'
import { ManifestTable, TagTable } from '~/components/ImageTables'
import { ErrorState, RepositoryOfflineState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { Breadcrumbs } from '~/components/Breadcrumbs'

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
  component: ImageDetailPage,
})

/**
 * Image-detail view of a docker repository: the pull commands (by tag and by
 * digest), the image's tags, and every manifest it holds — images, indexes
 * and referrers such as signatures — with sizes, platforms and timestamps.
 * Loading / not-found / error states mirror the package-detail screen.
 */
function ImageDetailPage() {
  const { repo, _splat } = Route.useParams()
  const image = _splat ?? ''
  const { tag } = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const detail = useImageDetail(repo, image)

  const notFound = (
    <EmptyState title="Image not found">
      No readable image <span className="font-mono">{image}</span> in
      repository <span className="font-mono">{repo}</span>.
    </EmptyState>
  )

  if (image === '') return notFound

  if (detail.isLoading) {
    return <Text>Loading image…</Text>
  }

  if (detail.isError) {
    // A 404 means the image (or repo) is not visible / does not exist; render
    // it as a not-found empty state rather than a scary error panel.
    if (detail.error instanceof ApiError && detail.error.status === 404) {
      return notFound
    }
    if (isRepositoryOffline(detail.error)) {
      return <RepositoryOfflineState onRetry={() => void detail.refetch()} />
    }
    return (
      <ErrorState
        title="Could not load image"
        message={detail.error?.message}
        onRetry={() => void detail.refetch()}
      />
    )
  }

  const img = detail.data
  if (!img) return null

  return (
    <section className="space-y-8">
      <div className="space-y-2">
        <Breadcrumbs
          items={[
            { label: 'Repositories', to: '/' },
            { label: img.repo, to: '/repos/$repo', params: { repo: img.repo } },
            { label: img.image },
          ]}
        />
        <div className="flex flex-wrap items-center gap-3">
          <Heading className="break-all">{img.image}</Heading>
          <span className="flex items-center gap-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            {img.repo}
            <RepoKindBadge kind={img.repo_kind} />
          </span>
        </div>
      </div>

      <PullPanel
        detail={img}
        selectedTag={tag}
        onSelectTag={(next) =>
          void navigate({ search: { tag: next }, replace: true })
        }
      />

      <section aria-labelledby="image-tags">
        <Subheading id="image-tags">Tags</Subheading>
        <div className="mt-3">
          {img.tags.length === 0 ? (
            <EmptyState title="No tags">
              This image has only untagged manifests; pull one by digest.
            </EmptyState>
          ) : (
            <TagTable tags={img.tags} />
          )}
        </div>
      </section>

      <Divider />

      <section aria-labelledby="image-manifests">
        <Subheading id="image-manifests">Manifests</Subheading>
        <div className="mt-3">
          <ManifestTable
            manifests={img.manifests}
            showSource={img.repo_kind === 'group'}
          />
        </div>
      </section>
    </section>
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
    <section
      aria-labelledby="image-pull"
      className="space-y-4 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Subheading id="image-pull">Pull</Subheading>
          <Text className="mt-1">
            Log in first with <Code>docker login {detail.registry}</Code>,
            using an API token from the{' '}
            <Link
              to="/tokens"
              className="text-sky-600 hover:underline dark:text-sky-400"
            >
              Tokens
            </Link>{' '}
            page as the password.
          </Text>
        </div>
        {detail.tags.length > 1 && current && (
          <Field className="w-48">
            <Label>Tag</Label>
            <Select
              value={current.tag}
              onChange={(e) => onSelectTag(e.target.value)}
            >
              {detail.tags.map((t) => (
                <option key={t.tag} value={t.tag}>
                  {t.tag}
                </option>
              ))}
            </Select>
          </Field>
        )}
      </div>
      {current && (
        <CommandSnippet
          label="By tag"
          command={`docker pull ${detail.pull_name}:${current.tag}`}
          copyLabel="Copy pull command"
        />
      )}
      {digest && (
        <CommandSnippet
          label="By digest"
          command={`docker pull ${detail.pull_name}@${digest}`}
          copyLabel="Copy pull-by-digest command"
        />
      )}
    </section>
  )
}
