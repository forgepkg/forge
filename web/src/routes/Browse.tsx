import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { useBrowseRepos } from '~/queries/useBrowseRepos'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import {
  CellStack,
  FormatTag,
  Icon,
  KindBadge,
  Page,
  PageHeader,
  Panel,
  SegmentedControl,
  Skeleton,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Toolbar,
  formatIcon,
  formatLabel,
} from '~/components/ui'

/** The browse root's URL state: an optional format filter. */
interface BrowseSearch {
  format?: string
}

export const Route = createFileRoute('/_app/')({
  validateSearch: (search: Record<string, unknown>): BrowseSearch =>
    typeof search.format === 'string' && search.format.length > 0
      ? { format: search.format }
      : {},
  component: Browse,
})

/**
 * Browse root: the repositories the signed-in user may read, rendered as the
 * top level of the folder view (repository → packages → versions, or for a
 * docker repository: repository → images → tags). Each row shows the kind and
 * the format; with repositories of several formats, a filter keeps one
 * format's (in the URL, so it is shareable). Search is per repository and
 * lives on the repository screen, not here. An offline repository carries an
 * "offline" badge.
 */
function Browse() {
  const repos = useBrowseRepos()
  const { format } = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const all = repos.data ?? []
  const formats = [...new Set([...all.map((r) => r.format), ...(format ? [format] : [])])].sort()
  const shown = all.filter((r) => !format || r.format === format)

  return (
    <Page>
      <PageHeader
        title="Browse"
        description="The repositories you can read. Open one to browse and search its packages, images or files, and to get its connection commands."
      />

      {repos.isError ? (
        <ErrorState
          title="Could not load repositories"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <Skeleton variant="table" rows={4} columns={4} label="Loading repositories…" />
      ) : all.length === 0 ? (
        <EmptyState title="No repositories" icon="Repository">
          You have no readable repositories yet. Ask an administrator to grant
          you access.
        </EmptyState>
      ) : (
        <Panel title="Repositories" count={shown.length} flush>
          {formats.length > 1 && (
            <Toolbar>
              <SegmentedControl
                label="Filter by format"
                value={format ?? ''}
                onChange={(f) => void navigate({ search: f ? { format: f } : {} })}
                items={[
                  { id: '', label: 'All', count: all.length },
                  ...formats.map((f) => ({
                    id: f,
                    label: formatLabel(f),
                    count: all.filter((r) => r.format === f).length,
                  })),
                ]}
              />
            </Toolbar>
          )}
          {shown.length === 0 ? (
            <EmptyState
              title={`No ${formatLabel(format ?? '')} repositories`}
              bordered={false}
            >
              None of the repositories you may read has this format.
            </EmptyState>
          ) : (
            <Table caption="Repositories you can read">
              <TableHead>
                <TableHeader>Repository</TableHeader>
                <TableHeader width="120px">Kind</TableHeader>
                <TableHeader width="120px">Format</TableHeader>
                <TableHeader width="140px">Status</TableHeader>
              </TableHead>
              <TableBody>
                {shown.map((repo) => (
                  <TableRow key={repo.name}>
                    <TableCell lead>
                      <CellStack sub={repo.url}>
                        <Link
                          to="/repos/$repo"
                          params={{ repo: repo.name }}
                          className="fg-link-strong"
                        >
                          <Icon name={formatIcon(repo.format)} size={16} />
                          <span>{repo.name}</span>
                        </Link>
                      </CellStack>
                    </TableCell>
                    <TableCell>
                      <KindBadge kind={repo.kind} />
                    </TableCell>
                    <TableCell>
                      <FormatTag format={repo.format} />
                    </TableCell>
                    <TableCell>
                      {repo.online === false ? (
                        <StatusBadge
                          tone="neutral"
                          title={
                            repo.kind === 'proxy'
                              ? 'Offline: shows only the packages Forge has cached'
                              : 'Offline for maintenance'
                          }
                        >
                          offline
                        </StatusBadge>
                      ) : (
                        <StatusBadge tone="ok">online</StatusBadge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
      )}
    </Page>
  )
}

/** A folder glyph for folder-view rows (raw directories). */
export function FolderIcon() {
  return <Icon name="Folder" size={16} className="text-ink-faint" />
}

/** A right-pointing chevron at the end of folder-view rows. */
export function ChevronIcon() {
  return <Icon name="ChevronRight" size={16} className="ml-auto text-ink-faint" />
}
