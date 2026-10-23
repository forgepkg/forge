import { useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'

import type { RepoView } from '~/api/repositories'
import {
  useDeleteRepository,
  useRepositories,
} from '~/queries/useRepositories'
import {
  Button,
  CellActions,
  CellStack,
  Dialog,
  FormatTag,
  Icon,
  KindBadge,
  Menu,
  Notice,
  Page,
  PageHeader,
  Panel,
  SearchField,
  SegmentedControl,
  Skeleton,
  Stat,
  StatRow,
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
  type MenuItem,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { EmptyState } from '~/components/EmptyState'
import { capitalize, repositoryFacts } from '~/components/RepositoryForm'

export const Route = createFileRoute('/_app/manage/repositories')({
  component: RepositoriesList,
})

type KindFilter = 'all' | 'hosted' | 'proxy' | 'group'

/**
 * Admin repositories list. Lists every repository with its format (NuGet /
 * Docker), kind, online / anonymous-read flags and its notable settings, and
 * links to edit / (for groups) members / delete from each row's menu. Above
 * the table, the counts by format, offline and anonymous read, and a filter by
 * name and kind over the loaded list (not kept in the URL). Delete asks in a
 * dialog and surfaces the server's conflict message above the table (a hosted
 * repo with packages refuses deletion).
 */
function RepositoriesList() {
  const repos = useRepositories()
  const del = useDeleteRepository()
  const [pendingDelete, setPendingDelete] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<KindFilter>('all')

  function confirmDelete(name: string) {
    del.mutate(name, {
      onSettled: () => setPendingDelete(null),
    })
  }

  const all = repos.data ?? []
  const needle = query.trim().toLowerCase()
  const shown = all.filter(
    (r) =>
      (kind === 'all' || r.kind === kind) &&
      (needle === '' || r.name.toLowerCase().includes(needle)),
  )
  const target = all.find((r) => r.name === pendingDelete)

  return (
    <Page>
      <PageHeader
        title="Repositories"
        description="Create and manage hosted, proxy, and group repositories — NuGet feeds and Docker registries."
        actions={
          <Button variant="primary" icon="Plus" href="/manage/repositories/new">
            New repository
          </Button>
        }
      />

      {del.isError && (
        <Notice tone="danger" title={`Could not delete ${del.variables}`}>
          {del.error.body || del.error.message}
        </Notice>
      )}

      {repos.isError ? (
        <ErrorState
          title="Could not load repositories"
          message={repos.error?.message}
          onRetry={() => void repos.refetch()}
        />
      ) : repos.isLoading ? (
        <Skeleton variant="table" rows={5} columns={4} label="Loading repositories…" />
      ) : all.length === 0 ? (
        <EmptyState title="No repositories yet" icon="Repository">
          Create your first repository to start serving packages.
        </EmptyState>
      ) : (
        <>
          <RepositoryStats repos={all} />
          <Panel title="All repositories" count={all.length} flush>
            <Toolbar>
              <SearchField
                label="Filter repositories"
                placeholder="Filter by name…"
                value={query}
                onChange={setQuery}
                className="min-w-0 flex-[0_1_320px]"
              />
              <SegmentedControl
                label="Filter by kind"
                value={kind}
                onChange={setKind}
                items={[
                  { id: 'all', label: 'All', count: all.length },
                  ...(['hosted', 'proxy', 'group'] as const).map((k) => ({
                    id: k,
                    label: capitalize(k),
                    count: all.filter((r) => r.kind === k).length,
                  })),
                ]}
              />
            </Toolbar>
            {shown.length === 0 ? (
              <EmptyState
                title="No repositories match"
                icon="Search"
                bordered={false}
                action={
                  <Button
                    size="sm"
                    onClick={() => {
                      setQuery('')
                      setKind('all')
                    }}
                  >
                    Clear the filter
                  </Button>
                }
              >
                {noMatch(kind, query.trim())}
              </EmptyState>
            ) : (
              <Table caption="All repositories">
                <TableHead>
                  <TableHeader>Name</TableHeader>
                  <TableHeader width="130px">Format</TableHeader>
                  <TableHeader width="100px">Kind</TableHeader>
                  <TableHeader width="200px">Status</TableHeader>
                  <TableHeader width="56px" align="right">
                    <span className="fg-sr">Actions</span>
                  </TableHeader>
                </TableHead>
                <TableBody>
                  {shown.map((repo) => (
                    <RepoRow
                      key={repo.id}
                      repo={repo}
                      onRequestDelete={() => setPendingDelete(repo.name)}
                    />
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>
        </>
      )}

      <Dialog
        open={target !== undefined}
        onClose={() => setPendingDelete(null)}
        title={`Delete ${target?.name ?? ''}?`}
        icon="Trash"
        tone="danger"
        description={target && deleteConsequence(target)}
        confirmLabel={del.isPending ? 'Deleting…' : `Delete ${target?.name ?? ''}`}
        confirmVariant="danger-solid"
        confirmIcon="Trash"
        confirmDisabled={del.isPending}
        onConfirm={() => target && confirmDelete(target.name)}
      />
    </Page>
  )
}

/** Why the filter shows nothing. */
function noMatch(kind: KindFilter, query: string): string {
  const what = kind === 'all' ? 'repository' : `${kind} repository`
  return query === ''
    ? `There is no ${what}.`
    : `No ${what} has a name containing “${query}”.`
}

/** What deleting a repository takes with it, for the confirmation. */
function deleteConsequence(repo: RepoView): string {
  const failing = 'Clients that use its URL start failing. This cannot be undone.'
  if (repo.kind === 'hosted') {
    return `A hosted repository is deleted only once it holds nothing: Forge refuses while ${repo.format === 'docker' ? 'images' : repo.format === 'raw' ? 'files' : 'packages'} are left. ${failing}`
  }
  if (repo.kind === 'proxy') return `Its cache goes with it. ${failing}`
  return `Its members stay as they are. ${failing}`
}

/** The overview row: counts from the list already loaded. */
function RepositoryStats({ repos }: { repos: RepoView[] }) {
  const formats = [...new Set(repos.map((r) => r.format))].sort()
  const offline = repos.filter((r) => !r.online).length
  const anonymous = repos.filter((r) => r.anonymous_read).length
  return (
    <StatRow>
      <Stat
        label="Repositories"
        icon="Repository"
        value={repos.length}
        sub={formats
          .map((f) => `${repos.filter((r) => r.format === f).length} ${formatLabel(f)}`)
          .join(' · ')}
      />
      <Stat
        label="Offline"
        icon="Alert"
        value={offline}
        sub={`of ${repos.length} ${repos.length === 1 ? 'repository' : 'repositories'}`}
      />
      <Stat
        label="Anonymous read"
        icon="Globe"
        value={anonymous}
        sub="readable without signing in"
      />
    </StatRow>
  )
}

function RepoRow({
  repo,
  onRequestDelete,
}: {
  repo: RepoView
  onRequestDelete: () => void
}) {
  const facts = repositoryFacts(repo)
  const items: MenuItem[] = [
    { label: 'Edit', icon: 'Pencil', href: `/manage/repositories/${repo.name}` },
  ]
  if (repo.kind === 'group') {
    items.push({
      label: 'Members',
      icon: 'Users',
      href: `/manage/repositories/${repo.name}/members`,
    })
  }
  items.push(
    { divider: true },
    { label: 'Delete', icon: 'Trash', danger: true, onSelect: onRequestDelete },
  )
  return (
    <TableRow>
      <TableCell lead>
        <CellStack sub={facts.length > 0 ? capitalize(facts.join(' · ')) : undefined}>
          <Link
            to="/manage/repositories/$repo"
            params={{ repo: repo.name }}
            className="fg-link-strong"
          >
            <Icon name={formatIcon(repo.format)} size={16} />
            <span>{repo.name}</span>
          </Link>
        </CellStack>
      </TableCell>
      <TableCell>
        <FormatTag format={repo.format} />
      </TableCell>
      <TableCell>
        <KindBadge kind={repo.kind} />
      </TableCell>
      <TableCell>
        <span className="fg-cell-badges">
          {repo.online ? (
            <StatusBadge tone="ok">online</StatusBadge>
          ) : (
            <StatusBadge>offline</StatusBadge>
          )}
          {repo.anonymous_read && (
            <StatusBadge tone="warn" icon="Globe">
              anonymous read
            </StatusBadge>
          )}
        </span>
      </TableCell>
      <TableCell align="right">
        <CellActions>
          <Menu items={items} label={`Actions for ${repo.name}`} iconOnly />
        </CellActions>
      </TableCell>
    </TableRow>
  )
}
