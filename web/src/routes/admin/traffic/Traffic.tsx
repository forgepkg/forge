import { useState } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { isTrafficRange, type TrafficOverview, type TrafficRange } from '~/api/traffic'
import { formatBytes, formatDateTime } from '~/lib/oci'
import { accountLabel, latencySummary, share, stepLabel, surfaceLabel } from '~/lib/traffic'
import { useTrafficOverview } from '~/queries/useTraffic'
import { TRAFFIC_METRICS, TrafficChart, type TrafficMetric } from '~/components/TrafficChart'
import { TrafficFilters } from '~/components/TrafficFilters'
import { ErrorState } from '~/components/ErrorState'
import {
  Button,
  Chip,
  EmptyState,
  Notice,
  Page,
  PageHeader,
  Panel,
  SegmentedControl,
  Skeleton,
  Stat,
  StatRow,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '~/components/ui'

/** The screen's URL state: the range, and an instance or repository to narrow to. */
export interface TrafficSearch {
  range?: TrafficRange
  instance?: string
  repository?: string
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

export const Route = createFileRoute('/_app/manage/traffic')({
  validateSearch: (search: Record<string, unknown>): TrafficSearch => ({
    range: isTrafficRange(search.range) ? search.range : undefined,
    instance: text(search.instance),
    repository: text(search.repository),
  }),
  component: TrafficScreen,
})

const count = new Intl.NumberFormat()

/**
 * The traffic screen (`/admin/traffic`): what every instance answered in a
 * range — requests over time, their totals and latency, the repositories,
 * surfaces and statuses, and the clients with the most requests, each
 * opening its own view with its request log. The range, the instance and
 * the repository are in the URL, so a view can be shared.
 */
function TrafficScreen() {
  const search = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const range = search.range ?? '24h'
  const overview = useTrafficOverview({
    range,
    instance: search.instance,
    repository: search.repository,
  })
  const set = (next: Partial<TrafficSearch>) =>
    void navigate({ search: (prev) => ({ ...prev, ...next }) })

  return (
    <Page>
      <PageHeader
        title="Traffic"
        icon="Activity"
        description="What every instance of this install answered: requests over time, by repository and status, and the clients with the most requests. The numbers are written to the object store once a minute."
        actions={
          <Button href="/manage/traffic/settings" icon="Sliders" size="sm">
            Settings
          </Button>
        }
      />
      <TrafficFilters
        range={range}
        onRange={(r) => set({ range: r })}
        instance={search.instance}
        instances={overview.data?.instances ?? []}
        onInstance={(i) => set({ instance: i })}
      />
      {search.repository && (
        <p className="fg-text">
          Only <Chip>{search.repository}</Chip>{' '}
          <Button size="sm" variant="ghost" icon="X" onClick={() => set({ repository: undefined })}>
            All repositories
          </Button>
        </p>
      )}
      {overview.isError ? (
        <ErrorState
          title="Could not load the traffic"
          message={overview.error.body || overview.error.message}
          onRetry={() => void overview.refetch()}
        />
      ) : !overview.data ? (
        <Skeleton lines={6} label="Loading the traffic…" />
      ) : (
        <div className={overview.isPlaceholderData ? 'grid gap-6 opacity-60' : 'grid gap-6'}>
          <Body data={overview.data} repository={search.repository} />
        </div>
      )}
    </Page>
  )
}

function Body({ data, repository }: { data: TrafficOverview; repository?: string }) {
  const [metric, setMetric] = useState<TrafficMetric>('requests')
  const [view, setView] = useState<'chart' | 'table'>('chart')
  const { totals, recording } = data
  return (
    <>
      {!recording.enabled && (
        <Notice tone="warn" title="Traffic is not recorded">
          Recording is switched off in the traffic settings: no instance counts
          requests until it is switched on again. What was written before stays
          until it expires.
        </Notice>
      )}
      <StatRow>
        <Stat
          label="Requests"
          icon="Activity"
          value={count.format(totals.requests)}
          sub={latencySummary(totals) ?? undefined}
        />
        <Stat label="Data sent" icon="Download" value={formatBytes(totals.bytes)} />
        <Stat
          label="4xx answers"
          icon="Alert"
          value={count.format(totals.client_errors)}
          sub={`${count.format(totals.denied)} refused, ${count.format(totals.not_found)} not found, ${count.format(totals.throttled)} throttled`}
        />
        <Stat
          label="5xx answers"
          icon="Alert"
          value={count.format(totals.server_errors)}
          sub={`${share(totals.server_errors, totals.requests)} of the requests`}
        />
      </StatRow>

      <Panel
        title="Over time"
        description={`${TRAFFIC_METRICS.find((m) => m.id === metric)?.label}, ${stepLabel(data.step_seconds)}, from ${formatDateTime(data.from)} to ${formatDateTime(data.to)}. The last minutes fill in as the instances write them.`}
        actions={
          <div className="fg-filters">
            <SegmentedControl label="Measure" value={metric} onChange={setMetric} items={TRAFFIC_METRICS} />
            <SegmentedControl
              label="Show as"
              value={view}
              onChange={setView}
              items={[
                { id: 'chart', label: 'Chart' },
                { id: 'table', label: 'Table' },
              ]}
            />
          </div>
        }
      >
        {totals.requests === 0 ? (
          <EmptyState title="No requests in this range" icon="Activity" bordered={false}>
            Nothing was counted here yet. Each instance writes what it counted
            once a minute.
          </EmptyState>
        ) : (
          <TrafficChart points={data.series} stepSeconds={data.step_seconds} metric={metric} view={view} />
        )}
      </Panel>

      <Panel
        title="Top clients"
        count={data.clients.length}
        description="The client networks with the most requests (an IPv6 client counts by its /64), from each minute's or hour's top 100. Open one for its requests."
        flush
      >
        {!recording.client_addresses && (
          <Notice tone="info">
            Client addresses are not recorded: the traffic settings switch them off.
          </Notice>
        )}
        {data.clients.length === 0 ? (
          <EmptyState title="No clients in this range" icon="Globe" bordered={false} />
        ) : (
          <ClientTable data={data} />
        )}
        {repository && (
          <p className="fg-text fg-text--small px-5 pb-4">
            The top clients count every repository.
          </p>
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Repositories" count={data.repositories.length} flush>
          {data.repositories.length === 0 ? (
            <EmptyState title="No repository requests" icon="Repository" bordered={false} />
          ) : (
            <Table caption="Repositories by requests" dense>
              <TableHead>
                <TableHeader>Repository</TableHeader>
                <TableHeader align="right">Requests</TableHeader>
                <TableHeader align="right">Data sent</TableHeader>
                <TableHeader align="right">4xx</TableHeader>
                <TableHeader align="right">5xx</TableHeader>
              </TableHead>
              <TableBody>
                {data.repositories.map((r) => (
                  <TableRow key={r.name}>
                    <TableCell lead>
                      <Link
                        to="/manage/traffic"
                        search={(prev) => ({ ...prev, repository: r.name })}
                        className="fg-link"
                      >
                        {r.name}
                      </Link>
                    </TableCell>
                    <TableCell align="right">{count.format(r.requests)}</TableCell>
                    <TableCell align="right">{formatBytes(r.bytes)}</TableCell>
                    <TableCell align="right">{count.format(r.client_errors)}</TableCell>
                    <TableCell align="right">{count.format(r.server_errors)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
        <Panel title="Surfaces and statuses" flush>
          <Table caption="Requests by surface" dense>
            <TableHead>
              <TableHeader>Surface</TableHeader>
              <TableHeader align="right">Requests</TableHeader>
              <TableHeader align="right">Data sent</TableHeader>
            </TableHead>
            <TableBody>
              {data.surfaces.map((s) => (
                <TableRow key={s.surface}>
                  <TableCell lead>{surfaceLabel(s.surface)}</TableCell>
                  <TableCell align="right">{count.format(s.requests)}</TableCell>
                  <TableCell align="right">{formatBytes(s.bytes)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Table caption="Requests by status" dense>
            <TableHead>
              <TableHeader>Status</TableHeader>
              <TableHeader align="right">Requests</TableHeader>
              <TableHeader align="right">Share</TableHeader>
            </TableHead>
            <TableBody>
              {data.statuses.map((s) => (
                <TableRow key={s.status}>
                  <TableCell lead>
                    <span className="fg-mono">{s.status}</span>
                  </TableCell>
                  <TableCell align="right">{count.format(s.requests)}</TableCell>
                  <TableCell align="right">{share(s.requests, totals.requests)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      </div>
    </>
  )
}

function ClientTable({ data }: { data: TrafficOverview }) {
  return (
    <Table caption="Top clients">
      <TableHead>
        <TableHeader>Client</TableHeader>
        <TableHeader align="right">Requests</TableHeader>
        <TableHeader align="right">Data sent</TableHeader>
        <TableHeader align="right">4xx</TableHeader>
        <TableHeader align="right">5xx</TableHeader>
        <TableHeader>Last account</TableHeader>
        <TableHeader>Last user agent</TableHeader>
        <TableHeader>Instances</TableHeader>
        <TableHeader>Last seen</TableHeader>
      </TableHead>
      <TableBody>
        {data.clients.map((c) => (
          <TableRow key={c.network}>
            <TableCell lead nowrap>
              <Link
                to="/manage/traffic/client"
                search={(prev) => ({
                  network: c.network,
                  range: prev.range,
                  instance: prev.instance,
                })}
                className="fg-link fg-mono"
              >
                {c.network}
              </Link>
              {c.address && c.address !== c.network && (
                <div className="fg-text fg-text--small fg-mono">{c.address}</div>
              )}
            </TableCell>
            <TableCell align="right">{count.format(c.requests)}</TableCell>
            <TableCell align="right">{formatBytes(c.bytes)}</TableCell>
            <TableCell align="right">{count.format(c.client_errors)}</TableCell>
            <TableCell align="right">{count.format(c.server_errors)}</TableCell>
            <TableCell>{accountLabel(c.account, c.username, c.user_id)}</TableCell>
            <TableCell>
              <span className="fg-mono" title={c.user_agent ?? undefined}>
                {c.user_agent ? truncate(c.user_agent, 40) : '—'}
              </span>
            </TableCell>
            <TableCell>{c.hosts.join(', ')}</TableCell>
            <TableCell nowrap>{formatDateTime(c.last_seen)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}
