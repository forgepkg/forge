import { createFileRoute, useNavigate } from '@tanstack/react-router'

import {
  isTrafficRange,
  type TrafficClientDetail,
  type TrafficRange,
  type TrafficTally,
} from '~/api/traffic'
import { formatBytes, formatDateTime } from '~/lib/oci'
import { accountLabel, share, stepLabel, statusTone, surfaceLabel } from '~/lib/traffic'
import { useTrafficClient } from '~/queries/useTraffic'
import { TrafficChart } from '~/components/TrafficChart'
import { TrafficFilters } from '~/components/TrafficFilters'
import { ErrorState } from '~/components/ErrorState'
import {
  EmptyState,
  Notice,
  Page,
  PageHeader,
  Panel,
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
} from '~/components/ui'

/** The screen's URL state: the client network, the range and an instance. */
export interface TrafficClientSearch {
  network: string
  range?: TrafficRange
  instance?: string
}

export const Route = createFileRoute('/_app/manage/traffic/client')({
  validateSearch: (search: Record<string, unknown>): TrafficClientSearch => ({
    network: typeof search.network === 'string' ? search.network : '',
    range: isTrafficRange(search.range) ? search.range : undefined,
    instance:
      typeof search.instance === 'string' && search.instance.length > 0
        ? search.instance
        : undefined,
  }),
  component: TrafficClientScreen,
})

const count = new Intl.NumberFormat()

/**
 * One client network's traffic (`/admin/traffic/client`): its requests over
 * time, from the time buckets it was among the top clients of, and its
 * requests in the request log — what it asked for, as whom, with which
 * client, and how each was answered.
 */
function TrafficClientScreen() {
  const search = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const range = search.range ?? '24h'
  const detail = useTrafficClient(search.network, { range, instance: search.instance })
  const set = (next: Partial<TrafficClientSearch>) =>
    void navigate({ search: (prev) => ({ ...prev, ...next }) })

  return (
    <Page>
      <PageHeader
        title={search.network || 'Client'}
        icon="Globe"
        crumbs={[
          { label: 'Traffic', to: '/manage/traffic', search: { range: search.range, instance: search.instance } },
          { label: search.network || 'Client' },
        ]}
        description="A client network's requests: its counts while it was among the top clients, and its requests in the request log."
      />
      {!search.network ? (
        <EmptyState title="No client named" icon="Globe">
          Open a client from the top clients of the traffic screen.
        </EmptyState>
      ) : (
        <>
          <TrafficFilters
            range={range}
            onRange={(r) => set({ range: r })}
            instance={search.instance}
            instances={detail.data?.instances ?? []}
            onInstance={(i) => set({ instance: i })}
          />
          {detail.isError ? (
            <ErrorState
              title="Could not load the client's traffic"
              message={detail.error.body || detail.error.message}
              onRetry={() => void detail.refetch()}
            />
          ) : !detail.data ? (
            <Skeleton lines={6} label="Loading the client's traffic…" />
          ) : (
            <div className={detail.isPlaceholderData ? 'grid gap-6 opacity-60' : 'grid gap-6'}>
              <Body data={detail.data} />
            </div>
          )}
        </>
      )}
    </Page>
  )
}

function Body({ data }: { data: TrafficClientDetail }) {
  const totals = data.totals
  const log = data.log
  return (
    <>
      {!data.recording.client_addresses && (
        <Notice tone="info">
          Client addresses are not recorded now: the traffic settings switch
          them off. What was recorded before stays until it expires.
        </Notice>
      )}
      <StatRow>
        <Stat label="Requests" icon="Activity" value={count.format(totals?.requests ?? 0)} />
        <Stat label="Data sent" icon="Download" value={formatBytes(totals?.bytes ?? 0)} />
        <Stat
          label="4xx answers"
          icon="Alert"
          value={count.format(totals?.client_errors ?? 0)}
          sub={`${count.format(totals?.denied ?? 0)} refused, ${count.format(totals?.throttled ?? 0)} throttled`}
        />
        <Stat
          label="5xx answers"
          icon="Alert"
          value={count.format(totals?.server_errors ?? 0)}
        />
        <Stat
          label="Last seen"
          icon="Clock"
          value={formatDateTime(totals?.last_seen)}
          sub={totals?.hosts.length ? `on ${totals.hosts.join(', ')}` : undefined}
        />
      </StatRow>

      <Panel
        title="Over time"
        description={`Requests, ${stepLabel(data.step_seconds)}, counted while this client was among the top 100 of a minute or an hour.`}
      >
        {!totals ? (
          <EmptyState title="Not among the top clients in this range" icon="Activity" bordered={false} />
        ) : (
          <TrafficChart points={data.series} stepSeconds={data.step_seconds} metric="requests" view="chart" />
        )}
      </Panel>

      <Panel
        title="Request log"
        count={log.matched}
        description={`Its requests from ${formatDateTime(log.from)} to ${formatDateTime(log.to)} (the last 24 hours of the range at most)${
          log.matched > log.entries.length ? `, the newest ${log.entries.length} shown` : ''
        }.`}
        flush
      >
        {!data.recording.request_log && (
          <Notice tone="info">
            The request log is switched off in the traffic settings: new
            requests are not logged.
          </Notice>
        )}
        {log.entries.length === 0 ? (
          <EmptyState title="No requests in the log" icon="File" bordered={false} />
        ) : (
          <LogTable data={data} />
        )}
      </Panel>

      {log.matched > 0 && (
        <div className="grid gap-6 lg:grid-cols-2">
          <TallyPanel title="Paths" tallies={log.paths} total={log.matched} mono />
          <TallyPanel title="User agents" tallies={log.user_agents} total={log.matched} mono />
          <TallyPanel
            title="Accounts"
            tallies={log.accounts.map((a) => ({
              value: accountLabel(a.account, a.username, a.user_id),
              requests: a.requests,
            }))}
            total={log.matched}
          />
          <TallyPanel title="Statuses" tallies={log.statuses} total={log.matched} mono />
        </div>
      )}
    </>
  )
}

function LogTable({ data }: { data: TrafficClientDetail }) {
  return (
    <Table caption="Request log" dense>
      <TableHead>
        <TableHeader>Time</TableHeader>
        <TableHeader>Request</TableHeader>
        <TableHeader>Status</TableHeader>
        <TableHeader align="right">Data sent</TableHeader>
        <TableHeader align="right">Took</TableHeader>
        <TableHeader>Account</TableHeader>
        <TableHeader>User agent</TableHeader>
        <TableHeader>Instance</TableHeader>
      </TableHead>
      <TableBody>
        {data.log.entries.map((e, i) => (
          <TableRow key={`${e.time}-${i}`}>
            <TableCell nowrap>{new Date(e.time).toLocaleString()}</TableCell>
            <TableCell>
              <span className="fg-mono">
                {e.method} {e.path}
              </span>
              <div className="fg-text fg-text--small">
                {e.repository ?? surfaceLabel(e.surface)}
                {e.address && e.address !== data.network ? ` · ${e.address}` : ''}
              </div>
            </TableCell>
            <TableCell>
              <StatusBadge tone={statusTone(e.status)}>{String(e.status)}</StatusBadge>
            </TableCell>
            <TableCell align="right">{formatBytes(e.bytes)}</TableCell>
            <TableCell align="right" nowrap>
              {e.duration_ms < 10 ? e.duration_ms.toFixed(1) : Math.round(e.duration_ms)} ms
            </TableCell>
            <TableCell>{accountLabel(e.account, e.username, e.user_id)}</TableCell>
            <TableCell>
              <span className="fg-mono">{e.user_agent ?? '—'}</span>
            </TableCell>
            <TableCell>{e.host}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function TallyPanel({
  title,
  tallies,
  total,
  mono = false,
}: {
  title: string
  tallies: TrafficTally[]
  total: number
  mono?: boolean
}) {
  return (
    <Panel title={title} flush>
      <Table caption={`${title} in the request log`} dense>
        <TableHead>
          <TableHeader>{title.replace(/s$/, '')}</TableHeader>
          <TableHeader align="right">Requests</TableHeader>
          <TableHeader align="right">Share</TableHeader>
        </TableHead>
        <TableBody>
          {tallies.map((t) => (
            <TableRow key={t.value}>
              <TableCell>{mono ? <span className="fg-mono">{t.value}</span> : t.value}</TableCell>
              <TableCell align="right">{count.format(t.requests)}</TableCell>
              <TableCell align="right">{share(t.requests, total)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Panel>
  )
}
