import { useState, type ReactNode } from 'react'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'

import { isTrafficRange, NONE, type TrafficOverview, type TrafficRange } from '~/api/traffic'
import { formatBytes } from '~/lib/oci'
import { asnLabel, countryName, dayLabel, repositoryLabel, share } from '~/lib/traffic'
import { useTrafficOverview } from '~/queries/useTraffic'
import { TRAFFIC_METRICS, TrafficChart, type TrafficMetric } from '~/components/TrafficChart'
import { TrafficFilters } from '~/components/TrafficFilters'
import { ErrorState } from '~/components/ErrorState'
import {
  Button,
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

/** The screen's URL state: the range, an instance, and what to narrow to. */
export interface TrafficSearch {
  range?: TrafficRange
  instance?: string
  /** `-` for the requests to no repository. */
  repository?: string
  network?: string
  /** ISO code; `-` for unknown. */
  country?: string
  /** `0` for unknown. */
  asn?: string
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

export const Route = createFileRoute('/_app/manage/traffic')({
  validateSearch: (search: Record<string, unknown>): TrafficSearch => ({
    range: isTrafficRange(search.range) ? search.range : undefined,
    instance: text(search.instance),
    repository: text(search.repository),
    network: text(search.network),
    country: text(search.country),
    asn: /^\d+$/.test(String(search.asn ?? '')) ? String(search.asn) : undefined,
  }),
  component: TrafficScreen,
})

const count = new Intl.NumberFormat()

/** The filters a list row sets: what it is, in the URL's words. */
type Narrow = Pick<TrafficSearch, 'repository' | 'network' | 'country' | 'asn'>

/**
 * The traffic screen (`/admin/traffic`): how many requests each client
 * network made to each repository, by day, and where they came from
 * (countries and autonomous systems, with a geolocation database). Every
 * list narrows the view: open a repository to see where its requests came
 * from, a country or a network to see what it asked for. The range, the
 * instance and the filters are in the URL, so a view can be shared.
 */
function TrafficScreen() {
  const search = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const range = search.range ?? '30d'
  const overview = useTrafficOverview({
    range,
    instance: search.instance,
    repository: search.repository,
    network: search.network,
    country: search.country,
    asn: search.asn,
  })
  const set = (next: Partial<TrafficSearch>) =>
    void navigate({ search: (prev) => ({ ...prev, ...next }) })

  return (
    <Page>
      <PageHeader
        title="Traffic"
        icon="Activity"
        description="How many requests each client made to each repository, by day, over every instance, and where they came from. Open a repository, country, network or client to narrow the view to it."
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
      <ActiveFilters search={search} onClear={set} />
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
          <Body data={overview.data} />
        </div>
      )}
    </Page>
  )
}

/** The filters in force, each with a button that removes it. */
function ActiveFilters({
  search,
  onClear,
}: {
  search: TrafficSearch
  onClear: (next: Partial<TrafficSearch>) => void
}) {
  const active: { key: keyof Narrow; label: string }[] = []
  if (search.repository) {
    active.push({
      key: 'repository',
      label: `Repository: ${search.repository === NONE ? repositoryLabel('') : search.repository}`,
    })
  }
  if (search.country) {
    active.push({
      key: 'country',
      label: `Country: ${countryName(search.country === NONE ? '' : search.country)}`,
    })
  }
  if (search.asn) {
    active.push({ key: 'asn', label: `Network: ${search.asn === '0' ? 'Unknown' : `AS${search.asn}`}` })
  }
  if (search.network) active.push({ key: 'network', label: `Client: ${search.network}` })
  if (active.length === 0) return null
  return (
    <div className="fg-filters" aria-label="Filters">
      {active.map((f) => (
        <Button
          key={f.key}
          size="sm"
          variant="secondary"
          iconEnd="X"
          aria-label={`Remove the filter ${f.label}`}
          onClick={() => onClear({ [f.key]: undefined })}
        >
          {f.label}
        </Button>
      ))}
      {active.length > 1 && (
        <Button
          size="sm"
          variant="ghost"
          onClick={() =>
            onClear({ repository: undefined, country: undefined, asn: undefined, network: undefined })
          }
        >
          Clear all
        </Button>
      )}
    </div>
  )
}

/** A link that narrows the view to `narrow`, keeping the range and instance. */
function NarrowLink({ narrow, children, mono }: { narrow: Narrow; children: ReactNode; mono?: boolean }) {
  return (
    <Link
      to="/manage/traffic"
      search={(prev: TrafficSearch) => ({ ...prev, ...narrow })}
      className={mono ? 'fg-link fg-mono' : 'fg-link'}
    >
      {children}
    </Link>
  )
}

function Body({ data }: { data: TrafficOverview }) {
  const [metric, setMetric] = useState<TrafficMetric>('requests')
  const [view, setView] = useState<'chart' | 'table'>('chart')
  const { totals, recording } = data
  const located = recording.countries || recording.asns || totals.countries > 0 || totals.asns > 0
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
        <Stat label="Requests" icon="Activity" value={count.format(totals.requests)} />
        <Stat label="Data sent" icon="Download" value={formatBytes(totals.bytes)} />
        <Stat
          label="Clients"
          icon="Users"
          value={count.format(totals.clients)}
          sub={recording.client_addresses ? 'client networks (IPv6 by /64)' : 'addresses are not recorded'}
        />
        <Stat
          label="Countries"
          icon="Globe"
          value={located ? count.format(totals.countries) : '—'}
          sub={located ? `${count.format(totals.asns)} autonomous systems` : 'no geolocation database'}
        />
      </StatRow>

      <Panel
        title="By day"
        description={`${TRAFFIC_METRICS.find((m) => m.id === metric)?.label}, from ${dayLabel(data.from)} to ${dayLabel(data.to)} (UTC). Today fills in as the instances write it, once a minute.`}
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
          <TrafficChart days={data.days} metric={metric} view={data.days.length < 2 ? 'table' : view} />
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Repositories" count={data.repositories.length} flush>
          {data.repositories.length === 0 ? (
            <EmptyState title="No requests" icon="Repository" bordered={false} />
          ) : (
            <Table caption="Repositories by requests" dense>
              <TableHead>
                <TableHeader>Repository</TableHeader>
                <TableHeader align="right">Requests</TableHeader>
                <TableHeader align="right">Data sent</TableHeader>
                <TableHeader align="right">Clients</TableHeader>
              </TableHead>
              <TableBody>
                {data.repositories.map((r) => (
                  <TableRow key={r.name}>
                    <TableCell lead>
                      <NarrowLink narrow={{ repository: r.name || NONE }}>{repositoryLabel(r.name)}</NarrowLink>
                    </TableCell>
                    <TableCell align="right">{count.format(r.requests)}</TableCell>
                    <TableCell align="right">{formatBytes(r.bytes)}</TableCell>
                    <TableCell align="right">{count.format(r.clients)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
        <Panel
          title="Countries"
          count={data.countries.filter((c) => c.country).length}
          flush
          footer={located ? <Attribution /> : undefined}
        >
          {!located ? (
            <EmptyState title="Countries are not looked up" icon="Globe" bordered={false}>
              Set a MaxMind account in the{' '}
              <Link to="/manage/traffic/settings" className="fg-link">
                traffic settings
              </Link>{' '}
              to see where the requests come from.
            </EmptyState>
          ) : (
            <Table caption="Countries by requests" dense>
              <TableHead>
                <TableHeader>Country</TableHeader>
                <TableHeader align="right">Requests</TableHeader>
                <TableHeader align="right">Share</TableHeader>
                <TableHeader align="right">Clients</TableHeader>
              </TableHead>
              <TableBody>
                {data.countries.map((c) => (
                  <TableRow key={c.country}>
                    <TableCell lead>
                      <NarrowLink narrow={{ country: c.country || NONE }}>{countryName(c.country)}</NarrowLink>
                      {c.country && <span className="fg-muted fg-mono"> {c.country}</span>}
                    </TableCell>
                    <TableCell align="right">{count.format(c.requests)}</TableCell>
                    <TableCell align="right">{share(c.requests, totals.requests)}</TableCell>
                    <TableCell align="right">{count.format(c.clients)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
      </div>

      {located && (
        <Panel
          title="Networks"
          count={data.asns.length}
          description="The autonomous systems the requests came from: the provider or company each client network belongs to."
          flush
          footer={<Attribution />}
        >
          <Table caption="Autonomous systems by requests" dense>
            <TableHead>
              <TableHeader>Autonomous system</TableHeader>
              <TableHeader align="right">Requests</TableHeader>
              <TableHeader align="right">Share</TableHeader>
              <TableHeader align="right">Data sent</TableHeader>
              <TableHeader align="right">Clients</TableHeader>
            </TableHead>
            <TableBody>
              {data.asns.map((a) => (
                <TableRow key={a.asn}>
                  <TableCell lead>
                    <NarrowLink narrow={{ asn: String(a.asn) }}>{asnLabel(a.asn, a.org)}</NarrowLink>
                  </TableCell>
                  <TableCell align="right">{count.format(a.requests)}</TableCell>
                  <TableCell align="right">{share(a.requests, totals.requests)}</TableCell>
                  <TableCell align="right">{formatBytes(a.bytes)}</TableCell>
                  <TableCell align="right">{count.format(a.clients)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}

      <Panel
        title="Top clients"
        count={data.clients.length}
        description="The client networks with the most requests (an IPv6 client counts by its /64). Open one to see which repositories it used, day by day."
        flush
      >
        {!recording.client_addresses && (
          <Notice tone="info">
            Client addresses are not recorded: the traffic settings switch them
            off. Requests are still counted by repository and country.
          </Notice>
        )}
        {data.clients.length === 0 ? (
          <EmptyState title="No clients in this range" icon="Users" bordered={false} />
        ) : (
          <Table caption="Top clients">
            <TableHead>
              <TableHeader>Client</TableHeader>
              <TableHeader align="right">Requests</TableHeader>
              <TableHeader align="right">Data sent</TableHeader>
              {located && <TableHeader>Country</TableHeader>}
              {located && <TableHeader>Network</TableHeader>}
              <TableHeader>Repositories</TableHeader>
              <TableHeader align="right">Days</TableHeader>
              <TableHeader>Last seen</TableHeader>
            </TableHead>
            <TableBody>
              {data.clients.map((c) => (
                <TableRow key={c.network}>
                  <TableCell lead nowrap>
                    <NarrowLink narrow={{ network: c.network }} mono>
                      {c.network}
                    </NarrowLink>
                    {c.address && c.address !== c.network && (
                      <div className="fg-text fg-text--small fg-mono">{c.address}</div>
                    )}
                  </TableCell>
                  <TableCell align="right">{count.format(c.requests)}</TableCell>
                  <TableCell align="right">{formatBytes(c.bytes)}</TableCell>
                  {located && <TableCell>{countryName(c.country)}</TableCell>}
                  {located && <TableCell>{asnLabel(c.asn, c.as_org)}</TableCell>}
                  <TableCell>{c.repositories.map(repositoryLabel).join(', ')}</TableCell>
                  <TableCell align="right">{count.format(c.days)}</TableCell>
                  <TableCell nowrap>{dayLabel(c.last_day)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Panel>
    </>
  )
}

/** The credit MaxMind's GeoLite license asks for wherever its data is shown. */
function Attribution() {
  return (
    <p className="fg-text fg-text--small">
      Countries and networks: GeoLite Data created by MaxMind, available from{' '}
      <a className="fg-link" href="https://www.maxmind.com" target="_blank" rel="noreferrer">
        maxmind.com
      </a>
      .
    </p>
  )
}
