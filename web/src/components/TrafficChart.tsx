import { useEffect, useId, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'

import type { TrafficDay } from '~/api/traffic'
import { formatBytes } from '~/lib/oci'
import { dayLabel } from '~/lib/traffic'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '~/components/ui'

/** What the chart plots of each day. */
export type TrafficMetric = 'requests' | 'bytes' | 'clients'

export const TRAFFIC_METRICS: { id: TrafficMetric; label: string }[] = [
  { id: 'requests', label: 'Requests' },
  { id: 'bytes', label: 'Data sent' },
  { id: 'clients', label: 'Clients' },
]

const METRIC_NAMES: Record<TrafficMetric, string> = {
  requests: 'Requests',
  bytes: 'Data sent',
  clients: 'Client networks',
}

const compact = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 })
const full = new Intl.NumberFormat()

/** `n` as a metric's value: bytes in binary units, counts in full. */
export function formatMetric(metric: TrafficMetric, n: number): string {
  return metric === 'bytes' ? formatBytes(n) : full.format(n)
}

/** An axis tick: compact once the axis reaches 10,000. */
function formatTick(metric: TrafficMetric, n: number, max: number): string {
  if (metric === 'bytes') return formatBytes(n)
  return max >= 10_000 ? compact.format(n) : full.format(n)
}

/** About `count` round ticks from 0 to at least `max`. */
function niceTicks(max: number, count = 4): number[] {
  if (max <= 0) return [0, 1]
  const raw = max / count
  const power = 10 ** Math.floor(Math.log10(raw))
  const step = [1, 2, 2.5, 5, 10].map((m) => m * power).find((s) => s >= raw) ?? raw
  const ticks: number[] = []
  for (let t = 0; t <= max + step * 0.999; t += step) ticks.push(Math.round(t * 1e6) / 1e6)
  return ticks
}

/** A day on the axis: `Oct 30`. */
function shortDay(day: string): string {
  const d = new Date(`${day}T00:00:00Z`)
  return Number.isNaN(d.getTime())
    ? day
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' })
}

/** How many days apart the axis labels may be. */
const LABEL_EVERY = [1, 2, 7, 14, 30, 61, 91]

const HEIGHT = 220
const MARGIN = { top: 12, right: 16, bottom: 28, left: 64 }

/**
 * One measure of the traffic by day: an area with a 2px line, a crosshair
 * that snaps to the nearest day and a tooltip with its value (the arrow keys
 * step through the days), or the same days as a table. Drawn at the width it
 * is given, so its text keeps its size.
 */
export function TrafficChart({
  days,
  metric,
  view,
}: {
  days: TrafficDay[]
  metric: TrafficMetric
  view: 'chart' | 'table'
}) {
  if (view === 'table') {
    return <DayTable days={days} metric={metric} />
  }
  return <AreaChart days={days} metric={metric} />
}

function AreaChart({ days, metric }: { days: TrafficDay[]; metric: TrafficMetric }) {
  const box = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(720)
  const [active, setActive] = useState<number | null>(null)
  const tipId = useId()

  useEffect(() => {
    const el = box.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(([entry]) => {
      const w = Math.round(entry.contentRect.width)
      if (w > 0) setWidth(w)
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const values = days.map((d) => d[metric])
  const max = Math.max(0, ...values)
  const ticks = niceTicks(max)
  const top = ticks[ticks.length - 1] || 1
  const plotW = Math.max(width - MARGIN.left - MARGIN.right, 1)
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom
  const x = (i: number) =>
    MARGIN.left + (days.length <= 1 ? plotW / 2 : (i / (days.length - 1)) * plotW)
  const y = (v: number) => MARGIN.top + plotH - (v / top) * plotH
  const line = days.map((_, i) => `${i === 0 ? 'M' : 'L'}${x(i)},${y(values[i])}`).join('')
  const area =
    days.length > 0 ? `${line}L${x(days.length - 1)},${y(0)}L${x(0)},${y(0)}Z` : ''
  // Room for a label: about 6.5px a character, and a gap; counted back from
  // the last day, so today always has one.
  const perDay = days.length <= 1 ? plotW : plotW / (days.length - 1)
  const wanted = Math.ceil((shortDay(days[0]?.day ?? '').length * 6.5 + 24) / perDay)
  const every = LABEL_EVERY.find((n) => n >= wanted) ?? wanted
  const labelled = (i: number) => (days.length - 1 - i) % every === 0
  const total = values.reduce((a, b) => a + b, 0)

  function nearest(e: PointerEvent<SVGSVGElement>): number | null {
    if (days.length === 0) return null
    const rect = e.currentTarget.getBoundingClientRect()
    const px = e.clientX - rect.left - MARGIN.left
    const i = days.length <= 1 ? 0 : Math.round((px / plotW) * (days.length - 1))
    return Math.min(days.length - 1, Math.max(0, i))
  }

  function onKey(e: KeyboardEvent<SVGSVGElement>) {
    if (days.length === 0) return
    const step = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity }[e.key]
    if (step === undefined) return
    e.preventDefault()
    const from = active ?? (step > 0 ? -1 : days.length)
    setActive(Math.min(days.length - 1, Math.max(0, from + step)))
  }

  const tip = active !== null ? days[active] : null
  const tipLeft = active !== null ? Math.min(Math.max(x(active), 80), width - 80) : 0

  return (
    <div ref={box} className="fg-chart">
      <svg
        width={width}
        height={HEIGHT}
        role="img"
        tabIndex={0}
        aria-label={`${METRIC_NAMES[metric]} by day: ${formatMetric(metric, total)} in all, at most ${formatMetric(metric, max)} a day. Use the arrow keys to read each day.`}
        aria-describedby={tip ? tipId : undefined}
        onPointerMove={(e) => setActive(nearest(e))}
        onPointerLeave={() => setActive(null)}
        onBlur={() => setActive(null)}
        onKeyDown={onKey}
      >
        {ticks.map((t) => (
          <g key={t}>
            <line className="fg-chart-grid" x1={MARGIN.left} x2={width - MARGIN.right} y1={y(t)} y2={y(t)} />
            <text className="fg-chart-axis" x={MARGIN.left - 8} y={y(t)} dy="0.32em" textAnchor="end">
              {formatTick(metric, t, top)}
            </text>
          </g>
        ))}
        {days.map((d, i) =>
          labelled(i) ? (
            <text key={d.day} className="fg-chart-axis" x={x(i)} y={HEIGHT - 8} textAnchor="middle">
              {shortDay(d.day)}
            </text>
          ) : null,
        )}
        <path className="fg-chart-area" d={area} />
        <path className="fg-chart-line" d={line} />
        {active !== null && tip && (
          <g>
            <line className="fg-chart-cross" x1={x(active)} x2={x(active)} y1={MARGIN.top} y2={y(0)} />
            <circle className="fg-chart-dot" cx={x(active)} cy={y(values[active])} r={4} />
          </g>
        )}
      </svg>
      {tip && active !== null && (
        <div id={tipId} className="fg-chart-tip" style={{ left: tipLeft }} role="status">
          <div className="fg-chart-tip-value">
            <span className="fg-chart-key" aria-hidden="true" />
            {formatMetric(metric, values[active])}
          </div>
          <div className="fg-chart-tip-label">
            {METRIC_NAMES[metric]}, {dayLabel(tip.day)}
          </div>
        </div>
      )}
    </div>
  )
}

/** The days of the chart as rows, newest first. */
function DayTable({ days, metric }: { days: TrafficDay[]; metric: TrafficMetric }) {
  return (
    <Table caption={`${METRIC_NAMES[metric]} by day`}>
      <TableHead>
        <TableHeader>Day</TableHeader>
        <TableHeader align="right">Requests</TableHeader>
        <TableHeader align="right">Data sent</TableHeader>
        <TableHeader align="right">Clients</TableHeader>
      </TableHead>
      <TableBody>
        {[...days].reverse().map((d) => (
          <TableRow key={d.day}>
            <TableCell nowrap>{dayLabel(d.day)}</TableCell>
            <TableCell align="right">{full.format(d.requests)}</TableCell>
            <TableCell align="right">{formatBytes(d.bytes)}</TableCell>
            <TableCell align="right">{full.format(d.clients)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
