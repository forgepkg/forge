import { useEffect, useId, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'

import type { TrafficPoint } from '~/api/traffic'
import { formatBytes } from '~/lib/oci'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '~/components/ui'

/** What the chart plots of each point. */
export type TrafficMetric = 'requests' | 'bytes' | 'client_errors' | 'server_errors'

export const TRAFFIC_METRICS: { id: TrafficMetric; label: string }[] = [
  { id: 'requests', label: 'Requests' },
  { id: 'bytes', label: 'Data sent' },
  { id: 'client_errors', label: '4xx' },
  { id: 'server_errors', label: '5xx' },
]

const METRIC_NAMES: Record<TrafficMetric, string> = {
  requests: 'Requests',
  bytes: 'Data sent',
  client_errors: '4xx answers',
  server_errors: '5xx answers',
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

/** A point's time as the axis and the tooltip say it. */
function timeLabel(iso: string, stepSeconds: number, withDate: boolean): string {
  const d = new Date(iso)
  if (stepSeconds >= 86_400) return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  return withDate
    ? `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`
    : time
}

/** The intervals time labels may be apart, in seconds. */
const LABEL_INTERVALS = [
  60, 300, 600, 900, 1_800, 3_600, 7_200, 10_800, 21_600, 43_200, 86_400, 172_800, 604_800,
]

const HEIGHT = 220
const MARGIN = { top: 12, right: 12, bottom: 28, left: 64 }

/**
 * One series of a traffic view over time: an area with a 2px line, a
 * crosshair that snaps to the nearest point and a tooltip with its value
 * (the arrow keys step through the points), or the same points as a table.
 * Drawn at the width it is given, so its text keeps its size.
 */
export function TrafficChart({
  points,
  stepSeconds,
  metric,
  view,
}: {
  points: TrafficPoint[]
  stepSeconds: number
  metric: TrafficMetric
  view: 'chart' | 'table'
}) {
  if (view === 'table') {
    return <PointTable points={points} stepSeconds={stepSeconds} metric={metric} />
  }
  return <AreaChart points={points} stepSeconds={stepSeconds} metric={metric} />
}

function AreaChart({
  points,
  stepSeconds,
  metric,
}: {
  points: TrafficPoint[]
  stepSeconds: number
  metric: TrafficMetric
}) {
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

  const values = points.map((p) => p[metric])
  const max = Math.max(0, ...values)
  const ticks = niceTicks(max)
  const top = ticks[ticks.length - 1] || 1
  const plotW = Math.max(width - MARGIN.left - MARGIN.right, 1)
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom
  const x = (i: number) =>
    MARGIN.left + (points.length <= 1 ? plotW / 2 : (i / (points.length - 1)) * plotW)
  const y = (v: number) => MARGIN.top + plotH - (v / top) * plotH
  const line = points.map((_, i) => `${i === 0 ? 'M' : 'L'}${x(i)},${y(values[i])}`).join('')
  const area =
    points.length > 0
      ? `${line}L${x(points.length - 1)},${y(0)}L${x(0)},${y(0)}Z`
      : ''
  const multiDay =
    points.length > 1 &&
    new Date(points[0].start).toDateString() !==
      new Date(points[points.length - 1].start).toDateString()
  // Room for a time label: about 6.5px a character, and a gap.
  const withDate = multiDay && stepSeconds < 86_400
  const labelWidth = (points[0] ? timeLabel(points[0].start, stepSeconds, withDate).length : 5) * 6.5 + 24
  const perPoint = points.length <= 1 ? plotW : plotW / (points.length - 1)
  // Labels on round times (every 3 hours, every day), as far apart as they need.
  const wanted = Math.max(1, Math.ceil(labelWidth / perPoint)) * stepSeconds
  const interval =
    LABEL_INTERVALS.find((s) => s >= wanted && s % stepSeconds === 0) ?? wanted
  const labelled = (iso: string) => (Date.parse(iso) / 1000) % interval === 0
  const total = values.reduce((a, b) => a + b, 0)

  function nearest(e: PointerEvent<SVGSVGElement>): number | null {
    if (points.length === 0) return null
    const rect = e.currentTarget.getBoundingClientRect()
    const px = e.clientX - rect.left - MARGIN.left
    const i = points.length <= 1 ? 0 : Math.round((px / plotW) * (points.length - 1))
    return Math.min(points.length - 1, Math.max(0, i))
  }

  function onKey(e: KeyboardEvent<SVGSVGElement>) {
    if (points.length === 0) return
    const step = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity }[e.key]
    if (step === undefined) return
    e.preventDefault()
    const from = active ?? (step > 0 ? -1 : points.length)
    setActive(Math.min(points.length - 1, Math.max(0, from + step)))
  }

  const tip = active !== null ? points[active] : null
  const tipLeft = active !== null ? Math.min(Math.max(x(active), 80), width - 80) : 0

  return (
    <div ref={box} className="fg-chart">
      <svg
        width={width}
        height={HEIGHT}
        role="img"
        tabIndex={0}
        aria-label={`${METRIC_NAMES[metric]} over time: ${formatMetric(metric, total)} in all, at most ${formatMetric(metric, max)} per point. Use the arrow keys to read each point.`}
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
        {points.map((p, i) =>
          labelled(p.start) ? (
            <text key={p.start} className="fg-chart-axis" x={x(i)} y={HEIGHT - 8} textAnchor="middle">
              {timeLabel(p.start, stepSeconds, withDate)}
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
            {METRIC_NAMES[metric]}, {timeLabel(tip.start, stepSeconds, true)}
          </div>
        </div>
      )}
    </div>
  )
}

/** The points of the chart as rows, newest first. */
function PointTable({
  points,
  stepSeconds,
  metric,
}: {
  points: TrafficPoint[]
  stepSeconds: number
  metric: TrafficMetric
}) {
  return (
    <Table caption={`${METRIC_NAMES[metric]} over time`}>
      <TableHead>
        <TableHeader>From</TableHeader>
        <TableHeader align="right">Requests</TableHeader>
        <TableHeader align="right">Data sent</TableHeader>
        <TableHeader align="right">4xx</TableHeader>
        <TableHeader align="right">5xx</TableHeader>
      </TableHead>
      <TableBody>
        {[...points].reverse().map((p) => (
          <TableRow key={p.start}>
            <TableCell nowrap>{timeLabel(p.start, stepSeconds, true)}</TableCell>
            <TableCell align="right">{full.format(p.requests)}</TableCell>
            <TableCell align="right">{formatBytes(p.bytes)}</TableCell>
            <TableCell align="right">{full.format(p.client_errors)}</TableCell>
            <TableCell align="right">{full.format(p.server_errors)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
