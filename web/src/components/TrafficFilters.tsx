import { TRAFFIC_RANGES, type TrafficInstance, type TrafficRange } from '~/api/traffic'
import { formatDateTime } from '~/lib/oci'
import { SegmentedControl, Select } from '~/components/ui'

/**
 * The filters of a traffic view, in one row above what they scope: the
 * range first, then the instance (all of them, or one).
 */
export function TrafficFilters({
  range,
  onRange,
  instance,
  instances,
  onInstance,
}: {
  range: TrafficRange
  onRange: (range: TrafficRange) => void
  instance: string | undefined
  instances: TrafficInstance[]
  onInstance: (instance: string | undefined) => void
}) {
  // An instance named in the URL stays selectable when the range holds no
  // file of it.
  const known =
    instance && !instances.some((i) => i.id === instance)
      ? [...instances, { id: instance, host: instance, started_at: null }]
      : instances
  return (
    <div className="fg-filters">
      <SegmentedControl
        label="Range"
        value={range}
        onChange={onRange}
        items={TRAFFIC_RANGES.map((r) => ({ id: r.id, label: r.label }))}
      />
      <Select
        aria-label="Instance"
        value={instance ?? ''}
        onChange={(e) => onInstance(e.target.value || undefined)}
      >
        <option value="">All instances ({instances.length})</option>
        {known.map((i) => (
          <option key={i.id} value={i.id}>
            {i.started_at ? `${i.host}, started ${formatDateTime(i.started_at)}` : i.host}
          </option>
        ))}
      </Select>
    </div>
  )
}
