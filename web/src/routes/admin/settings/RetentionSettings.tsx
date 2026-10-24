import { useState, type FormEvent } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { RetentionSettings } from '~/api/settings'
import {
  useRetentionSettings,
  useUpdateRetentionSettings,
} from '~/queries/useSettings'
import {
  intervalFromSeconds,
  type IntervalUnit,
} from '~/components/RetentionPolicyForm'
import {
  Button,
  Checkbox,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  Switch,
  TextField,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/manage/settings/retention')({
  component: RetentionSettingsScreen,
})

const DESCRIPTION =
  'Whether retention runs, and how long its audit log is kept, for every repository and every instance at once. Each repository’s policy is set on its own Retention screen (Repositories → the repository → Retention).'

/** `seconds` in its largest whole unit (`90 days`, `1 hour`). */
function describeDuration(seconds: number): string {
  const { value, unit } = intervalFromSeconds(seconds)
  return `${value} ${value === '1' ? unit.slice(0, -1) : unit}`
}

const UNIT_SECONDS: Record<IntervalUnit, number> = {
  days: 86400,
  hours: 3600,
  minutes: 60,
  seconds: 1,
}

/**
 * Retention settings (`/admin/settings/retention`): the switch that stops
 * every retention run, and how long the audit log is kept. Each is a form
 * panel that saves its own field (`PUT` changes only what it names), so
 * saving one never undoes a change another administrator made to the other.
 */
function RetentionSettingsScreen() {
  const settings = useRetentionSettings()

  return (
    <Page>
      <PageHeader title="Retention" icon="Clock" description={DESCRIPTION} />
      {settings.isError ? (
        <ErrorState
          title="Could not load the retention settings"
          message={settings.error?.message}
          onRetry={() => void settings.refetch()}
        />
      ) : settings.isLoading || !settings.data ? (
        <Skeleton lines={4} label="Loading the retention settings…" />
      ) : (
        <>
          <RunsForm settings={settings.data} />
          <AuditForm settings={settings.data} />
        </>
      )}
    </Page>
  )
}

/** Whether retention runs at all. */
function RunsForm({ settings }: { settings: RetentionSettings }) {
  const update = useUpdateRetentionSettings()
  const [on, setOn] = useState(settings.runs_enabled)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    update.mutate({ runs_enabled: on })
  }

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Runs"
      description="Switch retention off to stop every deletion at once, for instance during an incident or a migration."
      footer={
        <Button type="submit" variant="primary" disabled={update.isPending}>
          {update.isPending ? 'Saving…' : 'Save runs'}
        </Button>
      }
    >
      <div className="fg-form">
        <Switch
          label="Retention runs"
          checked={on}
          onChange={setOn}
          description="Off, no policy runs: scheduled runs and Run now wait, and a run in progress stops before its next batch. Policies can still be edited and previewed."
        />
        {!settings.runs_enabled && (
          <Notice tone="warn">
            Retention runs are switched off: nothing is unlisted, deleted or
            evicted until they are switched on again.
          </Notice>
        )}
        {update.isError && (
          <Notice tone="danger">{update.error.body || update.error.message}</Notice>
        )}
        {update.isSuccess && <Notice tone="ok">Saved.</Notice>}
      </div>
    </Panel>
  )
}

/** How long the audit log is kept. */
function AuditForm({ settings }: { settings: RetentionSettings }) {
  const update = useUpdateRetentionSettings()
  const keepsAll = settings.audit_retention_seconds === 0
  const initial = intervalFromSeconds(keepsAll ? 90 * 86400 : settings.audit_retention_seconds)
  const [keepAll, setKeepAll] = useState(keepsAll)
  const [value, setValue] = useState(initial.value)
  const [unit, setUnit] = useState<IntervalUnit>(initial.unit)
  const [error, setError] = useState<string | null>(null)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (keepAll) {
      setError(null)
      update.mutate({ audit_retention_seconds: 0 })
      return
    }
    const n = value.trim()
    if (!/^\d+$/.test(n) || Number(n) < 1) {
      setError('Enter a whole number of at least 1.')
      return
    }
    setError(null)
    update.mutate({ audit_retention_seconds: Number(n) * UNIT_SECONDS[unit] })
  }

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      noValidate
      title="Audit log"
      description={`Every run records what it unlisted, deleted or skipped, dry runs included. Rows are kept ${
        settings.audit_retention_seconds === 0
          ? 'forever'
          : `for ${describeDuration(settings.audit_retention_seconds)}`
      }, then deleted.`}
      footer={
        <Button type="submit" variant="primary" disabled={update.isPending}>
          {update.isPending ? 'Saving…' : 'Save audit log'}
        </Button>
      }
    >
      <div className="fg-form">
        <Checkbox
          label="Keep every audit row"
          checked={keepAll}
          onChange={setKeepAll}
          description="Dry-run policies add a row per matching version on every run, so the log grows without a limit."
        />
        {!keepAll && (
          <div className="fg-fieldrow">
            <TextField
              label="Keep audit rows for"
              inputMode="numeric"
              mono
              value={value}
              onChange={(e) => setValue(e.target.value)}
              error={error}
            />
            <SelectField
              label="Unit"
              value={unit}
              onChange={(e) => setUnit(e.target.value as IntervalUnit)}
            >
              <option value="days">Days</option>
              <option value="hours">Hours</option>
              <option value="minutes">Minutes</option>
              <option value="seconds">Seconds</option>
            </SelectField>
          </div>
        )}
        {update.isError && (
          <Notice tone="danger">{update.error.body || update.error.message}</Notice>
        )}
        {update.isSuccess && <Notice tone="ok">Saved.</Notice>}
      </div>
    </Panel>
  )
}
