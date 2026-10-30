import { useState, type FormEvent } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { TrafficSettings } from '~/api/traffic'
import { useTrafficSettings, useUpdateTrafficSettings } from '~/queries/useTraffic'
import {
  Button,
  Checkbox,
  Notice,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  Switch,
  TextField,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/manage/traffic/settings')({
  component: TrafficSettingsScreen,
})

const DESCRIPTION =
  'What the traffic statistics record and how long they are kept, for every instance at once. Each instance follows a change within a minute.'

/** The longest retention the server accepts, in days. */
const MAX_DAYS = 36_500

/**
 * Traffic settings (`/admin/settings/traffic`): what is recorded (requests
 * at all, client addresses, the request log) and how long each part is kept.
 * Each is a form panel that saves its own fields (`PUT` changes only what
 * it names), so saving one never undoes a change another administrator made
 * to the other.
 */
function TrafficSettingsScreen() {
  const settings = useTrafficSettings()

  return (
    <Page>
      <PageHeader
        title="Traffic settings"
        icon="Activity"
        crumbs={[{ label: 'Traffic', to: '/manage/traffic' }, { label: 'Settings' }]}
        description={DESCRIPTION}
      />
      {settings.isError ? (
        <ErrorState
          title="Could not load the traffic settings"
          message={settings.error?.message}
          onRetry={() => void settings.refetch()}
        />
      ) : settings.isLoading || !settings.data ? (
        <Skeleton lines={4} label="Loading the traffic settings…" />
      ) : (
        <>
          <RecordingForm settings={settings.data} />
          <RetentionForm settings={settings.data} />
        </>
      )}
    </Page>
  )
}

/** What is recorded. */
function RecordingForm({ settings }: { settings: TrafficSettings }) {
  const update = useUpdateTrafficSettings()
  const [enabled, setEnabled] = useState(settings.enabled)
  const [addresses, setAddresses] = useState(settings.client_addresses)
  const [log, setLog] = useState(settings.request_log)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    update.mutate({ enabled, client_addresses: addresses, request_log: log })
  }

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Recording"
      description="Every instance counts the requests it answers and writes them to the object store once a minute, as Parquet files under traffic/ in Forge's bucket."
      footer={
        <Button type="submit" variant="primary" disabled={update.isPending}>
          {update.isPending ? 'Saving…' : 'Save recording'}
        </Button>
      }
    >
      <div className="fg-form">
        <Switch
          label="Count requests"
          checked={enabled}
          onChange={setEnabled}
          description="Off, nothing is counted or written; what was written stays until it expires."
        />
        <Switch
          label="Client addresses"
          checked={addresses}
          onChange={setAddresses}
          description="The top clients and the addresses in the request log. Addresses are personal data: they are kept apart from the counts, for as long as the retention below says."
        />
        <Switch
          label="Request log"
          checked={log}
          onChange={setLog}
          description="Every request with its time, path, status, size, duration, account and user agent: the log a client's view shows."
        />
        {update.isError && (
          <Notice tone="danger">{update.error.body || update.error.message}</Notice>
        )}
        {update.isSuccess && <Notice tone="ok">Saved.</Notice>}
      </div>
    </Panel>
  )
}

/** A whole number of days, or the error to show. */
function days(value: string, min: number): number | string {
  const n = value.trim()
  if (!/^\d+$/.test(n) || Number(n) < min || Number(n) > MAX_DAYS) {
    return `Enter a whole number of days from ${min} to ${MAX_DAYS.toLocaleString()}.`
  }
  return Number(n)
}

/** How long each part is kept. */
function RetentionForm({ settings }: { settings: TrafficSettings }) {
  const update = useUpdateTrafficSettings()
  const keepsAll = settings.statistics_retention_days === 0
  const [keepAll, setKeepAll] = useState(keepsAll)
  const [statistics, setStatistics] = useState(String(keepsAll ? 400 : settings.statistics_retention_days))
  const [clients, setClients] = useState(String(settings.client_retention_days))
  const [log, setLog] = useState(String(settings.request_log_retention_days))
  const [errors, setErrors] = useState<Record<string, string>>({})

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const parsed = {
      statistics: keepAll ? 0 : days(statistics, 1),
      clients: days(clients, 1),
      log: days(log, 1),
    }
    const found = Object.fromEntries(
      Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
    )
    setErrors(found)
    if (Object.keys(found).length > 0) return
    update.mutate({
      statistics_retention_days: parsed.statistics as number,
      client_retention_days: parsed.clients as number,
      request_log_retention_days: parsed.log as number,
    })
  }

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      noValidate
      title="Retention"
      description="Each instance deletes the files past their retention about once an hour, whichever instance wrote them. The counts by minute, for the views of the last 48 hours, are kept three days."
      footer={
        <Button type="submit" variant="primary" disabled={update.isPending}>
          {update.isPending ? 'Saving…' : 'Save retention'}
        </Button>
      }
    >
      <div className="fg-form">
        <Checkbox
          label="Keep the counts by hour"
          checked={keepAll}
          onChange={setKeepAll}
          description="Requests by repository, surface and status, without client addresses: a few small files a day."
        />
        {!keepAll && (
          <TextField
            label="Keep the counts by hour for (days)"
            inputMode="numeric"
            mono
            value={statistics}
            onChange={(e) => setStatistics(e.target.value)}
            error={errors.statistics}
          />
        )}
        <TextField
          label="Keep the top clients for (days)"
          inputMode="numeric"
          mono
          value={clients}
          onChange={(e) => setClients(e.target.value)}
          error={errors.clients}
        />
        <TextField
          label="Keep the request log for (days)"
          inputMode="numeric"
          mono
          value={log}
          onChange={(e) => setLog(e.target.value)}
          error={errors.log}
          description="The largest part: a file per instance and minute."
        />
        {update.isError && (
          <Notice tone="danger">{update.error.body || update.error.message}</Notice>
        )}
        {update.isSuccess && <Notice tone="ok">Saved.</Notice>}
      </div>
    </Panel>
  )
}
