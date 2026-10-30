import { useState, type FormEvent } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { GeoDatabase, GeoipStatus, TrafficSettings } from '~/api/traffic'
import { formatBytes, formatDateTime } from '~/lib/oci'
import {
  useDownloadGeoip,
  useGeoip,
  useRemoveGeoip,
  useTrafficSettings,
  useUpdateGeoip,
  useUpdateTrafficSettings,
} from '~/queries/useTraffic'
import {
  Button,
  Code,
  Dialog,
  FactList,
  FormActions,
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
  'What the traffic statistics record, how long they are kept, and where the countries and networks of the clients come from, for every instance at once. Each instance follows a change within a minute.'

/** The longest retention the server accepts, in days. */
const MAX_DAYS = 36_500

/**
 * Traffic settings (`/admin/settings/traffic`, `/admin/traffic/geoip`):
 * what is recorded and how long it is kept, and the MaxMind account the
 * geolocation databases are downloaded with. Each panel saves its own
 * fields (`PUT` changes only what it names), so saving one never undoes a
 * change another administrator made to the other.
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
          <GeolocationPanel />
        </>
      )}
    </Page>
  )
}

/** A whole number of days, or the error to show. */
function days(value: string): number | string {
  const n = value.trim()
  if (!/^\d+$/.test(n) || Number(n) < 1 || Number(n) > MAX_DAYS) {
    return `Enter a whole number of days from 1 to ${MAX_DAYS.toLocaleString()}.`
  }
  return Number(n)
}

/** What is recorded and how long it is kept. */
function RecordingForm({ settings }: { settings: TrafficSettings }) {
  const update = useUpdateTrafficSettings()
  const [enabled, setEnabled] = useState(settings.enabled)
  const [addresses, setAddresses] = useState(settings.client_addresses)
  const [retention, setRetention] = useState(String(settings.retention_days))
  const [error, setError] = useState<string | null>(null)

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const kept = days(retention)
    if (typeof kept === 'string') {
      setError(kept)
      return
    }
    setError(null)
    update.mutate({ enabled, client_addresses: addresses, retention_days: kept })
  }

  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      noValidate
      title="Recording"
      description="Every instance counts its requests by day, repository and client, and writes them to the object store once a minute, as Parquet files under traffic/v1/ in Forge's bucket."
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
          description="Addresses are personal data. Off, requests are still counted by repository, country and network: the address is looked up in memory and dropped."
        />
        <TextField
          label="Keep the statistics for (days)"
          inputMode="numeric"
          mono
          value={retention}
          onChange={(e) => setRetention(e.target.value)}
          error={error}
          description="Each instance deletes older days about once an hour."
        />
        {update.isError && (
          <Notice tone="danger">{update.error.body || update.error.message}</Notice>
        )}
        {update.isSuccess && <Notice tone="ok">Saved.</Notice>}
      </div>
    </Panel>
  )
}

function database(db: GeoDatabase | null): string {
  if (!db) return 'Not loaded'
  const built = db.built_at ? `, built ${formatDateTime(db.built_at)}` : ''
  return `${db.database_type}${built} (${formatBytes(db.size)})`
}

/** The geolocation databases and the MaxMind account they come from. */
function GeolocationPanel() {
  const status = useGeoip()
  return (
    <Panel
      title="Geolocation"
      description={
        <>
          The country and autonomous system (the provider or company) of each
          client come from MaxMind&apos;s free GeoLite2 databases. With a
          MaxMind account ID and license key, Forge downloads them every three
          days and keeps them in its bucket for every instance. Without
          internet access, put the <Code>.mmdb</Code> files there yourself as{' '}
          <Code>traffic/v1/geoip/country.mmdb</Code> and{' '}
          <Code>traffic/v1/geoip/asn.mmdb</Code>.
        </>
      }
    >
      {status.isError ? (
        <ErrorState
          title="Could not load the geolocation databases"
          message={status.error.body || status.error.message}
          onRetry={() => void status.refetch()}
        />
      ) : !status.data ? (
        <Skeleton lines={3} label="Loading the geolocation databases…" />
      ) : (
        <GeolocationBody status={status.data} />
      )}
    </Panel>
  )
}

function GeolocationBody({ status }: { status: GeoipStatus }) {
  const update = useUpdateGeoip()
  const download = useDownloadGeoip()
  const remove = useRemoveGeoip()
  const [accountId, setAccountId] = useState(status.maxmind.account_id ?? '')
  const [licenseKey, setLicenseKey] = useState('')
  const [errors, setErrors] = useState<{ account?: string; key?: string }>({})
  const [confirming, setConfirming] = useState(false)
  const m = status.maxmind
  const configured = m.account_id !== null && m.license_key_set

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const found: { account?: string; key?: string } = {}
    if (!/^\d+$/.test(accountId.trim())) found.account = 'Enter your MaxMind account ID, a number.'
    if (!licenseKey.trim() && !m.license_key_set) found.key = 'Enter a license key.'
    setErrors(found)
    if (Object.keys(found).length > 0) return
    update.mutate(
      {
        account_id: accountId.trim(),
        ...(licenseKey.trim() ? { license_key: licenseKey.trim() } : {}),
      },
      { onSuccess: () => setLicenseKey('') },
    )
  }

  return (
    <div className="grid gap-4">
      <FactList
        items={[
          { term: 'MaxMind account', value: configured ? m.account_id : 'Not set' },
          { term: 'Countries', value: database(status.country) },
          { term: 'Networks (ASN)', value: database(status.asn) },
          {
            term: 'Last download',
            value: m.last_success ? formatDateTime(m.last_success) : 'Never',
          },
        ]}
      />
      {m.last_error && (
        <Notice tone="danger" title="The last download failed">
          {m.last_error}
        </Notice>
      )}
      <form className="fg-form" onSubmit={handleSubmit} noValidate>
        <div className="fg-fieldrow">
          <TextField
            label="MaxMind account ID"
            inputMode="numeric"
            mono
            value={accountId}
            onChange={(e) => setAccountId(e.target.value)}
            error={errors.account}
          />
          <TextField
            label="License key"
            type="password"
            autoComplete="off"
            mono
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            error={errors.key}
            placeholder={m.license_key_set ? '••••••••' : undefined}
            description={m.license_key_set ? 'Stored. Enter a new one to replace it.' : undefined}
          />
        </div>
        <p className="fg-text fg-text--small">
          Create a free account and a license key at{' '}
          <a className="fg-link" href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noreferrer">
            maxmind.com
          </a>
          . The key is stored encrypted. Forge downloads {m.editions.join(' and ')} from{' '}
          <Code>{m.url}</Code>.
        </p>
        {update.isError && (
          <Notice tone="danger">{update.error.body || update.error.message}</Notice>
        )}
        {download.isError && (
          <Notice tone="danger">{download.error.body || download.error.message}</Notice>
        )}
        {download.isSuccess && !m.last_error && (
          <Notice tone="ok">Downloaded: every instance uses the databases within ten minutes.</Notice>
        )}
        <FormActions>
          {configured && (
            <Button type="button" variant="danger" onClick={() => setConfirming(true)}>
              Turn off
            </Button>
          )}
          {configured && (
            <Button
              type="button"
              icon="Download"
              disabled={download.isPending}
              onClick={() => download.mutate()}
            >
              {download.isPending ? 'Downloading…' : 'Download now'}
            </Button>
          )}
          <Button type="submit" variant="primary" disabled={update.isPending}>
            {update.isPending ? 'Saving…' : 'Save account'}
          </Button>
        </FormActions>
      </form>
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        icon="Globe"
        tone="danger"
        title="Turn geolocation off?"
        description="Forge forgets the MaxMind account and deletes the databases from its bucket. Requests are no longer located; the countries already counted stay."
        confirmLabel="Turn off"
        onConfirm={() => {
          remove.mutate(undefined, {
            onSuccess: () => {
              setAccountId('')
              setLicenseKey('')
            },
          })
          setConfirming(false)
        }}
      />
    </div>
  )
}
