import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import type { BlobCacheStats, KeyView, RotationLayer, RotationResult } from '~/api/system'
import type { ApiError } from '~/lib/httpClient'
import { formatBytes, formatDateTime } from '~/lib/oci'
import { useBlobCache, useCryptoKeys, useRotateKeys } from '~/queries/useSystem'
import { ErrorState } from '~/components/ErrorState'
import {
  Button,
  Code,
  Dialog,
  EmptyState,
  FactList,
  FormActions,
  Notice,
  Page,
  PageHeader,
  Panel,
  ProgressBar,
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
  type Tone,
} from '~/components/ui'

export const Route = createFileRoute('/_app/manage/system')({
  component: SystemPage,
})

/**
 * The system screen: the secret encryption at rest (key metadata, and the
 * on-demand rotations of `POST /admin/crypto/rotate/{dek,kek,root}`) and the
 * local blob cache of the instance that answered. Both are read-only views
 * of `/admin/crypto/keys` and `/admin/blob-cache` but for the rotations.
 */
function SystemPage() {
  return (
    <Page>
      <PageHeader
        title="System"
        description="How Forge protects the secrets it stores, and how the local blob cache of this instance is doing."
      />
      <SecretEncryption />
      <BlobCache />
    </Page>
  )
}

const ROTATIONS: Record<
  RotationLayer,
  { label: string; title: string; description: string; confirm: string }
> = {
  dek: {
    label: 'Rotate DEK',
    title: 'Rotate the data key?',
    description:
      'Forge creates a new data-encryption key, encrypts every stored secret again with it and revokes the data keys nothing uses any more. Clients notice nothing.',
    confirm: 'Rotate DEK',
  },
  kek: {
    label: 'Rotate KEK',
    title: 'Rotate the key-encryption key?',
    description:
      'Forge creates a new key-encryption key and wraps every data key with it; the secrets themselves stay as they are. Clients notice nothing.',
    confirm: 'Rotate KEK',
  },
  root: {
    label: 'Re-wrap under the current root',
    title: 'Re-wrap the key-encryption keys?',
    description:
      'Forge wraps every key-encryption key with the root key it is configured with now. Run it after swapping the root key, the second step of a root-key rotation.',
    confirm: 'Re-wrap keys',
  },
}

/** What a finished rotation did, in a sentence. */
function rotationSummary(result: RotationResult): string {
  switch (result.rotated) {
    case 'dek':
      return `The data key is now version ${result.new_version}: ${plural(result.resealed_secrets, 'secret')} encrypted again, ${plural(result.revoked_deks, 'old data key')} revoked.`
    case 'kek':
      return `The key-encryption key is now version ${result.new_version}; every data key is wrapped with it.`
    case 'root':
      return `${plural(result.rewrapped_keks, 'key-encryption key')} wrapped under the current root key.`
  }
}

/** A failed rotation: a held lock is a conflict to retry, anything else its message. */
function rotationError(error: ApiError): string {
  if (error.status === 409 && /already running/i.test(error.body)) {
    return 'Another rotation is running; try again in a moment.'
  }
  return error.body || error.message
}

/** "1 secret" / "3 secrets"; `many` for an irregular plural. */
function plural(n: number, noun: string, many = `${noun}s`): string {
  return `${n} ${n === 1 ? noun : many}`
}

const KEY_TONES: Record<string, Tone> = {
  active: 'ok',
  retiring: 'warn',
  revoked: 'neutral',
}

/** Secret encryption at rest: its state, its keys and their rotations. */
function SecretEncryption() {
  const keys = useCryptoKeys()
  const rotate = useRotateKeys()
  const [confirming, setConfirming] = useState<RotationLayer | null>(null)

  if (keys.isError) {
    return (
      <ErrorState
        title="Could not load the encryption keys"
        message={keys.error.message}
        onRetry={() => void keys.refetch()}
      />
    )
  }

  const data = keys.data
  return (
    <Panel
      title="Secret encryption"
      description="Proxy passwords, realm secrets, the email credentials, the registry-token key and the OIDC signing keys are encrypted with a data key (DEK), which a key-encryption key (KEK) wraps, which the root key from the configuration wraps."
      footer={
        data && (
          <FormActions>
            {(['dek', 'kek', 'root'] as const).map((layer) => (
              <Button
                key={layer}
                icon="Refresh"
                disabled={rotate.isPending}
                onClick={() => {
                  rotate.reset()
                  setConfirming(layer)
                }}
              >
                {ROTATIONS[layer].label}
              </Button>
            ))}
          </FormActions>
        )
      }
    >
      {!data ? (
        <Skeleton label="Loading the encryption keys…" />
      ) : (
        <>
          <FactList
            items={[{ term: 'Root key version', value: data.root_key_version, mono: true }]}
          />
          <KeyTable keys={data.keys} />
        </>
      )}
      {rotate.isSuccess && <Notice tone="ok">{rotationSummary(rotate.data)}</Notice>}
      {rotate.isError && <Notice tone="danger">{rotationError(rotate.error)}</Notice>}
      <Dialog
        open={confirming !== null}
        onClose={() => setConfirming(null)}
        icon="Key"
        tone="warn"
        title={confirming ? ROTATIONS[confirming].title : ''}
        description={confirming ? ROTATIONS[confirming].description : undefined}
        confirmLabel={confirming ? ROTATIONS[confirming].confirm : undefined}
        onConfirm={() => {
          if (!confirming) return
          rotate.mutate(confirming)
          setConfirming(null)
        }}
      />
    </Panel>
  )
}

/** The KEKs, then the DEKs, newest first. */
function KeyTable({ keys }: { keys: KeyView[] }) {
  const sorted = [...keys].sort(
    (a, b) => b.layer.localeCompare(a.layer) || b.version - a.version,
  )
  if (sorted.length === 0) {
    return <p className="fg-text">No keys yet; Forge creates them with the first secret it stores.</p>
  }
  return (
    <Table caption="Encryption keys">
      <TableHead>
        <TableHeader width="70px">Layer</TableHeader>
        <TableHeader width="80px" align="right">
          Version
        </TableHeader>
        <TableHeader>State</TableHeader>
        <TableHeader>Algorithm</TableHeader>
        <TableHeader>Wrapped by</TableHeader>
        <TableHeader>Created</TableHeader>
        <TableHeader>Rotated</TableHeader>
      </TableHead>
      <TableBody>
        {sorted.map((k) => (
          <TableRow key={`${k.layer}-${k.version}`}>
            <TableCell lead>{k.layer.toUpperCase()}</TableCell>
            <TableCell align="right">
              <span className="fg-mono">{k.version}</span>
            </TableCell>
            <TableCell>
              <StatusBadge tone={KEY_TONES[k.state] ?? 'neutral'}>{k.state}</StatusBadge>
            </TableCell>
            <TableCell>
              <span className="fg-mono">{k.algorithm}</span>
            </TableCell>
            <TableCell>
              <span className="fg-mono">
                {k.layer === 'kek'
                  ? `root ${k.root_key_version ?? '—'}`
                  : `KEK ${k.wrapping_kek_version ?? '—'}`}
              </span>
            </TableCell>
            <TableCell nowrap>{formatDateTime(k.created_at)}</TableCell>
            <TableCell nowrap>{formatDateTime(k.rotated_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

/** The answering instance's local blob cache, with a refresh. */
function BlobCache() {
  const cache = useBlobCache()
  return (
    <Panel
      title="Local blob cache"
      description="Blobs Forge keeps on a local volume so they need not come from S3 again. The numbers count since the instance started."
      actions={
        <Button
          size="sm"
          icon="Refresh"
          disabled={cache.isFetching}
          onClick={() => void cache.refetch()}
        >
          Refresh
        </Button>
      }
    >
      {cache.isError ? (
        <ErrorState
          title="Could not load the blob cache"
          message={cache.error.message}
          onRetry={() => void cache.refetch()}
        />
      ) : !cache.data ? (
        <Skeleton label="Loading the blob cache…" />
      ) : (
        <BlobCacheBody stats={cache.data} />
      )}
    </Panel>
  )
}

function BlobCacheBody({ stats }: { stats: BlobCacheStats }) {
  const instance = (
    <p className="fg-text fg-text--small">
      Answered by <span className="fg-strong">{stats.instance.host ?? 'an unnamed instance'}</span>,
      started {formatDateTime(stats.instance.started_at)}. Each replica has a cache of its own;
      ask a replica directly to see its numbers.
    </p>
  )
  if (!stats.enabled) {
    return (
      <>
        <EmptyState title="This instance has no local blob cache" icon="Database" bordered={false}>
          Every blob is read from S3. Set a <Code>[blob_cache]</Code> path on a
          local volume to keep the blobs read most there, and to serve them while
          S3 is unreachable.
        </EmptyState>
        {instance}
      </>
    )
  }
  const reads = stats.hits + stats.misses
  return (
    <>
      {stats.object_store_down && (
        <Notice tone="warn" title="S3 is unreachable">
          This instance serves what its cache holds; other blobs fail until S3
          answers again.
        </Notice>
      )}
      <StatRow>
        <Stat
          label="Hit ratio"
          icon="CheckCircle"
          value={reads === 0 ? '—' : `${Math.round(stats.hit_ratio * 100)}%`}
          sub={`${plural(stats.hits, 'hit')}, ${plural(stats.misses, 'miss', 'misses')}`}
        />
        <Stat
          label="Served from the cache"
          icon="Download"
          value={formatBytes(stats.hit_bytes)}
          sub={`${plural(stats.hits_while_store_down, 'hit')} while S3 was down`}
        />
        <Stat
          label="Evictions"
          icon="Trash"
          value={stats.evictions}
          sub={`${formatBytes(stats.evicted_bytes)} evicted`}
        />
      </StatRow>
      <ProgressBar
        label="Size"
        value={stats.size_bytes}
        max={Math.max(stats.limit_bytes, 1)}
        valueText={`${formatBytes(stats.size_bytes)} of ${formatBytes(stats.limit_bytes)}${stats.limit_auto ? ' (auto)' : ''}`}
        sub={plural(stats.entries, 'entry', 'entries')}
      />
      <FactList
        items={[
          { term: 'Path', value: stats.path, mono: true },
          { term: 'Fills', value: stats.fills },
          { term: 'Fill failures', value: stats.fill_failures },
          { term: 'Corrupt entries', value: stats.corrupt },
          { term: 'Bypassed', value: stats.bypassed },
          { term: 'Reserved for fills', value: formatBytes(stats.reserved_bytes) },
        ]}
      />
      {instance}
    </>
  )
}
