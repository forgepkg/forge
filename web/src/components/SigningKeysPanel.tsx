import { useState } from 'react'

import type { RepoView, SigningKey } from '~/api/repositories'
import {
  useAddSigningKey,
  useDeleteSigningKey,
  useSigningKeys,
} from '~/queries/useRepositories'
import {
  Button,
  CodeBlock,
  Dialog,
  Notice,
  Panel,
  Skeleton,
  StatusBadge,
  TextField,
  TextareaField,
} from '~/components/ui'

/** A fingerprint in groups of four, as gpg prints it. */
export function groupedFingerprint(fingerprint: string): string {
  return fingerprint.replace(/(.{4})(?=.)/g, '$1 ')
}

/** Keys expiring within this many days are shown as expiring soon. */
const SOON_DAYS = 30

/**
 * What the panel says of a key's expiry (`expires_at`; `null` never
 * expires): a key that has expired signs no longer, since apt refuses its
 * signature.
 */
export function keyExpiry(
  expiresAt: string | null | undefined,
  now: Date = new Date(),
): { state: 'never' | 'valid' | 'soon' | 'expired'; label: string } {
  const at = expiresAt ? new Date(expiresAt) : null
  if (!at || Number.isNaN(at.getTime())) return { state: 'never', label: 'never expires' }
  const date = at.toLocaleDateString(undefined, { dateStyle: 'medium' })
  if (at.getTime() <= now.getTime()) return { state: 'expired', label: `expired ${date}` }
  const soon = at.getTime() - now.getTime() < SOON_DAYS * 86_400_000
  return { state: soon ? 'soon' : 'valid', label: `expires ${date}` }
}

/**
 * The OpenPGP keys that sign a hosted apt repository's indexes
 * (`/admin/repositories/{name}/signing-keys`). Every key signs, so a key is
 * rotated by adding the new one (generated, or imported with its
 * passphrase), letting clients trust it, then deleting the old one; the
 * last key cannot be deleted. Delete asks first, in a dialog naming the key
 * and the key clients must trust instead. Secret keys are never shown. A
 * panel of the edit screen.
 */
export function SigningKeysPanel({ repo }: { repo: RepoView }) {
  const keys = useSigningKeys(repo.name)
  const add = useAddSigningKey(repo.name)
  const remove = useDeleteSigningKey(repo.name)
  const [importing, setImporting] = useState(false)
  const [secretKey, setSecretKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [pendingDelete, setPendingDelete] = useState<string | null>(null)
  const keyUrl = `/repository/${encodeURIComponent(repo.name)}/key.asc`

  function generate() {
    add.mutate({})
  }

  function submitImport(e: React.FormEvent) {
    e.preventDefault()
    add.mutate(
      { secret_key: secretKey, ...(passphrase !== '' ? { passphrase } : {}) },
      {
        onSuccess: () => {
          setSecretKey('')
          setPassphrase('')
          setImporting(false)
        },
      },
    )
  }

  const list = keys.data ?? []
  const expired = list.filter((k) => keyExpiry(k.expires_at).state === 'expired')
  const target = list.find((k) => k.fingerprint === pendingDelete)
  const remaining = list.filter((k) => k.fingerprint !== pendingDelete)

  function confirmDelete(fingerprint: string) {
    remove.mutate(fingerprint, { onSettled: () => setPendingDelete(null) })
  }

  return (
    <Panel
      title="Signing keys"
      description={
        <>
          Every key signs the repository’s <code>InRelease</code> and <code>Release.gpg</code>.
          To rotate, add a key, let clients download <a href={keyUrl} className="fg-link">key.asc</a>{' '}
          (it holds every key), then delete the old one.
        </>
      }
    >
      {keys.isLoading && <Skeleton lines={3} label="Loading signing keys…" />}
      {keys.isError && (
        <Notice tone="danger" title="Could not load the signing keys">
          {keys.error.body || keys.error.message}
        </Notice>
      )}
      {list.length > 0 && expired.length === list.length ? (
        <Notice
          tone="danger"
          title={list.length === 1 ? 'The signing key has expired' : 'Every signing key has expired'}
        >
          Nothing signs this repository&apos;s indexes: they are not updated, and{' '}
          <code>apt-get update</code> fails. Generate or import a key, give clients the new{' '}
          <code>key.asc</code>, then delete the expired key.
        </Notice>
      ) : (
        expired.length > 0 && (
          <Notice tone="warn" title="An expired key signs no longer">
            {expired.map((key) => groupedFingerprint(key.fingerprint)).join(', ')} expired: the
            indexes are signed by the other keys only, and clients that trust only an expired key
            fail <code>apt-get update</code>. Delete it once no client needs it.
          </Notice>
        )
      )}
      {list.map((key) => (
        <div key={key.fingerprint} className="flex flex-col gap-2">
          <CodeBlock
            title={
              <>
                {key.user_id || 'Key'} · {key.algorithm} · <span className="font-mono">{groupedFingerprint(key.fingerprint)}</span>
              </>
            }
            copyLabel={`Copy public key ${key.fingerprint}`}
            code={key.public_key}
            placeholders={[]}
          />
          <div className="flex flex-wrap items-center gap-3">
            <KeyExpiryBadge expiresAt={key.expires_at} />
            <Button
              variant="danger"
              size="sm"
              icon="Trash"
              disabled={list.length < 2 || remove.isPending}
              title={list.length < 2 ? 'A repository keeps at least one signing key.' : undefined}
              onClick={() => setPendingDelete(key.fingerprint)}
            >
              Delete key
            </Button>
          </div>
        </div>
      ))}
      <Dialog
        open={target !== undefined}
        onClose={() => setPendingDelete(null)}
        title="Delete this signing key?"
        icon="Trash"
        tone="danger"
        description={target && deleteConsequence(target, remaining)}
        confirmLabel={remove.isPending ? 'Deleting…' : 'Delete key'}
        confirmVariant="danger-solid"
        confirmIcon="Trash"
        confirmDisabled={remove.isPending}
        onConfirm={() => target && confirmDelete(target.fingerprint)}
      />
      {remove.isError && (
        <Notice tone="danger" title="Could not delete the key">
          {remove.error.body || remove.error.message}
        </Notice>
      )}
      <div className="flex flex-wrap gap-2">
        <Button type="button" icon="Key" onClick={generate} disabled={add.isPending}>
          {add.isPending && !importing ? 'Generating…' : 'Generate a new key'}
        </Button>
        <Button
          type="button"
          variant="secondary"
          icon="Upload"
          onClick={() => setImporting((v) => !v)}
        >
          Import a key
        </Button>
      </div>
      {importing && (
        <form onSubmit={submitImport} className="flex flex-col gap-3">
          <TextareaField
            label="Secret key"
            mono
            rows={6}
            value={secretKey}
            onChange={(e) => setSecretKey(e.target.value)}
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
            description="ASCII-armored (gpg --armor --export-secret-keys <id>). It is kept encrypted, without its passphrase, and never shown again."
          />
          <TextField
            label="Passphrase"
            type="password"
            optional
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="off"
          />
          <div>
            <Button type="submit" disabled={add.isPending || secretKey.trim() === ''}>
              {add.isPending ? 'Importing…' : 'Import key'}
            </Button>
          </div>
        </form>
      )}
      {add.isError && (
        <Notice tone="danger" title="Could not add the key">
          {add.error.body || add.error.message}
        </Notice>
      )}
    </Panel>
  )
}

/** A key's expiry: when it stops signing, or stopped. */
function KeyExpiryBadge({ expiresAt }: { expiresAt: string | null | undefined }) {
  const { state, label } = keyExpiry(expiresAt)
  if (state === 'expired') {
    return (
      <StatusBadge tone="danger" title="apt refuses the signature of an expired key: it signs no longer.">
        {label}
      </StatusBadge>
    )
  }
  if (state === 'soon') {
    return (
      <StatusBadge
        tone="warn"
        title="Once it has expired it signs no longer: add its successor before, so that clients can trust it in time."
      >
        {label}
      </StatusBadge>
    )
  }
  return <StatusBadge tone={state === 'valid' ? 'ok' : 'neutral'}>{label}</StatusBadge>
}

/**
 * What deleting a signing key means, for the confirmation: its secret never
 * leaves the server, and clients that trust only it fail `apt-get update`.
 */
function deleteConsequence(key: SigningKey, remaining: SigningKey[]): string {
  const trust =
    remaining.length === 1
      ? `the remaining key ${groupedFingerprint(remaining[0].fingerprint)}`
      : remaining.length > 1
        ? `one of the remaining keys (${remaining.map((k) => groupedFingerprint(k.fingerprint)).join(', ')})`
        : 'another key'
  return `The key ${groupedFingerprint(key.fingerprint)} stops signing the repository. Clients must trust ${trust} first (download key.asc again), or apt-get update fails with NO_PUBKEY. This cannot be undone.`
}
