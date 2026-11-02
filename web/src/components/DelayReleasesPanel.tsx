import { useState } from 'react'

import type { RepoView } from '~/api/repositories'
import {
  useDelayReleases,
  useReleaseFromDelay,
  useWithdrawDelayRelease,
} from '~/queries/useRepositories'
import {
  Button,
  Code,
  Notice,
  Panel,
  StatusBadge,
  TextField,
  TextareaField,
} from '~/components/ui'

/**
 * The versions of a proxy released from its package delay early
 * (`/admin/repositories/{name}/delay-releases`), and a form to release one by
 * package id and version: also a version the proxy has not seen upstream yet,
 * which is then served as soon as it appears. A release needs a reason, which
 * is kept with it and written to the audit log. Withdrawing a release makes
 * the version wait out its delay again. A panel of the edit screen's side
 * column; a delayed version can also be released from its package's page.
 */
export function DelayReleasesPanel({ repo }: { repo: RepoView }) {
  const releases = useDelayReleases(repo.name)
  const release = useReleaseFromDelay(repo.name)
  const withdraw = useWithdrawDelayRelease(repo.name)
  const [pkg, setPkg] = useState('')
  const [version, setVersion] = useState('')
  const [reason, setReason] = useState('')

  const ready = pkg.trim() !== '' && version.trim() !== '' && reason.trim() !== ''

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!ready) return
    release.mutate(
      { id: pkg.trim(), version: version.trim(), reason: reason.trim() },
      {
        onSuccess: () => {
          setPkg('')
          setVersion('')
          setReason('')
        },
      },
    )
  }

  const list = releases.data ?? []
  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Released early"
      description="Versions served before their package delay is over, each with the reason it was released. The package's other versions keep their delay."
    >
      {releases.isError ? (
        <Notice tone="danger" title="Could not load the releases">
          {releases.error.body || releases.error.message}
        </Notice>
      ) : list.length === 0 ? (
        <p className="fg-text">{releases.isLoading ? 'Loading…' : 'No version was released early.'}</p>
      ) : (
        <ul className="grid gap-3" aria-label="Versions released early">
          {list.map((r) => (
            <li key={`${r.package}@${r.version}`} className="grid gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <Code>
                  {r.package} {r.version}
                </Code>
                {!r.seen && (
                  <StatusBadge
                    tone="warn"
                    title="Not seen upstream yet: the release applies as soon as the proxy sees it."
                  >
                    pending
                  </StatusBadge>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  icon="Trash"
                  iconOnly
                  disabled={withdraw.isPending}
                  onClick={() => withdraw.mutate({ id: r.package, version: r.version })}
                >
                  {`Withdraw the release of ${r.package} ${r.version}`}
                </Button>
              </span>
              <span className="fg-field-desc">
                {r.reason} — {r.released_by}, {new Date(r.released_at).toLocaleString()}
              </span>
            </li>
          ))}
        </ul>
      )}
      {withdraw.isError && (
        <Notice tone="danger" title="Could not withdraw the release">
          {withdraw.error.body || withdraw.error.message}
        </Notice>
      )}
      <div className="fg-fieldrow">
        <TextField
          label="Package"
          mono
          value={pkg}
          onChange={(e) => setPkg(e.target.value)}
          placeholder={repo.format === 'npm' ? 'left-pad' : 'Newtonsoft.Json'}
        />
        <TextField
          label="Version"
          mono
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          placeholder="13.0.4"
        />
      </div>
      <TextareaField
        label="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        rows={2}
        maxLength={1000}
        placeholder="e.g. CVE-2026-1234: the fix must ship today"
        description="Required; kept with the release and written to the audit log. A version not seen upstream yet is served as soon as it appears."
      />
      <div>
        <Button type="submit" icon="Clock" disabled={!ready || release.isPending}>
          {release.isPending ? 'Releasing…' : 'Release now'}
        </Button>
      </div>
      {release.isSuccess && (
        <Notice tone="ok">
          Released {release.data.package} {release.data.version}
          {release.data.seen
            ? ': it is served now.'
            : ': it is served as soon as the proxy sees it upstream.'}
        </Notice>
      )}
      {release.isError && (
        <Notice tone="danger" title="Could not release the version">
          {release.error.body || release.error.message}
        </Notice>
      )}
    </Panel>
  )
}
