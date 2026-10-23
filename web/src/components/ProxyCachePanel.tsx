import { useState } from 'react'

import type { RepoView } from '~/api/repositories'
import { useInvalidateProxyCache } from '~/queries/useRepositories'
import { Button, Notice, Panel, TextField } from '~/components/ui'

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

/**
 * A proxy repository's cache invalidation (`POST …/proxy-cache/invalidate`).
 * The proxy remembers the upstream's "not found" answers for the not-found
 * TTL and its listings (a docker proxy: its tags) for the metadata TTL; this
 * makes it ask the upstream again, for one package (an image) or for the
 * whole repository. Downloaded packages stay cached. A raw proxy re-validates
 * its cached files (of a file or a directory, or all of them) on their next
 * download. A panel of the edit screen's side column.
 */
export function ProxyCachePanel({ repo }: { repo: RepoView }) {
  const invalidate = useInvalidateProxyCache(repo.name)
  const [pkg, setPkg] = useState('')
  const docker = repo.format === 'docker'
  const raw = repo.format === 'raw'

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const name = pkg.trim()
    invalidate.mutate(name ? { package: name } : {})
  }

  const done = invalidate.isSuccess ? invalidate.data : null
  const target = invalidate.variables?.package
  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Proxy cache"
      description={
        <>
          {docker
            ? 'The proxy serves a cached tag without asking the upstream for the metadata TTL, and remembers an image or tag the upstream did not have for the not-found TTL.'
            : raw
              ? 'The proxy serves a cached file without asking the upstream for its maximum age, and remembers a file the upstream did not have for the not-found TTL.'
              : 'The proxy remembers the upstream’s listings for the metadata TTL, and a package the upstream did not have for the not-found TTL.'}{' '}
          {raw
            ? 'Invalidate the cache to ask the upstream again, for example after a file changed there. Cached files stay, and are re-validated on their next download.'
            : 'Invalidate the cache to ask the upstream again, for example after a package was published there. Downloaded packages stay cached.'}
        </>
      }
    >
      <TextField
        label={docker ? 'Image' : raw ? 'File or directory' : 'Package id'}
        optional
        mono
        value={pkg}
        onChange={(e) => setPkg(e.target.value)}
        placeholder={
          docker ? 'library/nginx' : raw ? 'chromium/7350/' : 'Newtonsoft.Json'
        }
        description="Leave empty for the whole repository."
      />
      <div>
        <Button type="submit" icon="Refresh" disabled={invalidate.isPending}>
          {invalidate.isPending ? 'Invalidating…' : 'Invalidate cache'}
        </Button>
      </div>
      {done && (
        <Notice tone="ok">
          {target ? `Invalidated ${target}: ` : 'Invalidated the whole cache: '}
          {docker
            ? `${plural(done.tags_expired, 'tag is', 'tags are')} re-validated on the next pull.`
            : raw
              ? `${plural(done.files_expired ?? 0, 'cached file is', 'cached files are')} re-validated on the next download; “not found” answers are forgotten.`
              : `${plural(done.not_found_cleared, '“not found” answer', '“not found” answers')} forgotten; listings are fetched again.`}
        </Notice>
      )}
      {invalidate.isError && (
        <Notice tone="danger" title="Could not invalidate the cache">
          {invalidate.error.body || invalidate.error.message}
        </Notice>
      )}
    </Panel>
  )
}
