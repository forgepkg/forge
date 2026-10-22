import { useState } from 'react'

import type { RepoView } from '~/api/repositories'
import { useInvalidateProxyCache } from '~/queries/useRepositories'
import { Button } from '~/components/catalyst/button'
import { Description, Field, Label } from '~/components/catalyst/fieldset'
import { Subheading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Text } from '~/components/catalyst/text'

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

/**
 * A proxy repository's cache invalidation (`POST …/proxy-cache/invalidate`).
 * The proxy remembers the upstream's "not found" answers for the not-found
 * TTL and its listings (a docker proxy: its tags) for the metadata TTL; this
 * makes it ask the upstream again, for one package (an image) or for the
 * whole repository. Downloaded packages stay cached.
 */
export function ProxyCachePanel({ repo }: { repo: RepoView }) {
  const invalidate = useInvalidateProxyCache(repo.name)
  const [pkg, setPkg] = useState('')
  const docker = repo.format === 'docker'

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const name = pkg.trim()
    invalidate.mutate(name ? { package: name } : {})
  }

  const done = invalidate.isSuccess ? invalidate.data : null
  const target = invalidate.variables?.package
  return (
    <form
      onSubmit={handleSubmit}
      className="space-y-3 rounded-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10"
    >
      <Subheading>Proxy cache</Subheading>
      <Text>
        {docker
          ? 'The proxy serves a cached tag without asking the upstream for the metadata TTL, and remembers an image or tag the upstream did not have for the not-found TTL.'
          : 'The proxy remembers the upstream’s listings for the metadata TTL, and a package the upstream did not have for the not-found TTL.'}{' '}
        Invalidate the cache to ask the upstream again, for example after a
        package was published there. Downloaded packages stay cached.
      </Text>
      <div className="flex flex-wrap items-end gap-3">
        <Field className="min-w-64">
          <Label>{docker ? 'Image' : 'Package id'}</Label>
          <Description>Leave empty for the whole repository.</Description>
          <Input
            value={pkg}
            onChange={(e) => setPkg(e.target.value)}
            placeholder={docker ? 'library/nginx' : 'Newtonsoft.Json'}
          />
        </Field>
        <Button type="submit" outline disabled={invalidate.isPending}>
          {invalidate.isPending ? 'Invalidating…' : 'Invalidate cache'}
        </Button>
      </div>
      {done && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          {target ? `Invalidated ${target}: ` : 'Invalidated the whole cache: '}
          {docker
            ? `${plural(done.tags_expired, 'tag is', 'tags are')} re-validated on the next pull.`
            : `${plural(done.not_found_cleared, '“not found” answer', '“not found” answers')} forgotten; listings are fetched again.`}
        </p>
      )}
      {invalidate.isError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {invalidate.error.body || invalidate.error.message}
        </p>
      )}
    </form>
  )
}
