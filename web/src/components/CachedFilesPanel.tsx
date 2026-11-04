import { useState } from 'react'

import type { RepoView } from '~/api/repositories'
import { useDeleteCachedFiles } from '~/queries/useRepositories'
import { Button, Notice, Panel, TextField } from '~/components/ui'

/**
 * Evicting a file an apt proxy cached from its upstream
 * (`DELETE /admin/repositories/{name}/files?path=…`): a package or a
 * `by-hash` copy is kept for good once it was checked, and this deletes it
 * so the next download fetches it from the upstream again. A path ending in
 * `/` evicts a directory. A panel of the edit screen's side column.
 */
export function CachedFilesPanel({ repo }: { repo: RepoView }) {
  const remove = useDeleteCachedFiles(repo.name)
  const [path, setPath] = useState('')

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const target = path.trim().replace(/^\/+/, '')
    if (target) remove.mutate(target)
  }

  const done = remove.isSuccess ? remove.data : null
  return (
    <Panel
      as="form"
      onSubmit={handleSubmit}
      title="Cached files"
      description="The proxy keeps a package or a by-hash copy for good once it matched the upstream’s index. Delete a cached file to have the next download fetch it from the upstream again, for example after a client reported a hash sum mismatch."
    >
      <TextField
        label="File or directory"
        mono
        value={path}
        onChange={(e) => setPath(e.target.value)}
        placeholder="pool/main/h/hello/hello_2.10-3_amd64.deb"
        description="A path ending in / deletes a directory and every file below it."
      />
      <div>
        <Button
          type="submit"
          icon="Trash"
          disabled={remove.isPending || !path.trim()}
        >
          {remove.isPending ? 'Deleting…' : 'Delete cached file'}
        </Button>
      </div>
      {done && (
        <Notice tone="ok">
          {done.deleted === 1
            ? `Deleted ${remove.variables}: the next download fetches it again.`
            : `Deleted ${done.deleted} cached files under ${remove.variables}.`}
        </Notice>
      )}
      {remove.isError && (
        <Notice tone="danger" title="Could not delete the cached file">
          {remove.error.body || remove.error.message}
        </Notice>
      )}
    </Panel>
  )
}
