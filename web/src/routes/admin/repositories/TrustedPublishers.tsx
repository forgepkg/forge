import { useState } from 'react'

import type {
  TrustedPublisherBody,
  TrustedPublisherView,
} from '~/api/repositories'
import { useRealms } from '~/queries/useRealms'
import {
  useCreateTrustedPublisher,
  useDeleteTrustedPublisher,
  useTrustedPublishers,
  useUpdateTrustedPublisher,
} from '~/queries/useRepositories'
import { Button, Input, Notice, Panel, Select, Textarea } from '~/components/ui'

interface Draft {
  id?: number
  name: string
  description: string
  realm: string
  includes: string
  excludes: string
  conditions: string
  delete: boolean
}

function emptyDraft(realm = ''): Draft {
  return {
    name: '',
    description: '',
    realm,
    includes: '',
    excludes: '',
    conditions: '[\n  {\n    "claim": "repository_id",\n    "any_of": [""]\n  },\n  {\n    "claim": "repository_owner_id",\n    "any_of": [""]\n  }\n]',
    delete: false,
  }
}

function splitLines(value: string) {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

function fromPublisher(publisher: TrustedPublisherView): Draft {
  return {
    id: publisher.id,
    name: publisher.name,
    description: publisher.description,
    realm: publisher.realm,
    includes: publisher.packages.includes.join('\n'),
    excludes: publisher.packages.excludes.join('\n'),
    conditions: JSON.stringify(publisher.conditions, null, 2),
    delete: publisher.actions.includes('delete'),
  }
}

export function TrustedPublishers({ repository }: { repository: string }) {
  const publishers = useTrustedPublishers(repository)
  const realms = useRealms()
  const create = useCreateTrustedPublisher(repository)
  const update = useUpdateTrustedPublisher(repository)
  const remove = useDeleteTrustedPublisher(repository)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [formError, setFormError] = useState<string | null>(null)

  const workloadRealms =
    realms.data?.filter(
      (realm) => realm.kind === 'workload_identity' && realm.enabled,
    ) ?? []
  const pending = create.isPending || update.isPending

  function edit(publisher?: TrustedPublisherView) {
    setFormError(null)
    setDraft(publisher ? fromPublisher(publisher) : emptyDraft(workloadRealms[0]?.name))
  }

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!draft) return
    let conditions: TrustedPublisherBody['conditions']
    try {
      conditions = JSON.parse(draft.conditions) as TrustedPublisherBody['conditions']
      if (!Array.isArray(conditions)) throw new Error('Conditions must be a JSON array.')
    } catch (error) {
      setFormError(error instanceof Error ? error.message : 'Invalid conditions JSON.')
      return
    }
    const body: TrustedPublisherBody = {
      name: draft.name.trim(),
      description: draft.description,
      realm: draft.realm,
      packages: {
        includes: splitLines(draft.includes),
        excludes: splitLines(draft.excludes),
      },
      conditions,
      actions: draft.delete ? ['write', 'delete'] : ['write'],
    }
    const onSuccess = () => {
      setDraft(null)
      setFormError(null)
    }
    if (draft.id === undefined) {
      create.mutate(body, { onSuccess })
    } else {
      update.mutate({ id: draft.id, body }, { onSuccess })
    }
  }

  return (
    <Panel title="Trusted publishers">
      <p className="fg-text fg-text--small">
        Grant a workload identity write access to selected packages without
        adding write grants to its realm role.
      </p>
      {publishers.isError && (
        <Notice tone="danger" title="Could not load trusted publishers">
          {publishers.error.message}
        </Notice>
      )}
      {publishers.data?.map((publisher) => (
        <div className="fg-row" key={publisher.id}>
          <div className="fg-stack">
            <strong>{publisher.name}</strong>
            <span className="fg-text fg-text--small">
              {publisher.realm} · {publisher.packages.includes.join(', ') || 'all packages'}
              {publisher.actions.includes('delete') ? ' · write and delete' : ' · write'}
            </span>
          </div>
          <div className="fg-actions">
            <Button variant="secondary" size="sm" onClick={() => edit(publisher)}>
              Edit
            </Button>
            <Button
              variant="danger"
              size="sm"
              disabled={remove.isPending}
              onClick={() => remove.mutate(publisher.id)}
            >
              Delete
            </Button>
          </div>
        </div>
      ))}
      {publishers.data?.length === 0 && (
        <p className="fg-text fg-text--small">No trusted publishers configured.</p>
      )}
      {!draft && (
        <Button
          variant="secondary"
          onClick={() => edit()}
          disabled={workloadRealms.length === 0}
        >
          Add trusted publisher
        </Button>
      )}
      {realms.isError && (
        <Notice tone="danger" title="Could not load workload identity realms">
          {realms.error.message}
        </Notice>
      )}
      {workloadRealms.length === 0 && !realms.isError && (
        <p className="fg-text fg-text--small">
          Create an enabled workload identity realm before adding a trusted publisher.
        </p>
      )}
      {draft && (
        <form className="fg-stack" onSubmit={submit}>
          {formError && <Notice tone="danger">{formError}</Notice>}
          {(create.isError || update.isError) && (
            <Notice tone="danger" title="Could not save trusted publisher">
              {(create.error ?? update.error)?.body ||
                (create.error ?? update.error)?.message}
            </Notice>
          )}
          <label className="fg-label" htmlFor="trusted-publisher-name">Name</label>
          <Input
            id="trusted-publisher-name"
            required
            value={draft.name}
            onChange={(event) => setDraft({ ...draft, name: event.target.value })}
          />
          <label className="fg-label" htmlFor="trusted-publisher-realm">Realm</label>
          <Select
            id="trusted-publisher-realm"
            required
            value={draft.realm}
            onChange={(event) => setDraft({ ...draft, realm: event.target.value })}
          >
            {workloadRealms.map((realm) => (
              <option key={realm.id} value={realm.name}>{realm.name}</option>
            ))}
          </Select>
          <label className="fg-label" htmlFor="trusted-publisher-description">Description</label>
          <Input
            id="trusted-publisher-description"
            value={draft.description}
            onChange={(event) =>
              setDraft({ ...draft, description: event.target.value })
            }
          />
          <label className="fg-label" htmlFor="trusted-publisher-includes">Package includes (one glob per line)</label>
          <Textarea
            id="trusted-publisher-includes"
            value={draft.includes}
            onChange={(event) => setDraft({ ...draft, includes: event.target.value })}
          />
          <label className="fg-label" htmlFor="trusted-publisher-excludes">Package excludes (one glob per line)</label>
          <Textarea
            id="trusted-publisher-excludes"
            value={draft.excludes}
            onChange={(event) => setDraft({ ...draft, excludes: event.target.value })}
          />
          <label className="fg-label" htmlFor="trusted-publisher-conditions">Claim conditions (JSON array)</label>
          <Textarea
            id="trusted-publisher-conditions"
            mono
            rows={8}
            required
            value={draft.conditions}
            onChange={(event) =>
              setDraft({ ...draft, conditions: event.target.value })
            }
          />
          <label className="fg-label">
            <input
              type="checkbox"
              checked={draft.delete}
              onChange={(event) => setDraft({ ...draft, delete: event.target.checked })}
            />
            Allow unlist and delete
          </label>
          <div className="fg-actions">
            <Button type="submit" disabled={pending}>
              {draft.id === undefined ? 'Create' : 'Save'}
            </Button>
            <Button variant="secondary" onClick={() => setDraft(null)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </Panel>
  )
}
