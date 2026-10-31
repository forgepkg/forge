import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'

import {
  decideDeviceCode,
  deviceRequestQueryOptions,
  normalizeUserCode,
  type DeviceRequest,
  type DeviceScope,
} from '~/api/device'
import { ApiError } from '~/lib/httpClient'
import { useMe } from '~/queries/useMe'
import {
  Button,
  Code,
  FactList,
  FormActions,
  Notice,
  Page,
  PageHeader,
  Panel,
  Skeleton,
  TextField,
} from '~/components/ui'

interface DeviceSearch {
  /** The code, filled in from the client's link (`verification_uri_complete`). */
  code?: string
}

export const Route = createFileRoute('/_app/device')({
  validateSearch: (search: Record<string, unknown>): DeviceSearch => ({
    code:
      typeof search.code === 'string' && search.code.length <= 32 ? search.code : undefined,
  }),
  component: Device,
})

const HEADER_DESCRIPTION =
  'Sign in a command-line client, such as forge login or a Docker or NuGet credential helper, with the code it shows.'

/** A code entered (or filled in) and looked up; `attempt` repeats a lookup. */
interface Lookup {
  code: string
  attempt: number
}

/**
 * The device login's page (RFC 8628): the code a command-line client shows
 * is entered here, or filled in from the link the client prints, by a
 * signed-in user (the app's login gate sends a visitor through the sign-in
 * and back, with the code). The page shows which client asks for what, from
 * where and since when, and the code to compare with the terminal; nothing is
 * approved without the user's click on **Approve**, a filled-in code neither
 * (remote phishing, RFC 8628 §5.4).
 */
function Device() {
  const { code: linked } = Route.useSearch()
  const [draft, setDraft] = useState(linked ?? '')
  const [formError, setFormError] = useState<string | null>(() =>
    linked !== undefined && normalizeUserCode(linked) === null ? MALFORMED : null,
  )
  const [lookup, setLookup] = useState<Lookup | null>(() => {
    const code = linked === undefined ? null : normalizeUserCode(linked)
    return code === null ? null : { code, attempt: 0 }
  })
  const request = useQuery({
    ...deviceRequestQueryOptions(lookup?.code ?? '', lookup?.attempt ?? 0),
    enabled: lookup !== null,
  })
  const [decided, setDecided] = useState<boolean | null>(null)
  const decide = useMutation<void, ApiError, { code: string; approve: boolean }>({
    mutationFn: ({ code, approve }) => decideDeviceCode(code, approve),
    onSuccess: (_, { approve }) => setDecided(approve),
  })
  const header = (
    <PageHeader title="Sign in a device" icon="Terminal" description={HEADER_DESCRIPTION} />
  )

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const code = normalizeUserCode(draft)
    if (code === null) {
      setFormError(MALFORMED)
      return
    }
    setFormError(null)
    decide.reset()
    setLookup((previous) => ({ code, attempt: (previous?.attempt ?? 0) + 1 }))
  }

  function enterAnother() {
    decide.reset()
    setLookup(null)
    setDraft('')
  }

  if (decided !== null) {
    return (
      <Page>
        {header}
        <Notice tone={decided ? 'ok' : 'info'} title={decided ? 'Signed in' : 'Denied'}>
          {decided
            ? 'The client is signed in as you. Return to your terminal; you can close this page.'
            : 'The client was not signed in. Return to your terminal; you can close this page.'}
        </Notice>
      </Page>
    )
  }

  if (lookup !== null && request.isLoading) {
    return (
      <Page>
        {header}
        <Skeleton variant="text" label="Looking up the code…" />
      </Page>
    )
  }

  if (lookup !== null && request.data) {
    return (
      <Page>
        {header}
        <Approval
          request={request.data}
          pending={decide.isPending}
          error={decide.isError ? decide.error : null}
          onDecide={(approve) => decide.mutate({ code: lookup.code, approve })}
          onEnterAnother={enterAnother}
        />
      </Page>
    )
  }

  const lookupError = lookup !== null && request.isError ? request.error : null
  return (
    <Page>
      {header}
      <Panel
        as="form"
        onSubmit={handleSubmit}
        noValidate
        title="Enter the code"
        description="Type the code your terminal shows. Upper or lower case, with or without the hyphen."
        footer={
          <Button type="submit" variant="primary">
            Continue
          </Button>
        }
      >
        <div className="fg-form">
          <TextField
            label="Code"
            mono
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value)
              setFormError(null)
            }}
            placeholder="BCDF-GHJK"
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            maxLength={32}
            error={formError ? <span role="alert">{formError}</span> : undefined}
          />
        </div>
        {lookupError && <LookupError error={lookupError} />}
      </Panel>
    </Page>
  )
}

const MALFORMED = 'Enter the eight letters your terminal shows, such as BCDF-GHJK.'

/** Why a code could not be looked up. */
function LookupError({ error }: { error: ApiError }) {
  if (error.status === 404) {
    return (
      <Notice tone="warn" title="No sign-in is waiting for this code">
        It is mistyped, it expired, or it was answered already. Check the code your terminal
        shows, or start the sign-in again for a new one.
      </Notice>
    )
  }
  if (error.status === 429) {
    return (
      <Notice tone="danger" title="Too many wrong codes">
        Try again {inWhile(error.retryAfterSeconds)}.
      </Notice>
    )
  }
  if (error.status === 400) {
    return <Notice tone="warn">{MALFORMED}</Notice>
  }
  return (
    <Notice tone="danger" title="Could not look up the code">
      {error.body || error.message}
    </Notice>
  )
}

/** `in 5 minutes`, from a `Retry-After`. */
function inWhile(seconds: number | undefined): string {
  if (seconds === undefined) return 'in a few minutes'
  if (seconds < 60) return `in ${seconds} second${seconds === 1 ? '' : 's'}`
  const minutes = Math.ceil(seconds / 60)
  return `in ${minutes} minute${minutes === 1 ? '' : 's'}`
}

const LEVELS: Record<NonNullable<DeviceScope['level']>, string> = {
  read: 'Read',
  write: 'Read and write',
  delete: 'Read, write and delete',
}

/** What the token may do, in words. */
export function describeScope(scope: DeviceScope | null): string {
  if (scope === null) return 'Everything you may do'
  const level = scope.level ? LEVELS[scope.level] : 'Everything you may do'
  if (scope.repositories.length === 0) return level
  const where = scope.repositories.length === 1 ? 'repository' : 'repositories'
  return `${level}, on the ${where} ${scope.repositories.join(', ')}`
}

/** The pending request, with its Approve and Deny. */
function Approval({
  request,
  pending,
  error,
  onDecide,
  onEnterAnother,
}: {
  request: DeviceRequest
  pending: boolean
  error: ApiError | null
  onDecide: (approve: boolean) => void
  onEnterAnother: () => void
}) {
  const me = useMe()
  const username = me.data?.user.username
  const client = request.client_name ?? request.client_id
  const gone = error?.status === 404
  return (
    <Panel
      title={`${client} asks to sign in`}
      description={
        <>
          Approve only a sign-in you started yourself, and only if your terminal shows the code{' '}
          <Code>{request.user_code}</Code>. The client gets a token that acts as{' '}
          {username ? <Code>{username}</Code> : 'you'} on this server.
        </>
      }
    >
      <FactList
        items={[
          { term: 'Code', value: request.user_code, mono: true },
          {
            term: 'Client',
            value: (
              <>
                {client} (<Code>{request.client_id}</Code>)
              </>
            ),
          },
          { term: 'Access', value: describeScope(request.scope) },
          ...(request.client_ip
            ? [{ term: 'From address', value: request.client_ip, mono: true }]
            : []),
          { term: 'Requested', value: new Date(request.created_at).toLocaleString() },
          { term: 'Expires', value: new Date(request.expires_at).toLocaleString() },
        ]}
      />
      {gone ? (
        <Notice tone="warn" title="This sign-in is no longer pending">
          It expired or was answered already. Start the sign-in again for a new code.
        </Notice>
      ) : (
        error && (
          <Notice tone="danger" title="Could not answer the sign-in">
            {error.status === 429
              ? `Too many wrong codes; try again ${inWhile(error.retryAfterSeconds)}.`
              : error.body || error.message}
          </Notice>
        )
      )}
      <FormActions>
        <Button variant="ghost" disabled={pending} onClick={onEnterAnother}>
          Enter another code
        </Button>
        <Button variant="ghost" disabled={pending || gone} onClick={() => onDecide(false)}>
          Deny
        </Button>
        <Button variant="primary" disabled={pending || gone} onClick={() => onDecide(true)}>
          {pending ? 'Signing in…' : 'Approve'}
        </Button>
      </FormActions>
    </Panel>
  )
}
