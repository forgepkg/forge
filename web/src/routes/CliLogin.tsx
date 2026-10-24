import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'

import { cliLoginQueryOptions, decideCliLogin } from '~/api/cliLogin'
import { ApiError } from '~/lib/httpClient'
import { useMe } from '~/queries/useMe'
import { EmptyState } from '~/components/EmptyState'
import { ErrorState } from '~/components/ErrorState'
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
} from '~/components/ui'

export const Route = createFileRoute('/_app/cli-login/$secret')({
  component: CliLogin,
})

/**
 * The page `npm login` opens in the browser (its web login): the signed-in
 * user sees which client asks, for which repository and from where, and
 * signs it in as themselves or refuses. The client polls the registry and
 * receives a token once approved. A request that was decided, expired or
 * never existed answers 404, shown as "no longer pending".
 */
function CliLogin() {
  const { secret } = Route.useParams()
  const me = useMe()
  const request = useQuery(cliLoginQueryOptions(secret))
  const [decided, setDecided] = useState<boolean | null>(null)
  const decide = useMutation({
    mutationFn: (approve: boolean) => decideCliLogin(secret, approve),
    onSuccess: (_, approve) => setDecided(approve),
  })
  const header = <PageHeader title="Sign in a command-line client" icon="Terminal" />

  if (decided !== null) {
    return (
      <Page>
        {header}
        <Notice tone={decided ? 'ok' : 'info'} title={decided ? 'Signed in' : 'Refused'}>
          {decided
            ? 'The client is signed in as you. Return to your terminal; you can close this page.'
            : 'The client was not signed in. Return to your terminal; you can close this page.'}
        </Notice>
      </Page>
    )
  }

  if (request.isLoading) {
    return (
      <Page>
        {header}
        <Skeleton variant="text" label="Loading the login request…" />
      </Page>
    )
  }

  if (request.isError) {
    const gone = request.error instanceof ApiError && request.error.status === 404
    return (
      <Page>
        {header}
        {gone ? (
          <EmptyState title="This login request is no longer pending" icon="Clock">
            It was answered already, or it expired. Run <Code>npm login</Code> again
            for a new one.
          </EmptyState>
        ) : (
          <ErrorState
            title="Could not load the login request"
            message={request.error?.message}
            onRetry={() => void request.refetch()}
          />
        )}
      </Page>
    )
  }

  const login = request.data
  if (!login) return null
  const gone = decide.error instanceof ApiError && decide.error.status === 404
  const username = me.data?.user.username

  return (
    <Page>
      {header}
      <Panel
        title={`${login.client} asks to sign in`}
        description={
          <>
            Approve only a login you started yourself, with <Code>npm login</Code>. The
            client gets a token that acts as{' '}
            {username ? <Code>{username}</Code> : 'you'} on this server.
          </>
        }
      >
        <FactList
          items={[
            { term: 'Client', value: login.client, mono: true },
            { term: 'Repository', value: login.repository, mono: true },
            ...(login.hostname
              ? [{ term: 'Computer', value: login.hostname, mono: true }]
              : []),
            ...(login.client_ip
              ? [{ term: 'From address', value: login.client_ip, mono: true }]
              : []),
            { term: 'Requested', value: new Date(login.created_at).toLocaleString() },
            { term: 'Expires', value: new Date(login.expires_at).toLocaleString() },
          ]}
        />
        {gone ? (
          <Notice tone="warn" title="This login request is no longer pending">
            It was answered already, or it expired. Run <Code>npm login</Code> again for a
            new one.
          </Notice>
        ) : (
          decide.isError && (
            <Notice tone="danger" title="Could not answer the login request">
              {decide.error.message}
            </Notice>
          )
        )}
        <FormActions>
          <Button
            variant="ghost"
            disabled={decide.isPending || gone}
            onClick={() => decide.mutate(false)}
          >
            Refuse
          </Button>
          <Button
            variant="primary"
            disabled={decide.isPending || gone}
            onClick={() => decide.mutate(true)}
          >
            {decide.isPending ? 'Signing in…' : 'Sign in'}
          </Button>
        </FormActions>
      </Panel>
    </Page>
  )
}
