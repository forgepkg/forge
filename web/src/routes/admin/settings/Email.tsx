import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import {
  DEFAULT_INVITATION_TTL_HOURS,
  DEFAULT_SMTP_PORTS,
  type EmailSettingsInput,
  type EmailSettingsView,
  type EmailTransport,
  type GraphClientAuth,
  type GraphTransportView,
  type SmtpTls,
  type SmtpTransportView,
} from '~/api/email'
import {
  useDeleteEmailSettings,
  useEmailSettings,
  useSaveEmailSettings,
  useSendTestEmail,
} from '~/queries/useEmail'
import { Badge } from '~/components/catalyst/badge'
import { Button } from '~/components/catalyst/button'
import { Checkbox, CheckboxField } from '~/components/catalyst/checkbox'
import {
  Description,
  Field,
  FieldGroup,
  Fieldset,
  Label,
  Legend,
} from '~/components/catalyst/fieldset'
import { Heading, Subheading } from '~/components/catalyst/heading'
import { Input } from '~/components/catalyst/input'
import { Select } from '~/components/catalyst/select'
import { Code, Text } from '~/components/catalyst/text'
import { CommandSnippet } from '~/components/CopyButton'
import { ErrorState } from '~/components/ErrorState'
import { federatedSubject } from '~/components/RealmForm'

export const Route = createFileRoute('/_app/manage/settings/email')({
  component: EmailSettingsScreen,
})

/** The transports the page offers. */
export type TransportKind = EmailTransport['kind']

/** The form's state: every field as typed, those of each transport. */
export interface EmailFormValues {
  enabled: boolean
  from_address: string
  from_name: string
  reply_to: string
  invitation_ttl_hours: string
  kind: TransportKind
  // smtp
  host: string
  port: string
  tls: SmtpTls
  username: string
  /** Blank keeps the stored password (for the same host and username). */
  password: string
  // microsoft_graph
  tenant_id: string
  client_id: string
  /** Blank: the From address. */
  sender: string
  client_authentication: GraphClientAuth
  /** Blank keeps the stored secret (for the same tenant and app). */
  client_secret: string
}

/** The entra sign-in host, as the server builds the federated subject. */
const MICROSOFT_LOGIN_HOST = 'https://login.microsoftonline.com'

/** The audience of Forge's client assertions. */
const ASSERTION_AUDIENCE = 'api://AzureADTokenExchange'

/**
 * The subject of Forge's client assertions for a Graph app, as the server
 * derives it: the same as a federated OIDC realm of that app and tenant, so
 * one federated credential serves both.
 */
export function graphFederatedSubject(tenantId: string, clientId: string): string {
  return federatedSubject(`${MICROSOFT_LOGIN_HOST}/${tenantId.trim()}/v2.0`, clientId)
}

function smtpOf(stored?: EmailSettingsView): SmtpTransportView | undefined {
  return stored?.transport.kind === 'smtp' ? stored.transport : undefined
}

function graphOf(stored?: EmailSettingsView): GraphTransportView | undefined {
  return stored?.transport.kind === 'microsoft_graph' ? stored.transport : undefined
}

/** The form seeded from the stored settings, or empty for new ones. */
export function seedEmailFormValues(stored?: EmailSettingsView): EmailFormValues {
  const smtp = smtpOf(stored)
  const graph = graphOf(stored)
  return {
    enabled: stored?.enabled ?? true,
    from_address: stored?.from_address ?? '',
    from_name: stored?.from_name ?? '',
    reply_to: stored?.reply_to ?? '',
    invitation_ttl_hours: String(
      stored?.invitation_ttl_hours ?? DEFAULT_INVITATION_TTL_HOURS,
    ),
    kind: stored?.transport.kind ?? 'smtp',
    host: smtp?.host ?? '',
    port: smtp?.port !== undefined ? String(smtp.port) : '',
    tls: smtp?.tls ?? 'starttls',
    username: smtp?.username ?? '',
    tenant_id: graph?.tenant_id ?? '',
    client_id: graph?.client_id ?? '',
    sender: graph?.sender ?? '',
    client_authentication: graph?.client_authentication ?? 'client_secret',
    // Never seeded: secrets are write-only.
    password: '',
    client_secret: '',
  }
}

/**
 * The `PUT` body: blank optional fields are left out (the server's defaults
 * apply), and so is a blank password (the stored one is kept).
 */
export function toEmailSettingsInput(values: EmailFormValues): EmailSettingsInput {
  const optional = (v: string) => (v.trim() === '' ? undefined : v.trim())
  const ttl = Number(values.invitation_ttl_hours.trim())
  const port = values.port.trim()
  return {
    enabled: values.enabled,
    from_address: values.from_address.trim(),
    from_name: optional(values.from_name),
    reply_to: optional(values.reply_to),
    invitation_ttl_hours:
      values.invitation_ttl_hours.trim() === '' || Number.isNaN(ttl)
        ? DEFAULT_INVITATION_TTL_HOURS
        : ttl,
    transport:
      values.kind === 'microsoft_graph'
        ? {
            kind: 'microsoft_graph',
            tenant_id: values.tenant_id.trim(),
            client_id: values.client_id.trim(),
            sender: optional(values.sender),
            client_authentication: values.client_authentication,
            client_secret:
              values.client_authentication === 'client_secret' && values.client_secret !== ''
                ? values.client_secret
                : undefined,
          }
        : {
            kind: 'smtp',
            host: values.host.trim(),
            port: port === '' ? undefined : Number(port),
            tls: values.tls,
            username: optional(values.username),
            password: values.password === '' ? undefined : values.password,
          },
  }
}

const TRANSPORT_LABELS: Record<TransportKind, string> = {
  smtp: 'SMTP server',
  microsoft_graph: 'Microsoft 365 (Graph)',
}

const TLS_LABELS: Record<SmtpTls, string> = {
  starttls: 'STARTTLS',
  implicit: 'TLS (SMTPS)',
  none: 'None: a relay on this host only',
}

/**
 * **Admin → Email** (`/manage/settings/email`): the email service Forge sends
 * invitations and notifications through. The settings exist in the database
 * only (no `forge.toml` section, no `FORGE_*` variable): this screen is where
 * they are made. Shows the stored settings (the password write-only), the
 * outcome of the last send, a test send, and removing the settings.
 */
function EmailSettingsScreen() {
  const settings = useEmailSettings()
  // Held here: the form remounts with what a save stored, its outcome stays.
  const save = useSaveEmailSettings()

  if (settings.isError) {
    return (
      <ErrorState
        title="Could not load the email settings"
        message={settings.error?.message}
        onRetry={() => void settings.refetch()}
      />
    )
  }
  if (settings.isLoading || !settings.data) {
    return <Text>Loading email settings…</Text>
  }
  const stored = settings.data.configured ? settings.data : undefined

  return (
    <section className="space-y-8">
      <div>
        <Heading>Email</Heading>
        <Text className="mt-1">
          The service Forge sends email through: invitations to new accounts
          and notifications. It is configured here only; no{' '}
          <Code>forge.toml</Code> setting or environment variable sets it, and a
          change applies to every instance shortly after it is saved.
        </Text>
      </div>
      {stored && <SendStatus stored={stored} />}
      {/* Remount on a new `updated_at`, so the form shows what was stored. */}
      <EmailSettingsForm key={stored?.updated_at ?? 'new'} stored={stored} save={save} />
      {stored && <TestSend />}
      {stored && <RemoveSettings />}
    </section>
  )
}

/** Whether email is on, the last send's outcome, unreadable secrets. */
function SendStatus({ stored }: { stored: EmailSettingsView }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {stored.enabled ? (
          <Badge color="emerald">Sending</Badge>
        ) : (
          <Badge color="zinc">Turned off</Badge>
        )}
        {stored.last_success_at && (
          <Text className="!text-sm">
            Last sent {new Date(stored.last_success_at).toLocaleString()}.
          </Text>
        )}
      </div>
      {stored.secrets_unreadable && (
        <p
          role="alert"
          className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-sm/6 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400"
        >
          The stored password does not decrypt (the secret-encryption root key
          changed). Enter it again below.
        </p>
      )}
      {stored.last_failure && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
        >
          The last send failed ({new Date(stored.last_failure.at).toLocaleString()}):{' '}
          {stored.last_failure.error}
        </p>
      )}
    </div>
  )
}

/** The settings form; `PUT`s the whole document. */
function EmailSettingsForm({
  stored,
  save,
}: {
  stored?: EmailSettingsView
  save: ReturnType<typeof useSaveEmailSettings>
}) {
  const [values, setValues] = useState(() => seedEmailFormValues(stored))
  const set = <K extends keyof EmailFormValues>(key: K, value: EmailFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }))


  function submit(e: React.FormEvent) {
    e.preventDefault()
    save.mutate(toEmailSettingsInput(values))
  }

  return (
    <form onSubmit={submit} className="space-y-8" aria-label="Email settings">
      {save.isSuccess && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Saved.
        </p>
      )}
      {save.isError && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
        >
          {save.error.body || save.error.message}
        </p>
      )}

      <Fieldset>
        <Legend>Sender</Legend>
        <FieldGroup>
          <CheckboxField>
            <Checkbox checked={values.enabled} onChange={(c) => set('enabled', c)} />
            <Label>Send email</Label>
            <Description>
              Turned off, Forge keeps the settings but sends nothing.
            </Description>
          </CheckboxField>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <Label>From address</Label>
              <Input
                type="email"
                required
                placeholder="forge@example.com"
                value={values.from_address}
                onChange={(e) => set('from_address', e.target.value)}
              />
            </Field>
            <Field>
              <Label>From name</Label>
              <Input
                placeholder="Forge"
                value={values.from_name}
                onChange={(e) => set('from_name', e.target.value)}
              />
            </Field>
            <Field>
              <Label>Reply-To</Label>
              <Input
                type="email"
                value={values.reply_to}
                onChange={(e) => set('reply_to', e.target.value)}
              />
              <Description>Optional: where replies go.</Description>
            </Field>
            <Field>
              <Label>Invitation lifetime (hours)</Label>
              <Input
                type="number"
                min={1}
                max={720}
                value={values.invitation_ttl_hours}
                onChange={(e) => set('invitation_ttl_hours', e.target.value)}
              />
              <Description>How long an invitation link stays valid (1 to 720).</Description>
            </Field>
          </div>
        </FieldGroup>
      </Fieldset>

      <Fieldset>
        <Legend>Transport</Legend>
        <FieldGroup>
          <Field className="sm:max-w-xs">
            <Label>Send through</Label>
            <Select
              value={values.kind}
              onChange={(e) => set('kind', e.target.value as TransportKind)}
            >
              {(Object.keys(TRANSPORT_LABELS) as TransportKind[]).map((kind) => (
                <option key={kind} value={kind}>
                  {TRANSPORT_LABELS[kind]}
                </option>
              ))}
            </Select>
          </Field>
          {values.kind === 'microsoft_graph' ? (
            <GraphFields values={values} set={set} stored={stored} />
          ) : (
            <SmtpFields values={values} set={set} stored={stored} />
          )}
        </FieldGroup>
      </Fieldset>

      <Button type="submit" disabled={save.isPending}>
        {save.isPending ? 'Saving…' : 'Save'}
      </Button>
    </form>
  )
}

type SetField = <K extends keyof EmailFormValues>(key: K, value: EmailFormValues[K]) => void

/** "set" or "not set" next to a write-only secret's label. */
function SecretBadge({ set }: { set: boolean }) {
  return set ? <Badge color="emerald">set</Badge> : <Badge color="zinc">not set</Badge>
}

/** The SMTP server's fields. */
function SmtpFields({
  values,
  set,
  stored,
}: {
  values: EmailFormValues
  set: SetField
  stored?: EmailSettingsView
}) {
  const smtp = smtpOf(stored)
  // The server keeps a stored password only for the same host and username.
  const keepsPassword =
    !!smtp?.password_set &&
    !stored?.secrets_unreadable &&
    values.host.trim() === smtp.host &&
    values.username.trim() === (smtp.username ?? '')
  return (
    <>
      <Text>
        SMTP submission with a username and password, or none for a relay.
        The server&apos;s certificate is always verified against the
        system&apos;s trusted roots.
      </Text>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <Label>Host</Label>
          <Input
            required
            placeholder="smtp.example.com"
            value={values.host}
            onChange={(e) => set('host', e.target.value)}
          />
        </Field>
        <Field>
          <Label>Encryption</Label>
          <Select value={values.tls} onChange={(e) => set('tls', e.target.value as SmtpTls)}>
            {(Object.keys(TLS_LABELS) as SmtpTls[]).map((tls) => (
              <option key={tls} value={tls}>
                {TLS_LABELS[tls]}
              </option>
            ))}
          </Select>
          {values.tls === 'none' && (
            <Description>
              Without TLS only a loopback host (a relay on this machine) is
              accepted.
            </Description>
          )}
        </Field>
        <Field>
          <Label>Port</Label>
          <Input
            type="number"
            min={1}
            max={65535}
            placeholder={String(DEFAULT_SMTP_PORTS[values.tls])}
            value={values.port}
            onChange={(e) => set('port', e.target.value)}
          />
        </Field>
        <Field>
          <Label>Username</Label>
          <Input
            autoComplete="off"
            value={values.username}
            onChange={(e) => set('username', e.target.value)}
          />
          <Description>Leave blank for a relay that takes mail without signing in.</Description>
        </Field>
        {values.username.trim() !== '' && (
          <Field>
            <Label>
              Password{' '}
              <SecretBadge set={!!smtp?.password_set && !stored?.secrets_unreadable} />
            </Label>
            <Input
              type="password"
              autoComplete="new-password"
              placeholder={keepsPassword ? '(stored)' : ''}
              value={values.password}
              onChange={(e) => set('password', e.target.value)}
            />
            <Description>
              {keepsPassword
                ? 'A password is stored; leave blank to keep it.'
                : 'Never shown again once saved.'}
            </Description>
          </Field>
        )}
      </div>
    </>
  )
}

/**
 * The Microsoft Graph app's fields: the tenant and app registration, the
 * mailbox it sends as, and how it signs in. A federated credential shows the
 * values to enter on the app (Certificates & secrets → Federated credentials
 * → Other issuer); Forge's issuer URL is known once the settings are saved.
 */
function GraphFields({
  values,
  set,
  stored,
}: {
  values: EmailFormValues
  set: SetField
  stored?: EmailSettingsView
}) {
  const graph = graphOf(stored)
  const sameApp =
    !!graph &&
    values.tenant_id.trim().toLowerCase() === graph.tenant_id.toLowerCase() &&
    values.client_id.trim().toLowerCase() === graph.client_id.toLowerCase()
  const keepsSecret = !!graph?.client_secret_set && !stored?.secrets_unreadable && sameApp
  const subject =
    values.tenant_id.trim() !== '' && values.client_id.trim() !== ''
      ? graphFederatedSubject(values.tenant_id, values.client_id)
      : null
  return (
    <>
      <Text>
        Forge signs in as an Entra app registration and sends with Microsoft
        Graph; no mailbox password is stored and SMTP AUTH can stay off. Give
        the app Exchange Online&apos;s <Code>Application Mail.Send</Code> role
        scoped to the sender mailbox (RBAC for Applications) rather than a
        tenant-wide <Code>Mail.Send</Code> consent.
      </Text>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <Label>Tenant</Label>
          <Input
            required
            placeholder="contoso.onmicrosoft.com"
            value={values.tenant_id}
            onChange={(e) => set('tenant_id', e.target.value)}
          />
          <Description>The directory (tenant) id, or one of its domains.</Description>
        </Field>
        <Field>
          <Label>Application (client) id</Label>
          <Input
            required
            value={values.client_id}
            onChange={(e) => set('client_id', e.target.value)}
          />
        </Field>
        <Field>
          <Label>Sender mailbox</Label>
          <Input
            placeholder={values.from_address || 'the From address'}
            value={values.sender}
            onChange={(e) => set('sender', e.target.value)}
          />
          <Description>Its UPN or object id; blank sends as the From address.</Description>
        </Field>
        <Field>
          <Label>Sign in with</Label>
          <Select
            value={values.client_authentication}
            onChange={(e) => set('client_authentication', e.target.value as GraphClientAuth)}
          >
            <option value="client_secret">A client secret</option>
            <option value="federated_credential">
              A federated credential (no secret)
            </option>
          </Select>
        </Field>
        {values.client_authentication === 'client_secret' && (
          <Field>
            <Label>
              Client secret{' '}
              <SecretBadge set={!!graph?.client_secret_set && !stored?.secrets_unreadable} />
            </Label>
            <Input
              type="password"
              autoComplete="new-password"
              placeholder={keepsSecret ? '(stored)' : ''}
              value={values.client_secret}
              onChange={(e) => set('client_secret', e.target.value)}
            />
            <Description>
              {keepsSecret
                ? 'A secret is stored; leave blank to keep it.'
                : 'Never shown again once saved.'}
            </Description>
          </Field>
        )}
      </div>
      {values.client_authentication === 'federated_credential' && (
        <div className="space-y-3 rounded-lg bg-zinc-950/[2.5%] px-3 py-3 ring-1 ring-zinc-950/5 dark:bg-white/[2.5%] dark:ring-white/10">
          <p className="text-sm/6 text-zinc-600 dark:text-zinc-400">
            Forge signs in with a client assertion it signs itself, as an
            OpenID Connect issuer publishing{' '}
            <code>/.well-known/openid-configuration</code> and its keys (rotated
            automatically). Add a federated credential for an <em>other
            issuer</em> to the app registration with these values; Entra must
            reach Forge&apos;s issuer URL over https.
          </p>
          {stored?.federated_credential ? (
            <CommandSnippet
              command={stored.federated_credential.issuer}
              label="Issuer"
              copyLabel="Copy issuer"
            />
          ) : (
            <p className="text-sm/6 text-zinc-600 dark:text-zinc-400">
              Forge&apos;s issuer URL is shown once the settings are saved.
            </p>
          )}
          {subject && (
            <CommandSnippet
              command={subject}
              label="Subject identifier"
              copyLabel="Copy subject identifier"
            />
          )}
          <CommandSnippet
            command={ASSERTION_AUDIENCE}
            label="Audience"
            copyLabel="Copy audience"
          />
        </div>
      )}
    </>
  )
}

/** A test send with the stored settings, to `to` or the calling admin. */
function TestSend() {
  const test = useSendTestEmail()
  const [to, setTo] = useState('')
  return (
    <section className="space-y-3 border-t border-zinc-950/5 pt-6 dark:border-white/10">
      <Subheading>Test</Subheading>
      <Text>
        Sends a test message with the stored settings, even while sending is
        turned off.
      </Text>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault()
          test.mutate(to.trim() || undefined)
        }}
      >
        <Field className="min-w-64 flex-1">
          <Label>Recipient</Label>
          <Input
            type="email"
            placeholder="Your address"
            value={to}
            onChange={(e) => setTo(e.target.value)}
          />
        </Field>
        <Button type="submit" outline disabled={test.isPending}>
          {test.isPending ? 'Sending…' : 'Send test email'}
        </Button>
      </form>
      {test.data?.sent && (
        <p
          role="status"
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2 text-sm/6 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400"
        >
          Sent to {test.data.to}.
        </p>
      )}
      {(test.data?.sent === false || test.isError) && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
        >
          {test.data?.sent === false
            ? `Sending to ${test.data.to} failed: ${test.data.error ?? 'unknown error'}`
            : test.error?.body || test.error?.message}
        </p>
      )}
    </section>
  )
}

/** Remove the settings, after a confirmation: Forge then sends no email. */
function RemoveSettings() {
  const remove = useDeleteEmailSettings()
  const [confirming, setConfirming] = useState(false)
  return (
    <section className="space-y-3 border-t border-zinc-950/5 pt-6 dark:border-white/10">
      <Subheading>Remove</Subheading>
      <Text>
        Removes the settings and the stored password. Forge then sends no
        email, and invitations cannot be sent.
      </Text>
      {remove.isError && (
        <p
          role="alert"
          className="rounded-lg border border-red-500/25 bg-red-500/5 px-3 py-2 text-sm/6 text-red-700 dark:bg-red-500/10 dark:text-red-400"
        >
          {remove.error.body || remove.error.message}
        </p>
      )}
      {confirming ? (
        <div className="flex items-center gap-3">
          <Button
            color="red"
            disabled={remove.isPending}
            onClick={() => remove.mutate(undefined, { onSettled: () => setConfirming(false) })}
          >
            {remove.isPending ? 'Removing…' : 'Remove the email settings'}
          </Button>
          <Button plain onClick={() => setConfirming(false)}>
            Cancel
          </Button>
        </div>
      ) : (
        <Button outline onClick={() => setConfirming(true)}>
          Remove…
        </Button>
      )}
    </section>
  )
}
