import { useEffect, useRef, useState } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useQueryClient } from '@tanstack/react-query'

import {
  DEFAULT_INVITATION_TTL_HOURS,
  DEFAULT_SMTP_PORTS,
  emailKeys,
  oauthErrorText,
  pollEmailOauthDevice,
  type DeviceAuthorization,
  type EmailSettingsInput,
  type EmailSettingsView,
  type EmailTransport,
  type GraphClientAuth,
  type GraphTransportView,
  type RegistrationAuth,
  type SmtpOauthTransportView,
  type SmtpTls,
  type SmtpTransportView,
} from '~/api/email'
import { ApiError } from '~/lib/httpClient'
import { assignLocation } from '~/lib/navigation'
import { formatDateTime } from '~/lib/oci'
import {
  useDeleteEmailSettings,
  useEmailOauthClientCredentials,
  useEmailSettings,
  useForgetEmailOauthClient,
  useRegisterEmailOauthClient,
  useSaveEmailSettings,
  useSendTestEmail,
  useStartEmailOauthCodeFlow,
  useStartEmailOauthDeviceFlow,
} from '~/queries/useEmail'
import {
  Button,
  Code,
  Columns,
  CopyButton,
  CopyField,
  Dialog,
  FactList,
  Fieldset,
  FormActions,
  Notice,
  Page,
  PageHeader,
  Panel,
  SelectField,
  Skeleton,
  StatusBadge,
  Switch,
  TextField,
  type Fact,
} from '~/components/ui'
import { ErrorState } from '~/components/ErrorState'
import { federatedSubject } from '~/components/RealmForm'

/**
 * How an SMTP-with-OAuth authorization in the browser ended: the callback
 * sends the browser back here with `?oauth=<outcome>` (and the OAuth `error`
 * code when there is one).
 */
export type OauthOutcome =
  | 'authorized'
  | 'expired'
  | 'other_session'
  | 'refused'
  | 'changed'
  | 'no_refresh_token'
  | 'token_failed'
  | 'unavailable'

const OAUTH_OUTCOMES: Record<OauthOutcome, string> = {
  authorized: 'The mailbox authorized Forge: it can send now.',
  expired: 'The authorization expired or was completed already. Start it again.',
  other_session:
    'The authorization was started in another browser or by another administrator. Start it again here.',
  refused: 'The authorization server refused the authorization.',
  changed: 'The email settings changed during the authorization. Start it again.',
  no_refresh_token:
    "The authorization server issued no refresh token, so Forge could send only for a short while. Allow Forge's client the refresh_token grant (some servers want the offline_access scope) and authorize again.",
  token_failed:
    'The authorization server did not exchange the authorization for a token. The server log says why.',
  unavailable: 'The authorization could not be stored. Try again.',
}

export interface EmailSearch {
  oauth?: OauthOutcome
  error?: string
}

export const Route = createFileRoute('/_app/manage/settings/email')({
  component: EmailSettingsScreen,
  validateSearch: (search: Record<string, unknown>): EmailSearch => ({
    oauth:
      typeof search.oauth === 'string' && search.oauth in OAUTH_OUTCOMES
        ? (search.oauth as OauthOutcome)
        : undefined,
    // An OAuth error code (RFC 6749 §5.2), never free text.
    error:
      typeof search.error === 'string' && /^[a-z0-9_]{1,64}$/.test(search.error)
        ? search.error
        : undefined,
  }),
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
  // smtp_oauth (with host, port, tls, and username as the mailbox)
  issuer: string
  scope: string
  /** A client entered by hand; blank keeps the stored client. */
  oauth_client_id: string
  /** Blank keeps the stored secret. */
  oauth_client_secret: string
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

function oauthOf(stored?: EmailSettingsView): SmtpOauthTransportView | undefined {
  return stored?.transport.kind === 'smtp_oauth' ? stored.transport : undefined
}

/** The form seeded from the stored settings, or empty for new ones. */
export function seedEmailFormValues(stored?: EmailSettingsView): EmailFormValues {
  const smtp = smtpOf(stored)
  const graph = graphOf(stored)
  const oauth = oauthOf(stored)
  const server = smtp ?? oauth
  return {
    enabled: stored?.enabled ?? true,
    from_address: stored?.from_address ?? '',
    from_name: stored?.from_name ?? '',
    reply_to: stored?.reply_to ?? '',
    invitation_ttl_hours: String(
      stored?.invitation_ttl_hours ?? DEFAULT_INVITATION_TTL_HOURS,
    ),
    kind: stored?.transport.kind ?? 'smtp',
    host: server?.host ?? '',
    port: server?.port !== undefined ? String(server.port) : '',
    tls: server?.tls ?? 'starttls',
    username: server?.username ?? '',
    tenant_id: graph?.tenant_id ?? '',
    client_id: graph?.client_id ?? '',
    sender: graph?.sender ?? '',
    client_authentication: graph?.client_authentication ?? 'client_secret',
    issuer: oauth?.issuer ?? '',
    scope: oauth?.scope ?? '',
    // A client Forge registered is kept without naming it.
    oauth_client_id: oauth && !oauth.registered ? (oauth.client_id ?? '') : '',
    // Never seeded: secrets are write-only.
    password: '',
    client_secret: '',
    oauth_client_secret: '',
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
      values.kind === 'smtp_oauth'
        ? {
            kind: 'smtp_oauth',
            host: values.host.trim(),
            port: port === '' ? undefined : Number(port),
            tls: values.tls,
            issuer: values.issuer.trim(),
            username: values.username.trim(),
            scope: optional(values.scope),
            client_id: optional(values.oauth_client_id),
            client_secret:
              values.oauth_client_id.trim() !== '' && values.oauth_client_secret !== ''
                ? values.oauth_client_secret
                : undefined,
          }
        : values.kind === 'microsoft_graph'
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
  smtp_oauth: 'SMTP server with OAuth',
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
 * they are made. The main column holds the settings form (the secrets
 * write-only) and, for SMTP with OAuth, registering Forge and authorizing
 * it; the side column the stored settings' status, a test send and removing
 * the settings.
 */
function EmailSettingsScreen() {
  const settings = useEmailSettings()
  const search = Route.useSearch()
  // Held here: the form remounts with what a save stored, its outcome stays.
  const save = useSaveEmailSettings()

  const header = (
    <PageHeader
      title="Email"
      description={
        <>
          The service Forge sends email through: invitations to new accounts
          and notifications. It is configured here only; no{' '}
          <Code>forge.toml</Code> setting or environment variable sets it, and a
          change applies to every instance shortly after it is saved.
        </>
      }
    />
  )

  if (settings.isError) {
    return (
      <Page>
        {header}
        <ErrorState
          title="Could not load the email settings"
          message={settings.error?.message}
          onRetry={() => void settings.refetch()}
        />
      </Page>
    )
  }
  if (settings.isLoading || !settings.data) {
    return (
      <Page>
        {header}
        <Skeleton lines={6} label="Loading email settings…" />
      </Page>
    )
  }
  const stored = settings.data.configured ? settings.data : undefined
  const oauth = oauthOf(stored)

  return (
    <Page>
      {header}
      {search.oauth && <OauthOutcomeNotice outcome={search.oauth} error={search.error} />}
      <Columns
        asideLabel="Email service"
        aside={
          stored && (
            <>
              <SendStatus stored={stored} />
              <TestSend />
              <RemoveSettings />
            </>
          )
        }
      >
        {stored && <SendProblems stored={stored} />}
        {/*
         * Remount on a new `updated_at` or OAuth client, so the form shows what
         * was stored.
         */}
        <EmailSettingsForm
          key={`${stored?.updated_at ?? 'new'} ${oauth?.client_id ?? ''}`}
          stored={stored}
          save={save}
        />
        {stored && oauth && <OauthAuthorization stored={stored} oauth={oauth} />}
      </Columns>
    </Page>
  )
}

/** The side column's facts: whether email is on, how, and the last send. */
function SendStatus({ stored }: { stored: EmailSettingsView }) {
  const facts: Fact[] = [
    {
      term: 'State',
      value: stored.enabled ? (
        <StatusBadge tone="ok">sending</StatusBadge>
      ) : (
        <StatusBadge tone="neutral">turned off</StatusBadge>
      ),
    },
    { term: 'Transport', value: TRANSPORT_LABELS[stored.transport.kind] },
  ]
  if (stored.last_success_at) {
    facts.push({ term: 'Last sent', value: formatDateTime(stored.last_success_at) })
  }
  return (
    <Panel title="Status">
      <FactList items={facts} />
    </Panel>
  )
}

/** What needs attention: unreadable secrets, and the last send's failure. */
function SendProblems({ stored }: { stored: EmailSettingsView }) {
  if (!stored.secrets_unreadable && !stored.last_failure) return null
  return (
    <>
      {stored.secrets_unreadable && (
        <Notice tone="warn">
          The stored password does not decrypt (the secret-encryption root key
          changed). Enter it again below.
        </Notice>
      )}
      {stored.last_failure && (
        <Notice tone="danger">
          The last send failed ({formatDateTime(stored.last_failure.at)}):{' '}
          {stored.last_failure.error}
        </Notice>
      )}
    </>
  )
}

/**
 * The settings form; `PUT`s the whole document. The sender and the transport
 * are a panel each, with the outcome and the Save button after them.
 */
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
    <form onSubmit={submit} className="flex flex-col gap-6" aria-label="Email settings">
      <Panel title="Sender">
        <div className="fg-form">
          <Switch
            label="Send email"
            // The label wraps the description too: name the switch by its label alone.
            aria-label="Send email"
            checked={values.enabled}
            onChange={(c) => set('enabled', c)}
            description="Turned off, Forge keeps the settings but sends nothing."
          />
          <div className="fg-fieldrow items-start">
            <TextField
              label="From address"
              type="email"
              required
              placeholder="forge@example.com"
              value={values.from_address}
              onChange={(e) => set('from_address', e.target.value)}
            />
            <TextField
              label="From name"
              placeholder="Forge"
              value={values.from_name}
              onChange={(e) => set('from_name', e.target.value)}
            />
            <TextField
              label="Reply-To"
              type="email"
              value={values.reply_to}
              onChange={(e) => set('reply_to', e.target.value)}
              description="Optional: where replies go."
            />
            <TextField
              label="Invitation lifetime (hours)"
              mono
              type="number"
              min={1}
              max={720}
              value={values.invitation_ttl_hours}
              onChange={(e) => set('invitation_ttl_hours', e.target.value)}
              description="How long an invitation link stays valid (1 to 720)."
            />
          </div>
        </div>
      </Panel>

      <Panel title="Transport">
        <div className="fg-form">
          <SelectField
            label="Send through"
            value={values.kind}
            onChange={(e) => set('kind', e.target.value as TransportKind)}
          >
            {(Object.keys(TRANSPORT_LABELS) as TransportKind[]).map((kind) => (
              <option key={kind} value={kind}>
                {TRANSPORT_LABELS[kind]}
              </option>
            ))}
          </SelectField>
          {values.kind === 'microsoft_graph' ? (
            <GraphFields values={values} set={set} stored={stored} />
          ) : values.kind === 'smtp_oauth' ? (
            <OauthFields values={values} set={set} stored={stored} />
          ) : (
            <SmtpFields values={values} set={set} stored={stored} />
          )}
        </div>
      </Panel>

      {save.isSuccess && <Notice tone="ok">Saved.</Notice>}
      {save.data?.warning && (
        <Notice tone="warn">
          Forge&apos;s earlier OAuth client was not deleted ({save.data.warning}).
        </Notice>
      )}
      {save.isError && <Notice tone="danger">{save.error.body || save.error.message}</Notice>}
      <FormActions>
        <Button type="submit" variant="primary" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save'}
        </Button>
      </FormActions>
    </form>
  )
}

type SetField = <K extends keyof EmailFormValues>(key: K, value: EmailFormValues[K]) => void

/** "set" or "not set" next to a write-only secret's label. */
function SecretBadge({ set }: { set: boolean }) {
  return set ? (
    <StatusBadge tone="ok">set</StatusBadge>
  ) : (
    <StatusBadge tone="neutral">not set</StatusBadge>
  )
}

/** A write-only secret: blank keeps the stored one when the server would. */
function SecretField({
  label,
  set,
  keeps,
  value,
  onChange,
  keepHint = 'A secret is stored; leave blank to keep it.',
  blankHint = 'Never shown again once saved.',
}: {
  label: string
  /** Whether a readable secret is stored. */
  set: boolean
  /** Whether a blank field keeps the stored secret. */
  keeps: boolean
  value: string
  onChange: (value: string) => void
  keepHint?: string
  blankHint?: string
}) {
  return (
    <TextField
      label={
        <>
          {label} <SecretBadge set={set} />
        </>
      }
      type="password"
      autoComplete="new-password"
      placeholder={keeps ? '(stored)' : ''}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      description={keeps ? keepHint : blankHint}
    />
  )
}

/** The SMTP server's host, then its encryption and port side by side. */
function SmtpServerFields({ values, set }: { values: EmailFormValues; set: SetField }) {
  return (
    <>
      <TextField
        label="Host"
        mono
        required
        placeholder="smtp.example.com"
        value={values.host}
        onChange={(e) => set('host', e.target.value)}
      />
      <div className="fg-fieldrow items-start">
        <SelectField
          label="Encryption"
          value={values.tls}
          onChange={(e) => set('tls', e.target.value as SmtpTls)}
          description={
            values.tls === 'none'
              ? 'Without TLS only a loopback host (a relay on this machine) is accepted.'
              : undefined
          }
        >
          {(Object.keys(TLS_LABELS) as SmtpTls[]).map((tls) => (
            <option key={tls} value={tls}>
              {TLS_LABELS[tls]}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Port"
          mono
          type="number"
          min={1}
          max={65535}
          placeholder={String(DEFAULT_SMTP_PORTS[values.tls])}
          value={values.port}
          onChange={(e) => set('port', e.target.value)}
        />
      </div>
    </>
  )
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
      <p className="fg-text">
        SMTP submission with a username and password, or none for a relay.
        The server&apos;s certificate is always verified against the
        system&apos;s trusted roots.
      </p>
      <SmtpServerFields values={values} set={set} />
      <div className="fg-fieldrow items-start">
        <TextField
          label="Username"
          autoComplete="off"
          value={values.username}
          onChange={(e) => set('username', e.target.value)}
          description="Leave blank for a relay that takes mail without signing in."
        />
        {values.username.trim() !== '' && (
          <SecretField
            label="Password"
            set={!!smtp?.password_set && !stored?.secrets_unreadable}
            keeps={keepsPassword}
            value={values.password}
            onChange={(v) => set('password', v)}
            keepHint="A password is stored; leave blank to keep it."
          />
        )}
      </div>
    </>
  )
}

/**
 * The Microsoft Graph app's fields: the tenant and app registration, the
 * mailbox it sends as, and how it signs in. A federated credential shows the
 * values to enter on the app (Certificates & secrets → Federated credentials
 * → Other issuer), each with a Copy button; Forge's issuer URL is known once
 * the settings are saved.
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
      <p className="fg-text">
        Forge signs in as an Entra app registration and sends with Microsoft
        Graph; no mailbox password is stored and SMTP AUTH can stay off. Give
        the app Exchange Online&apos;s <Code>Application Mail.Send</Code> role
        scoped to the sender mailbox (RBAC for Applications) rather than a
        tenant-wide <Code>Mail.Send</Code> consent.
      </p>
      <div className="fg-fieldrow items-start">
        <TextField
          label="Tenant"
          mono
          required
          placeholder="contoso.onmicrosoft.com"
          value={values.tenant_id}
          onChange={(e) => set('tenant_id', e.target.value)}
          description="The directory (tenant) id, or one of its domains."
        />
        <TextField
          label="Application (client) id"
          mono
          required
          value={values.client_id}
          onChange={(e) => set('client_id', e.target.value)}
        />
      </div>
      <TextField
        label="Sender mailbox"
        placeholder={values.from_address || 'the From address'}
        value={values.sender}
        onChange={(e) => set('sender', e.target.value)}
        description="Its UPN or object id; blank sends as the From address."
      />
      <div className="fg-fieldrow items-start">
        <SelectField
          label="Sign in with"
          value={values.client_authentication}
          onChange={(e) => set('client_authentication', e.target.value as GraphClientAuth)}
        >
          <option value="client_secret">A client secret</option>
          <option value="federated_credential">A federated credential (no secret)</option>
        </SelectField>
        {values.client_authentication === 'client_secret' && (
          <SecretField
            label="Client secret"
            set={!!graph?.client_secret_set && !stored?.secrets_unreadable}
            keeps={keepsSecret}
            value={values.client_secret}
            onChange={(v) => set('client_secret', v)}
          />
        )}
      </div>
      {values.client_authentication === 'federated_credential' && (
        <Fieldset
          legend="Federated credential"
          description={
            <>
              Forge signs in with a client assertion it signs itself, as an
              OpenID Connect issuer publishing{' '}
              <Code>/.well-known/openid-configuration</Code> and its keys
              (rotated automatically). Add a federated credential for an{' '}
              <em>other issuer</em> to the app registration with these values;
              Entra must reach Forge&apos;s issuer URL over https.
            </>
          }
        >
          {stored?.federated_credential ? (
            <CopyField
              label="Issuer"
              value={stored.federated_credential.issuer}
              copyLabel="Copy issuer"
            />
          ) : (
            <p className="fg-text">
              Forge&apos;s issuer URL is shown once the settings are saved.
            </p>
          )}
          {subject && (
            <CopyField
              label="Subject identifier"
              value={subject}
              copyLabel="Copy subject identifier"
            />
          )}
          <CopyField label="Audience" value={ASSERTION_AUDIENCE} copyLabel="Copy audience" />
        </Fieldset>
      )}
    </>
  )
}

/**
 * SMTP with OAuth: the server, the mailbox, the authorization server, and
 * the client when it is entered by hand (Forge can register itself after
 * the save instead).
 */
function OauthFields({
  values,
  set,
  stored,
}: {
  values: EmailFormValues
  set: SetField
  stored?: EmailSettingsView
}) {
  const oauth = oauthOf(stored)
  const sameIssuer = !!oauth && values.issuer.trim().replace(/\/+$/, '') === oauth.issuer
  const registered = sameIssuer && !!oauth.registered && !!oauth.client_id
  const keepsSecret =
    sameIssuer &&
    !!oauth.client_secret_set &&
    !stored?.secrets_unreadable &&
    values.oauth_client_id.trim() === (oauth.client_id ?? '')
  return (
    <>
      <p className="fg-text">
        SMTP submission with an OAuth access token (SASL{' '}
        <Code>OAUTHBEARER</Code>, or <Code>XOAUTH2</Code>) from the mail
        server&apos;s own authorization server, Stalwart&apos;s for one. Forge
        registers itself there or uses a client you enter, and the mailbox
        authorizes it once, below; no mailbox password is stored.
      </p>
      <SmtpServerFields values={values} set={set} />
      <TextField
        label="Mailbox"
        required
        autoComplete="off"
        placeholder={values.from_address || 'forge@example.com'}
        value={values.username}
        onChange={(e) => set('username', e.target.value)}
        description="The account Forge sends as; it authorizes Forge."
      />
      <TextField
        label="Authorization server"
        mono
        required
        type="url"
        placeholder="https://mail.example.com"
        value={values.issuer}
        onChange={(e) => set('issuer', e.target.value)}
        description={
          <>
            Its issuer URL: Forge reads{' '}
            <Code>/.well-known/oauth-authorization-server</Code> there.
          </>
        }
      />
      <TextField
        label="Scope"
        mono
        value={values.scope}
        onChange={(e) => set('scope', e.target.value)}
        description="Space-separated, when the server wants one."
      />
      {registered ? (
        <p className="fg-text">
          Forge registered itself as the client <Code>{oauth.client_id}</Code>;
          forget it below to use another.
        </p>
      ) : (
        <div className="fg-fieldrow items-start">
          <TextField
            label="Client id"
            mono
            autoComplete="off"
            value={values.oauth_client_id}
            onChange={(e) => set('oauth_client_id', e.target.value)}
            description="Blank: register Forge after saving, when the server allows dynamic client registration. Otherwise register a client there with the redirect URI shown once the settings are saved."
          />
          {values.oauth_client_id.trim() !== '' && (
            <SecretField
              label="Client secret"
              set={!!oauth?.client_secret_set && !stored?.secrets_unreadable}
              keeps={keepsSecret}
              value={values.oauth_client_secret}
              onChange={(v) => set('oauth_client_secret', v)}
              blankHint="Blank for a public client. Never shown again once saved."
            />
          )}
        </div>
      )}
    </>
  )
}

/** How the authorization in the browser ended, with a way to dismiss it. */
function OauthOutcomeNotice({ outcome, error }: { outcome: OauthOutcome; error?: string }) {
  const navigate = useNavigate()
  const dismiss = () =>
    void navigate({ to: '/manage/settings/email', search: {}, replace: true })
  return (
    <Notice
      tone={outcome === 'authorized' ? 'ok' : 'danger'}
      action={
        <Button size="sm" variant="ghost" onClick={dismiss}>
          Dismiss
        </Button>
      }
    >
      {OAUTH_OUTCOMES[outcome]}
      {error && (
        <>
          {' '}
          (<Code>{error}</Code>)
        </>
      )}
    </Notice>
  )
}

/** The text of a failed OAuth request. */
function errorText(e: unknown): string {
  return e instanceof ApiError ? oauthErrorText(e) : String(e)
}

/**
 * Forge's client at the authorization server and the mailbox's
 * authorization, for the stored `smtp_oauth` settings: register Forge or
 * forget its client, and authorize it in this browser, on another device, or
 * by the client credentials grant. The redirect URI to register a client
 * with closes the panel.
 */
function OauthAuthorization({
  stored,
  oauth,
}: {
  stored: EmailSettingsView
  oauth: SmtpOauthTransportView
}) {
  const register = useRegisterEmailOauthClient()
  const [registerAs, setRegisterAs] = useState<'nothing' | 'token' | 'account'>('nothing')
  const [registrationUsername, setRegistrationUsername] = useState('')
  const [registrationPassword, setRegistrationPassword] = useState('')
  const forget = useForgetEmailOauthClient()
  const codeFlow = useStartEmailOauthCodeFlow()
  const deviceFlow = useStartEmailOauthDeviceFlow()
  const clientCredentials = useEmailOauthClientCredentials()
  const [initialAccessToken, setInitialAccessToken] = useState('')
  const [device, setDevice] = useState<DeviceAuthorization | null>(null)
  const [deviceAuthorized, setDeviceAuthorized] = useState(false)
  const failed = [register, forget, codeFlow, deviceFlow, clientCredentials].find(
    (m) => m.isError,
  )
  const warning = register.data?.warning ?? forget.data?.warning
  const busy =
    register.isPending ||
    forget.isPending ||
    codeFlow.isPending ||
    deviceFlow.isPending ||
    clientCredentials.isPending ||
    device !== null

  return (
    <Panel
      title="Authorization"
      description="Forge's client at the authorization server, and the mailbox's authorization to send with it."
    >
      {failed?.error && <Notice tone="danger">{errorText(failed.error)}</Notice>}
      {warning && (
        <Notice tone="warn">
          Forge&apos;s earlier registration was not deleted at the
          authorization server ({warning}); remove it there.
        </Notice>
      )}
      {!oauth.client_id ? (
        <form
          className="fg-form"
          onSubmit={(e) => {
            e.preventDefault()
            const auth: RegistrationAuth =
              registerAs === 'token'
                ? { initial_access_token: initialAccessToken.trim() }
                : registerAs === 'account'
                  ? { username: registrationUsername.trim(), password: registrationPassword }
                  : {}
            register.mutate(auth, {
              onSuccess: () => {
                setInitialAccessToken('')
                setRegistrationPassword('')
              },
            })
          }}
        >
          <p className="fg-text">
            Forge has no client at the authorization server yet. Register it,
            when the server allows dynamic client registration (RFC 7591), or
            enter a client above.
          </p>
          <SelectField
            label="Register as"
            value={registerAs}
            onChange={(e) => setRegisterAs(e.target.value as typeof registerAs)}
            description="How the server authenticates registrations. Stalwart wants an account allowed to register OAuth clients. Used once, never stored."
          >
            <option value="nothing">Anyone (open registration)</option>
            <option value="token">An initial access token</option>
            <option value="account">An account of the mail server</option>
          </SelectField>
          {registerAs === 'token' && (
            <TextField
              label="Initial access token"
              type="password"
              required
              autoComplete="off"
              value={initialAccessToken}
              onChange={(e) => setInitialAccessToken(e.target.value)}
            />
          )}
          {registerAs === 'account' && (
            <div className="fg-fieldrow items-start">
              <TextField
                label="Account"
                required
                autoComplete="off"
                value={registrationUsername}
                onChange={(e) => setRegistrationUsername(e.target.value)}
              />
              <TextField
                label="Account password"
                type="password"
                required
                autoComplete="off"
                value={registrationPassword}
                onChange={(e) => setRegistrationPassword(e.target.value)}
              />
            </div>
          )}
          <div className="fg-actions">
            <Button type="submit" disabled={busy}>
              {register.isPending ? 'Registering…' : 'Register Forge'}
            </Button>
          </div>
        </form>
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="fg-text">
              Client <Code>{oauth.client_id}</Code>,{' '}
              {oauth.registered ? 'registered by Forge' : 'entered by hand'}.
            </p>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => forget.mutate()}>
              Forget client
            </Button>
          </div>
          <AuthorizationState oauth={oauth} />
          {deviceAuthorized && !device && (
            <Notice tone="ok">The mailbox authorized Forge: it can send now.</Notice>
          )}
          {device ? (
            <DeviceFlow
              flow={device}
              onDone={(authorized) => {
                setDevice(null)
                setDeviceAuthorized(authorized)
              }}
            />
          ) : (
            <div className="fg-actions">
              <Button
                disabled={busy}
                onClick={() =>
                  codeFlow.mutate(undefined, {
                    onSuccess: ({ authorization_url }) => assignLocation(authorization_url),
                  })
                }
              >
                Authorize in this browser
              </Button>
              <Button
                disabled={busy}
                onClick={() =>
                  deviceFlow.mutate(undefined, {
                    onSuccess: (flow) => {
                      setDeviceAuthorized(false)
                      setDevice(flow)
                    },
                  })
                }
              >
                Authorize on another device
              </Button>
              <Button variant="ghost" disabled={busy} onClick={() => clientCredentials.mutate()}>
                Use the client credentials grant
              </Button>
            </div>
          )}
        </>
      )}
      {stored.oauth_redirect_uri && (
        <div className="fg-form">
          <CopyField
            label="Redirect URI"
            value={stored.oauth_redirect_uri}
            copyLabel="Copy redirect URI"
            description="Where the authorization server sends the browser back to. A client entered by hand must allow it."
          />
        </div>
      )}
    </Panel>
  )
}

/** Whether Forge can get tokens, and how. */
function AuthorizationState({ oauth }: { oauth: SmtpOauthTransportView }) {
  if (oauth.authorization_error) {
    return (
      <Notice tone="warn">
        The mailbox must authorize Forge again: {oauth.authorization_error}
      </Notice>
    )
  }
  if (oauth.grant === 'refresh_token') {
    return (
      <p className="fg-text flex flex-wrap items-center gap-2">
        <StatusBadge tone="ok">authorized</StatusBadge>
        <span>by {oauth.username}; Forge refreshes its access token when it needs one.</span>
      </p>
    )
  }
  if (oauth.grant === 'client_credentials') {
    return (
      <p className="fg-text flex flex-wrap items-center gap-2">
        <StatusBadge tone="ok">client credentials</StatusBadge>
        <span>Forge gets its access tokens as the client itself.</span>
      </p>
    )
  }
  return (
    <p className="fg-text flex flex-wrap items-center gap-2">
      <StatusBadge tone="warn">not authorized</StatusBadge>
      <span>Forge cannot send until it is authorized.</span>
    </p>
  )
}

/**
 * A device authorization in progress: the code to enter and where, polled
 * every `interval` seconds until the mailbox decides.
 */
function DeviceFlow({
  flow,
  onDone,
}: {
  flow: DeviceAuthorization
  onDone: (authorized: boolean) => void
}) {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)
  // The latest callback, without restarting the polling for each render.
  const done = useRef(onDone)
  useEffect(() => {
    done.current = onDone
  })
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const poll = async () => {
      try {
        const result = await pollEmailOauthDevice(flow.flow_id)
        if (cancelled) return
        if (result.status === 'authorized') {
          queryClient.setQueryData(emailKeys.settings(), result.settings)
          done.current(true)
          return
        }
        if (result.status === 'failed') {
          setError(result.error)
          return
        }
        setNote(result.error ?? null)
      } catch (e) {
        if (!cancelled) setError(errorText(e))
        return
      }
      timer = setTimeout(() => void poll(), flow.interval * 1000)
    }
    timer = setTimeout(() => void poll(), flow.interval * 1000)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [flow, queryClient])

  return (
    <div className="grid gap-4 rounded-md border border-line p-4">
      <p className="fg-text">
        Open{' '}
        <a
          href={flow.verification_uri_complete ?? flow.verification_uri}
          target="_blank"
          rel="noreferrer"
          className="fg-link"
        >
          {flow.verification_uri}
        </a>{' '}
        on any device, sign in as the mailbox, and enter this code:
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <span className="fg-mono rounded-sm border border-line bg-surface-sunken px-3 py-1 text-xl tracking-widest text-ink">
          {flow.user_code}
        </span>
        <CopyButton value={flow.user_code} label="Copy code" withText />
      </div>
      {error ? (
        <Notice tone="danger">{error}</Notice>
      ) : (
        <Notice tone="info" title="Waiting for the authorization…">
          Forge asks the authorization server every {flow.interval} second
          {flow.interval === 1 ? '' : 's'} until the mailbox decides; keep this
          page open until then.{note && ` (${note})`}
        </Notice>
      )}
      <div>
        <Button variant="ghost" onClick={() => onDone(false)}>
          {error ? 'Close' : 'Cancel'}
        </Button>
      </div>
    </div>
  )
}

/** A test send with the stored settings, to `to` or the calling admin. */
function TestSend() {
  const test = useSendTestEmail()
  const [to, setTo] = useState('')
  return (
    <Panel
      as="form"
      title="Test message"
      description="Sends a test message with the stored settings, even while sending is turned off."
      onSubmit={(e) => {
        e.preventDefault()
        test.mutate(to.trim() || undefined)
      }}
    >
      <TextField
        label="Recipient"
        type="email"
        placeholder="Your address"
        value={to}
        onChange={(e) => setTo(e.target.value)}
      />
      <div>
        <Button type="submit" icon="Mail" disabled={test.isPending}>
          {test.isPending ? 'Sending…' : 'Send test email'}
        </Button>
      </div>
      {test.data?.sent && <Notice tone="ok">Sent to {test.data.to}.</Notice>}
      {(test.data?.sent === false || test.isError) && (
        <Notice tone="danger">
          {test.data?.sent === false
            ? `Sending to ${test.data.to} failed: ${test.data.error ?? 'unknown error'}`
            : test.error?.body || test.error?.message}
        </Notice>
      )}
    </Panel>
  )
}

/**
 * Remove the settings, after a confirmation in a dialog: Forge then sends no
 * email.
 */
function RemoveSettings() {
  const remove = useDeleteEmailSettings()
  const [confirming, setConfirming] = useState(false)
  return (
    <Panel title="Danger zone">
      <p className="fg-text">
        Removes the settings and the stored password. Forge then sends no
        email, and invitations cannot be sent.
      </p>
      {remove.isError && (
        <Notice tone="danger">{remove.error.body || remove.error.message}</Notice>
      )}
      <div>
        <Button variant="danger" icon="Trash" onClick={() => setConfirming(true)}>
          Remove email settings
        </Button>
      </div>
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Remove the email settings?"
        icon="Trash"
        tone="danger"
        description="Forge then sends no email, and invitations cannot be sent until email is set up again. The stored password and secrets are deleted with the settings."
        confirmLabel={remove.isPending ? 'Removing…' : 'Remove the email settings'}
        confirmVariant="danger-solid"
        confirmDisabled={remove.isPending}
        onConfirm={() => remove.mutate(undefined, { onSettled: () => setConfirming(false) })}
      />
    </Panel>
  )
}
