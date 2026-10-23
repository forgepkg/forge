import { useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'

import {
  DEFAULT_INVITATION_TTL_HOURS,
  DEFAULT_SMTP_PORTS,
  type EmailSettingsInput,
  type EmailSettingsView,
  type SmtpTls,
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
import { ErrorState } from '~/components/ErrorState'

export const Route = createFileRoute('/_app/manage/settings/email')({
  component: EmailSettingsScreen,
})

/** The form's state: every field as typed. */
export interface EmailFormValues {
  enabled: boolean
  from_address: string
  from_name: string
  reply_to: string
  invitation_ttl_hours: string
  host: string
  port: string
  tls: SmtpTls
  username: string
  /** Blank keeps the stored password (for the same host and username). */
  password: string
}

/** The form seeded from the stored settings, or empty for new ones. */
export function seedEmailFormValues(stored?: EmailSettingsView): EmailFormValues {
  const smtp = stored?.transport
  return {
    enabled: stored?.enabled ?? true,
    from_address: stored?.from_address ?? '',
    from_name: stored?.from_name ?? '',
    reply_to: stored?.reply_to ?? '',
    invitation_ttl_hours: String(
      stored?.invitation_ttl_hours ?? DEFAULT_INVITATION_TTL_HOURS,
    ),
    host: smtp?.host ?? '',
    port: smtp?.port !== undefined ? String(smtp.port) : '',
    tls: smtp?.tls ?? 'starttls',
    username: smtp?.username ?? '',
    // Never seeded: the password is write-only.
    password: '',
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
    transport: {
      kind: 'smtp',
      host: values.host.trim(),
      port: port === '' ? undefined : Number(port),
      tls: values.tls,
      username: optional(values.username),
      password: values.password === '' ? undefined : values.password,
    },
  }
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

  // The server keeps a stored password only for the same host and username.
  const keepsPassword =
    !!stored?.transport.password_set &&
    !stored.secrets_unreadable &&
    values.host.trim() === stored.transport.host &&
    values.username.trim() === (stored.transport.username ?? '')

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
            <Select value="smtp" onChange={() => undefined}>
              <option value="smtp">SMTP server</option>
            </Select>
          </Field>
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
              <Select
                value={values.tls}
                onChange={(e) => set('tls', e.target.value as SmtpTls)}
              >
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
                  {stored?.transport.password_set && !stored.secrets_unreadable ? (
                    <Badge color="emerald">set</Badge>
                  ) : (
                    <Badge color="zinc">not set</Badge>
                  )}
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
        </FieldGroup>
      </Fieldset>

      <Button type="submit" disabled={save.isPending}>
        {save.isPending ? 'Saving…' : 'Save'}
      </Button>
    </form>
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
