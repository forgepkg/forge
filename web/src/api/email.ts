import { ApiError, httpClient } from '~/lib/httpClient'

/**
 * Admin email-service settings API (`/admin/settings/email`, #319). The
 * settings live in the database only: there is no `forge.toml` section and no
 * `FORGE_*` variable for them.
 *
 *  - `GET` returns the settings without their secrets (`{configured: false}`
 *    before any): each secret is a `<key>_set` flag.
 *  - `PUT` stores them. A secret the body omits keeps the stored one, unless
 *    the transport or a field the secret belongs to (the SMTP host or
 *    username) changed.
 *  - `DELETE` removes them: Forge sends no email.
 *  - `POST /test` sends a test message to `to`, or to the calling admin's
 *    address; a failed send answers 502 with the server's error.
 */

/** How an SMTP connection is protected (certificates are always verified). */
export type SmtpTls = 'implicit' | 'starttls' | 'none'

/** SMTP submission, as `PUT` takes it. */
export interface SmtpTransport {
  kind: 'smtp'
  host: string
  /** Absent: the TLS mode's usual port (465, 587 or 25). */
  port?: number
  tls: SmtpTls
  /** Absent: no authentication (a relay). */
  username?: string
  /** SECRET — write-only; omit to keep the stored one. */
  password?: string
}

/** SMTP submission, as `GET` returns it. */
export interface SmtpTransportView extends Omit<SmtpTransport, 'password'> {
  password_set: boolean
}

/**
 * How Forge signs in as the Graph app registration: a client secret, or a
 * client assertion it signs with its own issuer keys (a federated identity
 * credential on the app; no secret is stored).
 */
export type GraphClientAuth = 'client_secret' | 'federated_credential'

/** Microsoft Graph `sendMail` as an Entra app registration, as `PUT` takes it. */
export interface GraphTransport {
  kind: 'microsoft_graph'
  /** The tenant id, or one of its domains (`contoso.onmicrosoft.com`). */
  tenant_id: string
  /** The app registration's application (client) id. */
  client_id: string
  /** The mailbox to send as (UPN or object id); absent: the `From` address. */
  sender?: string
  /** Absent: `client_secret`. */
  client_authentication?: GraphClientAuth
  /** SECRET — write-only; omit to keep the stored one (same tenant and app). */
  client_secret?: string
}

/** Microsoft Graph, as `GET` returns it. */
export interface GraphTransportView extends Omit<GraphTransport, 'client_secret'> {
  client_secret_set: boolean
}

/** The transport, by `kind`. */
export type EmailTransport = SmtpTransport | GraphTransport

/** The transport, by `kind`, as `GET` returns it. */
export type EmailTransportView = SmtpTransportView | GraphTransportView

/**
 * What the Graph app's federated identity credential must name (derived by
 * the server): only for `federated_credential` authentication.
 */
export interface FederatedCredential {
  /** Forge's issuer URL (its public base URL). */
  issuer: string
  subject: string
  audience: string
}

/** `PUT /admin/settings/email` body. */
export interface EmailSettingsInput {
  /** `false` keeps the settings but sends nothing. */
  enabled: boolean
  from_address: string
  from_name?: string
  reply_to?: string
  /** How long an invitation link stays valid (1 to 720 hours). */
  invitation_ttl_hours: number
  transport: EmailTransport
}

/** The outcome of the last send that failed. */
export interface EmailFailure {
  at: string
  error: string
}

/** `GET /admin/settings/email` once settings are stored. */
export interface EmailSettingsView {
  configured: true
  enabled: boolean
  from_address: string
  from_name?: string
  reply_to?: string
  invitation_ttl_hours: number
  transport: EmailTransportView
  /** Only for a Graph app with `federated_credential` authentication. */
  federated_credential?: FederatedCredential
  /** The stored secrets do not decrypt (a lost root key): enter them again. */
  secrets_unreadable: boolean
  last_failure: EmailFailure | null
  last_success_at: string | null
  updated_at: string
}

/** `GET /admin/settings/email`. */
export type EmailSettings = EmailSettingsView | { configured: false }

/** `POST /admin/settings/email/test` answer. */
export interface TestEmailResult {
  sent: boolean
  to: string
  error?: string
}

/** The usual port of a TLS mode, as the server defaults it. */
export const DEFAULT_SMTP_PORTS: Record<SmtpTls, number> = {
  implicit: 465,
  starttls: 587,
  none: 25,
}

/** The server's default invitation lifetime, in hours. */
export const DEFAULT_INVITATION_TTL_HOURS = 72

export const emailKeys = {
  settings: () => ['email', 'settings'] as const,
}

/** `GET /admin/settings/email`. */
export function fetchEmailSettings(signal?: AbortSignal): Promise<EmailSettings> {
  return httpClient.get<EmailSettings>('/admin/settings/email', { signal })
}

/** `PUT /admin/settings/email`. */
export function putEmailSettings(body: EmailSettingsInput): Promise<EmailSettingsView> {
  return httpClient.put<EmailSettingsView>('/admin/settings/email', body)
}

/** `DELETE /admin/settings/email`. */
export function deleteEmailSettings(): Promise<void> {
  return httpClient.delete<void>('/admin/settings/email')
}

/**
 * `POST /admin/settings/email/test`. A send the server attempted and that
 * failed (502) resolves with `sent: false` and the server's error, so the
 * page can show it; other errors reject.
 */
export async function sendTestEmail(to?: string): Promise<TestEmailResult> {
  try {
    return await httpClient.post<TestEmailResult>(
      '/admin/settings/email/test',
      to ? { to } : {},
    )
  } catch (e) {
    if (e instanceof ApiError && e.status === 502) {
      try {
        return JSON.parse(e.body) as TestEmailResult
      } catch {
        // Not the JSON a failed send answers with: report the error as is.
      }
    }
    throw e
  }
}
