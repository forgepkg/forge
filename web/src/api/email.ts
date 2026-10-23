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
 *
 * SMTP with OAuth (`smtp_oauth`, #321) adds `/oauth/*`: registering Forge
 * with the mail server's authorization server (RFC 7591), and the mailbox
 * authorizing it, in this browser (the code flow, which returns to this page
 * with `?oauth=…`), with a code on another device (RFC 8628), or not at all
 * (the client credentials grant). The client Forge registered and the
 * authorization are Forge's: a `PUT` never sets them.
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

/** How an `smtp_oauth` transport gets its access tokens (Forge sets it). */
export type OauthGrant = 'refresh_token' | 'client_credentials'

/** SMTP submission with an OAuth access token, as `PUT` takes it. */
export interface SmtpOauthTransport {
  kind: 'smtp_oauth'
  host: string
  /** Absent: the TLS mode's usual port. */
  port?: number
  tls: SmtpTls
  /** The authorization server's issuer URL (https). */
  issuer: string
  /** The mailbox Forge sends as; it authorizes Forge. */
  username: string
  /** The scope to ask for; absent: none. */
  scope?: string
  /**
   * A client entered by hand. Absent, or the stored one: the stored client
   * (registered by Forge or entered) is kept for the same issuer.
   */
  client_id?: string
  /** SECRET — write-only; omit to keep the stored one. */
  client_secret?: string
}

/** SMTP with OAuth, as `GET` returns it: with Forge's state. */
export interface SmtpOauthTransportView extends Omit<SmtpOauthTransport, 'client_secret'> {
  client_secret_set: boolean
  /** Forge registered the client (RFC 7591), rather than it being entered. */
  registered?: boolean
  /** Where Forge's registration is managed (RFC 7592), when the server said. */
  registration_client_uri?: string
  registration_access_token_set: boolean
  /** How Forge gets tokens, once authorized. */
  grant?: OauthGrant
  refresh_token_set: boolean
  /** Why the mailbox must authorize Forge again (a refused refresh). */
  authorization_error?: string
}

/** The transport, by `kind`. */
export type EmailTransport = SmtpTransport | GraphTransport | SmtpOauthTransport

/** The transport, by `kind`, as `GET` returns it. */
export type EmailTransportView = SmtpTransportView | GraphTransportView | SmtpOauthTransportView

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
  /** Only for `smtp_oauth`: the redirect URI of Forge's client. */
  oauth_redirect_uri?: string
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

/**
 * `PUT /admin/settings/email`. `warning` names an OAuth client Forge
 * registered that these settings no longer use and that it could not delete.
 */
export function putEmailSettings(body: EmailSettingsInput): Promise<EmailSettingsWithWarning> {
  return httpClient.put<EmailSettingsWithWarning>('/admin/settings/email', body)
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

/** An OAuth answer that carries the settings, and why Forge's old registration was not deleted. */
export type EmailSettingsWithWarning = EmailSettingsView & { warning?: string | null }

/** How the mailbox authorizes Forge. */
export type OauthAuthorizeMethod = 'authorization_code' | 'device' | 'client_credentials'

/** A started device authorization: the code to enter, and where. */
export interface DeviceAuthorization {
  flow_id: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string | null
  /** Seconds. */
  expires_in: number
  /** Seconds between polls. */
  interval: number
}

/** `POST /admin/settings/email/oauth/device/{id}` answer. */
export type DevicePollResult =
  | { status: 'pending'; error?: string }
  | { status: 'authorized'; settings: EmailSettingsView }
  | { status: 'failed'; failure: string; error: string }

/**
 * The text of a failed OAuth request: the authorization server's error a 502
 * carries, or the body.
 */
export function oauthErrorText(e: ApiError): string {
  if (e.status === 502) {
    try {
      const parsed = JSON.parse(e.body) as { error?: string }
      if (parsed.error) return parsed.error
    } catch {
      // Not JSON: the body as is.
    }
  }
  return e.body || e.message
}

/**
 * How Forge's registration is authenticated, when the server wants it to be:
 * an initial access token, or an account allowed to register clients (HTTP
 * Basic; Stalwart takes one). Used once, never stored.
 */
export type RegistrationAuth =
  | { initial_access_token: string }
  | { username: string; password: string }
  | Record<string, never>

/** `POST /admin/settings/email/oauth/register`: register Forge (RFC 7591). */
export function registerEmailOauthClient(
  auth: RegistrationAuth,
): Promise<EmailSettingsWithWarning> {
  return httpClient.post<EmailSettingsWithWarning>('/admin/settings/email/oauth/register', auth)
}

/** `DELETE /admin/settings/email/oauth/client`: forget the client and its authorization. */
export function forgetEmailOauthClient(): Promise<EmailSettingsWithWarning> {
  return httpClient.delete<EmailSettingsWithWarning>('/admin/settings/email/oauth/client')
}

/** `POST /admin/settings/email/oauth/authorize` with `authorization_code`. */
export function startEmailOauthCodeFlow(): Promise<{ authorization_url: string }> {
  return httpClient.post('/admin/settings/email/oauth/authorize', {
    method: 'authorization_code',
  })
}

/** `POST /admin/settings/email/oauth/authorize` with `device`. */
export function startEmailOauthDeviceFlow(): Promise<DeviceAuthorization> {
  return httpClient.post('/admin/settings/email/oauth/authorize', { method: 'device' })
}

/** `POST /admin/settings/email/oauth/authorize` with `client_credentials`. */
export function authorizeEmailOauthClientCredentials(): Promise<{ settings: EmailSettingsView }> {
  return httpClient.post('/admin/settings/email/oauth/authorize', {
    method: 'client_credentials',
  })
}

/** `POST /admin/settings/email/oauth/device/{id}`: poll a device authorization. */
export function pollEmailOauthDevice(flowId: string): Promise<DevicePollResult> {
  return httpClient.post<DevicePollResult>(
    `/admin/settings/email/oauth/device/${encodeURIComponent(flowId)}`,
    {},
  )
}
