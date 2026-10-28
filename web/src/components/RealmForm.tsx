import { useEffect, useRef, useState, type ReactNode } from 'react'

import type {
  ClientAuthentication,
  CredentialForwardingConfig,
  OidcRealmConfig,
  RealmConfig,
  RealmKind,
  RealmView,
  TrustedHeaderConfig,
  WorkloadIdentityConfig,
} from '~/api/realms'
import { ADMIN_ROLE } from '~/api/rbac'
import { useRoles } from '~/queries/useRbac'
import {
  Button,
  Checkbox,
  ChoiceCards,
  Code,
  Columns,
  CopyField,
  Dialog,
  FormActions,
  Icon,
  Notice,
  Panel,
  SelectField,
  Switch,
  TextareaField,
  TextField,
  type ChoiceCard,
  type IconName,
} from '~/components/ui'

/**
 * Shared auth-realm create/edit form: a column of panels (General, then the
 * kind's own), the buttons at its end, and a side column. Kind-conditional
 * fields:
 *
 *  - **oidc** → identity provider (issuer / client / write-only secret or a
 *    federated credential: Forge's own client assertions, no secret) /
 *    sign-in (button label, login domains, required claims) / accounts
 *    (claims, provisioning, admin mapping). The side column lists what to
 *    enter in the IdP's app registration: the redirect URI and, for a
 *    federated credential, the issuer, subject and audience it must name.
 *  - **credential_forwarding** → upstream URL / acceptance criteria /
 *    write-only key pepper / groups / timeouts and caching TTLs / kept
 *    password hashes
 *  - **workload_identity** (WIF) → public OIDC issuer / allowed audiences /
 *    optional authorized parties / bounded token lifetime / ordered
 *    claim→role rules (no secrets, no redaction)
 *  - **trusted_header** → the header naming the account, the header and
 *    write-only secret the proxy proves itself with (a random one can be
 *    generated and copied into the proxy's configuration before saving),
 *    account provisioning; the side column says what the proxy must do
 *  - **local** → no config; only name + enabled are editable (built-in realm)
 *
 * On **create** the kind is chosen from cards (local is built-in and cannot
 * be created); on **edit** it is fixed and shown read-only, and saving a realm
 * people sign in with (local, OIDC, credential forwarding) as disabled asks
 * first in a dialog, as the realm list's toggle does. Secrets follow the
 * RepositoryForm `upstream_password` pattern: never seeded from the
 * (redacted) GET, placeholder shows "set to replace" when `<key>_set` is
 * true, and a blank field keeps the stored secret on edit — except that the
 * server drops a stored OIDC client secret when the issuer or client ID
 * changes, so the form then warns and requires a new one. A submit that fails
 * validation moves focus to the first field it marks.
 *
 * `PATCH` replaces the whole config, so every field is sent on each save.
 * String-array fields (scopes, login domains, groups, audiences, claim
 * values) are edited one entry per line: a value may contain commas (an LDAP
 * DN such as `CN=Forge Admins,OU=Groups,DC=corp`) and must survive a save
 * unchanged. Status lists are comma-separated numbers. Blank numeric fields
 * are omitted so the server defaults apply.
 */

/** A draft mirrors the form fields; numbers/lists stay strings while editing. */
export interface RealmFormValues {
  kind: RealmKind
  name: string
  enabled: boolean
  // oidc
  auto_provision: boolean
  // oidc
  issuer: string
  client_id: string
  /** Newly-typed secret; blank ⇒ "leave unchanged" on edit / invalid on create. */
  client_secret: string
  client_authentication: ClientAuthentication
  /** Blank ⇒ the server default, `api://AzureADTokenExchange`. */
  assertion_audience: string
  /** One scope per line. */
  scopes: string
  clock_skew_seconds: string
  allow_http_issuer: boolean
  username_claim: string
  email_claim: string
  display_name_claim: string
  link_existing_by_username: boolean
  /** One group per line. */
  admin_groups: string
  admin_claim: string
  /** One domain per line. */
  login_domains: string
  /** One host per line. */
  endpoint_hosts: string
  /** One `claim = value` per line, a claim repeated per value (parsed to a map on submit). */
  required_claims: string
  button_label: string
  // credential_forwarding
  url: string
  method: string
  success_status: string
  reject_status: string
  connect_timeout_ms: string
  request_timeout_ms: string
  /** One group per line. */
  required_groups: string
  groups_path: string
  identity_path: string
  /** Credential forwarding: accept a plain-http, non-loopback URL. */
  allow_http: boolean
  /** Credential forwarding: keep a hash of every password the upstream accepts. */
  capture_password_hash: boolean
  /** Credential forwarding: stop forwarding, sign in with the kept hashes. */
  captured_password_only: boolean
  admin_group: string
  positive_ttl_secs: string
  negative_ttl_secs: string
  /** Newly-typed pepper; blank ⇒ "leave unchanged" on edit / invalid on create. */
  key_pepper: string
  // workload_identity (WIF). Reuses `issuer`, `allow_http_issuer`, and
  // `clock_skew_seconds` above since only one kind is active at a time.
  /** One allowed audience per line (parsed to string[] on submit). */
  allowed_audiences: string
  /** Optional exact `azp` values for issuers that emit authorized-party claims, one per line. */
  allowed_authorized_parties: string
  /** Extra identity claims (custom issuers), one per line. */
  identity_claims: string
  /** Maximum accepted token age and declared token lifetime. */
  max_token_age_seconds: string
  /** Expiry-bounded signature-verification cache TTL (`jti` tokens only). */
  positive_cache_seconds: string
  /** Lifetime of an API key the token exchange issues (blank ⇒ 3600). */
  api_key_ttl_seconds: string
  /** Ordered claim→role rules; anyOf holds one value per line per condition. */
  wifRules: Array<{
    role: string
    /** Every project of a self-managed issuer, read-only (`issuer_wide`). */
    issuerWide: boolean
    conditions: Array<{ claim: string; anyOf: string }>
  }>
  // trusted_header
  username_header: string
  secret_header: string
  /** Newly-typed secret; blank ⇒ "leave unchanged" on edit / invalid on create. */
  secret: string
  /** Trusted header: create a user's account on its first request (off by default). */
  header_auto_provision: boolean
}

export interface RealmFormProps {
  /** Edit mode locks the kind; create mode offers the non-local kinds. */
  mode: 'create' | 'edit'
  /** Existing realm (edit mode) used to seed defaults; absent in create mode. */
  existing?: RealmView
  /** Disabled while a mutation is in flight. */
  submitting: boolean
  /** Server-side error (e.g. 400 invalid config, 409 duplicate name). */
  serverError?: string | null
  /** Emits the validated form values for the caller to turn into an API body. */
  onSubmit: (values: RealmFormValues) => void
  /** Cancel affordance (navigates back to the list). */
  onCancel: () => void
  /** The screen's panels for the side column, above the form's own. */
  aside?: ReactNode
}

/**
 * What stops working when a realm is disabled: the text of the confirmation
 * the realm list and the edit form show before sending the disable. `null`
 * for a kind that needs none.
 */
export function disableRealmWarning(kind: RealmKind, name: string): string | null {
  switch (kind) {
    case 'local':
      return `Disabling ${name} stops every password login: browser sign-in and NuGet clients sending a password over Basic. API tokens keep working.`
    case 'oidc':
      return `Disabling ${name} stops sign-in through its identity provider: people who use it can no longer sign in to Forge. API tokens keep working.`
    case 'credential_forwarding':
      return `Disabling ${name} stops the logins it checks against its upstream: NuGet clients sending those passwords over Basic, and browser sign-in with them. API tokens keep working.`
    case 'workload_identity':
      return `Disabling ${name} stops its token exchange and revokes every API key it issued: CI jobs using one fail with 401 until they exchange a new token. Enabling the realm again does not bring the keys back.`
    case 'trusted_header':
      return `Disabling ${name} stops its proxy's headers from naming anyone: the requests the proxy forwards without a credential of their own are anonymous. API tokens keep working.`
    default:
      return null
  }
}

/** A string list as one entry per line (entries may contain commas). */
function joinLines(list?: string[]): string {
  return (list ?? []).join('\n')
}

/** Status codes as comma-separated text. */
function joinNumbers(list?: number[]): string {
  return (list ?? []).join(', ')
}

/** `{ tid: ['a', 'b'] }` -> `tid = a` and `tid = b`, one value per line. */
export function formatClaimRules(rules?: Record<string, string[]>): string {
  return Object.entries(rules ?? {})
    .flatMap(([claim, values]) => values.map((value) => `${claim} = ${value}`))
    .join('\n')
}

/**
 * Parse `claim = value` lines into the `required_claims` map; a repeated
 * claim collects its values. Only the first `=` separates, so a value may
 * contain `=` and `,` (`groups = CN=Forge Users,OU=Groups,DC=corp`).
 */
export function parseClaimRules(raw: string): Record<string, string[]> {
  const rules: Record<string, string[]> = {}
  for (const line of raw.split(/\r?\n/)) {
    const eq = line.indexOf('=')
    if (eq < 0) continue
    const claim = line.slice(0, eq).trim()
    const value = line.slice(eq + 1).trim()
    if (claim === '' || value === '') continue
    const values = (rules[claim] ??= [])
    if (!values.includes(value)) values.push(value)
  }
  return rules
}

/** Form values for a new realm, or seeded from an existing one (edit). */
export function seedRealmFormValues(existing?: RealmView): RealmFormValues {
  const oidc = (existing?.kind === 'oidc' ? existing.config : {}) as OidcRealmConfig
  const fwd = (
    existing?.kind === 'credential_forwarding' ? existing.config : {}
  ) as CredentialForwardingConfig
  const wif = (
    existing?.kind === 'workload_identity' ? existing.config : {}
  ) as WorkloadIdentityConfig
  const header = (
    existing?.kind === 'trusted_header' ? existing.config : {}
  ) as TrustedHeaderConfig
  return {
    kind: existing?.kind ?? 'oidc',
    name: existing?.name ?? '',
    enabled: existing?.enabled ?? true,
    auto_provision: oidc.auto_provision ?? true,
    issuer: (existing?.kind === 'workload_identity' ? wif.issuer : oidc.issuer) ?? '',
    client_id: oidc.client_id ?? '',
    // Never seed secrets — they are write-only and redacted on read.
    client_secret: '',
    client_authentication: oidc.client_authentication ?? 'client_secret',
    assertion_audience: oidc.assertion_audience ?? '',
    scopes: joinLines(oidc.scopes),
    clock_skew_seconds:
      existing?.kind === 'workload_identity'
        ? wif.clock_skew_seconds != null
          ? String(wif.clock_skew_seconds)
          : ''
        : oidc.clock_skew_seconds != null
          ? String(oidc.clock_skew_seconds)
          : '',
    allow_http_issuer:
      (existing?.kind === 'workload_identity'
        ? wif.allow_http_issuer
        : oidc.allow_http_issuer) ?? false,
    username_claim: oidc.username_claim ?? '',
    email_claim: oidc.email_claim ?? '',
    display_name_claim: oidc.display_name_claim ?? '',
    link_existing_by_username: oidc.link_existing_by_username ?? false,
    admin_groups: joinLines(oidc.admin_groups),
    admin_claim: oidc.admin_claim ?? '',
    login_domains: joinLines(oidc.login_domains),
    endpoint_hosts: joinLines(oidc.endpoint_hosts),
    required_claims: formatClaimRules(oidc.required_claims),
    button_label: oidc.button_label ?? '',
    url: fwd.url ?? '',
    method: fwd.method ?? '',
    success_status: joinNumbers(fwd.success_status),
    reject_status: joinNumbers(fwd.reject_status),
    connect_timeout_ms: fwd.connect_timeout_ms != null ? String(fwd.connect_timeout_ms) : '',
    request_timeout_ms: fwd.request_timeout_ms != null ? String(fwd.request_timeout_ms) : '',
    required_groups: joinLines(fwd.required_groups),
    groups_path: fwd.groups_path ?? '',
    identity_path: fwd.identity_path ?? '',
    allow_http: fwd.allow_http ?? false,
    capture_password_hash: fwd.capture_password_hash ?? false,
    captured_password_only: fwd.captured_password_only ?? false,
    admin_group: fwd.admin_group ?? '',
    positive_ttl_secs: fwd.positive_ttl_secs != null ? String(fwd.positive_ttl_secs) : '',
    negative_ttl_secs: fwd.negative_ttl_secs != null ? String(fwd.negative_ttl_secs) : '',
    key_pepper: '',
    allowed_audiences: joinLines(wif.allowed_audiences),
    allowed_authorized_parties: joinLines(wif.allowed_authorized_parties),
    identity_claims: joinLines(wif.identity_claims),
    max_token_age_seconds:
      wif.max_token_age_seconds != null ? String(wif.max_token_age_seconds) : '',
    positive_cache_seconds:
      wif.positive_cache_seconds != null ? String(wif.positive_cache_seconds) : '',
    api_key_ttl_seconds:
      wif.api_key_ttl_seconds != null ? String(wif.api_key_ttl_seconds) : '',
    wifRules: (wif.rules ?? []).map((rule) => ({
      role: rule.role ?? '',
      issuerWide: rule.issuer_wide ?? false,
      conditions: (rule.conditions ?? []).map((c) => ({
        claim: c.claim ?? '',
        anyOf: joinLines(c.any_of),
      })),
    })),
    username_header: header.username_header ?? '',
    secret_header: header.secret_header ?? '',
    secret: '',
    header_auto_provision: header.auto_provision ?? false,
  }
}

/** Each realm kind in words, with its icon and one sentence on what it is for. */
export const REALM_KINDS: Record<
  RealmKind,
  { label: string; icon: IconName; description: string }
> = {
  local: {
    label: 'Local',
    icon: 'Lock',
    description: 'Usernames and passwords stored in Forge itself.',
  },
  oidc: {
    label: 'OpenID Connect',
    icon: 'Globe',
    description:
      'People sign in to Forge through your identity provider, such as Entra ID, Keycloak or Google.',
  },
  credential_forwarding: {
    label: 'Credential forwarding',
    icon: 'Key',
    description:
      'Forge checks the passwords of the accounts you create for it against an upstream HTTP endpoint.',
  },
  workload_identity: {
    label: 'Workload identity',
    icon: 'Terminal',
    description:
      'CI jobs, such as GitHub Actions or GitLab CI, authenticate with their OIDC token and get a role.',
  },
  trusted_header: {
    label: 'Trusted header',
    icon: 'Shield',
    description:
      'The load balancer or SSO proxy in front of Forge names the account in a header, for the people or networks it admits.',
  },
}

/** The kinds a realm can be created as (local is built in). */
const KIND_CARDS: ChoiceCard<RealmKind>[] = (
  ['oidc', 'credential_forwarding', 'workload_identity', 'trusted_header'] as const
).map((kind) => ({
  id: kind,
  title: REALM_KINDS[kind].label,
  icon: REALM_KINDS[kind].icon,
  description: REALM_KINDS[kind].description,
}))

/** The description of a list field edited one entry per line. */
const ONE_PER_LINE = 'One per line.'

/** The realm form itself (see the module comment above). */
export function RealmForm({
  mode,
  existing,
  submitting,
  serverError,
  onSubmit,
  onCancel,
  aside,
}: RealmFormProps) {
  const [values, setValues] = useState<RealmFormValues>(() =>
    seedRealmFormValues(existing),
  )
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [confirmSave, setConfirmSave] = useState(false)
  // A secret generated in this form, shown to copy until it is replaced.
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null)
  // Counts the submits that failed validation: each one moves focus to the
  // first field marked invalid, whose error is read with it (the field errors
  // are not live regions).
  const [failedSubmits, setFailedSubmits] = useState(0)
  const form = useRef<HTMLFormElement>(null)

  useEffect(() => {
    if (failedSubmits === 0) return
    form.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus()
  }, [failedSubmits])

  // Saving a realm as disabled ends the logins (or the keys) it serves, and
  // any write to a workload-identity realm revokes the API keys it issued
  // for good, so the save waits for an explicit confirmation, as the list's
  // toggle does.
  const saveWarning =
    mode !== 'edit' || !existing?.enabled
      ? null
      : !values.enabled
        ? disableRealmWarning(existing.kind, existing.name)
        : existing.kind === 'workload_identity'
          ? `Saving ${existing.name} revokes every API key it issued: CI jobs using one fail with 401 until they exchange a new token. The keys stay revoked.`
          : null

  // The server keeps a stored client secret only while the issuer and client
  // ID stay the same (it must not reach another IdP), so after changing
  // either one the save needs a new secret.
  const storedOidc = (existing?.kind === 'oidc' ? existing.config : {}) as OidcRealmConfig
  const usesClientSecret = values.client_authentication === 'client_secret'
  const secretWillDrop =
    mode === 'edit' &&
    values.kind === 'oidc' &&
    usesClientSecret &&
    hasStoredSecret(existing, 'client_secret_set') &&
    (secretBinding(values.issuer) !== secretBinding(storedOidc.issuer ?? '') ||
      secretBinding(values.client_id) !== secretBinding(storedOidc.client_id ?? ''))

  function set<K extends keyof RealmFormValues>(key: K, value: RealmFormValues[K]) {
    setValues((v) => ({ ...v, [key]: value }))
  }

  function validate(): boolean {
    const next: Record<string, string> = {}
    if (values.name.trim() === '') {
      next.name = 'A realm name is required.'
    }
    if (values.kind === 'oidc') {
      if (values.issuer.trim() === '') {
        next.issuer = 'An issuer URL is required.'
      }
      if (values.client_id.trim() === '') {
        next.client_id = 'A client ID is required.'
      }
      if (!usesClientSecret) {
        // Forge signs a client assertion instead: no secret.
      } else if (
        (mode === 'create' || !hasStoredSecret(existing, 'client_secret_set')) &&
        values.client_secret === ''
      ) {
        next.client_secret = 'A client secret is required.'
      } else if (secretWillDrop && values.client_secret === '') {
        next.client_secret =
          'Enter the client secret for the new issuer or client ID.'
      }
      if (!isBlankNumber(values.clock_skew_seconds)) {
        next.clock_skew_seconds = 'Clock skew must be a non-negative number.'
      }
    }
    if (values.kind === 'credential_forwarding') {
      if (values.url.trim() === '') {
        next.url = 'An upstream URL is required.'
      }
      if (mode === 'create' && values.key_pepper === '') {
        next.key_pepper = 'A key pepper is required.'
      }
      if (!isBlankNumberList(values.success_status)) {
        next.success_status = 'Status codes must be comma-separated numbers.'
      }
      if (!isBlankNumberList(values.reject_status)) {
        next.reject_status = 'Status codes must be comma-separated numbers.'
      }
      for (const key of [
        'connect_timeout_ms',
        'request_timeout_ms',
        'positive_ttl_secs',
        'negative_ttl_secs',
      ] as const) {
        if (!isBlankNumber(values[key])) {
          next[key] = 'Must be a non-negative number.'
        }
      }
    }
    if (values.kind === 'workload_identity') {
      if (values.issuer.trim() === '') {
        next.issuer = 'An issuer URL is required.'
      } else if (!isUrlIsh(values.issuer)) {
        next.issuer = 'The issuer must be a valid URL.'
      }
      if (parseLines(values.allowed_audiences).length === 0) {
        next.allowed_audiences = 'At least one allowed audience is required.'
      }
      if (!isBlankNumberInRange(values.clock_skew_seconds, 0, 300)) {
        next.clock_skew_seconds = 'Clock skew must be between 0 and 300 seconds.'
      }
      if (!isBlankNumberInRange(values.max_token_age_seconds, 1, 86400)) {
        next.max_token_age_seconds = 'Maximum token age must be between 1 and 86400 seconds.'
      }
      if (!isBlankNumberInRange(values.positive_cache_seconds, 0, 300)) {
        next.positive_cache_seconds = 'Positive cache TTL must be between 0 and 300 seconds.'
      }
      if (!isBlankNumberInRange(values.api_key_ttl_seconds, 60, 86400)) {
        next.api_key_ttl_seconds = 'API key lifetime must be between 60 and 86400 seconds.'
      }
      if (values.wifRules.length === 0) {
        next.wifRules = 'At least one rule is required.'
      }
      const firstIssuerWide = values.wifRules.findIndex((rule) => rule.issuerWide)
      values.wifRules.forEach((rule, ri) => {
        if (rule.role.trim() === '') {
          next[`wifRule.${ri}.role`] = 'A role is required.'
        } else if (rule.role.trim() === 'admin') {
          next[`wifRule.${ri}.role`] =
            'Workload identity cannot grant the built-in global admin role.'
        }
        if (!rule.issuerWide && firstIssuerWide !== -1 && firstIssuerWide < ri) {
          // Rules are first-match: the issuer-wide rule would take this one's
          // workloads.
          next[`wifRule.${firstIssuerWide}.issuerWide`] =
            `Rules are first-match, so a rule for every project comes after every other rule; here it would take the workloads of rule ${ri + 1}. Remove it, and add it again as the last rule.`
        }
        if (rule.issuerWide && isPublicWifIssuer(values.issuer)) {
          next[`wifRule.${ri}.issuerWide`] =
            'Anyone can mint a GitHub Actions or GitLab.com token: pin the rule to a repository or project instead.'
        } else if (!rule.issuerWide && rule.conditions.length === 0) {
          next[`wifRule.${ri}.conditions`] =
            'At least one claim condition is required; catch-all trust is not allowed.'
        } else if (!wifRuleHasIdentityScope(values.issuer, rule)) {
          next[`wifRule.${ri}.conditions`] = isGitHubActionsIssuer(values.issuer)
            ? 'GitHub Actions rules must include both repository_id and repository_owner_id.'
            : isGitLabComIssuer(values.issuer)
              ? 'GitLab.com rules must include a numeric project ID (job_project_id or project_id) and namespace ID (job_namespace_id or namespace_id).'
              : 'Include a workload identity claim such as sub, repository_id, job_project_id, project_path, or a provider-specific workload ID; ref/environment alone is unsafe.'
        }
        rule.conditions.forEach((cond, ci) => {
          if (cond.claim.trim() === '') {
            next[`wifRule.${ri}.cond.${ci}.claim`] = 'A claim is required.'
          }
          if (parseLines(cond.anyOf).length === 0) {
            next[`wifRule.${ri}.cond.${ci}.anyOf`] =
              'At least one value is required.'
          }
        })
      })
    }
    if (values.kind === 'trusted_header') {
      for (const key of ['username_header', 'secret_header'] as const) {
        if (values[key].trim() === '') {
          next[key] = 'A header name is required.'
        } else if (!HEADER_NAME.test(values[key].trim())) {
          next[key] = 'A header name such as X-Forwarded-User, without spaces or colons.'
        }
      }
      if (
        !next.secret_header &&
        values.secret_header.trim().toLowerCase() ===
          values.username_header.trim().toLowerCase()
      ) {
        next.secret_header = 'The secret needs a header of its own.'
      }
      if (values.secret === '') {
        if (mode === 'create' || !hasStoredSecret(existing, 'secret_set')) {
          next.secret = 'A secret is required.'
        }
      } else {
        const error = secretError(values.secret)
        if (error) next.secret = error
      }
    }
    setErrors(next)
    return Object.keys(next).length === 0
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) {
      setFailedSubmits((n) => n + 1)
      return
    }
    if (saveWarning) {
      setConfirmSave(true)
      return
    }
    onSubmit(values)
  }

  function saveConfirmed() {
    setConfirmSave(false)
    if (!validate()) {
      setFailedSubmits((n) => n + 1)
      return
    }
    onSubmit(values)
  }

  const isLocal = values.kind === 'local'
  const isOidc = values.kind === 'oidc'
  const isForwarding = values.kind === 'credential_forwarding'
  const isWorkloadIdentity = values.kind === 'workload_identity'
  const isTrustedHeader = values.kind === 'trusted_header'

  function setRule(
    index: number,
    update: (rule: RealmFormValues['wifRules'][number]) => RealmFormValues['wifRules'][number],
  ) {
    setValues((v) => ({
      ...v,
      wifRules: v.wifRules.map((r, i) => (i === index ? update(r) : r)),
    }))
  }

  function setCondition(
    ruleIndex: number,
    condIndex: number,
    patch: Partial<RealmFormValues['wifRules'][number]['conditions'][number]>,
  ) {
    setRule(ruleIndex, (r) => ({
      ...r,
      conditions: r.conditions.map((c, i) => (i === condIndex ? { ...c, ...patch } : c)),
    }))
  }

  function addRule() {
    setValues((v) => {
      // Ahead of the rules for every project, which must come last.
      const at = v.wifRules.findIndex((r) => r.issuerWide)
      const end = at === -1 ? v.wifRules.length : at
      return {
        ...v,
        wifRules: [
          ...v.wifRules.slice(0, end),
          { role: '', issuerWide: false, conditions: [{ claim: '', anyOf: '' }] },
          ...v.wifRules.slice(end),
        ],
      }
    })
  }

  function setIssuerWide(index: number, issuerWide: boolean) {
    setRule(index, (r) => {
      // A rule for every project needs no condition: drop the blank ones.
      const kept = issuerWide
        ? r.conditions.filter((c) => c.claim.trim() !== '' || c.anyOf.trim() !== '')
        : r.conditions
      return {
        ...r,
        issuerWide,
        conditions:
          !issuerWide && kept.length === 0 ? [{ claim: '', anyOf: '' }] : kept,
      }
    })
  }

  function removeRule(index: number) {
    setValues((v) => ({
      ...v,
      wifRules: v.wifRules.filter((_, i) => i !== index),
    }))
  }

  function addCondition(ruleIndex: number) {
    setRule(ruleIndex, (r) => ({
      ...r,
      conditions: [...r.conditions, { claim: '', anyOf: '' }],
    }))
  }

  function removeCondition(ruleIndex: number, condIndex: number) {
    setRule(ruleIndex, (r) => ({
      ...r,
      conditions: r.conditions.filter((_, i) => i !== condIndex),
    }))
  }

  const nameField = (
    <TextField
      label="Name"
      mono
      value={values.name}
      onChange={(e) => set('name', e.target.value)}
      autoFocus={mode === 'create'}
      error={errors.name}
    />
  )

  // The side column: the caller's panels, then what to enter at the IdP or
  // what the proxy must do.
  const registration = isOidc ? (
    <AppRegistration values={values} saved={existing?.federated_credential} />
  ) : isTrustedHeader ? (
    <ProxySetup values={values} />
  ) : null
  const side =
    aside || registration ? (
      <>
        {aside}
        {registration}
      </>
    ) : undefined

  return (
    <Columns aside={side} asideLabel="About this realm">
      <form ref={form} onSubmit={handleSubmit} className="flex flex-col gap-6">
        <Panel
          title="General"
          description={
            isLocal
              ? 'The local realm is built in (argon2 passwords); it has no configuration beyond its name and enabled flag.'
              : undefined
          }
        >
          <div className="fg-form">
            {mode === 'edit' ? (
              <div className="fg-fieldrow items-start">
                {nameField}
                <TextField
                  label="Kind"
                  value={REALM_KINDS[values.kind]?.label ?? values.kind}
                  readOnly
                  description="The kind cannot be changed after creation."
                />
              </div>
            ) : (
              nameField
            )}
          </div>
          {mode === 'create' && (
            <ChoiceCards
              label="Kind"
              name="realm-kind"
              options={KIND_CARDS}
              value={values.kind}
              onChange={(kind) => set('kind', kind)}
            />
          )}
          <Switch
            label="Enabled"
            aria-label="Enabled"
            description="Used for sign-in and credential checks. A disabled realm is skipped."
            checked={values.enabled}
            onChange={(c) => {
              set('enabled', c)
              setConfirmSave(false)
            }}
          />
        </Panel>

        {isOidc && (
          <>
            <Panel
              title="Identity provider"
              description="The OpenID Connect provider people sign in with, and how Forge authenticates to it."
            >
              <div className="fg-form">
                <TextField
                  label="Issuer URL"
                  mono
                  value={values.issuer}
                  onChange={(e) => set('issuer', e.target.value)}
                  placeholder="https://idp.example.com/realms/main"
                  error={errors.issuer}
                />
                <div className="fg-fieldrow items-start">
                  <TextField
                    label="Client ID"
                    mono
                    autoComplete="off"
                    value={values.client_id}
                    onChange={(e) => set('client_id', e.target.value)}
                    error={errors.client_id}
                  />
                  <SelectField
                    label="Client authentication"
                    value={values.client_authentication}
                    onChange={(e) =>
                      set('client_authentication', e.target.value as ClientAuthentication)
                    }
                  >
                    <option value="client_secret">Client secret</option>
                    <option value="federated_credential">
                      Federated credential (no secret)
                    </option>
                  </SelectField>
                </div>
                {usesClientSecret ? (
                  <SecretField
                    label="Client secret"
                    error={errors.client_secret}
                    value={values.client_secret}
                    onChange={(v) => set('client_secret', v)}
                    stored={mode === 'edit' && hasStoredSecret(existing, 'client_secret_set')}
                    willDrop={secretWillDrop}
                  />
                ) : (
                  <TextField
                    label="Assertion audience"
                    mono
                    value={values.assertion_audience}
                    onChange={(e) => set('assertion_audience', e.target.value)}
                    placeholder={DEFAULT_ASSERTION_AUDIENCE}
                    description={
                      <>
                        Leave blank for Entra&apos;s default. Sovereign clouds use their
                        own (e.g. <Code>api://AzureADTokenExchangeUSGov</Code>). What the
                        IdP&apos;s federated credential must name is under App
                        registration.
                      </>
                    }
                  />
                )}
                {secretWillDrop && values.client_secret === '' && (
                  <Notice tone="warn" role="status">
                    The issuer or client ID differs from the stored one. The stored
                    client secret will be dropped when you save, so enter the
                    client secret for the new issuer or client ID.
                  </Notice>
                )}
                <TextareaField
                  label="Scopes"
                  mono
                  rows={3}
                  value={values.scopes}
                  onChange={(e) => set('scopes', e.target.value)}
                  placeholder={'openid\nprofile\nemail'}
                  description={ONE_PER_LINE}
                />
                <TextField
                  label="Clock skew (seconds)"
                  type="number"
                  min={0}
                  mono
                  value={values.clock_skew_seconds}
                  onChange={(e) => set('clock_skew_seconds', e.target.value)}
                  placeholder="60"
                  error={errors.clock_skew_seconds}
                />
                <TextareaField
                  label="Endpoint hosts"
                  mono
                  rows={2}
                  value={values.endpoint_hosts}
                  onChange={(e) => set('endpoint_hosts', e.target.value)}
                  placeholder={'oauth2.googleapis.com\nwww.googleapis.com'}
                  description="Hosts besides the issuer's that the IdP's token and key endpoints may use (Google, AWS Cognito). One per line; leave empty for most IdPs."
                />
                <Checkbox
                  label="Allow plain-HTTP issuer (testing only)"
                  checked={values.allow_http_issuer}
                  onChange={(c) => set('allow_http_issuer', c)}
                />
              </div>
            </Panel>

            <Panel
              title="Sign-in"
              description="How the login screen leads people to this identity provider, and who may sign in through it."
            >
              <div className="fg-form">
                <TextField
                  label="Button label"
                  value={values.button_label}
                  onChange={(e) => set('button_label', e.target.value)}
                  placeholder="Login with SSO"
                />
                <TextareaField
                  label="Login domains"
                  mono
                  rows={2}
                  value={values.login_domains}
                  onChange={(e) => set('login_domains', e.target.value)}
                  placeholder={'example.com\ncorp.example.com'}
                  description="Email domains routed to this IdP by identifier-first login. One per line."
                />
                <TextareaField
                  label="Required claims"
                  mono
                  rows={2}
                  value={values.required_claims}
                  onChange={(e) => set('required_claims', e.target.value)}
                  placeholder="tid = 00000000-0000-0000-0000-000000000000"
                  description={
                    <>
                      Only tokens carrying one of the listed values may sign in. One{' '}
                      <Code>claim = value</Code> per line; repeat the claim for each
                      further value. Use it to restrict a multi-tenant app to your
                      tenant (<Code>tid</Code>) or a Google Workspace domain (
                      <Code>hd</Code>).
                    </>
                  }
                />
              </div>
            </Panel>

            <Panel
              title="Accounts"
              description="How Forge names the accounts that sign in, and who becomes an administrator."
            >
              <div className="fg-form">
                <div className="grid items-start gap-4 sm:grid-cols-3">
                  <TextField
                    label="Username claim"
                    mono
                    value={values.username_claim}
                    onChange={(e) => set('username_claim', e.target.value)}
                    placeholder="preferred_username"
                  />
                  <TextField
                    label="Email claim"
                    mono
                    value={values.email_claim}
                    onChange={(e) => set('email_claim', e.target.value)}
                    placeholder="email"
                  />
                  <TextField
                    label="Display-name claim"
                    mono
                    value={values.display_name_claim}
                    onChange={(e) => set('display_name_claim', e.target.value)}
                    placeholder="name"
                  />
                </div>
                {/* Full width: a group may be a long LDAP DN. */}
                <TextareaField
                  label="Admin groups"
                  mono
                  rows={2}
                  value={values.admin_groups}
                  onChange={(e) => set('admin_groups', e.target.value)}
                  placeholder="forge-admins"
                  description={ONE_PER_LINE}
                />
                <TextField
                  label="Admin claim"
                  mono
                  value={values.admin_claim}
                  onChange={(e) => set('admin_claim', e.target.value)}
                  placeholder="roles"
                />
                <Checkbox
                  label="Auto-provision users on first login"
                  checked={values.auto_provision}
                  onChange={(c) => set('auto_provision', c)}
                />
                <Checkbox
                  label="Link existing users by username"
                  checked={values.link_existing_by_username}
                  onChange={(c) => set('link_existing_by_username', c)}
                />
              </div>
            </Panel>
          </>
        )}

        {isForwarding && (
          <>
            <Panel
              title="Upstream"
              description={
                <>
                  The realm signs in only the accounts created for it under{' '}
                  <strong>Admin → Users</strong>, and sends the upstream the part of
                  their name before the <Code>@</Code>: <Code>alice@example.com</Code>{' '}
                  signs in as <Code>alice</Code>.
                </>
              }
            >
              <div className="fg-form">
                <TextField
                  label="Upstream URL"
                  mono
                  value={values.url}
                  onChange={(e) => set('url', e.target.value)}
                  placeholder="https://auth.example.com/check"
                  error={errors.url}
                />
                <div className="grid items-start gap-4 sm:grid-cols-3">
                  <TextField
                    label="Method"
                    mono
                    value={values.method}
                    onChange={(e) => set('method', e.target.value)}
                    placeholder="GET"
                  />
                  <TextField
                    label="Success statuses"
                    mono
                    value={values.success_status}
                    onChange={(e) => set('success_status', e.target.value)}
                    placeholder="200"
                    error={errors.success_status}
                  />
                  <TextField
                    label="Reject statuses"
                    mono
                    value={values.reject_status}
                    onChange={(e) => set('reject_status', e.target.value)}
                    placeholder="401, 403"
                    error={errors.reject_status}
                  />
                </div>
                <TextField
                  label="Identity path"
                  mono
                  value={values.identity_path}
                  onChange={(e) => set('identity_path', e.target.value)}
                  placeholder="login"
                  description="Where the upstream's success response names the account it authenticated. When set, that name must equal the username entered. Required when the upstream accepts a secret with any username (personal access tokens); leave empty only if the upstream itself binds the username to the password."
                />
                <SecretField
                  label="Key pepper"
                  error={errors.key_pepper}
                  value={values.key_pepper}
                  onChange={(v) => set('key_pepper', v)}
                  stored={mode === 'edit' && hasStoredSecret(existing, 'key_pepper_set')}
                />
                <Checkbox
                  label="Allow a plain-http upstream"
                  aria-label="Allow a plain-http upstream"
                  description="Every login sends the user's password to the upstream URL, so it must be https (or a loopback address) unless this is checked."
                  checked={values.allow_http}
                  onChange={(c) => set('allow_http', c)}
                />
              </div>
            </Panel>

            <Panel
              title="Groups"
              description="Read from the upstream's success response at the groups path."
            >
              <div className="fg-form">
                <TextareaField
                  label="Required groups"
                  mono
                  rows={2}
                  value={values.required_groups}
                  onChange={(e) => set('required_groups', e.target.value)}
                  placeholder="developers"
                  description={ONE_PER_LINE}
                />
                <div className="fg-fieldrow items-start">
                  <TextField
                    label="Groups path"
                    mono
                    value={values.groups_path}
                    onChange={(e) => set('groups_path', e.target.value)}
                    placeholder="user.groups"
                  />
                  <TextField
                    label="Admin group"
                    mono
                    value={values.admin_group}
                    onChange={(e) => set('admin_group', e.target.value)}
                  />
                </div>
              </div>
            </Panel>

            <Panel
              title="Timeouts and cache"
              description="How long Forge waits for the upstream, and how long it remembers an answer. Leave a field blank for its default."
            >
              <div className="fg-form">
                <div className="fg-fieldrow items-start">
                  <TextField
                    label="Connect timeout (ms)"
                    type="number"
                    min={0}
                    mono
                    value={values.connect_timeout_ms}
                    onChange={(e) => set('connect_timeout_ms', e.target.value)}
                    placeholder="2000"
                    error={errors.connect_timeout_ms}
                  />
                  <TextField
                    label="Request timeout (ms)"
                    type="number"
                    min={0}
                    mono
                    value={values.request_timeout_ms}
                    onChange={(e) => set('request_timeout_ms', e.target.value)}
                    placeholder="5000"
                    error={errors.request_timeout_ms}
                  />
                </div>
                <div className="fg-fieldrow items-start">
                  <TextField
                    label="Positive cache TTL (seconds)"
                    type="number"
                    min={0}
                    mono
                    value={values.positive_ttl_secs}
                    onChange={(e) => set('positive_ttl_secs', e.target.value)}
                    placeholder="300"
                    error={errors.positive_ttl_secs}
                  />
                  <TextField
                    label="Negative cache TTL (seconds)"
                    type="number"
                    min={0}
                    mono
                    value={values.negative_ttl_secs}
                    onChange={(e) => set('negative_ttl_secs', e.target.value)}
                    placeholder="30"
                    error={errors.negative_ttl_secs}
                  />
                </div>
              </div>
            </Panel>

            <Panel
              title="Retiring the upstream"
              description="Keep the passwords the upstream accepts, so its users can go on signing in once it is gone."
            >
              <div className="fg-form">
                <Checkbox
                  label="Keep a password hash of successful logins"
                  aria-label="Keep a password hash of successful logins"
                  description="Stores an argon2id hash of each password the upstream accepts on the user's account, so the users can keep signing in once the upstream is retired. The upstream stays in charge while it is asked. Unchecking deletes the kept hashes."
                  checked={values.capture_password_hash}
                  onChange={(c) => {
                    set('capture_password_hash', c)
                    // Without kept hashes there is nothing to sign in with.
                    if (!c) set('captured_password_only', false)
                  }}
                />
                <Checkbox
                  label="Stop forwarding: sign in with kept passwords only"
                  aria-label="Stop forwarding: sign in with kept passwords only"
                  description="The upstream is no longer asked; users sign in with the last password it accepted for them. Users without a kept hash can no longer sign in through this realm."
                  checked={values.captured_password_only}
                  disabled={!values.capture_password_hash}
                  onChange={(c) => set('captured_password_only', c)}
                />
              </div>
            </Panel>
          </>
        )}

        {isWorkloadIdentity && (
          <>
            <Panel
              title="Token issuer"
              description="The CI provider whose OIDC tokens this realm accepts."
            >
              <div className="fg-form">
                <TextField
                  label="Issuer URL"
                  mono
                  value={values.issuer}
                  onChange={(e) => set('issuer', e.target.value)}
                  placeholder="https://token.actions.githubusercontent.com"
                  description="The OIDC issuer whose public JWKS validates incoming tokens."
                  error={errors.issuer}
                />
                <TextareaField
                  label="Allowed audiences"
                  mono
                  rows={2}
                  value={values.allowed_audiences}
                  onChange={(e) => set('allowed_audiences', e.target.value)}
                  placeholder="https://forge.example.com"
                  description={ONE_PER_LINE}
                  error={errors.allowed_audiences}
                />
                <TextareaField
                  label="Allowed authorized parties"
                  mono
                  rows={2}
                  value={values.allowed_authorized_parties}
                  onChange={(e) => set('allowed_authorized_parties', e.target.value)}
                  placeholder="Optional azp values"
                  description={
                    <>
                      Optional exact <Code>azp</Code> allowlist for issuers that emit it,
                      one per line. Leave blank for GitHub Actions and GitLab CI.
                    </>
                  }
                />
                <TextareaField
                  label="Identity claims"
                  mono
                  rows={2}
                  value={values.identity_claims}
                  onChange={(e) => set('identity_claims', e.target.value)}
                  placeholder="Optional, e.g. pipeline_id"
                  description={
                    <>
                      Claims a custom CI issuer uses as a stable workload identity, one
                      per line. Each rule must pin one of them or a built-in identity
                      claim (<Code>sub</Code>, <Code>repository_id</Code>,{' '}
                      <Code>job_project_id</Code>, …). Leave blank for GitHub Actions
                      and GitLab.
                    </>
                  }
                />
                <Checkbox
                  label="Allow plain-HTTP issuer (testing only)"
                  checked={values.allow_http_issuer}
                  onChange={(c) => set('allow_http_issuer', c)}
                />
              </div>
            </Panel>

            <Panel
              title="Lifetimes"
              description="Bounds on the tokens the realm accepts and on the keys it issues. Leave a field blank for its default."
            >
              <div className="fg-form">
                <TextField
                  label="Clock skew (seconds)"
                  type="number"
                  min={0}
                  max={300}
                  mono
                  value={values.clock_skew_seconds}
                  onChange={(e) => set('clock_skew_seconds', e.target.value)}
                  placeholder="60"
                  error={errors.clock_skew_seconds}
                />
                <TextField
                  label="Maximum token age (seconds)"
                  type="number"
                  min={1}
                  max={86400}
                  mono
                  value={values.max_token_age_seconds}
                  onChange={(e) => set('max_token_age_seconds', e.target.value)}
                  placeholder="39600"
                  description="Bounds both token age and declared lifetime. GitHub tokens are normally 10 minutes; GitLab tokens last as long as the job timeout. Use the shortest value your CI jobs support."
                  error={errors.max_token_age_seconds}
                />
                <TextField
                  label="Positive verification cache (seconds)"
                  type="number"
                  min={0}
                  max={300}
                  mono
                  value={values.positive_cache_seconds}
                  onChange={(e) => set('positive_cache_seconds', e.target.value)}
                  placeholder="60"
                  description={
                    <>
                      Caches signature verification only for tokens with{' '}
                      <Code>jti</Code>, never beyond <Code>exp</Code>. Claim rules and
                      roles are still evaluated on every request. Use 0 to disable.
                    </>
                  }
                  error={errors.positive_cache_seconds}
                />
                <TextField
                  label="Exchanged API key lifetime (seconds)"
                  type="number"
                  min={60}
                  max={86400}
                  mono
                  value={values.api_key_ttl_seconds}
                  onChange={(e) => set('api_key_ttl_seconds', e.target.value)}
                  placeholder="3600"
                  description={
                    <>
                      How long a key from the token exchange (
                      <Code>POST /api/v2/token</Code>) stays valid, whatever the CI
                      token&apos;s own lifetime. Editing this realm revokes all of its
                      outstanding keys.
                    </>
                  }
                  error={errors.api_key_ttl_seconds}
                />
              </div>
            </Panel>

            <Panel
              title="Rules"
              count={values.wifRules.length}
              description="Ordered; the first rule whose conditions all match grants its role. Every rule needs a workload identity condition; ref or environment alone is not enough. Public GitHub/GitLab issuers require immutable numeric repository/project and owner/namespace IDs. On a self-managed issuer, a last rule may take every project, read-only. Global admin is not allowed; grant a repository-scoped role."
            >
              {errors.wifRules && <FormError>{errors.wifRules}</FormError>}
              {values.wifRules.map((rule, ri) => (
                <div
                  key={ri}
                  className="grid gap-4 rounded-md border border-line p-4"
                >
                  <div className="flex items-center justify-between gap-3">
                    <h3 className="fg-subtitle">Rule {ri + 1}</h3>
                    <Button
                      size="sm"
                      variant="ghost"
                      icon="Trash"
                      onClick={() => removeRule(ri)}
                      aria-label={`Remove rule ${ri + 1}`}
                    >
                      Remove rule
                    </Button>
                  </div>
                  <div className="fg-form">
                    <WifRolePicker
                      value={rule.role}
                      onChange={(role) => setRule(ri, (r) => ({ ...r, role }))}
                      error={errors[`wifRule.${ri}.role`]}
                    />
                    <Switch
                      label="Every project of this issuer"
                      aria-label={`Rule ${ri + 1}: every project of this issuer`}
                      description="Matches every CI job the issuer signs a token for, with no workload identity condition; conditions only narrow it. The role only reads: its write and delete grants do not apply. Not for GitHub Actions or GitLab.com."
                      checked={rule.issuerWide}
                      disabled={!rule.issuerWide && isPublicWifIssuer(values.issuer)}
                      onChange={(c) => setIssuerWide(ri, c)}
                    />
                    {errors[`wifRule.${ri}.issuerWide`] && (
                      <FormError>{errors[`wifRule.${ri}.issuerWide`]}</FormError>
                    )}
                    {rule.issuerWide && (
                      <Notice tone="warn" role="status">
                        Every account that can create a project and run a pipeline on{' '}
                        {values.issuer.trim() === '' ? (
                          'this issuer'
                        ) : (
                          <Code>{normalizedIssuer(values.issuer)}</Code>
                        )}{' '}
                        reads with{' '}
                        {rule.role.trim() === '' ? 'this role' : <Code>{rule.role.trim()}</Code>}
                        , in a personal namespace or a fork too. A self-managed GitLab
                        with open sign-up is as public as GitLab.com. To let a project
                        publish, add a trusted publisher on the repository, or a rule
                        for its project ahead of this one.
                      </Notice>
                    )}
                  </div>
                  {errors[`wifRule.${ri}.conditions`] && (
                    <FormError>{errors[`wifRule.${ri}.conditions`]}</FormError>
                  )}
                  {rule.conditions.map((cond, ci) => (
                    <div
                      key={ci}
                      className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-start"
                    >
                      <TextField
                        label="Claim"
                        mono
                        value={cond.claim}
                        onChange={(e) => setCondition(ri, ci, { claim: e.target.value })}
                        placeholder="repository"
                        error={errors[`wifRule.${ri}.cond.${ci}.claim`]}
                      />
                      <TextareaField
                        label="Any of"
                        mono
                        rows={2}
                        value={cond.anyOf}
                        onChange={(e) => setCondition(ri, ci, { anyOf: e.target.value })}
                        placeholder={'acme/api\nacme/web'}
                        description={ONE_PER_LINE}
                        error={errors[`wifRule.${ri}.cond.${ci}.anyOf`]}
                      />
                      <Button
                        variant="ghost"
                        icon="X"
                        iconOnly
                        title="Remove condition"
                        aria-label={`Remove condition ${ci + 1} of rule ${ri + 1}`}
                        onClick={() => removeCondition(ri, ci)}
                        className="sm:mt-[26px]"
                      >
                        Remove
                      </Button>
                    </div>
                  ))}
                  <div>
                    <Button size="sm" icon="Plus" onClick={() => addCondition(ri)}>
                      Add condition
                    </Button>
                  </div>
                </div>
              ))}
              <div>
                <Button icon="Plus" onClick={addRule}>
                  Add rule
                </Button>
              </div>
            </Panel>
          </>
        )}

        {isTrustedHeader && (
          <>
            <Panel
              title="Proxy"
              description={
                <>
                  The headers the load balancer or reverse proxy in front of Forge sets
                  for the clients it admits. Forge reads them only from a peer in{' '}
                  <Code>auth.trusted_proxy_cidrs</Code>, for a request naming one of its
                  own host names.
                </>
              }
            >
              <div className="fg-form">
                <div className="fg-fieldrow items-start">
                  <TextField
                    label="Username header"
                    mono
                    autoComplete="off"
                    value={values.username_header}
                    onChange={(e) => set('username_header', e.target.value)}
                    placeholder="X-Forwarded-User"
                    description="Names the account: a UPN such as alice@example.com."
                    error={errors.username_header}
                  />
                  <TextField
                    label="Secret header"
                    mono
                    autoComplete="off"
                    value={values.secret_header}
                    onChange={(e) => set('secret_header', e.target.value)}
                    placeholder="X-Forge-Proxy-Secret"
                    description="Carries the secret that proves the request came through the proxy."
                    error={errors.secret_header}
                  />
                </div>
                <SecretField
                  label="Secret"
                  error={errors.secret}
                  value={values.secret}
                  onChange={(v) => {
                    set('secret', v)
                    setGeneratedSecret(null)
                  }}
                  stored={mode === 'edit' && hasStoredSecret(existing, 'secret_set')}
                />
                <div>
                  <Button
                    size="sm"
                    icon="Refresh"
                    onClick={() => {
                      const secret = randomSecret()
                      set('secret', secret)
                      setGeneratedSecret(secret)
                    }}
                  >
                    Generate a secret
                  </Button>
                </div>
                {generatedSecret && (
                  <CopyField
                    label="Generated secret"
                    value={generatedSecret}
                    copyLabel="Copy the secret"
                    description="Put it into the proxy's configuration: once saved, Forge never shows it again."
                  />
                )}
              </div>
            </Panel>

            <Panel
              title="Accounts"
              description={
                <>
                  The realm names only its own accounts, never a local, OIDC or other
                  realm&apos;s account of the same name, and never makes anyone an
                  administrator. Without provisioning, create the accounts under{' '}
                  <strong>Admin → Users</strong> with this realm. For a network or
                  machines the load balancer admits, create a service account under{' '}
                  <strong>Admin → Service accounts</strong> with this realm: only this
                  realm may name it.
                </>
              }
            >
              <div className="fg-form">
                <Checkbox
                  label="Create a user's account on its first request"
                  aria-label="Create a user's account on its first request"
                  description="For an SSO proxy whose users all may use Forge. The new accounts hold no role."
                  checked={values.header_auto_provision}
                  onChange={(c) => set('header_auto_provision', c)}
                />
              </div>
            </Panel>
          </>
        )}

        {serverError && (
          <Notice
            tone="danger"
            title={mode === 'create' ? 'Could not create the realm' : 'Could not save the realm'}
          >
            {serverError}
          </Notice>
        )}

        <FormActions>
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            icon={mode === 'create' ? 'Plus' : undefined}
            disabled={submitting}
          >
            {submitting
              ? 'Saving…'
              : mode === 'create'
                ? 'Create realm'
                : 'Save changes'}
          </Button>
        </FormActions>
      </form>

      {saveWarning && (
        <Dialog
          open={confirmSave}
          onClose={() => setConfirmSave(false)}
          title={values.enabled ? `Save ${existing?.name}?` : `Disable ${existing?.name}?`}
          description={saveWarning}
          icon="Alert"
          tone="warn"
          confirmLabel={values.enabled ? 'Save and revoke keys' : 'Disable and save'}
          confirmVariant="danger-solid"
          confirmDisabled={submitting}
          onConfirm={saveConfirmed}
        />
      )}
    </Columns>
  )
}

/** The audience Entra recommends for a federated identity credential. */
const DEFAULT_ASSERTION_AUDIENCE = 'api://AzureADTokenExchange'

/** Where the IdP sends people back to after an OIDC sign-in, under Forge's public base URL. */
const OIDC_CALLBACK_PATH = '/auth/oidc/callback'

/**
 * The subject of Forge's client assertions for a realm, as the server derives
 * it: `<client id>@<issuer without a trailing slash>`.
 */
export function federatedSubject(issuer: string, clientId: string): string {
  return `${clientId.trim()}@${issuer.trim().replace(/\/+$/, '')}`
}

/**
 * What to enter in the app registration at the IdP, for the side column of an
 * OIDC realm. The redirect URI is the same for every OIDC realm: Forge's
 * public base URL (as the saved federated credential names it, else as this
 * page was reached) plus `/auth/oidc/callback`. With a federated credential
 * (Forge's own client assertions), also the issuer, subject and audience the
 * IdP's credential must name (Entra: Certificates & secrets → Federated
 * credentials → Other issuer). Subject and audience follow the form; Forge's
 * issuer URL is known once the realm is saved.
 */
function AppRegistration({
  values,
  saved,
}: {
  values: RealmFormValues
  saved?: RealmView['federated_credential']
}) {
  const base = (saved?.issuer ?? window.location.origin).replace(/\/+$/, '')
  const federated = values.client_authentication === 'federated_credential'
  const subject =
    values.issuer.trim() !== '' && values.client_id.trim() !== ''
      ? federatedSubject(values.issuer, values.client_id)
      : null
  const audience = values.assertion_audience.trim() || DEFAULT_ASSERTION_AUDIENCE
  return (
    <Panel
      title="App registration"
      description="What to enter for Forge in the app registration at the identity provider."
    >
      <CopyField
        label="Redirect URI"
        value={`${base}${OIDC_CALLBACK_PATH}`}
        copyLabel="Copy redirect URI"
        description={
          <>
            Forge&apos;s public base URL followed by <Code>{OIDC_CALLBACK_PATH}</Code>.
          </>
        }
      />
      {federated && (
        <>
          <hr className="fg-divider" />
          <h3 className="fg-subtitle">Federated credential</h3>
          <p className="fg-text fg-text--small">
            Forge signs in at the IdP with a client assertion it signs itself, as an
            OpenID Connect issuer publishing{' '}
            <Code>/.well-known/openid-configuration</Code> and its keys (rotated
            automatically). Add a federated credential for an <em>other issuer</em>{' '}
            to the app registration with these values; the IdP must reach
            Forge&apos;s issuer URL over https.
          </p>
          {saved ? (
            <CopyField label="Issuer" value={saved.issuer} copyLabel="Copy issuer" />
          ) : (
            <p className="fg-text fg-text--small">
              Forge&apos;s issuer URL is shown once the realm is saved.
            </p>
          )}
          {subject && (
            <CopyField
              label="Subject identifier"
              value={subject}
              copyLabel="Copy subject identifier"
            />
          )}
          <CopyField label="Audience" value={audience} copyLabel="Copy audience" />
        </>
      )}
    </Panel>
  )
}

/**
 * What the proxy in front of Forge must do for a trusted-header realm, for
 * the side column: strip both headers from the requests it receives and set
 * them for the clients it admits; Forge believes only a trusted peer.
 */
function ProxySetup({ values }: { values: RealmFormValues }) {
  const user = values.username_header.trim() || 'X-Forwarded-User'
  const secret = values.secret_header.trim() || 'X-Forge-Proxy-Secret'
  return (
    <Panel title="Proxy setup" description="What the load balancer or proxy in front of Forge must do.">
      <ul className="fg-list fg-text--small">
        <li>
          Remove <Code>{user}</Code> and <Code>{secret}</Code> from every request a
          client sends, then set them only for the clients it admits: the account&apos;s
          name, and the secret.
        </li>
        <li>
          Be listed in <Code>auth.trusted_proxy_cidrs</Code>. From any other peer, Forge
          ignores the headers.
        </li>
        <li>
          Forward Forge&apos;s own host name (the public base URL&apos;s, or one in{' '}
          <Code>server.allowed_hosts</Code>).
        </li>
      </ul>
      <p className="fg-text fg-text--small">
        A request with a credential of its own (an API token, a password, a signed-in
        session) is that credential&apos;s, whatever the headers say. Publishing takes an
        API token; the deployment guide has examples for nginx, Traefik and HAProxy.
      </p>
    </Panel>
  )
}

/** A header name the realm can read: an HTTP token (no spaces or `:`). */
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/

/** The server's bounds on a trusted-header secret, in characters. */
const MIN_SECRET = 16
const MAX_SECRET = 1024

/** Why `secret` cannot be a trusted-header realm's secret, or `null`. */
export function secretError(secret: string): string | null {
  if (secret.length < MIN_SECRET || secret.length > MAX_SECRET) {
    return `Use ${MIN_SECRET} to ${MAX_SECRET} characters; generate one to be sure.`
  }
  if (!/^[\x21-\x7e]+$/.test(secret)) {
    return 'Printable ASCII without spaces only: it is sent as a header value.'
  }
  return null
}

/** 32 random bytes as hex: a secret for the proxy to prove itself with. */
export function randomSecret(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function hasStoredSecret(
  existing: RealmView | undefined,
  flag: 'client_secret_set' | 'key_pepper_set' | 'secret_set',
): boolean {
  const config = existing?.config as Record<string, unknown> | undefined
  return config?.[flag] === true
}

/**
 * Write-only secret input mirroring RepositoryForm's upstream-password UX.
 * `willDrop`: the save discards the stored secret, so a new one is required.
 */
function SecretField({
  label,
  error,
  value,
  onChange,
  stored,
  willDrop = false,
}: {
  label: string
  error?: string
  value: string
  onChange: (value: string) => void
  stored: boolean
  willDrop?: boolean
}) {
  const keepable = stored && !willDrop
  return (
    <TextField
      label={label}
      type="password"
      autoComplete="new-password"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={keepable ? '•••••••• (set to replace)' : 'Required'}
      description={
        keepable
          ? 'A secret is stored. Leave blank to keep it; type a new one to replace it.'
          : willDrop
            ? 'Required: the stored secret is not kept for a new issuer or client ID.'
            : 'Write-only. The stored secret is never shown after saving.'
      }
      error={error}
    />
  )
}

/** An error of no single field (the rule list, one rule's conditions), announced as it appears. */
function FormError({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="fg-field-error">
      <Icon name="Alert" size={14} />
      <span>{children}</span>
    </p>
  )
}

/** "" or a parseable non-negative number. */
function isBlankNumber(raw: string): boolean {
  if (raw.trim() === '') return true
  const n = Number(raw)
  return Number.isFinite(n) && n >= 0
}

/** "" or a finite number within the inclusive range. */
function isBlankNumberInRange(raw: string, min: number, max: number): boolean {
  if (raw.trim() === '') return true
  const n = Number(raw)
  return Number.isFinite(n) && n >= min && n <= max
}

/** "" or a comma-separated list of numbers. */
function isBlankNumberList(raw: string): boolean {
  return splitNumbers(raw).every((s) => Number.isFinite(Number(s)))
}

const GITHUB_ACTIONS_ISSUER = 'https://token.actions.githubusercontent.com'
const GITLAB_COM_ISSUER = 'https://gitlab.com'
const CONTEXT_ONLY_WIF_CLAIMS = new Set([
  'iss',
  'aud',
  'azp',
  'exp',
  'nbf',
  'iat',
  'jti',
  'nonce',
  'ref',
  'ref_path',
  'ref_type',
  'ref_protected',
  'environment',
  'environment_protected',
])

function normalizedIssuer(raw: string): string {
  return raw.trim().replace(/\/+$/, '')
}

/**
 * An OIDC issuer or client ID as the server compares them when deciding
 * whether a stored client secret still applies (trimmed, without trailing
 * slashes).
 */
function secretBinding(raw: string): string {
  return raw.trim().replace(/\/+$/, '')
}

function isGitHubActionsIssuer(raw: string): boolean {
  return normalizedIssuer(raw) === GITHUB_ACTIONS_ISSUER
}

function isGitLabComIssuer(raw: string): boolean {
  return normalizedIssuer(raw) === GITLAB_COM_ISSUER
}

/** GitHub Actions and GitLab.com: anyone can mint their tokens. */
function isPublicWifIssuer(raw: string): boolean {
  return isGitHubActionsIssuer(raw) || isGitLabComIssuer(raw)
}

/**
 * Mirror the server's defense against syntactically non-empty catch-all
 * rules. A rule for every project of a self-managed issuer is scoped by the
 * issuer alone.
 */
function wifRuleHasIdentityScope(
  issuer: string,
  rule: { issuerWide: boolean; conditions: Array<{ claim: string }> },
): boolean {
  if (rule.issuerWide) return !isPublicWifIssuer(issuer)
  const claims = rule.conditions.map((condition) => condition.claim.trim())
  if (isGitHubActionsIssuer(issuer)) {
    return (
      claims.includes('repository_id') &&
      claims.includes('repository_owner_id')
    )
  }
  if (isGitLabComIssuer(issuer)) {
    return (
      claims.some((claim) => ['project_id', 'job_project_id'].includes(claim)) &&
      claims.some((claim) =>
        ['namespace_id', 'job_namespace_id'].includes(claim),
      )
    )
  }
  return claims.some(
    (claim) => claim !== '' && !CONTEXT_ONLY_WIF_CLAIMS.has(claim),
  )
}

/** A parseable absolute URL (http/https or otherwise). */
function isUrlIsh(raw: string): boolean {
  try {
    new URL(raw.trim())
    return true
  } catch {
    return false
  }
}

/**
 * One entry per line -> trimmed, non-empty entries. Commas are kept: a value
 * such as `CN=Forge Admins,OU=Groups,DC=corp` is one entry.
 */
export function parseLines(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s !== '')
}

/** Comma- (or whitespace-) separated status codes -> non-empty entries. */
function splitNumbers(raw: string): string[] {
  return raw.split(/[\s,]+/).filter((s) => s !== '')
}

/** Comma-separated text -> numbers (status lists). */
export function parseNumberList(raw: string): number[] {
  return splitNumbers(raw).map((s) => Number(s))
}

/** Empty string ⇒ undefined (server default); otherwise the parsed number. */
function parseNumber(raw: string): number | undefined {
  if (raw.trim() === '') return undefined
  const n = Number(raw)
  return Number.isFinite(n) ? n : undefined
}

/**
 * Build the kind-specific config from validated form values. Blank optional
 * fields are omitted so server defaults apply; blank secrets are omitted so an
 * edit keeps the stored one (write-only contract). Exported so create + edit
 * map consistently.
 */
export function toRealmConfig(values: RealmFormValues): RealmConfig {
  if (values.kind === 'oidc') {
    const config: OidcRealmConfig = {
      issuer: values.issuer.trim(),
      client_id: values.client_id.trim(),
      auto_provision: values.auto_provision,
      link_existing_by_username: values.link_existing_by_username,
      allow_http_issuer: values.allow_http_issuer,
    }
    if (values.client_authentication === 'federated_credential') {
      config.client_authentication = 'federated_credential'
      const audience = values.assertion_audience.trim()
      if (audience !== '') config.assertion_audience = audience
    } else if (values.client_secret !== '') {
      config.client_secret = values.client_secret
    }
    const scopes = parseLines(values.scopes)
    if (scopes.length > 0) config.scopes = scopes
    const skew = parseNumber(values.clock_skew_seconds)
    if (skew !== undefined) config.clock_skew_seconds = skew
    if (values.username_claim.trim() !== '') config.username_claim = values.username_claim.trim()
    if (values.email_claim.trim() !== '') config.email_claim = values.email_claim.trim()
    if (values.display_name_claim.trim() !== '') {
      config.display_name_claim = values.display_name_claim.trim()
    }
    const adminGroups = parseLines(values.admin_groups)
    if (adminGroups.length > 0) config.admin_groups = adminGroups
    if (values.admin_claim.trim() !== '') config.admin_claim = values.admin_claim.trim()
    const loginDomains = parseLines(values.login_domains)
    if (loginDomains.length > 0) config.login_domains = loginDomains
    const endpointHosts = parseLines(values.endpoint_hosts)
    if (endpointHosts.length > 0) config.endpoint_hosts = endpointHosts
    const requiredClaims = parseClaimRules(values.required_claims)
    if (Object.keys(requiredClaims).length > 0) config.required_claims = requiredClaims
    if (values.button_label.trim() !== '') config.button_label = values.button_label.trim()
    return config
  }
  if (values.kind === 'credential_forwarding') {
    const config: CredentialForwardingConfig = {
      url: values.url.trim(),
    }
    if (values.method.trim() !== '') config.method = values.method.trim().toUpperCase()
    const success = parseNumberList(values.success_status)
    if (success.length > 0) config.success_status = success
    const reject = parseNumberList(values.reject_status)
    if (reject.length > 0) config.reject_status = reject
    const connect = parseNumber(values.connect_timeout_ms)
    if (connect !== undefined) config.connect_timeout_ms = connect
    const request = parseNumber(values.request_timeout_ms)
    if (request !== undefined) config.request_timeout_ms = request
    const requiredGroups = parseLines(values.required_groups)
    if (requiredGroups.length > 0) config.required_groups = requiredGroups
    if (values.groups_path.trim() !== '') config.groups_path = values.groups_path.trim()
    if (values.identity_path.trim() !== '') config.identity_path = values.identity_path.trim()
    if (values.allow_http) config.allow_http = true
    if (values.capture_password_hash) {
      config.capture_password_hash = true
      if (values.captured_password_only) config.captured_password_only = true
    }
    if (values.admin_group.trim() !== '') config.admin_group = values.admin_group.trim()
    const positive = parseNumber(values.positive_ttl_secs)
    if (positive !== undefined) config.positive_ttl_secs = positive
    const negative = parseNumber(values.negative_ttl_secs)
    if (negative !== undefined) config.negative_ttl_secs = negative
    if (values.key_pepper !== '') config.key_pepper = values.key_pepper
    return config
  }
  if (values.kind === 'workload_identity') {
    const config: WorkloadIdentityConfig = {
      issuer: values.issuer.trim(),
      allowed_audiences: parseLines(values.allowed_audiences),
      allow_http_issuer: values.allow_http_issuer,
      rules: values.wifRules.map((rule) => {
        const conditions = rule.conditions.map((cond) => ({
          claim: cond.claim.trim(),
          any_of: parseLines(cond.anyOf),
        }))
        return rule.issuerWide
          ? { role: rule.role.trim(), issuer_wide: true, conditions }
          : { role: rule.role.trim(), conditions }
      }),
    }
    const skew = parseNumber(values.clock_skew_seconds)
    if (skew !== undefined) config.clock_skew_seconds = skew
    const maxAge = parseNumber(values.max_token_age_seconds)
    if (maxAge !== undefined) config.max_token_age_seconds = maxAge
    const authorizedParties = parseLines(values.allowed_authorized_parties)
    if (authorizedParties.length > 0) {
      config.allowed_authorized_parties = authorizedParties
    }
    const positiveCache = parseNumber(values.positive_cache_seconds)
    if (positiveCache !== undefined) config.positive_cache_seconds = positiveCache
    const apiKeyTtl = parseNumber(values.api_key_ttl_seconds)
    if (apiKeyTtl !== undefined) config.api_key_ttl_seconds = apiKeyTtl
    const identityClaims = parseLines(values.identity_claims)
    if (identityClaims.length > 0) config.identity_claims = identityClaims
    return config
  }
  if (values.kind === 'trusted_header') {
    const config: TrustedHeaderConfig = {
      username_header: values.username_header.trim(),
      secret_header: values.secret_header.trim(),
      auto_provision: values.header_auto_provision,
    }
    if (values.secret !== '') config.secret = values.secret
    return config
  }
  // local (and reserved kinds): no config.
  return {}
}

/**
 * The role a workload-identity rule grants, picked from the roles that exist.
 * The built-in `admin` role is not offered (the server refuses it). A rule
 * naming a role that is not in the list (since deleted) keeps it, marked; if
 * the roles cannot be loaded, the name is typed instead.
 */
function WifRolePicker({
  value,
  onChange,
  error,
}: {
  value: string
  onChange: (role: string) => void
  error?: string
}) {
  const roles = useRoles()
  if (roles.isError) {
    return (
      <TextField
        label="Role"
        mono
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="ci-deployer"
        error={error}
      />
    )
  }
  const offered = (roles.data ?? []).filter((r) => r.name !== ADMIN_ROLE)
  const missing =
    roles.data != null && value !== '' && !offered.some((r) => r.name === value)
  return (
    <SelectField
      label="Role"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={roles.isLoading}
      error={error}
    >
      <option value="">{roles.isLoading ? 'Loading roles…' : 'Choose a role…'}</option>
      {missing && (
        <option value={value}>
          {value === ADMIN_ROLE ? `${value} (not allowed)` : `${value} (no such role)`}
        </option>
      )}
      {offered.map((r) => (
        <option key={r.id} value={r.name}>
          {r.name}
        </option>
      ))}
    </SelectField>
  )
}
