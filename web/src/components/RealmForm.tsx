import { useState } from 'react'

import type {
  CredentialForwardingConfig,
  OidcRealmConfig,
  RealmConfig,
  RealmKind,
  RealmView,
  WorkloadIdentityConfig,
} from '~/api/realms'
import { Button } from '~/components/catalyst/button'
import {
  Checkbox,
  CheckboxField,
  CheckboxGroup,
} from '~/components/catalyst/checkbox'
import {
  Description,
  ErrorMessage,
  Field,
  FieldGroup,
  Fieldset,
  Label,
  Legend,
} from '~/components/catalyst/fieldset'
import { Input } from '~/components/catalyst/input'
import { Textarea } from '~/components/catalyst/textarea'
import { Select } from '~/components/catalyst/select'

/**
 * Shared auth-realm create/edit form (§12.7). Kind-conditional fields:
 *
 *  - **oidc** → issuer / client / write-only secret / claims / provisioning /
 *    login domains / button label
 *  - **credential_forwarding** → upstream URL / acceptance criteria /
 *    timeouts / groups / caching TTLs / write-only key pepper
 *  - **workload_identity** (WIF) → public OIDC issuer / allowed audiences /
 *    bounded token lifetime / optional authorized parties / ordered
 *    claim→role rules (no secrets, no redaction)
 *  - **local** → no config; only name + enabled are editable (built-in realm)
 *
 * On **create** the kind is selectable (local is built-in and cannot be
 * created); on **edit** it is fixed and shown read-only. Secrets follow the
 * RepositoryForm `upstream_password` pattern: never seeded from the (redacted)
 * GET, placeholder shows "set to replace" when `<key>_set` is true, and a
 * blank field keeps the stored secret on edit.
 *
 * String-array fields (scopes, login domains, groups, status lists) are
 * comma-separated text inputs parsed on submit; status lists parse to numbers.
 * Blank numeric fields are omitted so the server defaults apply.
 */

/** A draft mirrors the form fields; numbers/lists stay strings while editing. */
export interface RealmFormValues {
  kind: RealmKind
  name: string
  enabled: boolean
  // Shared (oidc + credential_forwarding)
  auto_provision: boolean
  // oidc
  issuer: string
  client_id: string
  /** Newly-typed secret; blank ⇒ "leave unchanged" on edit / invalid on create. */
  client_secret: string
  scopes: string
  clock_skew_seconds: string
  allow_http_issuer: boolean
  username_claim: string
  email_claim: string
  display_name_claim: string
  link_existing_by_username: boolean
  admin_groups: string
  admin_claim: string
  login_domains: string
  /** One `claim = value, value` per line (parsed to a map on submit). */
  required_claims: string
  button_label: string
  // credential_forwarding
  url: string
  method: string
  success_status: string
  reject_status: string
  connect_timeout_ms: string
  request_timeout_ms: string
  required_groups: string
  groups_path: string
  identity_path: string
  admin_group: string
  positive_ttl_secs: string
  negative_ttl_secs: string
  /** Newly-typed pepper; blank ⇒ "leave unchanged" on edit / invalid on create. */
  key_pepper: string
  // workload_identity (WIF). Reuses `issuer`, `allow_http_issuer`, and
  // `clock_skew_seconds` above since only one kind is active at a time.
  /** Comma/newline-separated allowed audiences (parsed to string[] on submit). */
  allowed_audiences: string
  /** Optional exact `azp` values for issuers that emit authorized-party claims. */
  allowed_authorized_parties: string
  /** Maximum accepted token age and declared token lifetime. */
  max_token_age_seconds: string
  /** Expiry-bounded signature-verification cache TTL (`jti` tokens only). */
  positive_cache_seconds: string
  /** Ordered claim→role rules; anyOf is a comma-separated string per condition. */
  wifRules: Array<{
    role: string
    conditions: Array<{ claim: string; anyOf: string }>
  }>
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
}

function joinList(list?: (string | number)[]): string {
  return (list ?? []).join(', ')
}

/** `{ tid: ['a', 'b'] }` -> `tid = a, b` (one claim per line). */
export function formatClaimRules(rules?: Record<string, string[]>): string {
  return Object.entries(rules ?? {})
    .map(([claim, values]) => `${claim} = ${values.join(', ')}`)
    .join('\n')
}

/** Parse `claim = value, value` lines into the `required_claims` map. */
export function parseClaimRules(raw: string): Record<string, string[]> {
  const rules: Record<string, string[]> = {}
  for (const line of raw.split('\n')) {
    const eq = line.indexOf('=')
    if (eq < 0) continue
    const claim = line.slice(0, eq).trim()
    const values = parseList(line.slice(eq + 1))
    if (claim !== '' && values.length > 0) rules[claim] = values
  }
  return rules
}

function seed(existing?: RealmView): RealmFormValues {
  const oidc = (existing?.kind === 'oidc' ? existing.config : {}) as OidcRealmConfig
  const fwd = (
    existing?.kind === 'credential_forwarding' ? existing.config : {}
  ) as CredentialForwardingConfig
  const wif = (
    existing?.kind === 'workload_identity' ? existing.config : {}
  ) as WorkloadIdentityConfig
  return {
    kind: existing?.kind ?? 'oidc',
    name: existing?.name ?? '',
    enabled: existing?.enabled ?? true,
    auto_provision:
      (existing?.kind === 'oidc' ? oidc.auto_provision : fwd.auto_provision) ?? true,
    issuer: (existing?.kind === 'workload_identity' ? wif.issuer : oidc.issuer) ?? '',
    client_id: oidc.client_id ?? '',
    // Never seed secrets — they are write-only and redacted on read.
    client_secret: '',
    scopes: joinList(oidc.scopes),
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
    admin_groups: joinList(oidc.admin_groups),
    admin_claim: oidc.admin_claim ?? '',
    login_domains: joinList(oidc.login_domains),
    required_claims: formatClaimRules(oidc.required_claims),
    button_label: oidc.button_label ?? '',
    url: fwd.url ?? '',
    method: fwd.method ?? '',
    success_status: joinList(fwd.success_status),
    reject_status: joinList(fwd.reject_status),
    connect_timeout_ms: fwd.connect_timeout_ms != null ? String(fwd.connect_timeout_ms) : '',
    request_timeout_ms: fwd.request_timeout_ms != null ? String(fwd.request_timeout_ms) : '',
    required_groups: joinList(fwd.required_groups),
    groups_path: fwd.groups_path ?? '',
    identity_path: fwd.identity_path ?? '',
    admin_group: fwd.admin_group ?? '',
    positive_ttl_secs: fwd.positive_ttl_secs != null ? String(fwd.positive_ttl_secs) : '',
    negative_ttl_secs: fwd.negative_ttl_secs != null ? String(fwd.negative_ttl_secs) : '',
    key_pepper: '',
    allowed_audiences: joinList(wif.allowed_audiences),
    allowed_authorized_parties: joinList(wif.allowed_authorized_parties),
    max_token_age_seconds:
      wif.max_token_age_seconds != null ? String(wif.max_token_age_seconds) : '',
    positive_cache_seconds:
      wif.positive_cache_seconds != null ? String(wif.positive_cache_seconds) : '',
    wifRules: (wif.rules ?? []).map((rule) => ({
      role: rule.role ?? '',
      conditions: (rule.conditions ?? []).map((c) => ({
        claim: c.claim ?? '',
        anyOf: joinList(c.any_of),
      })),
    })),
  }
}

export function RealmForm({
  mode,
  existing,
  submitting,
  serverError,
  onSubmit,
  onCancel,
}: RealmFormProps) {
  const [values, setValues] = useState<RealmFormValues>(() => seed(existing))
  const [errors, setErrors] = useState<Record<string, string>>({})

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
      if (mode === 'create' && values.client_secret === '') {
        next.client_secret = 'A client secret is required.'
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
      if (parseList(values.allowed_audiences).length === 0) {
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
      if (values.wifRules.length === 0) {
        next.wifRules = 'At least one rule is required.'
      }
      values.wifRules.forEach((rule, ri) => {
        if (rule.role.trim() === '') {
          next[`wifRule.${ri}.role`] = 'A role is required.'
        } else if (rule.role.trim() === 'admin') {
          next[`wifRule.${ri}.role`] =
            'Workload identity cannot grant the built-in global admin role.'
        }
        if (rule.conditions.length === 0) {
          next[`wifRule.${ri}.conditions`] =
            'At least one claim condition is required; catch-all trust is not allowed.'
        } else if (!wifRuleHasIdentityScope(values.issuer, rule.conditions)) {
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
          if (parseList(cond.anyOf).length === 0) {
            next[`wifRule.${ri}.cond.${ci}.anyOf`] =
              'At least one value is required.'
          }
        })
      })
    }
    setErrors(next)
    return Object.keys(next).length === 0
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) return
    onSubmit(values)
  }

  const isLocal = values.kind === 'local'
  const isOidc = values.kind === 'oidc'
  const isForwarding = values.kind === 'credential_forwarding'
  const isWorkloadIdentity = values.kind === 'workload_identity'

  function setRule(
    index: number,
    update: (rule: RealmFormValues['wifRules'][number]) => RealmFormValues['wifRules'][number],
  ) {
    setValues((v) => ({
      ...v,
      wifRules: v.wifRules.map((r, i) => (i === index ? update(r) : r)),
    }))
  }

  function addRule() {
    setValues((v) => ({
      ...v,
      wifRules: [
        ...v.wifRules,
        { role: '', conditions: [{ claim: '', anyOf: '' }] },
      ],
    }))
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

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">
      <Field>
        <Label>Name</Label>
        <Input
          type="text"
          value={values.name}
          onChange={(e) => set('name', e.target.value)}
          autoFocus={mode === 'create'}
          invalid={!!errors.name}
        />
        {errors.name && <ErrorMessage role="alert">{errors.name}</ErrorMessage>}
      </Field>

      <Field>
        <Label>Kind</Label>
        {mode === 'create' ? (
          <Select
            value={values.kind}
            onChange={(e) => set('kind', e.target.value as RealmKind)}
          >
            <option value="oidc">oidc</option>
            <option value="credential_forwarding">credential_forwarding</option>
            <option value="workload_identity">workload_identity</option>
          </Select>
        ) : (
          <Input
            type="text"
            value={values.kind}
            readOnly
            aria-readonly="true"
          />
        )}
        {mode === 'edit' && (
          <Description>The kind cannot be changed after creation.</Description>
        )}
      </Field>

      <CheckboxField>
        <Checkbox
          checked={values.enabled}
          onChange={(c) => set('enabled', c)}
        />
        <Label>Enabled (used for sign-in / credential checks)</Label>
      </CheckboxField>

      {isLocal && (
        <p className="rounded-lg bg-zinc-950/[2.5%] px-3 py-2 text-sm/6 text-zinc-600 ring-1 ring-zinc-950/5 dark:bg-white/[2.5%] dark:text-zinc-400 dark:ring-white/10">
          The local realm is built in (argon2 passwords); it has no
          configuration beyond its name and enabled flag.
        </p>
      )}

      {isOidc && (
        <Fieldset className="border-t border-zinc-950/5 pt-4 dark:border-white/10">
          <Legend>OIDC provider</Legend>
          <FieldGroup>
            <Field>
              <Label>Issuer URL</Label>
              <Input
                type="text"
                value={values.issuer}
                onChange={(e) => set('issuer', e.target.value)}
                placeholder="https://idp.example.com/realms/main"
                invalid={!!errors.issuer}
              />
              {errors.issuer && (
                <ErrorMessage role="alert">{errors.issuer}</ErrorMessage>
              )}
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Client ID</Label>
                <Input
                  type="text"
                  autoComplete="off"
                  value={values.client_id}
                  onChange={(e) => set('client_id', e.target.value)}
                  invalid={!!errors.client_id}
                />
                {errors.client_id && (
                  <ErrorMessage role="alert">{errors.client_id}</ErrorMessage>
                )}
              </Field>
              <SecretField
                label="Client secret"
                error={errors.client_secret}
                value={values.client_secret}
                onChange={(v) => set('client_secret', v)}
                stored={mode === 'edit' && hasStoredSecret(existing, 'client_secret_set')}
              />
            </div>

            <Field>
              <Label>Scopes</Label>
              <Input
                type="text"
                value={values.scopes}
                onChange={(e) => set('scopes', e.target.value)}
                placeholder="openid, profile, email"
              />
              <ListHint />
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Clock skew (seconds)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.clock_skew_seconds}
                  onChange={(e) => set('clock_skew_seconds', e.target.value)}
                  placeholder="60"
                  invalid={!!errors.clock_skew_seconds}
                />
                {errors.clock_skew_seconds && (
                  <ErrorMessage role="alert">
                    {errors.clock_skew_seconds}
                  </ErrorMessage>
                )}
              </Field>
              <Field>
                <Label>Button label</Label>
                <Input
                  type="text"
                  value={values.button_label}
                  onChange={(e) => set('button_label', e.target.value)}
                  placeholder="Login with SSO"
                />
              </Field>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <Field>
                <Label>Username claim</Label>
                <Input
                  type="text"
                  value={values.username_claim}
                  onChange={(e) => set('username_claim', e.target.value)}
                  placeholder="preferred_username"
                />
              </Field>
              <Field>
                <Label>Email claim</Label>
                <Input
                  type="text"
                  value={values.email_claim}
                  onChange={(e) => set('email_claim', e.target.value)}
                  placeholder="email"
                />
              </Field>
              <Field>
                <Label>Display-name claim</Label>
                <Input
                  type="text"
                  value={values.display_name_claim}
                  onChange={(e) => set('display_name_claim', e.target.value)}
                  placeholder="name"
                />
              </Field>
            </div>

            <Field>
              <Label>Login domains</Label>
              <Input
                type="text"
                value={values.login_domains}
                onChange={(e) => set('login_domains', e.target.value)}
                placeholder="example.com, corp.example.com"
              />
              <Description>
                Email domains routed to this IdP by identifier-first login.
                Comma-separated.
              </Description>
            </Field>

            <Field>
              <Label>Required claims</Label>
              <Textarea
                rows={2}
                value={values.required_claims}
                onChange={(e) => set('required_claims', e.target.value)}
                placeholder="tid = 00000000-0000-0000-0000-000000000000"
              />
              <Description>
                Only tokens carrying one of the listed values may sign in, one
                claim per line (<span className="font-mono">claim = value, value</span>).
                Use it to restrict a multi-tenant app to your tenant
                (<span className="font-mono">tid</span>) or a Google Workspace
                domain (<span className="font-mono">hd</span>).
              </Description>
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Admin groups</Label>
                <Input
                  type="text"
                  value={values.admin_groups}
                  onChange={(e) => set('admin_groups', e.target.value)}
                  placeholder="forge-admins"
                />
                <ListHint />
              </Field>
              <Field>
                <Label>Admin claim</Label>
                <Input
                  type="text"
                  value={values.admin_claim}
                  onChange={(e) => set('admin_claim', e.target.value)}
                  placeholder="roles"
                />
              </Field>
            </div>

            <CheckboxGroup>
              <CheckboxField>
                <Checkbox
                  checked={values.auto_provision}
                  onChange={(c) => set('auto_provision', c)}
                />
                <Label>Auto-provision users on first login</Label>
              </CheckboxField>
              <CheckboxField>
                <Checkbox
                  checked={values.link_existing_by_username}
                  onChange={(c) => set('link_existing_by_username', c)}
                />
                <Label>Link existing users by username</Label>
              </CheckboxField>
              <CheckboxField>
                <Checkbox
                  checked={values.allow_http_issuer}
                  onChange={(c) => set('allow_http_issuer', c)}
                />
                <Label>Allow plain-HTTP issuer (testing only)</Label>
              </CheckboxField>
            </CheckboxGroup>
          </FieldGroup>
        </Fieldset>
      )}

      {isForwarding && (
        <Fieldset className="border-t border-zinc-950/5 pt-4 dark:border-white/10">
          <Legend>Credential-forwarding upstream</Legend>
          <FieldGroup>
            <Field>
              <Label>Upstream URL</Label>
              <Input
                type="text"
                value={values.url}
                onChange={(e) => set('url', e.target.value)}
                placeholder="https://auth.example.com/check"
                invalid={!!errors.url}
              />
              {errors.url && (
                <ErrorMessage role="alert">{errors.url}</ErrorMessage>
              )}
            </Field>

            <div className="grid gap-4 sm:grid-cols-3">
              <Field>
                <Label>Method</Label>
                <Input
                  type="text"
                  value={values.method}
                  onChange={(e) => set('method', e.target.value)}
                  placeholder="GET"
                />
              </Field>
              <Field>
                <Label>Success statuses</Label>
                <Input
                  type="text"
                  value={values.success_status}
                  onChange={(e) => set('success_status', e.target.value)}
                  placeholder="200"
                  invalid={!!errors.success_status}
                />
                {errors.success_status && (
                  <ErrorMessage role="alert">
                    {errors.success_status}
                  </ErrorMessage>
                )}
              </Field>
              <Field>
                <Label>Reject statuses</Label>
                <Input
                  type="text"
                  value={values.reject_status}
                  onChange={(e) => set('reject_status', e.target.value)}
                  placeholder="401, 403"
                  invalid={!!errors.reject_status}
                />
                {errors.reject_status && (
                  <ErrorMessage role="alert">
                    {errors.reject_status}
                  </ErrorMessage>
                )}
              </Field>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Connect timeout (ms)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.connect_timeout_ms}
                  onChange={(e) => set('connect_timeout_ms', e.target.value)}
                  placeholder="2000"
                  invalid={!!errors.connect_timeout_ms}
                />
                {errors.connect_timeout_ms && (
                  <ErrorMessage role="alert">
                    {errors.connect_timeout_ms}
                  </ErrorMessage>
                )}
              </Field>
              <Field>
                <Label>Request timeout (ms)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.request_timeout_ms}
                  onChange={(e) => set('request_timeout_ms', e.target.value)}
                  placeholder="5000"
                  invalid={!!errors.request_timeout_ms}
                />
                {errors.request_timeout_ms && (
                  <ErrorMessage role="alert">
                    {errors.request_timeout_ms}
                  </ErrorMessage>
                )}
              </Field>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <Field>
                <Label>Required groups</Label>
                <Input
                  type="text"
                  value={values.required_groups}
                  onChange={(e) => set('required_groups', e.target.value)}
                  placeholder="developers"
                />
                <ListHint />
              </Field>
              <Field>
                <Label>Groups path</Label>
                <Input
                  type="text"
                  value={values.groups_path}
                  onChange={(e) => set('groups_path', e.target.value)}
                  placeholder="user.groups"
                />
              </Field>
              <Field>
                <Label>Admin group</Label>
                <Input
                  type="text"
                  value={values.admin_group}
                  onChange={(e) => set('admin_group', e.target.value)}
                />
              </Field>
            </div>

            <Field>
              <Label>Identity path</Label>
              <Input
                type="text"
                value={values.identity_path}
                onChange={(e) => set('identity_path', e.target.value)}
                placeholder="login"
              />
              <Description>
                Where the upstream&apos;s success response names the account it
                authenticated. When set, that name must equal the username
                entered. Required when the upstream accepts a secret with any
                username (personal access tokens); leave empty only if the
                upstream itself binds the username to the password.
              </Description>
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <Label>Positive cache TTL (seconds)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.positive_ttl_secs}
                  onChange={(e) => set('positive_ttl_secs', e.target.value)}
                  placeholder="300"
                  invalid={!!errors.positive_ttl_secs}
                />
                {errors.positive_ttl_secs && (
                  <ErrorMessage role="alert">
                    {errors.positive_ttl_secs}
                  </ErrorMessage>
                )}
              </Field>
              <Field>
                <Label>Negative cache TTL (seconds)</Label>
                <Input
                  type="number"
                  min={0}
                  value={values.negative_ttl_secs}
                  onChange={(e) => set('negative_ttl_secs', e.target.value)}
                  placeholder="30"
                  invalid={!!errors.negative_ttl_secs}
                />
                {errors.negative_ttl_secs && (
                  <ErrorMessage role="alert">
                    {errors.negative_ttl_secs}
                  </ErrorMessage>
                )}
              </Field>
            </div>

            <SecretField
              label="Key pepper"
              error={errors.key_pepper}
              value={values.key_pepper}
              onChange={(v) => set('key_pepper', v)}
              stored={mode === 'edit' && hasStoredSecret(existing, 'key_pepper_set')}
            />

            <CheckboxField>
              <Checkbox
                checked={values.auto_provision}
                onChange={(c) => set('auto_provision', c)}
              />
              <Label>Auto-provision users on first successful check</Label>
            </CheckboxField>
          </FieldGroup>
        </Fieldset>
      )}

      {isWorkloadIdentity && (
        <Fieldset className="border-t border-zinc-950/5 pt-4 dark:border-white/10">
          <Legend>Workload-identity federation</Legend>
          <FieldGroup>
            <Field>
              <Label>Issuer URL</Label>
              <Input
                type="text"
                value={values.issuer}
                onChange={(e) => set('issuer', e.target.value)}
                placeholder="https://token.actions.githubusercontent.com"
                invalid={!!errors.issuer}
              />
              <Description>
                The OIDC issuer whose public JWKS validates incoming tokens.
              </Description>
              {errors.issuer && (
                <ErrorMessage role="alert">{errors.issuer}</ErrorMessage>
              )}
            </Field>

            <Field>
              <Label>Allowed audiences</Label>
              <Input
                type="text"
                value={values.allowed_audiences}
                onChange={(e) => set('allowed_audiences', e.target.value)}
                placeholder="https://forge.example.com"
                invalid={!!errors.allowed_audiences}
              />
              <ListHint />
              {errors.allowed_audiences && (
                <ErrorMessage role="alert">
                  {errors.allowed_audiences}
                </ErrorMessage>
              )}
            </Field>

            <Field>
              <Label>Clock skew (seconds)</Label>
              <Input
                type="number"
                min={0}
                max={300}
                value={values.clock_skew_seconds}
                onChange={(e) => set('clock_skew_seconds', e.target.value)}
                placeholder="60"
                invalid={!!errors.clock_skew_seconds}
              />
              {errors.clock_skew_seconds && (
                <ErrorMessage role="alert">
                  {errors.clock_skew_seconds}
                </ErrorMessage>
              )}
            </Field>

            <Field>
              <Label>Maximum token age (seconds)</Label>
              <Input
                type="number"
                min={1}
                max={86400}
                value={values.max_token_age_seconds}
                onChange={(e) => set('max_token_age_seconds', e.target.value)}
                placeholder="3600"
                invalid={!!errors.max_token_age_seconds}
              />
              <Description>
                Bounds both token age and declared lifetime. GitHub tokens are
                normally 10 minutes; use the shortest value your CI jobs support.
              </Description>
              {errors.max_token_age_seconds && (
                <ErrorMessage role="alert">
                  {errors.max_token_age_seconds}
                </ErrorMessage>
              )}
            </Field>

            <Field>
              <Label>Allowed authorized parties</Label>
              <Input
                type="text"
                value={values.allowed_authorized_parties}
                onChange={(e) => set('allowed_authorized_parties', e.target.value)}
                placeholder="Optional azp values"
              />
              <Description>
                Optional exact <code>azp</code> allowlist for issuers that emit
                it. Leave blank for GitHub Actions and GitLab CI.
              </Description>
            </Field>

            <Field>
              <Label>Positive verification cache (seconds)</Label>
              <Input
                type="number"
                min={0}
                max={300}
                value={values.positive_cache_seconds}
                onChange={(e) => set('positive_cache_seconds', e.target.value)}
                placeholder="60"
                invalid={!!errors.positive_cache_seconds}
              />
              <Description>
                Caches signature verification only for tokens with <code>jti</code>,
                never beyond <code>exp</code>. Claim rules and roles are still
                evaluated on every request. Use 0 to disable.
              </Description>
              {errors.positive_cache_seconds && (
                <ErrorMessage role="alert">
                  {errors.positive_cache_seconds}
                </ErrorMessage>
              )}
            </Field>

            <CheckboxField>
              <Checkbox
                checked={values.allow_http_issuer}
                onChange={(c) => set('allow_http_issuer', c)}
              />
              <Label>Allow plain-HTTP issuer (testing only)</Label>
            </CheckboxField>

            <Field>
              <Label>Rules</Label>
              <Description>
                Ordered; the first rule whose conditions all match grants its
                role. Every rule needs a workload identity condition; ref or
                environment alone is not enough. Public GitHub/GitLab issuers
                require immutable numeric repository/project and owner/namespace
                IDs. Global admin is not allowed; grant a repository-scoped role.
              </Description>
              {errors.wifRules && (
                <ErrorMessage role="alert">{errors.wifRules}</ErrorMessage>
              )}
            </Field>

            <div className="space-y-4">
              {values.wifRules.map((rule, ri) => (
                <div
                  key={ri}
                  className="rounded-lg border border-zinc-950/10 p-4 dark:border-white/10"
                >
                  <div className="flex items-start justify-between gap-3">
                    <Field className="flex-1">
                      <Label>Role</Label>
                      <Input
                        type="text"
                        value={rule.role}
                        onChange={(e) =>
                          setRule(ri, (r) => ({ ...r, role: e.target.value }))
                        }
                        placeholder="ci-deployer"
                        invalid={!!errors[`wifRule.${ri}.role`]}
                      />
                      {errors[`wifRule.${ri}.role`] && (
                        <ErrorMessage role="alert">
                          {errors[`wifRule.${ri}.role`]}
                        </ErrorMessage>
                      )}
                    </Field>
                    <Button
                      type="button"
                      plain
                      onClick={() => removeRule(ri)}
                      aria-label={`Remove rule ${ri + 1}`}
                    >
                      Remove rule
                    </Button>
                  </div>

                  <div className="mt-4 space-y-3">
                    {errors[`wifRule.${ri}.conditions`] && (
                      <Field>
                        <ErrorMessage role="alert">
                          {errors[`wifRule.${ri}.conditions`]}
                        </ErrorMessage>
                      </Field>
                    )}
                    {rule.conditions.map((cond, ci) => (
                      <div
                        key={ci}
                        className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
                      >
                        <Field>
                          <Label>Claim</Label>
                          <Input
                            type="text"
                            value={cond.claim}
                            onChange={(e) =>
                              setRule(ri, (r) => ({
                                ...r,
                                conditions: r.conditions.map((c, i) =>
                                  i === ci ? { ...c, claim: e.target.value } : c,
                                ),
                              }))
                            }
                            placeholder="repository"
                            invalid={!!errors[`wifRule.${ri}.cond.${ci}.claim`]}
                          />
                          {errors[`wifRule.${ri}.cond.${ci}.claim`] && (
                            <ErrorMessage role="alert">
                              {errors[`wifRule.${ri}.cond.${ci}.claim`]}
                            </ErrorMessage>
                          )}
                        </Field>
                        <Field>
                          <Label>Any of</Label>
                          <Input
                            type="text"
                            value={cond.anyOf}
                            onChange={(e) =>
                              setRule(ri, (r) => ({
                                ...r,
                                conditions: r.conditions.map((c, i) =>
                                  i === ci ? { ...c, anyOf: e.target.value } : c,
                                ),
                              }))
                            }
                            placeholder="acme/api, acme/web"
                            invalid={!!errors[`wifRule.${ri}.cond.${ci}.anyOf`]}
                          />
                          <ListHint />
                          {errors[`wifRule.${ri}.cond.${ci}.anyOf`] && (
                            <ErrorMessage role="alert">
                              {errors[`wifRule.${ri}.cond.${ci}.anyOf`]}
                            </ErrorMessage>
                          )}
                        </Field>
                        <Button
                          type="button"
                          plain
                          onClick={() => removeCondition(ri, ci)}
                          aria-label={`Remove condition ${ci + 1} of rule ${ri + 1}`}
                        >
                          Remove
                        </Button>
                      </div>
                    ))}
                    <Button
                      type="button"
                      outline
                      onClick={() => addCondition(ri)}
                    >
                      Add condition
                    </Button>
                  </div>
                </div>
              ))}
              <Button type="button" outline onClick={addRule}>
                Add rule
              </Button>
            </div>
          </FieldGroup>
        </Fieldset>
      )}

      {serverError && (
        <p role="alert" className="text-sm/6 text-red-600 dark:text-red-400">
          {serverError}
        </p>
      )}

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={submitting}>
          {submitting
            ? 'Saving…'
            : mode === 'create'
              ? 'Create realm'
              : 'Save changes'}
        </Button>
        <Button type="button" outline onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  )
}

function hasStoredSecret(
  existing: RealmView | undefined,
  flag: 'client_secret_set' | 'key_pepper_set',
): boolean {
  const config = existing?.config as Record<string, unknown> | undefined
  return config?.[flag] === true
}

/** Write-only secret input mirroring RepositoryForm's upstream-password UX. */
function SecretField({
  label,
  error,
  value,
  onChange,
  stored,
}: {
  label: string
  error?: string
  value: string
  onChange: (value: string) => void
  stored: boolean
}) {
  return (
    <Field>
      <Label>{label}</Label>
      <Input
        type="password"
        autoComplete="new-password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={stored ? '•••••••• (set to replace)' : 'Required'}
        invalid={!!error}
      />
      <Description>
        {stored
          ? 'A secret is stored. Leave blank to keep it; type a new one to replace it.'
          : 'Write-only. The stored secret is never shown after saving.'}
      </Description>
      {error && <ErrorMessage role="alert">{error}</ErrorMessage>}
    </Field>
  )
}

function ListHint() {
  return <Description>Comma-separated.</Description>
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
  return parseList(raw).every((s) => Number.isFinite(Number(s)))
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

function isGitHubActionsIssuer(raw: string): boolean {
  return normalizedIssuer(raw) === GITHUB_ACTIONS_ISSUER
}

function isGitLabComIssuer(raw: string): boolean {
  return normalizedIssuer(raw) === GITLAB_COM_ISSUER
}

/** Mirror the server's defense against syntactically non-empty catch-all rules. */
function wifRuleHasIdentityScope(
  issuer: string,
  conditions: Array<{ claim: string }>,
): boolean {
  const claims = conditions.map((condition) => condition.claim.trim())
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

/** Comma-separated text -> trimmed, non-empty entries. */
export function parseList(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '')
}

/** Comma-separated text -> numbers (status lists). */
export function parseNumberList(raw: string): number[] {
  return parseList(raw).map((s) => Number(s))
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
    if (values.client_secret !== '') config.client_secret = values.client_secret
    const scopes = parseList(values.scopes)
    if (scopes.length > 0) config.scopes = scopes
    const skew = parseNumber(values.clock_skew_seconds)
    if (skew !== undefined) config.clock_skew_seconds = skew
    if (values.username_claim.trim() !== '') config.username_claim = values.username_claim.trim()
    if (values.email_claim.trim() !== '') config.email_claim = values.email_claim.trim()
    if (values.display_name_claim.trim() !== '') {
      config.display_name_claim = values.display_name_claim.trim()
    }
    const adminGroups = parseList(values.admin_groups)
    if (adminGroups.length > 0) config.admin_groups = adminGroups
    if (values.admin_claim.trim() !== '') config.admin_claim = values.admin_claim.trim()
    const loginDomains = parseList(values.login_domains)
    if (loginDomains.length > 0) config.login_domains = loginDomains
    const requiredClaims = parseClaimRules(values.required_claims)
    if (Object.keys(requiredClaims).length > 0) config.required_claims = requiredClaims
    if (values.button_label.trim() !== '') config.button_label = values.button_label.trim()
    return config
  }
  if (values.kind === 'credential_forwarding') {
    const config: CredentialForwardingConfig = {
      url: values.url.trim(),
      auto_provision: values.auto_provision,
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
    const requiredGroups = parseList(values.required_groups)
    if (requiredGroups.length > 0) config.required_groups = requiredGroups
    if (values.groups_path.trim() !== '') config.groups_path = values.groups_path.trim()
    if (values.identity_path.trim() !== '') config.identity_path = values.identity_path.trim()
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
      allowed_audiences: parseList(values.allowed_audiences),
      allow_http_issuer: values.allow_http_issuer,
      rules: values.wifRules.map((rule) => {
        const conditions = rule.conditions.map((cond) => ({
          claim: cond.claim.trim(),
          any_of: parseList(cond.anyOf),
        }))
        return { role: rule.role.trim(), conditions }
      }),
    }
    const skew = parseNumber(values.clock_skew_seconds)
    if (skew !== undefined) config.clock_skew_seconds = skew
    const maxAge = parseNumber(values.max_token_age_seconds)
    if (maxAge !== undefined) config.max_token_age_seconds = maxAge
    const authorizedParties = parseList(values.allowed_authorized_parties)
    if (authorizedParties.length > 0) {
      config.allowed_authorized_parties = authorizedParties
    }
    const positiveCache = parseNumber(values.positive_cache_seconds)
    if (positiveCache !== undefined) config.positive_cache_seconds = positiveCache
    return config
  }
  // local (and reserved kinds): no config.
  return {}
}
