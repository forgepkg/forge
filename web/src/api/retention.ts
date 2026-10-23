import { httpClient } from '~/lib/httpClient'

/**
 * A repository's retention policy (`crates/server/src/admin/retention.rs`),
 * under `/admin/repositories/{name}/retention`:
 *
 *  - `GET` returns the stored policy (or `null`) and the run ledger (`null`
 *    until a policy was first stored). `PUT` validates and stores a policy,
 *    which arms the worker; `DELETE` removes it.
 *  - `POST …/preview` dry-runs the stored policy, or a draft `policy` from
 *    the body: checked like a `PUT` of it, evaluated even when disabled, and
 *    never stored.
 *  - `POST …/run` makes the policy due now; the worker starts the run on its
 *    next poll. 409 without a policy, or while retention runs are switched
 *    off for every repository (`/admin/settings/retention`).
 *  - `GET …/audit` returns audit rows, newest first, filtered by `run_id` and
 *    paged with `before` (an audit row id) and `limit`.
 *
 * A repository's policy takes one of three shapes, by its format
 * (`crates/core/src/retention/{model,files,images}.rs`): package rules for
 * NuGet, Helm and other package formats (hosted rules, or on a proxy
 * `scope: proxy_cached` eviction rules), file rules for raw repositories,
 * image rules for docker. Every shape has the same envelope. Unknown fields
 * are refused (422); an invalid rule is a 400 naming it.
 */

/** What a package rule does with a version it selects. */
export type RetentionAction = 'unlist' | 'hard_delete'

/** The versions a package rule looks at. */
export type ReleaseType = 'any' | 'releases' | 'prereleases'

/** A package rule's protections and triggers (all optional). */
export interface PackageCriteria {
  keep_last_n?: number
  keep_n_most_downloaded?: number
  older_than_days?: number
  not_downloaded_for_days?: number
  /** Proxy rules only. */
  not_pulled_for_days?: number
}

export interface PackageRule {
  id: string
  action: RetentionAction
  /** `hosted` (the default) on hosted repositories, `proxy_cached` on proxies. */
  scope?: 'hosted' | 'proxy_cached'
  release_type?: ReleaseType
  package_name_prefix?: string | null
  criteria: PackageCriteria
}

/** A raw repository's rule. */
export interface FileRule {
  id: string
  path_prefix?: string
  keep_newest_per_directory?: number
  older_than_days?: number
  not_downloaded_for_days?: number
}

/** A docker repository's rule. */
export interface ImageRule {
  id: string
  image_prefix?: string
  keep_last_n_tags?: number
  protected_tags?: string[]
  tag_older_than_days?: number
  tag_not_pulled_for_days?: number
  delete_untagged_after_days?: number
}

export type RetentionRule = PackageRule | FileRule | ImageRule

/** A policy of any shape: the envelope and its rules. */
export interface RetentionPolicy<R extends RetentionRule = RetentionRule> {
  version: number
  /** Default `true`; a disabled policy is stored but never runs. */
  enabled?: boolean
  /** Default `false`; runs record their decisions without applying them. */
  dry_run_only?: boolean
  /** Default 3600. Runs are at least a minute apart whatever this says. */
  min_run_interval_seconds?: number
  rules: R[]
}

/** What a completed run did (`retention_run.last_run_summary`). */
export interface RunSummary {
  evaluated?: number
  unlisted?: number
  deleted?: number
  blobs_enqueued?: number
  skipped?: number
}

/** The run ledger (`retention_run`). */
export interface RunState {
  state: 'idle' | 'running'
  next_run_at: string
  started_at: string | null
  finished_at: string | null
  locked_until: string | null
  last_error: string | null
  last_run_summary: RunSummary | null
}

export interface RetentionView {
  policy: RetentionPolicy | null
  last_run: RunState | null
  /**
   * Whether retention runs at all (`/admin/settings/retention`): while it is
   * off, no policy runs and Run now is refused.
   */
  runs_enabled: boolean
}

/** Why a version was selected: the triggers that held, with their days. */
export type DecisionReason = Record<string, unknown>

/** A hosted version a package policy unlists or deletes. */
export interface Decision {
  component_id: number
  package_name: string
  version: string
  action: RetentionAction
  rule_id: string
  reason: DecisionReason
}

/** A cached version a proxy policy evicts. */
export interface ProxyDecision {
  cached_version_id: number
  package_name: string
  version: string
  rule_id: string
  reason: DecisionReason
}

export interface TagDecision {
  image: string
  tag: string
  manifest_id: number
  digest: string
  rule_id: string
  reason: DecisionReason
}

export interface ManifestDecision {
  image: string
  manifest_id: number
  digest: string
  rule_id: string
  reason: DecisionReason
}

export interface FileDecision {
  file_id: number
  path: string
  blob_sha256: string
  rule_id: string
  reason: DecisionReason
}

export interface PreviewView {
  decisions: Decision[]
  proxy_decisions: ProxyDecision[]
  /** Docker repositories. */
  image_decisions?: { tags: TagDecision[]; manifests: ManifestDecision[] }
  /** Raw repositories. */
  file_decisions?: FileDecision[]
  counts: { evaluated: number; unlisted: number; deleted: number }
}

/**
 * One audit row. `target_kind` says what `package_name` and `version` hold:
 * `component` and `proxy_cached_version` a package id and version,
 * `oci_tag` an image and tag, `oci_manifest` an image and digest,
 * `raw_file` a path and the content's sha256.
 */
export interface AuditRecord {
  id: number
  run_id: string
  rule_id: string
  /** `unlist`, `hard_delete` or `skipped` (images: what was deleted). */
  action: string
  target_kind: string
  package_name: string
  version: string
  component_id: number | null
  blob_sha256: string | null
  ref_count_after: number | null
  blob_delete_enqueued: boolean
  dry_run: boolean
  reason: DecisionReason
  created_at: string
}

export interface AuditQuery {
  run_id?: string
  /** Rows older than this audit row id. */
  before?: number
  limit?: number
}

export const retentionKeys = {
  view: (repo: string) => ['retention', repo] as const,
  audits: (repo: string) => ['retention', repo, 'audit'] as const,
  audit: (repo: string, q: AuditQuery) =>
    ['retention', repo, 'audit', q.run_id ?? null, q.before ?? null, q.limit ?? null] as const,
}

function base(repo: string): string {
  return `/admin/repositories/${encodeURIComponent(repo)}/retention`
}

export function fetchRetention(
  repo: string,
  signal?: AbortSignal,
): Promise<RetentionView> {
  return httpClient.get<RetentionView>(base(repo), { signal })
}

export function saveRetention(
  repo: string,
  policy: RetentionPolicy,
): Promise<RetentionView> {
  return httpClient.put<RetentionView>(base(repo), { policy })
}

export function deleteRetention(repo: string): Promise<void> {
  return httpClient.delete<void>(base(repo))
}

/** Dry-run `policy` (a draft), or the stored policy when it is absent. */
export function previewRetention(
  repo: string,
  policy?: RetentionPolicy,
): Promise<PreviewView> {
  return httpClient.post<PreviewView>(
    `${base(repo)}/preview`,
    policy ? { policy } : {},
  )
}

export function runRetention(repo: string): Promise<{ scheduled: boolean }> {
  return httpClient.post<{ scheduled: boolean }>(`${base(repo)}/run`)
}

export function fetchRetentionAudit(
  repo: string,
  q: AuditQuery,
  signal?: AbortSignal,
): Promise<{ items: AuditRecord[] }> {
  return httpClient.get<{ items: AuditRecord[] }>(`${base(repo)}/audit`, {
    signal,
    query: { run_id: q.run_id, before: q.before, limit: q.limit },
  })
}
