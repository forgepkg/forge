-- envisia-forge retention / cleanup + policy-driven blob GC (slice 12.1)
--
-- Builds on 0001_init.sql. Adds:
--   * per-repository retention policy (jsonb) + advisory last-run marker
--   * download tracking columns (best-effort, like token.last_used_at)
--   * retention_run  : per-repo coordination ledger (authoritative scheduling
--                      state; claimed via FOR UPDATE SKIP LOCKED + a lease)
--   * retention_audit: append-only record of every applied/previewed decision
--
-- All blob deletion still flows through the slice-1 blob_outbox; nothing here
-- deletes S3 objects directly.

-- ---------------------------------------------------------------------------
-- repository: add the policy column (nullable => no retention)
-- ---------------------------------------------------------------------------
ALTER TABLE repository
    ADD COLUMN retention_policy       jsonb NULL,
    ADD COLUMN retention_last_run_at  timestamptz NULL;   -- advisory only; ledger is authoritative

-- ---------------------------------------------------------------------------
-- download tracking (best-effort writes, like token.last_used_at)
-- ---------------------------------------------------------------------------
ALTER TABLE asset
    ADD COLUMN last_downloaded_at  timestamptz NULL,
    ADD COLUMN download_count      bigint NOT NULL DEFAULT 0;

ALTER TABLE component
    ADD COLUMN last_downloaded_at  timestamptz NULL;       -- denormalized max over assets; for keep_n_most_downloaded

ALTER TABLE proxy_cached_version
    ADD COLUMN last_downloaded_at  timestamptz NULL;       -- proxy "not pulled in X days"

-- ---------------------------------------------------------------------------
-- retention_run: per-repo coordination ledger (no in-memory-only state)
--
-- One row per repository (created lazily/upserted the first time a repo with a
-- policy is seen). The worker claims a due row via
--   SELECT ... FOR UPDATE OF retention_run SKIP LOCKED
-- then marks it running with a lease (locked_until); a crashed instance's lease
-- expires and another instance reclaims it. `current_run_id` groups the audit
-- rows of the pass currently being applied.
-- ---------------------------------------------------------------------------
CREATE TABLE retention_run (
    repository_id     bigint PRIMARY KEY REFERENCES repository(id) ON DELETE CASCADE,
    state             text   NOT NULL DEFAULT 'idle' CHECK (state IN ('idle', 'running')),
    next_run_at       timestamptz NOT NULL DEFAULT now(),
    current_run_id    uuid   NULL,                  -- the run_id of the in-flight pass
    started_at        timestamptz NULL,
    finished_at       timestamptz NULL,
    locked_until      timestamptz NULL,             -- crash-safe lease, mirrors blob_outbox.locked_until
    last_error        text NULL,
    last_run_summary  jsonb NULL                    -- counts: evaluated/unlisted/deleted/blobs_enqueued
);

-- Worker claim query: due, idle (or lease-expired) repos with a policy attached.
CREATE INDEX retention_run_due_idx ON retention_run (next_run_at);

-- ---------------------------------------------------------------------------
-- retention_audit: append-only audit of every decision (applied or dry-run)
--
-- component_id FK is ON DELETE SET NULL so audit rows survive a hard delete of
-- the component they describe.
-- ---------------------------------------------------------------------------
CREATE TABLE retention_audit (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id         bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    run_id                uuid   NOT NULL,                    -- groups one evaluation pass
    rule_id               text   NOT NULL,
    action                text   NOT NULL CHECK (action IN ('unlist', 'hard_delete', 'skipped')),
    target_kind           text   NOT NULL CHECK (target_kind IN ('component', 'proxy_cached_version')),
    package_name          text   NOT NULL,
    version               text   NOT NULL,
    component_id          bigint NULL REFERENCES component(id) ON DELETE SET NULL,
    blob_sha256           text   NULL,                        -- the .nupkg blob touched
    ref_count_after       bigint NULL,                        -- observed after decrement
    blob_delete_enqueued  bool   NOT NULL DEFAULT false,
    dry_run               bool   NOT NULL DEFAULT false,
    reason                jsonb  NOT NULL,                     -- which criteria matched / protections applied
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX retention_audit_repo_run_idx ON retention_audit (repository_id, run_id);
CREATE INDEX retention_audit_created_idx  ON retention_audit (created_at);
