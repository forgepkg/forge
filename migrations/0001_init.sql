-- Forge's database schema: the 2.0.0 baseline.
--
-- 2.0.0 starts from an empty database. The migrations of 1.x and of the
-- builds before 2.0.0 were folded into this one file, and `forge_db::migrate`
-- refuses a database they created. A later schema change is a new migration
-- next to this one (`0002_<name>.sql`); this file is not edited again.
--
-- Sections, in order: repositories and their content; proxy caches; images
-- (Docker / OCI); raw files; retention; install-wide settings; secret
-- encryption; accounts and authentication; roles and grants; workload
-- identity and trusted publishing; email; imports.
--
-- Conventions:
--   * PKs are `id bigint GENERATED ALWAYS AS IDENTITY` unless noted.
--   * Timestamps are `timestamptz`; `created_at`/`updated_at` default to now().
--   * `updated_at` is maintained by the application (no update triggers).
--   * No in-memory-only state: every instance reads and coordinates through
--     these tables (row locks, leases, unique indexes), so a request or a
--     worker pass started on one instance can be finished by another.


-- ===========================================================================
-- Repositories and their content
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- repository
--
-- `config` holds the options of the repository's format and kind (Docker
-- host and tag rules, a group's writable member, prefer_hosted and reserved
-- prefixes, upload limits, raw options, ...). The proxy-only columns are NULL (or
-- their defaults) on other kinds; `allow_redeploy` is hosted-only.
-- ---------------------------------------------------------------------------
CREATE TABLE repository (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                    text NOT NULL UNIQUE,
    format                  text NOT NULL DEFAULT 'nuget',
    kind                    text NOT NULL CHECK (kind IN ('hosted', 'proxy', 'group')),
    -- Anonymous callers may read the repository, next to what the built-in
    -- `anonymous` role's grants allow.
    anonymous_read          bool NOT NULL DEFAULT false,
    online                  bool NOT NULL DEFAULT true,
    config                  jsonb NOT NULL DEFAULT '{}',
    -- proxy-only columns (nullable; used when kind = 'proxy')
    remote_url              text,
    package_delay_seconds   int NOT NULL DEFAULT 0,
    upstream_username       text,
    metadata_ttl_seconds    int,
    not_found_ttl_seconds   int,
    -- hosted-only column
    allow_redeploy          bool NOT NULL DEFAULT false,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    -- Retention policy (NULL => no retention) and when it last ran. The
    -- timestamp is advisory only: `retention_run` is authoritative.
    retention_policy        jsonb NULL,
    retention_last_run_at   timestamptz NULL,
    -- The proxy's upstream password: a self-describing envelope blob
    -- (format_version | algorithm | dek_version | nonce | ciphertext+tag),
    -- AAD bound to ('repository', 'upstream_password_enc', id). NULL = no
    -- password stored.
    upstream_password_enc   bytea NULL
);

-- Host-based routing: at most one docker repository per host name.
CREATE UNIQUE INDEX repository_docker_host_idx
    ON repository ((lower(config->>'host')))
    WHERE format = 'docker' AND config ? 'host';

-- ---------------------------------------------------------------------------
-- group_member
--
-- Once at least one member of a group is flagged `owner`, only flagged
-- members (and the hosted repositories inside a flagged nested group) own
-- package ids there: they alone hide proxy versions under prefer_hosted, and
-- they alone serve ids under reserved prefixes. In a group without a flagged
-- member every hosted member owns its ids.
-- ---------------------------------------------------------------------------
CREATE TABLE group_member (
    group_id   bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    member_id  bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    priority   int NOT NULL,
    owner      boolean NOT NULL DEFAULT false,
    PRIMARY KEY (group_id, member_id),
    UNIQUE (group_id, priority),
    CHECK (group_id <> member_id)
);

-- ---------------------------------------------------------------------------
-- blob: the content-addressed store (CAS), one row per stored object
--
-- Every row that names a blob (`asset`, `raw_file`, `oci_blob_link`,
-- `oci_manifest`, `oci_upload_part`) holds one `ref_count` reference, taken
-- with `blob_dao::commit_ingest_and_incref` / `commit_and_incref` and
-- released with `blob_dao::decref_and_maybe_enqueue_delete`.
--
-- A delete is split around an S3 call, so the row records an explicit
-- reservation (`state = 'deleting'`, `delete_*`) while no transaction is
-- held. Ingests register a lease (`blob_ingest`) before their S3 HEAD/PUT and
-- keep it until the reference-count transaction commits; a delete may only
-- reserve a zero-ref blob with no live ingest lease. This closes the
-- check/delete/revive race without holding a database transaction across
-- network I/O. `s3_key` is incarnation-qualified (opaque to PostgreSQL), so
-- a delayed DELETE from a fenced-out owner can only remove the old
-- incarnation, never a newly revived object.
-- ---------------------------------------------------------------------------
CREATE TABLE blob (
    sha256                 text PRIMARY KEY,
    size                   bigint NOT NULL,
    s3_key                 text NOT NULL,
    -- Moved only by `commit_*_and_incref` and
    -- `decref_and_maybe_enqueue_delete`. It may never go negative: a double
    -- decrement aborts its transaction instead of deleting an object another
    -- repository still references.
    ref_count              bigint NOT NULL DEFAULT 0,
    state                  text NOT NULL CHECK (state IN ('pending', 'committed', 'deleting')),
    created_at             timestamptz NOT NULL DEFAULT now(),
    delete_token           uuid,
    delete_previous_state  text,
    delete_started_at      timestamptz,
    CONSTRAINT blob_ref_count_nonnegative CHECK (ref_count >= 0),
    CONSTRAINT blob_delete_previous_state_check
        CHECK (delete_previous_state IS NULL OR delete_previous_state IN ('pending', 'committed')),
    CONSTRAINT blob_delete_reservation_check
        CHECK (
            (state = 'deleting'
                AND delete_token IS NOT NULL
                AND delete_previous_state IS NOT NULL
                AND delete_started_at IS NOT NULL)
            OR
            (state <> 'deleting'
                AND delete_token IS NULL
                AND delete_previous_state IS NULL
                AND delete_started_at IS NULL)
        )
);

-- Reconciler candidates. Both reconciler listings (`list_stale_pending`,
-- `list_stale_unreferenced`) only return zero-ref rows (`pending` and
-- `deleting` rows are zero-ref by construction) ordered by `created_at`, while
-- almost every row of a live registry is a referenced, committed blob. The
-- partial index keeps each pass proportional to the candidates rather than to
-- the whole CAS. Trade-off: `ref_count` becomes an indexed column, so
-- increments/decrements are no longer HOT updates; they happen once per
-- published/removed file, which is cheap compared to the per-minute scans
-- this avoids.
CREATE INDEX blob_zero_ref_created_at_idx
    ON blob (created_at)
    WHERE ref_count = 0;

-- An ingest's lease on a blob (see `blob` above).
CREATE TABLE blob_ingest (
    token        uuid PRIMARY KEY,
    blob_sha256  text NOT NULL REFERENCES blob(sha256) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX blob_ingest_live_idx ON blob_ingest (blob_sha256, expires_at);

-- ---------------------------------------------------------------------------
-- blob_outbox: deferred S3 deletes. Nothing deletes an S3 object directly;
-- every blob deletion (retention included) is a row here.
-- ---------------------------------------------------------------------------
CREATE TABLE blob_outbox (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    op            text NOT NULL CHECK (op IN ('delete_object')),
    sha256        text NOT NULL,
    s3_key        text NOT NULL,
    available_at  timestamptz NOT NULL DEFAULT now(),
    attempts      int NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    processed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Worker claim query: only unprocessed rows, better selectivity than a full-table index.
CREATE INDEX blob_outbox_claim_idx ON blob_outbox (available_at) WHERE processed_at IS NULL;

-- Per-blob "is a deferred delete still outstanding?" probes only ever look at
-- unprocessed rows: the supersede check in `reserve_delete` and the
-- `NOT EXISTS` in `list_stale_unreferenced` / the dangling-commit reservation.
CREATE INDEX blob_outbox_pending_sha256_idx
    ON blob_outbox (sha256)
    WHERE processed_at IS NULL;

-- Retention pruning of processed rows (`outbox_dao::prune_processed`) walks
-- the oldest processed rows first.
CREATE INDEX blob_outbox_processed_at_idx
    ON blob_outbox (processed_at)
    WHERE processed_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- component: a package version of a repository
--
-- `name` is the format's canonical package id, used for lookups and
-- uniqueness (NuGet lowercases it with full Unicode lowering, like
-- ToLowerInvariant: `Ünicode.Lib` is stored and looked up as `ünicode.lib`);
-- `original_id` keeps the id as the manifest gives it.
-- ---------------------------------------------------------------------------
CREATE TABLE component (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id       bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    name                text NOT NULL,
    original_id         text NOT NULL,
    version             text NOT NULL,
    version_original    text NOT NULL,
    listed              bool NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    -- Denormalized max over the assets' downloads; for keep_n_most_downloaded.
    last_downloaded_at  timestamptz NULL,
    -- The format's summary of the version's manifest (display metadata and
    -- dependency groups), computed once at publish so registration pages and
    -- search never fetch and parse manifests per request. A version without
    -- one (NULL) is summarized on first read and backfilled.
    manifest_summary    jsonb,
    -- Why the version should not be used any more (`npm deprecate`); NULL
    -- when it is not deprecated.
    deprecation         text,
    UNIQUE (repository_id, name, version)
);

CREATE INDEX component_repo_name_idx ON component (repository_id, name);

-- ---------------------------------------------------------------------------
-- asset: a file of a component, naming one CAS blob
-- ---------------------------------------------------------------------------
CREATE TABLE asset (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    component_id        bigint NOT NULL REFERENCES component(id) ON DELETE CASCADE,
    path                text NOT NULL,
    content_type        text NOT NULL,
    blob_sha256         text NOT NULL REFERENCES blob(sha256),
    size                bigint NOT NULL,
    sha512_base64       text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- Download tracking (best-effort writes, like token.last_used_at).
    last_downloaded_at  timestamptz NULL,
    download_count      bigint NOT NULL DEFAULT 0,
    UNIQUE (component_id, path)
);

-- Every `DELETE FROM blob` (the outbox / reconciler finalize step) checks the
-- `asset.blob_sha256` foreign key for referencing rows. Without an index that
-- check is a sequential scan of `asset` per deleted blob.
CREATE INDEX asset_blob_sha256_idx ON asset (blob_sha256);

-- ---------------------------------------------------------------------------
-- package_tag: a repository's tags of its packages (npm's dist-tags,
-- `latest`, `next`), naming versions
--
-- A hosted repository's are set by its clients; a proxy's are its
-- upstream's, as last read (served while the upstream is unreachable).
-- Retention never deletes a version a tag of a hosted repository names.
-- ---------------------------------------------------------------------------
CREATE TABLE package_tag (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    package       text        NOT NULL,
    tag           text        NOT NULL CHECK (tag <> ''),
    version       text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, package, tag)
);

CREATE INDEX package_tag_version_idx ON package_tag (repository_id, package, version);


-- ===========================================================================
-- Proxy caches
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- proxy_cached_version: what a proxy knows of an upstream package version
--
-- `name` is the canonical id (as in `component`). A row is enumerated (flat
-- index, registration, search) only once the upstream has `confirmed` the
-- version exists: an upstream version listing contained it, or it was
-- downloaded. The download singleflight creates a row for whatever version a
-- client asks for; such a row starts unconfirmed, so a request for a version
-- that does not exist (yet), or one whose fetch failed with a 5xx / timeout,
-- never shows up as a phantom version. The first confirmation also restarts
-- `first_seen_at`, so a row planted early by a request cannot shorten the
-- package-delay window of a later release.
--
-- The package-level negative-cache marker (`version = '*'`) is an unconfirmed
-- row: it is pruned with the other unconfirmed rows once its TTL lapsed, and
-- a listing or download of the package removes it.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_cached_version (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id         bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    name                  text NOT NULL,
    version               text NOT NULL,
    listed                bool NOT NULL DEFAULT true,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    downloaded            bool NOT NULL DEFAULT false,
    metadata_refreshed_at timestamptz,
    not_found             bool NOT NULL DEFAULT false,
    not_found_at          timestamptz,
    -- Proxy "not pulled in X days" (retention).
    last_downloaded_at    timestamptz NULL,
    confirmed             boolean NOT NULL DEFAULT true,
    -- The version disappeared from the upstream's listing (deleted upstream,
    -- e.g. a malicious release removed from nuget.org) and is no longer
    -- enumerated; a listing that names it again clears the flag. An upstream
    -- can serve a partial listing during an incident, so a version is retired
    -- only when it is still missing from a listing at least one metadata TTL
    -- after the first listing that left it out: `missing_since` records that
    -- first listing, and a listing that names the version clears it.
    upstream_missing      boolean NOT NULL DEFAULT false,
    missing_since         timestamptz NULL,
    -- The id's casing as the upstream registration names it, so proxy search
    -- answers `Newtonsoft.Json`, not `newtonsoft.json`. (A downloaded version
    -- knows its casing from the manifest: `component.original_id`.)
    original_id           text NULL,
    UNIQUE (repository_id, name, version)
);

-- ---------------------------------------------------------------------------
-- proxy_upstream_index: the upstream's service index, as last fetched
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_upstream_index (
    repository_id  bigint PRIMARY KEY REFERENCES repository(id) ON DELETE CASCADE,
    resources      jsonb NOT NULL,
    fetched_at     timestamptz NOT NULL DEFAULT now(),
    etag           text
);


-- ===========================================================================
-- Images (format `docker`): images, tags, blob links and upload sessions
--
-- An *image* is an OCI repository (`<name>` of `/v2/<name>/…`) inside a Forge
-- repository. Every byte (layers, configs, manifests, upload chunks) is a CAS
-- `blob`; the tables below only name blobs, and each row that names one holds
-- exactly one `blob.ref_count` reference, taken with
-- `blob_dao::commit_ingest_and_incref` / `commit_and_incref` in the
-- transaction that inserts the row and released with
-- `blob_dao::decref_and_maybe_enqueue_delete` in the one that deletes it:
--
--   * `oci_blob_link`   — a blob pushed, mounted or proxied into an image;
--   * `oci_manifest`    — a manifest's own bytes;
--   * `oci_upload_part` — a chunk of an upload session in progress.
--
-- A manifest does not hold references on its config and layers: they are
-- kept by the image's links, and the link sweeper drops only links that no
-- manifest of the same image names (`oci_manifest_ref`). A layer shared by
-- many images is one blob with one link (and one reference) per image.
--
-- `blob_dao`'s deletion guard counts the rows of all three tables (next to
-- `asset`), so a blob one of them names is never deleted even if its
-- `ref_count` drifted. None of them cascade from `blob`: the final
-- `DELETE FROM blob` fails while a row still names it.
-- ===========================================================================

CREATE TABLE oci_blob_link (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image         text        NOT NULL,
    -- `sha256:<hex>` or `sha512:<hex>`: the digest the blob was pushed as.
    digest        text        NOT NULL,
    blob_sha256   text        NOT NULL REFERENCES blob(sha256),
    size          bigint      NOT NULL CHECK (size >= 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Last pull/HEAD (bumped at most hourly); keeps a recently used link
    -- away from the sweeper while a manifest that names it is pushed.
    last_used_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, image, digest)
);

CREATE INDEX oci_blob_link_blob_idx ON oci_blob_link (blob_sha256);
CREATE INDEX oci_blob_link_sweep_idx ON oci_blob_link (last_used_at);

CREATE TABLE oci_manifest (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id   bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image           text        NOT NULL,
    digest          text        NOT NULL,
    blob_sha256     text        NOT NULL REFERENCES blob(sha256),
    media_type      text        NOT NULL,
    -- `artifactType`, else the config media type (what referrers report).
    artifact_type   text,
    -- The `subject` this manifest refers to (signatures, SBOMs, …).
    subject_digest  text,
    size            bigint      NOT NULL CHECK (size >= 0),
    -- Display data: platforms, layer total, annotations of a referrer.
    summary         jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- NULL while a tag points here; since when it has had none otherwise
    -- (retention's "untagged for X days").
    untagged_since  timestamptz,
    last_pulled_at  timestamptz,
    UNIQUE (repository_id, image, digest)
);

CREATE INDEX oci_manifest_blob_idx ON oci_manifest (blob_sha256);
CREATE INDEX oci_manifest_subject_idx
    ON oci_manifest (repository_id, image, subject_digest)
    WHERE subject_digest IS NOT NULL;

-- What a manifest names: its config and layers (`blob`) or, for an index,
-- its child manifests (`manifest`). Plain digests, no references held.
CREATE TABLE oci_manifest_ref (
    manifest_id bigint NOT NULL REFERENCES oci_manifest(id) ON DELETE CASCADE,
    kind        text   NOT NULL CHECK (kind IN ('blob', 'manifest')),
    digest      text   NOT NULL,
    PRIMARY KEY (manifest_id, kind, digest)
);

CREATE INDEX oci_manifest_ref_digest_idx ON oci_manifest_ref (digest, kind);

CREATE TABLE oci_tag (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image         text        NOT NULL,
    tag           text        NOT NULL,
    manifest_id   bigint      NOT NULL REFERENCES oci_manifest(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Proxy: when the tag was last confirmed against the upstream.
    checked_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, image, tag)
);

CREATE INDEX oci_tag_manifest_idx ON oci_tag (manifest_id);

-- A blob upload session (`POST /v2/<name>/blobs/uploads/`). Its chunks are
-- CAS blobs (`oci_upload_part`), so a session works across instances and a
-- single-chunk upload (what docker and containerd send) needs no second
-- copy: the chunk already is the blob.
CREATE TABLE oci_upload (
    id            uuid        PRIMARY KEY,
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    image         text        NOT NULL,
    size          bigint      NOT NULL DEFAULT 0 CHECK (size >= 0),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oci_upload_updated_idx ON oci_upload (updated_at);

CREATE TABLE oci_upload_part (
    upload_id    uuid   NOT NULL REFERENCES oci_upload(id) ON DELETE CASCADE,
    seq          int    NOT NULL,
    start_offset bigint NOT NULL CHECK (start_offset >= 0),
    size         bigint NOT NULL CHECK (size > 0),
    blob_sha256  text   NOT NULL REFERENCES blob(sha256),
    -- The chunk's SHA-512 (standard base64), so a one-chunk upload pushed
    -- as `sha512:` is verified without reading the chunk back.
    sha512_base64 text  NOT NULL,
    PRIMARY KEY (upload_id, seq)
);

CREATE INDEX oci_upload_part_blob_idx ON oci_upload_part (blob_sha256);


-- ===========================================================================
-- Raw files (format `raw`)
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- raw_file: a file of a raw (generic file) repository, like Nexus'
-- raw-hosted, raw-proxy and raw-group repositories
--
-- A file is one row naming one CAS `blob`: the row holds exactly one
-- `blob.ref_count` reference, taken with `blob_dao::commit_ingest_and_incref`
-- in the transaction that inserts it (or points it at new content) and
-- released with `blob_dao::decref_and_maybe_enqueue_delete` in the one that
-- deletes it (or replaces its content). The same content under several paths
-- or in several repositories is one blob.
--
-- `path` is the normalized path without a leading `/`
-- (`pdfium/7350/pdfium-linux-x64.tgz`): no empty, `.` or `..` segments, no
-- backslash and no control characters. It is compared in byte order
-- (`COLLATE "C"`), so a directory is a range of the unique index and a
-- listing walks it in the order it pages in.
--
-- Proxies keep what their upstream said about a cached file (its `ETag` and
-- `Last-Modified`, for a conditional re-validation) and when the copy was
-- last confirmed (`checked_at`; NULL makes it due).
-- ---------------------------------------------------------------------------
CREATE TABLE raw_file (
    id                     bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id          bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    path                   text        COLLATE "C" NOT NULL
                                       CHECK (path <> '' AND left(path, 1) <> '/' AND right(path, 1) <> '/'),
    blob_sha256            text        NOT NULL REFERENCES blob(sha256),
    size                   bigint      NOT NULL CHECK (size >= 0),
    content_type           text        NOT NULL,
    -- The content's other digests, for the `.sha512`, `.sha1` and `.md5`
    -- sidecars (the SHA-256 is the blob's).
    sha512_base64          text        NOT NULL,
    sha1                   text        NOT NULL,
    md5                    text        NOT NULL,
    -- When the path was first stored, and when its content last changed
    -- (`Last-Modified`).
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- Last download (bumped at most hourly), for retention.
    last_downloaded_at     timestamptz,
    upstream_etag          text,
    upstream_last_modified text,
    checked_at             timestamptz,
    UNIQUE (repository_id, path)
);

CREATE INDEX raw_file_blob_idx ON raw_file (blob_sha256);


-- ===========================================================================
-- Retention
-- ===========================================================================

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
-- retention_audit: append-only audit of every decision (applied or dry-run),
-- on package versions, image tags and manifests, and raw files
--
-- component_id FK is ON DELETE SET NULL so audit rows survive a hard delete of
-- the component they describe. Rows are pruned after the audit retention
-- period of the retention settings.
-- ---------------------------------------------------------------------------
CREATE TABLE retention_audit (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id         bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    run_id                uuid   NOT NULL,                    -- groups one evaluation pass
    rule_id               text   NOT NULL,
    action                text   NOT NULL
        CHECK (action IN ('unlist', 'hard_delete', 'skipped', 'delete_tag', 'delete_manifest')),
    target_kind           text   NOT NULL
        CHECK (target_kind IN ('component', 'proxy_cached_version', 'oci_tag', 'oci_manifest', 'raw_file')),
    package_name          text   NOT NULL,
    version               text   NOT NULL,
    component_id          bigint NULL REFERENCES component(id) ON DELETE SET NULL,
    blob_sha256           text   NULL,                        -- the blob touched
    ref_count_after       bigint NULL,                        -- observed after decrement
    blob_delete_enqueued  bool   NOT NULL DEFAULT false,
    dry_run               bool   NOT NULL DEFAULT false,
    reason                jsonb  NOT NULL,                     -- which criteria matched / protections applied
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX retention_audit_repo_run_idx ON retention_audit (repository_id, run_id);
CREATE INDEX retention_audit_created_idx  ON retention_audit (created_at);

-- Every component delete (a package DELETE, a redeploy, a retention hard
-- delete) sets `component_id` NULL in the rows naming it; without this index
-- that scanned the whole audit table while it held the component and blob
-- locks.
CREATE INDEX retention_audit_component_idx
    ON retention_audit (component_id)
    WHERE component_id IS NOT NULL;

-- The audit listing pages a repository's rows newest first by id.
CREATE INDEX retention_audit_repo_id_idx
    ON retention_audit (repository_id, id DESC);


-- ===========================================================================
-- Install-wide settings
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- forge_setting: a key/value store for install-wide settings and markers
-- (the authentication and retention settings, generated keys, the bootstrap
-- admin's and the realm import's one-shot markers, ...). Empty on a new
-- install.
-- ---------------------------------------------------------------------------
CREATE TABLE forge_setting (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);


-- ===========================================================================
-- Secret encryption at rest
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- encryption_key: the wrapped-key store of the double envelope encryption
--
-- Per-secret ciphertext is sealed by a DEK, DEKs are wrapped by a KEK, KEKs
-- are wrapped by the root key (KMS/HSM in prod, env/file in lower
-- environments). This table holds ONLY wrapped key material (KEK rows
-- wrapped by the root, DEK rows wrapped by a KEK). The root key is NEVER
-- stored here — only its id + version label are referenced on KEK rows, so
-- root rotation is "re-wrap every KEK whose label differs".
--
-- The secrets themselves live next to what they belong to, each an envelope
-- blob AAD-bound to its row: `repository.upstream_password_enc`,
-- `auth_realm.secrets_enc`, `email_settings.secrets_enc`,
-- `nexus_import.password_enc`, and the `sealed:` values of `forge_setting`.
-- ---------------------------------------------------------------------------
CREATE TABLE encryption_key (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- 'kek' = wrapped by the root, wraps DEKs; 'dek' = wrapped by a KEK,
    -- seals secret values. No 'root' layer: the root lives outside the DB.
    layer                text   NOT NULL CHECK (layer IN ('kek', 'dek')),
    -- Monotonic per layer+scope; envelope blobs reference the DEK version,
    -- DEK rows reference their wrapping KEK version.
    version              int    NOT NULL,
    -- AEAD of THIS key's own bytes when wrapping children / sealing data.
    algorithm            text   NOT NULL CHECK (algorithm IN
                              ('aes-256-gcm', 'xchacha20-poly1305')),
    -- The wrapped key material: this key's raw bytes, encrypted by its parent.
    --   kek rows: wrapped by the ROOT (KMS Encrypt output / dev-root envelope)
    --   dek rows: wrapped by a KEK (envelope produced with that KEK)
    wrapped_key          bytea  NOT NULL,
    -- Parent reference (which wrapping key produced wrapped_key):
    --   kek rows: root_key_id + root_key_version set, wrapping_kek_version NULL
    --   dek rows: wrapping_kek_version set, root fields NULL
    root_key_id          text   NULL,
    root_key_version     text   NULL,
    wrapping_kek_version int    NULL,
    -- Lifecycle:
    --   active   = used for NEW wraps/encrypts (exactly one per layer+scope)
    --   retiring = still used to DECRYPT/UNWRAP existing material, not for new
    --   revoked  = no longer used at all (kept for audit)
    state                text   NOT NULL DEFAULT 'active'
                              CHECK (state IN ('active', 'retiring', 'revoked')),
    -- Forward-looking multi-tenant / multi-purpose discriminator; Forge uses
    -- the single 'default' scope.
    scope                text   NOT NULL DEFAULT 'default',
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- When the key left 'active' (rotation/revocation).
    rotated_at           timestamptz NULL,
    -- Layer-shape integrity: a KEK row carries root references and never a
    -- wrapping KEK; a DEK row carries a wrapping KEK and never root references.
    CONSTRAINT encryption_key_parent_shape CHECK (
        (layer = 'kek' AND root_key_id IS NOT NULL AND root_key_version IS NOT NULL
                       AND wrapping_kek_version IS NULL)
     OR (layer = 'dek' AND wrapping_kek_version IS NOT NULL
                       AND root_key_id IS NULL AND root_key_version IS NULL)
    ),
    UNIQUE (layer, scope, version)
);

-- At most one ACTIVE key per layer+scope (partial unique index): the
-- rotation flip (retire old + insert new active in one transaction) can never
-- leave zero or two active keys visible.
CREATE UNIQUE INDEX encryption_key_one_active
    ON encryption_key (layer, scope)
    WHERE state = 'active';

-- "Give me the active / all-retiring keys of a layer+scope" lookups.
CREATE INDEX encryption_key_layer_scope_state
    ON encryption_key (layer, scope, state);


-- ===========================================================================
-- Accounts and authentication
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- auth_realm: a configured authentication mechanism, with an order
--
-- The local password, OIDC, credential forwarding and workload identity are
-- realm *rows*, edited in the admin UI — no redeploy to add/disable/reorder
-- one. The server's password chain and the OIDC login runtime are rebuilt
-- from this table (snapshot-cached, multi-instance safe: the table is the
-- authority and every instance re-reads it).
--
-- `config` is kind-specific jsonb, without secrets: a realm's secrets (OIDC
-- `client_secret`, credential-forwarding `key_pepper`) are one envelope blob
-- in `secrets_enc` (the JSON object of the realm's secret keys) sealed under
-- the active DEK, with the AAD bound to ('auth_realm', 'secrets_enc', <row
-- id>) so a blob copied to another row fails to decrypt. They are write-only
-- at the API layer and redacted from every response.
--
-- An `[oidc]` or `[auth.upstream_basic]` block of the configuration is
-- seeded into a realm row by the server at startup (the TOML is not visible
-- to SQL), tracked by `forge_setting` markers.
-- ---------------------------------------------------------------------------
CREATE TABLE auth_realm (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text NOT NULL
                CHECK (kind IN ('local', 'oidc', 'credential_forwarding',
                                'workload_identity')),
    -- Display name AND URL slug (lowercase, dns-label-ish).
    name        text NOT NULL UNIQUE
                CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    enabled     bool NOT NULL DEFAULT true,
    -- Order in which realms are tried/listed: LOWER tries first. UNIQUE so the
    -- order is total; DEFERRABLE so an admin reorder can swap priorities in one
    -- transaction without tripping over intermediate duplicates.
    priority    int  NOT NULL UNIQUE DEFERRABLE INITIALLY IMMEDIATE,
    config      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    secrets_enc bytea
);

-- One enabled workload-identity realm owns one normalized issuer.
--
-- Realm routing is issuer-based and terminal after a match. Allowing two
-- enabled rows for the same issuer would make behavior priority-dependent and
-- leave the later policy unreachable. The admin API provides a friendly
-- pre-check; this index closes the concurrent-write and direct-SQL race.
CREATE UNIQUE INDEX auth_realm_enabled_wif_issuer_uq
    ON auth_realm ((rtrim(btrim(config ->> 'issuer'), '/')))
    WHERE kind = 'workload_identity' AND enabled;

-- The built-in local-password realm. Always present; `enabled` + `priority`
-- control whether/where local sits in the order. (Deleting it is refused at
-- the API layer; disabling it is allowed — e.g. an OIDC-only deployment.)
INSERT INTO auth_realm (kind, name, enabled, priority, config)
VALUES ('local', 'local', true, 10, '{}'::jsonb);

-- ---------------------------------------------------------------------------
-- app_user
--
-- `username` is canonical: trimmed, Unicode NFC, lowercased (see
-- crates/db/src/username.rs); password lookup, the login lockout, the
-- validated-credential cache and credential forwarding all agree on it.
-- ---------------------------------------------------------------------------
CREATE TABLE app_user (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username               text NOT NULL UNIQUE,
    -- The local password's argon2 hash. NULL for accounts of another realm
    -- (they have no local password) and for an invited local account until
    -- the user sets their password.
    password_hash          text,
    active                 bool NOT NULL DEFAULT true,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- HOW this user last authenticated / was provisioned: 'local' = argon2
    -- password; 'upstream-basic' = credential forwarding; 'oidc' = OIDC
    -- login.
    auth_source            text NOT NULL DEFAULT 'local',
    -- Opaque upstream identifier when the source is not local. For
    -- upstream-basic this is usually just the username; kept for symmetry
    -- with external_identity's (issuer, subject) linkage. NULL for local users.
    external_subject       text,
    -- Timestamp of the last successful authentication via a NON-local source
    -- (upstream-basic / oidc). Audit-only: lets an operator see when a user
    -- last proved themselves against the upstream, distinct from the
    -- updated_at/last_used bookkeeping. NULL until the first non-local auth.
    last_auth_source_at    timestamptz,
    -- Which realm authenticated/provisioned this user last. Authorization
    -- never branches on it; credential forwarding signs in only the accounts
    -- of its own realm.
    realm_id               bigint REFERENCES auth_realm(id) ON DELETE SET NULL,
    -- The account's realm was deleted (set by the trigger below). An orphaned
    -- upstream account is never matched by any realm again: an administrator
    -- deletes it or keeps it for its tokens, or switches it to a local
    -- account.
    realm_orphaned         boolean NOT NULL DEFAULT false,
    -- An argon2id hash of the last password the upstream of a
    -- credential-forwarding realm accepted, kept when the realm opts in
    -- (`config.capture_password_hash`, off by default). Written only after
    -- the upstream definitively accepted the password, and only when a login
    -- actually asked the upstream (not on a validated-credential cache hit).
    -- It is NOT a local password: `password_hash` stays NULL, so the local
    -- realm keeps skipping the account and the upstream stays the authority.
    -- Its only use is an explicit administrator switch of the account to a
    -- local one, which moves it into `password_hash`
    -- (`POST /admin/users/{id}/convert-to-local`, or every account of a realm
    -- at once). Turning the realm option off deletes the hashes; deleting the
    -- realm keeps them on its orphaned accounts.
    captured_password_hash text,
    captured_password_at   timestamptz,
    -- Where invitations (and later notifications) go; the username by
    -- default, since a UPN is not always a mailbox.
    email                  text,
    -- A local account whose password the user has not set yet. It may lack a
    -- password only while this holds; accepting an invitation sets the
    -- password and clears it in one statement.
    invited                boolean NOT NULL DEFAULT false,
    -- Constrain auth_source to the known set so a typo can never silently
    -- disable the local-password invariant below.
    CONSTRAINT app_user_auth_source_check
        CHECK (auth_source IN ('local', 'upstream-basic', 'oidc')),
    -- A 'local' user MUST have a password hash (otherwise password auth would
    -- be meaningless), unless it is invited.
    CONSTRAINT app_user_local_password_hash_check
        CHECK (auth_source <> 'local' OR password_hash IS NOT NULL OR invited),
    -- Only a credential-forwarding account carries a captured hash, and never
    -- alongside a local password.
    CONSTRAINT app_user_captured_password_hash_check
        CHECK (
            captured_password_hash IS NULL
            OR (auth_source = 'upstream-basic' AND password_hash IS NULL
                AND captured_password_at IS NOT NULL)
        ),
    CONSTRAINT app_user_invited_check
        CHECK (NOT invited OR (auth_source = 'local' AND password_hash IS NULL))
);

-- Two accounts can never differ only in case or Unicode composition: a unique
-- index on the canonical form. NFC needs a UTF8 database; on any other
-- encoding the index covers lower() alone (and lower() is ASCII-only under a
-- "C" ctype).
DO $$
BEGIN
    EXECUTE format(
        'CREATE UNIQUE INDEX app_user_username_canonical_key ON app_user ((%s))',
        CASE WHEN current_setting('server_encoding') = 'UTF8'
             THEN 'lower(normalize(username, NFC))'
             ELSE 'lower(username)' END);
END
$$;

-- Deleting a realm orphans its accounts (`realm_orphaned`): a NULL realm is
-- never a wildcard that the next realm whose directory knows the same
-- username could adopt, with the account's roles and tokens.
CREATE FUNCTION app_user_orphan_on_realm_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE app_user SET realm_orphaned = true, updated_at = now()
    WHERE realm_id = OLD.id;
    RETURN OLD;
END
$$;

CREATE TRIGGER app_user_orphan_on_realm_delete
    BEFORE DELETE ON auth_realm
    FOR EACH ROW EXECUTE FUNCTION app_user_orphan_on_realm_delete();

-- ---------------------------------------------------------------------------
-- token: API tokens
--
-- Only the SHA-256 of the secret is stored (`token_hash`).
-- ---------------------------------------------------------------------------
CREATE TABLE token (
    id                               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                          bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    name                             text NOT NULL,
    token_hash                       text NOT NULL UNIQUE,
    expires_at                       timestamptz,
    revoked_at                       timestamptz,
    last_used_at                     timestamptz,
    created_at                       timestamptz NOT NULL DEFAULT now(),
    -- Narrows the token to a subset of its owner's rights; it can never widen
    -- them. Shape (validated in Rust as `forge_core::authz::TokenScope`):
    --   { "level": "read" | "write" | "delete",
    --     "repositories": [<repository.id>, ...], "admin": true }
    -- An omitted "level" keeps the owner's levels and an omitted
    -- "repositories" all repos the owner can touch; only `"admin": true`
    -- keeps the owner's `admin` role. NULL equals `{}`. A malformed scope
    -- fails closed (the token carries no usable grants). The scope is applied
    -- after the per-user effective-set cache lookup, so the owner's cached
    -- set stays shared across all of that user's tokens.
    scope                            jsonb NULL,
    -- Minted from a session that credential forwarding established. Such a
    -- token is only as trustworthy as the upstream verdict behind that
    -- session: forcing re-authentication (`POST /admin/users/{id}/reauth`)
    -- revokes it with the sessions and cached verdicts; tokens an
    -- administrator minted for the user stay.
    minted_with_forwarded_credential boolean NOT NULL DEFAULT false
);

-- ---------------------------------------------------------------------------
-- external_identity: maps an IdP identity (issuer, subject) -> app_user
--
-- The join key is `(issuer, subject)` — NEVER email (emails are reassignable;
-- `sub` is the stable, issuer-scoped identifier). One app_user may have
-- several external_identity rows (multi-IdP); the unique constraint prevents
-- duplicate links. The denormalized claim columns are for display/debugging
-- only and carry no authority.
-- ---------------------------------------------------------------------------
CREATE TABLE external_identity (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    issuer              text   NOT NULL,            -- OIDC `iss` (exact match)
    subject             text   NOT NULL,            -- OIDC `sub` (stable per-issuer)
    -- denormalized last-seen claims, for display/debugging only (not authority):
    preferred_username  text,
    email               text,
    display_name        text,
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE INDEX external_identity_user_id_idx ON external_identity (user_id);

-- ---------------------------------------------------------------------------
-- session: server-side login sessions (the authority; the cookie is a pointer)
--
-- `token_hash` = sha256(cookie_secret), like `token.token_hash`, so a DB read
-- yields no usable credential. The plaintext 256-bit base64url secret lives
-- only in the `forge_session` cookie; the DB never sees it. Validity:
--   revoked_at IS NULL AND now() < idle_expiry AND now() < absolute_expiry
-- `idle_expiry` is refreshed (throttled) on use; `absolute_expiry` is the hard
-- cap. `csrf_secret` is a per-session secret for double-submit CSRF on the
-- cookie-authenticated mutating endpoints.
-- ---------------------------------------------------------------------------
CREATE TABLE session (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id               bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    external_identity_id  bigint REFERENCES external_identity(id) ON DELETE SET NULL,
    token_hash            text NOT NULL UNIQUE,      -- sha256(cookie secret), like token.token_hash
    csrf_secret           text NOT NULL,             -- per-session double-submit CSRF secret
    user_agent_hash       text,                      -- optional binding to detect cookie theft
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),  -- idle-timeout clock
    idle_expiry           timestamptz NOT NULL,                -- last_seen_at + idle_ttl, refreshed on use
    absolute_expiry       timestamptz NOT NULL,                -- hard cap regardless of activity
    revoked_at            timestamptz
);

CREATE INDEX session_user_id_idx ON session (user_id);
CREATE INDEX session_idle_expiry_idx ON session (idle_expiry);

-- ---------------------------------------------------------------------------
-- oidc_flow: ephemeral OIDC auth-code-flow state, shared across instances
--
-- Any instance can complete a callback that a different instance started.
-- `state` is the OAuth `state` param the IdP echoes back, so it is the
-- natural text PK and cannot be hashed. Rows are single-use: the callback runs
--   DELETE FROM oidc_flow WHERE state = $1 AND expires_at > now()
--     RETURNING nonce, pkce_verifier, redirect_to
-- which is naturally race-safe (only one DELETE returns the row) and blocks
-- replay: an unknown/expired/replayed state returns no row -> reject.
-- `pkce_verifier` must be sent verbatim to the IdP, so it is stored as-is;
-- rows are short-lived (e.g. now()+10min) and reaped on expiry.
-- ---------------------------------------------------------------------------
CREATE TABLE oidc_flow (
    state          text PRIMARY KEY,            -- CSPRNG; also the OAuth `state` param
    nonce          text NOT NULL,               -- CSPRNG; checked against ID-token `nonce`
    pkce_verifier  text NOT NULL,               -- PKCE code_verifier (S256), sent verbatim to IdP
    redirect_to    text NOT NULL,               -- validated post-login relative path
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL         -- short, e.g. now()+10min
);

CREATE INDEX oidc_flow_expires_at_idx ON oidc_flow (expires_at);

-- ---------------------------------------------------------------------------
-- validated_credential: durable backing store for the validated-credential
-- cache of credential forwarding
--
-- One row records the verdict of forwarding a (provider, username, password)
-- triple upstream. The password is NEVER stored: `cred_hmac` is
-- HMAC-SHA256(secret_pepper, provider_id | username | password) (hex), so a
-- DB-only compromise cannot brute-force passwords without the server-held
-- pepper, and the same password for two users yields distinct hmacs (no
-- cross-user inference). The cache crate (L1 moka + optional L2 redis) sits
-- in front; a cold instance with no Redis reads this table and avoids
-- re-forwarding.
--
-- `verdict` is the boolean decision (true = credentials valid, false =
-- definitively rejected). Infrastructure errors / timeouts are FAIL-CLOSED and
-- are NEVER written here (no row => re-forward; never cache an "unavailable").
-- `expires_at` bounds the trust window (positive/negative TTLs from config).
--
-- The forwarding singleflight is a short-lived *lease* recorded on the row
-- itself, never a transaction (a pooled connection) held open across the
-- upstream HTTP call, and never pg_advisory_*:
--   * a short statement claims the row (sets claim_token / claimed_until) and
--     commits; the winner forwards upstream holding no connection;
--   * the winner writes its verdict in a second short transaction, conditioned
--     on still holding its claim_token (a revocation that deleted the row in the
--     meantime fences the stale result);
--   * peers that find a live claim poll the row (no lock held) until the verdict
--     lands or the lease lapses, then take over.
-- A row with a non-NULL claim_token is never a verdict on its own: claims are
-- written with an expired expires_at, so every verdict read (expires_at > now())
-- ignores them.
-- ---------------------------------------------------------------------------
CREATE TABLE validated_credential (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider_id   text NOT NULL,
    username      text NOT NULL,
    -- HMAC-SHA256(pepper, provider_id | username | password), hex-encoded.
    -- NEVER the plaintext password.
    cred_hmac     text NOT NULL,
    -- true = valid (positive cache), false = rejected (negative cache).
    verdict       bool NOT NULL,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    claim_token   uuid,
    claimed_until timestamptz,
    -- The cache lookup key, and the row the singleflight claims.
    UNIQUE (provider_id, username, cred_hmac)
);

-- Lookup path: the cache factory reads by the unique triple (covered by the
-- UNIQUE constraint's index). This index serves the background sweeper that
-- reaps expired rows (DELETE ... WHERE expires_at < now()).
CREATE INDEX validated_credential_expires_at_idx
    ON validated_credential (expires_at);

-- Revocation path: "force re-auth user X" / deactivate-user deletes every cached
-- verdict for a username across all providers.
CREATE INDEX validated_credential_username_idx
    ON validated_credential (provider_id, username);

-- Per-username revocation fence for validated credentials.
--
-- A credential fill takes a shared row lock here in the transaction that
-- writes its verdict. Revocation advances the generation (exclusive row lock)
-- and deletes verdicts in the same transaction. The lock row exists even when
-- no verdict row does, closing the gap where an older fill could otherwise
-- recreate authority after revocation. Rows are transient lock anchors: the
-- sweeper reaps a row whose username has no verdicts left.
CREATE TABLE validated_credential_tag (
    username   text PRIMARY KEY,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- auth_success: successful-authentication activity log of credential
-- forwarding
--
-- One row per (username, auth_method), where auth_method is the credential
-- provider id (e.g. "upstream-basic", "realm:corporate"). Written ONLY when an
-- upstream forward definitively ACCEPTS a credential — rejected attempts never
-- touch this table, so unauthenticated spray cannot grow it. A later success
-- through the same method refreshes last_success_at in place, and each
-- username keeps at most its 5 most recently used auth methods (older method
-- rows are pruned on write, see validated_credential_dao::record_auth_success).
--
-- Purpose: answer "which users still actively authenticate through which
-- upstream?" when deciding to cut an upstream (e.g. Nexus) off. Freshness is
-- bounded by the positive verdict TTL: a success is recorded when a credential
-- is actually re-validated upstream, not on every cache hit.
-- ---------------------------------------------------------------------------
CREATE TABLE auth_success (
    username         text NOT NULL,
    auth_method      text NOT NULL,
    first_success_at timestamptz NOT NULL DEFAULT now(),
    last_success_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (username, auth_method)
);

-- ---------------------------------------------------------------------------
-- login_known_network: where a username signed in from
--
-- A username being guessed from many networks is backed off, except from the
-- networks it signed in from within 30 days (the owner's office, VPN or CI),
-- on every instance and across restarts. Successes are recorded here (at
-- most hourly per network) and read only while the username is being backed
-- off. The username is stored as the SHA-256 of its canonical form, the
-- network as an IPv4 address or an IPv6 /64 prefix.
-- ---------------------------------------------------------------------------
CREATE TABLE login_known_network (
    username_sha256 bytea       NOT NULL,
    network         text        NOT NULL,
    last_success_at timestamptz NOT NULL,
    PRIMARY KEY (username_sha256, network)
);

CREATE INDEX login_known_network_last_success_idx
    ON login_known_network (last_success_at);

-- ---------------------------------------------------------------------------
-- user_invitation: an invited account's invitation
--
-- An administrator creates a local account without a password, and the user
-- sets their own from a link. One invitation at a time: sending or copying a
-- new link replaces it, so the old link stops working. Only the SHA-256 of
-- the token is stored. `accepted_at` records the acceptance; an accepted,
-- expired or replaced token signs nobody up.
-- ---------------------------------------------------------------------------
CREATE TABLE user_invitation (
    user_id     bigint PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash  text NOT NULL UNIQUE,
    -- The address it was sent (or made) for.
    email       text NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_by  bigint REFERENCES app_user(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz,
    accepted_at timestamptz
);

-- ---------------------------------------------------------------------------
-- cli_login: a command-line client's login, approved in the browser
-- (`npm login`)
--
-- The client is given a login URL to open and a done URL to poll. Both carry
-- a secret; only their SHA-256 is stored. Signing in approves the login
-- (`user_id`), and the next poll of the done URL mints the client's token and
-- deletes the row.
-- ---------------------------------------------------------------------------
CREATE TABLE cli_login (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_hash    text        NOT NULL UNIQUE,
    done_hash     text        NOT NULL UNIQUE,
    -- The client (the repository's format: `npm`) and where it signs in.
    client        text        NOT NULL,
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    -- What the client said about itself, shown on the approval page.
    hostname      text,
    client_ip     text,
    user_id       bigint      REFERENCES app_user(id) ON DELETE CASCADE,
    approved_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);

CREATE INDEX cli_login_expires_idx ON cli_login (expires_at);


-- ===========================================================================
-- Roles and grants (RBAC)
--
--   * A grant gives a role one of three ordered access levels on one
--     repository or on ANY repository (NULL `repository_id`), optionally
--     narrowed to the packages a content selector matches:
--     `read` < `write` < `delete`, each including the ones below it.
--   * Grants are purely ADDITIVE: "no access" is the absence of a grant
--     (fail-closed). There are no explicit-deny rows.
--   * Administration is no grant: it is membership in the built-in `admin`
--     role, which allows everything.
--   * The effective-set query is a single flat join (user_role ->
--     repository_privilege); the cache crate sits in front of the resolved
--     effective set with explicit cross-node invalidation.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- role: a named, assignable role. `builtin` roles cannot be deleted or
-- renamed (enforced in the admin API).
-- ---------------------------------------------------------------------------
CREATE TABLE role (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE,             -- url-safe slug, e.g. 'admin'
    description text NOT NULL DEFAULT '',
    builtin     boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- content_selector: a reusable named include/exclude glob set on the (lowercased)
-- package name. Empty `includes` ([]) means match-all; `excludes` subtract.
-- ---------------------------------------------------------------------------
CREATE TABLE content_selector (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    includes    jsonb NOT NULL DEFAULT '["*"]'::jsonb,
    excludes    jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- repository_privilege: the grant. "this role gets <level> on <repo|ANY>,
-- optionally scoped by a content selector". A NULL repository_id = ANY repo; a
-- NULL selector_id = not package-scoped.
-- ---------------------------------------------------------------------------
CREATE TABLE repository_privilege (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_id       bigint NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    repository_id bigint NULL REFERENCES repository(id) ON DELETE CASCADE,  -- NULL = ANY
    selector_id   bigint NULL REFERENCES content_selector(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    level         text NOT NULL CHECK (level IN ('read', 'write', 'delete'))
);

-- One grant per (role, repository | ANY, selector); NULLs are folded via
-- COALESCE so (role, ANY, no-selector) is a single row.
CREATE UNIQUE INDEX repository_privilege_uq
    ON repository_privilege (role_id, COALESCE(repository_id, 0), COALESCE(selector_id, 0));
CREATE INDEX repository_privilege_role_idx ON repository_privilege (role_id);
CREATE INDEX repository_privilege_repo_idx ON repository_privilege (repository_id);

-- ---------------------------------------------------------------------------
-- user_role: assignment of roles to users.
-- ---------------------------------------------------------------------------
CREATE TABLE user_role (
    user_id bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id bigint NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_role_role_idx ON user_role (role_id);

-- ---------------------------------------------------------------------------
-- The built-in roles. They exist on every install, and nobody holds one
-- until it is assigned: a new install denies everything until an
-- administrator grants (the server assigns `admin` to the bootstrap admin).
--   * admin         — allow-all: membership is the administration; no grants.
--   * authenticated — `write` on every repository.
--   * anonymous     — the role every anonymous principal is evaluated
--                     against; no grants until an administrator adds some.
--   * writer        — read and publish packages on every repository: `write`
--                     is the level every push checks, for a package or image
--                     name the repository does not have yet too. No `delete`
--                     (unlisting or deleting versions, deleting tags) and no
--                     administration, so a leaked CI token of a writer cannot
--                     remove published versions.
-- Like any role's, their grants can be edited.
-- ---------------------------------------------------------------------------
INSERT INTO role (name, description, builtin) VALUES
    ('admin',         'Full administrative access to all repositories and privilege management.', true),
    ('authenticated', 'Legacy convenience role: read/write on all repositories (slice-1 open access).', true),
    ('anonymous',     'Grants applied to unauthenticated (anonymous) callers.', true),
    ('writer',        'Read and publish packages on every repository; no administration.', true);

INSERT INTO repository_privilege (role_id, repository_id, level)
SELECT id, NULL, 'write' FROM role WHERE name IN ('authenticated', 'writer') ORDER BY id;


-- ===========================================================================
-- Workload identity and trusted publishing
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- trusted_publish_audit: immutable provenance of every package mutation a
-- workload-identity principal performs (`action`: a publish, an unlist, a
-- relist or a delete)
--
-- This is intentionally independent of repository/auth-realm foreign keys:
-- deleting operational configuration must not erase the historical statement
-- that a federated workload published a package. Raw OIDC claims and bearer
-- tokens are never stored; subject and jti are SHA-256 digests supplied only
-- after full token verification. `trusted_publisher_*` name the trusted
-- publisher that allowed the mutation, if one did.
-- ---------------------------------------------------------------------------
CREATE TABLE trusted_publish_audit (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id          bigint NOT NULL,
    repository_name        text NOT NULL CHECK (repository_name <> ''),
    package_name           text NOT NULL CHECK (package_name <> ''),
    package_version        text NOT NULL CHECK (package_version <> ''),
    realm_id               bigint NOT NULL,
    realm_name             text NOT NULL CHECK (realm_name <> ''),
    issuer                 text NOT NULL CHECK (issuer <> ''),
    role_id                bigint NOT NULL,
    role_name              text NOT NULL CHECK (role_name <> ''),
    subject_sha256         bytea NOT NULL CHECK (octet_length(subject_sha256) = 32),
    jti_sha256             bytea CHECK (jti_sha256 IS NULL OR octet_length(jti_sha256) = 32),
    token_issued_at        timestamptz NOT NULL,
    published_at           timestamptz NOT NULL DEFAULT now(),
    action                 text NOT NULL DEFAULT 'publish'
        CHECK (action IN ('publish', 'unlist', 'relist', 'delete')),
    trusted_publisher_id   bigint,
    trusted_publisher_name text,
    CONSTRAINT trusted_publish_audit_publisher_pair
        CHECK ((trusted_publisher_id IS NULL) = (trusted_publisher_name IS NULL))
);

CREATE INDEX trusted_publish_audit_repo_time_idx
    ON trusted_publish_audit (repository_id, published_at DESC, id DESC);
CREATE INDEX trusted_publish_audit_subject_time_idx
    ON trusted_publish_audit (subject_sha256, published_at DESC, id DESC);

-- Make the ledger insert-only at the database boundary. The application role
-- owns the schema in the default deployment, so a trigger is the reliable
-- guard against accidental UPDATE/DELETE code paths (including cascades, of
-- which this table deliberately has none).
CREATE FUNCTION reject_trusted_publish_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'trusted_publish_audit is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trusted_publish_audit_append_only
BEFORE UPDATE OR DELETE ON trusted_publish_audit
FOR EACH ROW EXECUTE FUNCTION reject_trusted_publish_audit_mutation();

-- ---------------------------------------------------------------------------
-- workload_api_key: short-lived workload API keys, the trusted-publishing
-- token exchange (`POST /api/v2/token`)
--
-- A CI job presents its OIDC token, which a `workload_identity` realm
-- validates and maps to a role exactly as on any other request, and receives
-- an opaque API key in exchange. A row holds the SHA-256 of that key and the
-- workload principal captured at exchange time, so the key authorizes (and is
-- audited) exactly as the token it replaced. Raw tokens, keys and claims are
-- never stored: the subject and `jti` are SHA-256 digests.
--
-- The unique `(issuer_sha256, jti_sha256)` index is the redemption ledger: a
-- CI token can be exchanged once. A row therefore outlives its key until the
-- CI token itself has expired, so the token cannot be redeemed again after
-- its key lapses; the auth reaper deletes it once both have passed.
--
-- No foreign keys: a key is only honoured while its realm is enabled with the
-- very configuration (`config_sha256`) it was issued under, which the server
-- checks on every request, so deleting or editing the realm (or deleting the
-- role) revokes its keys without touching this table.
-- ---------------------------------------------------------------------------
CREATE TABLE workload_api_key (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_sha256        bytea       NOT NULL UNIQUE CHECK (octet_length(key_sha256) = 32),
    realm_id          bigint      NOT NULL,
    role_id           bigint      NOT NULL,
    issuer_sha256     bytea       NOT NULL CHECK (octet_length(issuer_sha256) = 32),
    config_sha256     bytea       NOT NULL CHECK (octet_length(config_sha256) = 32),
    subject_sha256    bytea       NOT NULL CHECK (octet_length(subject_sha256) = 32),
    jti_sha256        bytea       NOT NULL CHECK (octet_length(jti_sha256) = 32),
    -- The exchanged CI token's `iat` (recorded with publish audit rows) and
    -- `exp` (how long the redemption must be remembered).
    token_issued_at   timestamptz NOT NULL,
    token_expires_at  timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX workload_api_key_redemption_idx
    ON workload_api_key (issuer_sha256, jti_sha256);

-- ---------------------------------------------------------------------------
-- trusted_publisher: narrowly scoped workload publication rights on one
-- repository
-- ---------------------------------------------------------------------------
CREATE TABLE trusted_publisher (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id   bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    realm_id        bigint NOT NULL REFERENCES auth_realm(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (name <> ''),
    description     text NOT NULL DEFAULT '',
    includes        jsonb NOT NULL DEFAULT '[]'::jsonb
                    CHECK (jsonb_typeof(includes) = 'array'),
    excludes        jsonb NOT NULL DEFAULT '[]'::jsonb
                    CHECK (jsonb_typeof(excludes) = 'array'),
    conditions      jsonb NOT NULL CHECK (jsonb_typeof(conditions) = 'array'),
    actions         text[] NOT NULL
                    CHECK ('write' = ANY(actions)
                       AND actions <@ ARRAY['write', 'delete']::text[]),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, name)
);

CREATE INDEX trusted_publisher_realm_idx ON trusted_publisher (realm_id);

-- A key keeps the publisher definitions that matched the verified CI token.
-- Publisher ids intentionally have no FK: deleting a publisher must leave a
-- stale snapshot that fails its next live-definition check.
CREATE TABLE workload_api_key_trusted_publisher (
    workload_api_key_id bigint NOT NULL REFERENCES workload_api_key(id) ON DELETE CASCADE,
    trusted_publisher_id bigint NOT NULL,
    definition_sha256 bytea NOT NULL CHECK (octet_length(definition_sha256) = 32),
    PRIMARY KEY (workload_api_key_id, trusted_publisher_id)
);


-- ===========================================================================
-- Email
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- email_settings: the outgoing email service, configured in the admin UI only
-- (no forge.toml section and no FORGE_* variable), so it can change while the
-- server runs and holds the same value on every instance
--
-- One row (`id = 1`). `config` is the non-secret document: the sender, the
-- invitation lifetime and the transport (`transport.kind`). The transport's
-- secrets (the SMTP password, OAuth client secrets and tokens) are sealed
-- into `secrets_enc` with the envelope service, bound to the row and to the
-- fields they belong to (the SMTP host and username), like
-- `auth_realm.secrets_enc`.
--
-- `last_failure*` keep the error of the last send that failed, and
-- `last_success_at` when the last send went through, for the settings page.
-- A settings change clears them.
-- ---------------------------------------------------------------------------
CREATE TABLE email_settings (
    id              smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled         boolean NOT NULL DEFAULT true,
    config          jsonb NOT NULL,
    secrets_enc     bytea,
    last_failure    text,
    last_failure_at timestamptz,
    last_success_at timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- email_oauth_flow: the OAuth authorizations of the `smtp_oauth` transport in
-- progress: an administrator signs Forge in as the sender mailbox at the mail
-- server's authorization server, once.
--
-- * `code`: the authorization code flow with PKCE. `state` is the OAuth
--   `state` the callback echoes; the flow belongs to the administrator who
--   started it (`user_id`) and to their browser (`browser_binding`, a hash
--   of a cookie set when it started), and `pkce_verifier` goes to the token
--   endpoint with the code.
-- * `device`: the device authorization grant (RFC 8628). `device_code` is
--   polled at the token endpoint, no sooner than `next_poll_at`.
--
-- Rows are short-lived (`expires_at`) and deleted when the flow completes.
-- The verifier and the device code are secrets for minutes, like
-- `oidc_flow.pkce_verifier`.
-- ---------------------------------------------------------------------------
CREATE TABLE email_oauth_flow (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            text NOT NULL CHECK (kind IN ('code', 'device')),
    user_id         bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    -- The issuer, client and mailbox the flow authorizes: a result for
    -- settings that changed meanwhile is dropped.
    issuer          text NOT NULL,
    client_id       text NOT NULL,
    username        text NOT NULL,
    state           text UNIQUE,
    browser_binding text,
    pkce_verifier   text,
    device_code     text,
    interval_secs   integer,
    next_poll_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    CHECK (kind <> 'code' OR (state IS NOT NULL AND pkce_verifier IS NOT NULL
                              AND browser_binding IS NOT NULL)),
    CHECK (kind <> 'device' OR (device_code IS NOT NULL AND interval_secs IS NOT NULL))
);

CREATE INDEX email_oauth_flow_expires_at_idx ON email_oauth_flow (expires_at);


-- ===========================================================================
-- Imports
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- nexus_import: an import of a Nexus hosted repository into a Forge hosted
-- repository
--
-- An import copies the content of one Nexus 3 hosted repository (NuGet,
-- Docker, Helm) into one Forge hosted repository of the same format, through
-- the normal hosted write path. It runs in two phases on one instance at a
-- time (the `run_id` / `locked_until` lease, like `retention_run`):
--
-- 1. `scan` walks Nexus' component listing (and, for Docker, its asset
--    listing, where manifests pushed by digest live), page by page. Each
--    page's components become `nexus_import_item` rows (`pending`) and the
--    page's `continuationToken` becomes `cursor` in the same transaction, so
--    a restarted scan resumes at the page it had not finished.
-- 2. `copy` works through the pending items. Each item ends `imported`,
--    `replaced`, `identical` (already in Forge with the same bytes),
--    `conflict` (different bytes under the same version), `failed`, or,
--    for a dry run, `planned`. A failed item can be put back to `pending`
--    and copied again on its own.
--
-- The Nexus password is sealed with the secret encryption (`password_enc`,
-- AAD-bound to the row and to the origins it is sent to) and deleted when
-- the import completes. A cancelled or failed import keeps it so it can be
-- resumed; deleting the import deletes it.
-- ---------------------------------------------------------------------------
CREATE TABLE nexus_import (
    id                bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id     bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    -- The Nexus server (`https://nexus.example.com`, a context path included)
    -- and the hosted repository there.
    base_url          text        NOT NULL,
    source_repository text        NOT NULL,
    -- Docker: the base URL of the Nexus repository's registry API (its
    -- connector port, or `<base_url>/repository/<name>`).
    registry_url      text,
    username          text,
    password_enc      bytea,
    on_conflict       text        NOT NULL DEFAULT 'skip'
        CHECK (on_conflict IN ('skip', 'overwrite', 'fail')),
    concurrency       int         NOT NULL DEFAULT 4 CHECK (concurrency BETWEEN 1 AND 16),
    -- Report what would be copied, and the conflicts, without writing.
    dry_run           boolean     NOT NULL DEFAULT false,
    state             text        NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'cancelled', 'failed', 'completed')),
    phase             text        NOT NULL DEFAULT 'scan' CHECK (phase IN ('scan', 'copy')),
    -- Scan position: which listing (`components`, then `assets` for Docker)
    -- and the continuation token of its next page (NULL: the first).
    scan_listing      text        NOT NULL DEFAULT 'components'
        CHECK (scan_listing IN ('components', 'assets')),
    cursor            text,
    cancel_requested  boolean     NOT NULL DEFAULT false,
    -- What the scan saw: every asset of the repository and their size.
    assets_seen       bigint      NOT NULL DEFAULT 0,
    bytes_seen        bigint      NOT NULL DEFAULT 0,
    -- The `Server` header of the Nexus status endpoint (`Nexus/3.70.1-02 (OSS)`).
    nexus_version     text,
    last_error        text,
    created_by        bigint      REFERENCES app_user(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    started_at        timestamptz,
    finished_at       timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    run_id            uuid,
    locked_until      timestamptz
);

-- One active import per repository.
CREATE UNIQUE INDEX nexus_import_active_idx
    ON nexus_import (repository_id) WHERE state IN ('queued', 'running');
CREATE INDEX nexus_import_repository_idx ON nexus_import (repository_id, id DESC);

CREATE TABLE nexus_import_item (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    import_id     bigint      NOT NULL REFERENCES nexus_import(id) ON DELETE CASCADE,
    -- `component`: a Nexus component (a package version, a Docker tag);
    -- `manifest`: a Docker manifest Nexus holds by digest only, copied when
    -- it is a referrer (a signature, an SBOM) of an imported image.
    kind          text        NOT NULL CHECK (kind IN ('component', 'manifest')),
    name          text        NOT NULL,
    version       text        NOT NULL,
    state         text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'imported', 'replaced', 'identical', 'conflict',
                         'failed', 'planned')),
    detail        text,
    -- Nexus' size of the item's asset, and the bytes copied for it.
    size          bigint,
    bytes_copied  bigint      NOT NULL DEFAULT 0,
    -- What Nexus recorded: when it was published, last downloaded, by whom.
    published_at  timestamptz,
    downloaded_at timestamptz,
    uploader      text,
    -- The item as Nexus listed it (assets, checksums, download URLs), so it
    -- can be copied again without scanning.
    source        jsonb       NOT NULL,
    attempts      int         NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (import_id, kind, name, version)
);

CREATE INDEX nexus_import_item_state_idx ON nexus_import_item (import_id, state, id);
