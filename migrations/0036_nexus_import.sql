-- ---------------------------------------------------------------------------
-- 0036: import a Nexus hosted repository into a Forge hosted repository
-- ---------------------------------------------------------------------------
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
-- The Nexus credentials are sealed with the secret encryption
-- (`password_enc`, AAD-bound to the row and to the origins they are sent
-- to) or, without `[crypto]`, kept in `password`, and are deleted when the
-- import completes. A cancelled or failed import keeps them so it can be
-- resumed; deleting the import deletes them.

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
    password          text,
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
