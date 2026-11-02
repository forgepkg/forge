-- ---------------------------------------------------------------------------
-- proxy_document: a document a proxy's format fetched from its upstream
-- (an npm packument, a NuGet registration page or flat-container listing, a
-- service index), kept for every instance and across restarts
--
-- Until now each instance kept these in its own memory only (Redis is a
-- trust boundary), so every instance fetched every document itself, a
-- restart forgot them all, and large packuments evicted each other long
-- before their metadata TTL ended. Postgres is trusted and the CAS is
-- content-addressed, so keeping them here does not widen what a Redis
-- writer can reach.
--
-- One row per repository, URL and `Accept` header (`key` is the hex SHA-256
-- of `"{url}\n{accept}"`, or of `url` without one: npm's abbreviated and full
-- packuments share a URL), naming the CAS blob of the document's bytes. The
-- row holds exactly one `blob.ref_count` reference, taken with
-- `blob_dao::commit_ingest_and_incref` in the transaction that inserts it (or
-- points it at new content) and released with
-- `blob_dao::decref_and_maybe_enqueue_delete` in the one that deletes it (or
-- replaces its content).
--
-- `fetched_at` is when the upstream last sent the document or confirmed it
-- (`304 Not Modified`); `etag` and `last_modified` are the validators it gave
-- it, sent with the conditional request that revalidates it. `remote_url` and
-- `repository_updated_at` are the repository's as the document was fetched
-- or confirmed: it is served without asking the upstream only within the
-- metadata TTL of `fetched_at` and while the repository still has both (an
-- edit of the repository has it revalidated first), and its validators are
-- sent only while the repository still has that `remote_url`. Repointing a
-- proxy, invalidating its cache and deleting it delete its documents.
--
-- `used_at` is when the document was last read from here (written at most
-- hourly): the reconciler removes the documents nobody read for a week.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_document (
    id                    bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id         bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    key                   text        NOT NULL,
    url                   text        NOT NULL,
    accept                text,
    blob_sha256           text        NOT NULL REFERENCES blob(sha256),
    size                  bigint      NOT NULL CHECK (size >= 0),
    -- The origins the document's absolute URLs name, read once when it was
    -- fetched: the later requests of the same conversation may reach them.
    named_origins         text[]      NOT NULL DEFAULT '{}',
    etag                  text,
    last_modified         text,
    remote_url            text        NOT NULL,
    repository_updated_at timestamptz NOT NULL,
    fetched_at            timestamptz NOT NULL DEFAULT now(),
    used_at               timestamptz NOT NULL DEFAULT now(),
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, key)
);

-- The deletion guard (`blob_dao`) counts the rows naming a blob.
CREATE INDEX proxy_document_blob_idx ON proxy_document (blob_sha256);

-- The reconciler's pass over the documents nobody read for a while.
CREATE INDEX proxy_document_used_at_idx ON proxy_document (used_at);
