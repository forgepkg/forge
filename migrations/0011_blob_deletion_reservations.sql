-- Coordinate CAS ingests with deferred blob deletion.
--
-- A delete is split around an S3 call, so the database row records an explicit
-- reservation while no transaction is held.  New ingests register a lease
-- before their S3 HEAD/PUT and keep it until the reference-count transaction
-- commits.  A delete may only reserve a zero-ref blob with no live ingest
-- lease.  This closes the check/delete/revive race without holding a database
-- transaction across network I/O.
-- New CAS rows also use an incarnation-qualified S3 key. The key stays opaque
-- to PostgreSQL, but this ensures a delayed DELETE from a fenced-out owner can
-- only remove the old incarnation, never a newly revived object.
--
-- DEPLOYMENT BOUNDARY: binaries from before this migration neither acquire
-- blob_ingest leases nor write incarnation-qualified keys. Drain all old
-- writers and GC workers, including in-flight or ambiguous S3 DELETEs, before
-- applying this migration. Do not run old and new instances concurrently. See
-- DEVELOPMENT.md for the required quiescence/clean-namespace procedure.

ALTER TABLE blob
    DROP CONSTRAINT blob_state_check;

ALTER TABLE blob
    ADD CONSTRAINT blob_state_check
        CHECK (state IN ('pending', 'committed', 'deleting')),
    ADD COLUMN delete_token uuid,
    ADD COLUMN delete_previous_state text,
    ADD COLUMN delete_started_at timestamptz,
    ADD CONSTRAINT blob_delete_previous_state_check
        CHECK (delete_previous_state IS NULL OR delete_previous_state IN ('pending', 'committed')),
    ADD CONSTRAINT blob_delete_reservation_check
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
        );

CREATE TABLE blob_ingest (
    token        uuid PRIMARY KEY,
    blob_sha256  text NOT NULL REFERENCES blob(sha256) ON DELETE CASCADE,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX blob_ingest_live_idx ON blob_ingest (blob_sha256, expires_at);
