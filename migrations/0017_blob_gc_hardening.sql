-- Blob GC hardening (production-readiness review 2026-10-02: B1, M19).
--
-- 1. `blob.ref_count` may never go negative.
--
--    The reference count is only ever moved by `commit_*_and_incref` and
--    `decref_and_maybe_enqueue_delete`. A negative value can only come from a
--    double decrement (B1: two unlocked admin hard deletes of the same
--    version), and by the time it is observable the shared object has already
--    been queued for deletion while another repository still references it.
--    With this constraint any such drift aborts the decrementing transaction
--    instead of silently driving the count further down.
--
--    The constraint is added NOT VALID and then validated in the same
--    migration *only when no row already violates it*:
--      * A fresh 0.1.0 install (and any clean upgrade) has no drift, so it ends
--        up with a fully validated constraint. `blob` holds one row per unique
--        stored file, so the validation scan is cheap.
--      * A pre-release install that already hit B1 holds committed blobs
--        whose `ref_count` is below the number of assets naming them (often
--        0 with one reference left, sometimes negative). Those are repaired
--        first: `ref_count` is raised to the true asset count, which can only
--        prevent deletions, never cause one. A WARNING reports how many, as
--        their S3 objects may already be gone (restore them from the backup).
--      * Should any row still be negative after that (a non-committed blob),
--        failing the migration would stop the server from booting over state
--        it cannot repair by itself. Instead the constraint stays NOT VALID —
--        it is still enforced for every row inserted or updated from now on,
--        so a further decrement of a drifted row fails rather than deleting —
--        and a WARNING names the remedy. After repairing the rows, run
--        `ALTER TABLE blob VALIDATE CONSTRAINT blob_ref_count_nonnegative;`.
--        VALIDATE only takes a SHARE UPDATE EXCLUSIVE lock, so it can run
--        online.
ALTER TABLE blob
    ADD CONSTRAINT blob_ref_count_nonnegative CHECK (ref_count >= 0) NOT VALID;

DO $$
DECLARE
    repaired bigint;
    drifted bigint;
BEGIN
    WITH actual AS (
        SELECT b.sha256, count(a.id) AS n
        FROM blob b
        LEFT JOIN asset a ON a.blob_sha256 = b.sha256
        WHERE b.state = 'committed'
        GROUP BY b.sha256
    )
    UPDATE blob
    SET ref_count = actual.n
    FROM actual
    WHERE blob.sha256 = actual.sha256 AND blob.ref_count < actual.n;
    GET DIAGNOSTICS repaired = ROW_COUNT;
    IF repaired > 0 THEN
        RAISE WARNING 'repaired % blob ref_count(s) below their asset references (pre-0.1.0 double-decrement drift); check that their S3 objects still exist and restore any missing ones from the backup',
            repaired;
    END IF;

    SELECT count(*) INTO drifted FROM blob WHERE ref_count < 0;
    IF drifted = 0 THEN
        ALTER TABLE blob VALIDATE CONSTRAINT blob_ref_count_nonnegative;
    ELSE
        RAISE WARNING 'blob_ref_count_nonnegative left NOT VALID: % blob row(s) have a negative ref_count (double-decrement drift); repair them, then run ALTER TABLE blob VALIDATE CONSTRAINT blob_ref_count_nonnegative',
            drifted;
    END IF;
END
$$;

-- 2. Indexes on the GC hot paths.
--
--    These are plain (non-CONCURRENT) builds because migrations run in a
--    transaction; each briefly blocks writes to its table while it builds,
--    which is negligible at the table sizes of a 0.1.x install.

-- Every `DELETE FROM blob` (the outbox / reconciler finalize step) checks the
-- `asset.blob_sha256` foreign key for referencing rows. Without an index that
-- check is a sequential scan of `asset` per deleted blob.
CREATE INDEX asset_blob_sha256_idx ON asset (blob_sha256);

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
