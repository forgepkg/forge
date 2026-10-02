-- Lease-based credential-forwarding singleflight (review 2026-10-02, H1).
--
-- Until now a verdict-cache miss took a FOR UPDATE row lock on the
-- validated_credential anchor row and held that transaction -- a pooled
-- connection -- open across the upstream HTTP call. An upstream stall or a
-- password spray with rotating usernames could therefore drain the whole pool
-- and take every DB-backed request down with it.
--
-- The singleflight is now a short-lived *lease* recorded on the row itself:
--   * a short statement claims the row (sets claim_token / claimed_until) and
--     commits; the winner forwards upstream holding no connection;
--   * the winner writes its verdict in a second short transaction, conditioned
--     on still holding its claim_token (a revocation that deleted the row in the
--     meantime fences the stale result);
--   * peers that find a live claim poll the row (no lock held) until the verdict
--     lands or the lease lapses, then take over.
--
-- A row with a non-NULL claim_token is never a verdict on its own: claims are
-- written with an expired expires_at, so every verdict read (expires_at > now())
-- keeps ignoring them. Both columns are NULL on every existing row, which is
-- exactly "no claim", so this migration needs no backfill.
ALTER TABLE validated_credential
    ADD COLUMN claim_token   uuid,
    ADD COLUMN claimed_until timestamptz;
