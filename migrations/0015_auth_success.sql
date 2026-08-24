-- Successful-authentication activity log (slice 12.3 follow-up).
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
CREATE TABLE auth_success (
    username         text NOT NULL,
    auth_method      text NOT NULL,
    first_success_at timestamptz NOT NULL DEFAULT now(),
    last_success_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (username, auth_method)
);
