-- ---------------------------------------------------------------------------
-- proxy_package_listing: when a proxy's upstream last listed the versions of
-- a package (#836)
--
-- The web UI's package page answers from what Forge holds, without asking
-- the upstream on the request: it says how old that is ("cached 3 h ago"),
-- and starts a refresh off the request once the listing is past the
-- repository's metadata TTL, or older than the repository's last edit or
-- cache invalidation (`repository.updated_at`). The "listing refreshed"
-- marker the read path keeps for the TTL lives in the cache, which may be
-- per instance and forgets on restart, so the time is kept here.
--
-- One row per repository and package id as the proxy stores it (lowercased),
-- written each time the upstream answers the package's version listing.
-- Repointing the proxy to another upstream deletes its rows; deleting the
-- repository deletes them with it.
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_package_listing (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    name          text        NOT NULL,
    listed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, name)
);
