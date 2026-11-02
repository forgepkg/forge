-- ---------------------------------------------------------------------------
-- package_delay_release: versions of a proxy repository an administrator
-- released from the package delay early (#184).
--
-- A released version is served at once, while the package's other versions
-- keep their delay. The row is keyed by the package id as the proxy stores it
-- (lowercased) and the normalized version, not by a `proxy_cached_version`
-- row: a version the upstream has not listed yet can be released too, and the
-- release applies once the proxy sees it. Retention pruning a cached-version
-- row therefore never takes a release with it.
--
-- `reason` and `released_by` (the administrator's audit label at the time)
-- are what the action is audited by. Repointing the proxy to another upstream
-- deletes its releases: they were decisions about the previous upstream's
-- packages.
-- ---------------------------------------------------------------------------
CREATE TABLE package_delay_release (
    repository_id bigint NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    name          text NOT NULL,
    version       text NOT NULL,
    reason        text NOT NULL CHECK (btrim(reason) <> ''),
    released_by   text NOT NULL,
    released_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, name, version)
);
