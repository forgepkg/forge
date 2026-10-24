-- ---------------------------------------------------------------------------
-- 0047: package tags, deprecations and command-line logins (#41, npm)
-- ---------------------------------------------------------------------------
--
-- What a format plugin may keep about a package beyond its versions: the
-- tags that name versions (npm's dist-tags, `latest`, `next`), and whether
-- a version is deprecated. And the logins a command-line client asks the
-- user to approve in the browser (`npm login`).

-- A repository's tags of its packages. A hosted repository's are set by its
-- clients; a proxy's are its upstream's, as last read (served while the
-- upstream is unreachable). Retention never deletes a version a tag of a
-- hosted repository names.
CREATE TABLE package_tag (
    repository_id bigint      NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
    package       text        NOT NULL,
    tag           text        NOT NULL CHECK (tag <> ''),
    version       text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, package, tag)
);

CREATE INDEX package_tag_version_idx ON package_tag (repository_id, package, version);

-- Why a version should not be used any more (`npm deprecate`); NULL when it
-- is not deprecated.
ALTER TABLE component ADD COLUMN deprecation text;

-- A command-line client's login, approved in the browser: the client is
-- given a login URL to open and a done URL to poll. Both carry a secret;
-- only their SHA-256 is stored. Signing in approves the login (`user_id`),
-- and the next poll of the done URL mints the client's token and deletes
-- the row.
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
