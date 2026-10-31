-- ---------------------------------------------------------------------------
-- device_authorization: the device authorization grant (RFC 8628, #649)
--
-- A command-line client (`forge login`, `docker-credential-forge`,
-- `nuget-plugin-forge`) asks for a token at `POST /auth/device/code` and is
-- given two codes: the `device_code` it polls `POST /auth/device/token`
-- with, of which only the SHA-256 is stored, and the short `user_code` its
-- user types on the web UI's `/device` page. A signed-in user approves or
-- denies the request there (`user_id`, `status`); the client's next poll
-- after an approval mints an API token of that user and marks the row
-- `collected`, so a second poll gets `expired_token`. Unlike `cli_login`
-- (`npm login`) a request belongs to the Forge host, not to a repository.
--
-- The auth reaper deletes the rows past `expires_at`.
-- ---------------------------------------------------------------------------
CREATE TABLE device_authorization (
    id               bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_code_hash text        NOT NULL UNIQUE,
    -- Eight letters of the code alphabet, without the hyphen it is shown
    -- with (`BCDFGHJK` for `BCDF-GHJK`).
    user_code        text        NOT NULL UNIQUE,
    -- One of the Forge helpers' fixed client ids.
    client_id        text        NOT NULL,
    -- The requested scope, normalized (`write repository:npm-all`); NULL:
    -- the token carries the approving user's rights.
    scope            text,
    client_ip        text,
    status           text        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'collected')),
    user_id          bigint      REFERENCES app_user(id) ON DELETE CASCADE,
    -- The polling interval the client must keep (seconds); `slow_down`
    -- raises it by five.
    interval_seconds integer     NOT NULL CHECK (interval_seconds > 0),
    last_polled_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    decided_at       timestamptz,
    expires_at       timestamptz NOT NULL
);

CREATE INDEX device_authorization_expires_idx ON device_authorization (expires_at);
