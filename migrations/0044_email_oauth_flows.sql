-- The OAuth authorizations of the email service's `smtp_oauth` transport
-- (#321) in progress: an administrator signs Forge in as the sender mailbox
-- at the mail server's authorization server, once.
--
-- * `code`: the authorization code flow with PKCE. `state` is the OAuth
--   `state` the callback echoes; the flow belongs to the administrator who
--   started it (`user_id`) and to their browser (`browser_binding`, a hash
--   of a cookie set when it started), and `pkce_verifier` goes to the token
--   endpoint with the code.
-- * `device`: the device authorization grant (RFC 8628). `device_code` is
--   polled at the token endpoint, no sooner than `next_poll_at`.
--
-- Rows are short-lived (`expires_at`) and deleted when the flow completes.
-- The verifier and the device code are secrets for minutes, like
-- `oidc_flow.pkce_verifier`.
CREATE TABLE email_oauth_flow (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            text NOT NULL CHECK (kind IN ('code', 'device')),
    user_id         bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    -- The issuer, client and mailbox the flow authorizes: a result for
    -- settings that changed meanwhile is dropped.
    issuer          text NOT NULL,
    client_id       text NOT NULL,
    username        text NOT NULL,
    state           text UNIQUE,
    browser_binding text,
    pkce_verifier   text,
    device_code     text,
    interval_secs   integer,
    next_poll_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    CHECK (kind <> 'code' OR (state IS NOT NULL AND pkce_verifier IS NOT NULL
                              AND browser_binding IS NOT NULL)),
    CHECK (kind <> 'device' OR (device_code IS NOT NULL AND interval_secs IS NOT NULL))
);

CREATE INDEX email_oauth_flow_expires_at_idx ON email_oauth_flow (expires_at);
