-- Inviting users by email (#322): an administrator creates a local account
-- without a password, and the user sets their own from a link.
--
-- * `app_user.email`: where invitations (and later notifications) go; the
--   username by default, since a UPN is not always a mailbox.
-- * `app_user.invited`: a local account whose password the user has not set
--   yet. It may lack a password only while this holds; accepting an
--   invitation sets the password and clears it in one statement.
-- * `user_invitation`: the account's invitation, one at a time: sending or
--   copying a new link replaces it, so the old link stops working. Only the
--   SHA-256 of the token is stored. `accepted_at` records the acceptance; an
--   accepted, expired or replaced token signs nobody up.
ALTER TABLE app_user ADD COLUMN email text;
ALTER TABLE app_user ADD COLUMN invited boolean NOT NULL DEFAULT false;

ALTER TABLE app_user DROP CONSTRAINT app_user_local_password_hash_check;
ALTER TABLE app_user
    ADD CONSTRAINT app_user_local_password_hash_check
    CHECK (auth_source <> 'local' OR password_hash IS NOT NULL OR invited);
ALTER TABLE app_user
    ADD CONSTRAINT app_user_invited_check
    CHECK (NOT invited OR (auth_source = 'local' AND password_hash IS NULL));

CREATE TABLE user_invitation (
    user_id     bigint PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash  text NOT NULL UNIQUE,
    -- The address it was sent (or made) for.
    email       text NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_by  bigint REFERENCES app_user(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz,
    accepted_at timestamptz
);
