-- Outgoing email (#319): the email service, configured in the admin UI only
-- (no forge.toml section and no FORGE_* variable), so it can change while the
-- server runs and holds the same value on every instance.
--
-- One row (`id = 1`). `config` is the non-secret document: the sender, the
-- invitation lifetime and the transport (`transport.kind`: `smtp`, more
-- kinds later). The transport's secrets (the SMTP password) are sealed into
-- `secrets_enc` with the envelope service and stripped from `config`, bound
-- to the row and to the fields they belong to (the SMTP host and username),
-- like `auth_realm.secrets_enc`; without secret encryption they stay in
-- `config`, and the backfill seals them once encryption is enabled.
--
-- `last_failure*` keep the error of the last send that failed, and
-- `last_success_at` when the last send went through, for the settings page.
-- A settings change clears them.
CREATE TABLE email_settings (
    id              smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled         boolean NOT NULL DEFAULT true,
    config          jsonb NOT NULL,
    secrets_enc     bytea,
    last_failure    text,
    last_failure_at timestamptz,
    last_success_at timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
