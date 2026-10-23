//! Data access for `email_settings` (migration 0041): the one row of the
//! email service's settings, written in the admin UI only.
//!
//! `config` is the non-secret document. The transport's secrets are sealed
//! into `secrets_enc` and merged back by [`crate::secret_dao`]
//! ([`crate::secret_dao::store_email_settings`],
//! [`crate::secret_dao::email_config`]); the functions here store and read
//! the columns as they are.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool};

/// The `email_settings` row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct EmailSettingsRow {
    /// Whether Forge sends email; `false` keeps the settings without using
    /// them.
    pub enabled: bool,
    /// The non-secret settings (the transport's secrets stripped while they
    /// are sealed).
    pub config: JsonValue,
    /// The sealed transport secrets, or `None` (no secret, or no secret
    /// encryption: then they are in `config`).
    pub secrets_enc: Option<Vec<u8>>,
    /// The error of the last send that failed, since the last settings
    /// change.
    pub last_failure: Option<String>,
    /// When it failed.
    pub last_failure_at: Option<DateTime<Utc>>,
    /// When the last send went through, since the last settings change.
    pub last_success_at: Option<DateTime<Utc>>,
    /// When the settings last changed.
    pub updated_at: DateTime<Utc>,
}

/// The settings row, or `None` when email was never configured (or was
/// deleted).
pub async fn get<'e, E>(executor: E) -> sqlx::Result<Option<EmailSettingsRow>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(
        r#"
        SELECT enabled, config, secrets_enc, last_failure, last_failure_at,
               last_success_at, updated_at
        FROM email_settings
        WHERE id = 1
        "#,
    )
    .fetch_optional(executor)
    .await
}

/// Store the settings (insert or replace the row), clearing the last send's
/// outcome, and return the stored row.
pub async fn put<'e, E>(
    executor: E,
    enabled: bool,
    config: &JsonValue,
    secrets_enc: Option<&[u8]>,
) -> sqlx::Result<EmailSettingsRow>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(
        r#"
        INSERT INTO email_settings (id, enabled, config, secrets_enc)
        VALUES (1, $1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET
            enabled         = EXCLUDED.enabled,
            config          = EXCLUDED.config,
            secrets_enc     = EXCLUDED.secrets_enc,
            last_failure    = NULL,
            last_failure_at = NULL,
            last_success_at = NULL,
            updated_at      = now()
        RETURNING enabled, config, secrets_enc, last_failure, last_failure_at,
                  last_success_at, updated_at
        "#,
    )
    .bind(enabled)
    .bind(config)
    .bind(secrets_enc)
    .fetch_one(executor)
    .await
}

/// [`put`] as a compare-and-set: the row is written only while it is still
/// `expected` (its config, secrets and `updated_at`), so a concurrent admin
/// edit is never undone. Keeps the last send's outcome. `None` when the row
/// changed or is gone.
pub async fn put_if_unchanged<'e, E>(
    executor: E,
    expected: &EmailSettingsRow,
    config: &JsonValue,
    secrets_enc: Option<&[u8]>,
) -> sqlx::Result<Option<EmailSettingsRow>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as(
        r#"
        UPDATE email_settings
        SET config = $1, secrets_enc = $2
        WHERE id = 1
          AND config = $3
          AND secrets_enc IS NOT DISTINCT FROM $4
          AND updated_at = $5
        RETURNING enabled, config, secrets_enc, last_failure, last_failure_at,
                  last_success_at, updated_at
        "#,
    )
    .bind(config)
    .bind(secrets_enc)
    .bind(&expected.config)
    .bind(expected.secrets_enc.as_deref())
    .bind(expected.updated_at)
    .fetch_optional(executor)
    .await
}

/// Delete the settings: Forge sends no email. Returns whether there were any.
pub async fn delete(pool: &PgPool) -> sqlx::Result<bool> {
    let res = sqlx::query("DELETE FROM email_settings WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Record a send that failed with `error` (shown on the settings page).
pub async fn record_failure(pool: &PgPool, error: &str) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE email_settings SET last_failure = $1, last_failure_at = now() WHERE id = 1",
    )
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a send that went through.
pub async fn record_success(pool: &PgPool) -> sqlx::Result<()> {
    sqlx::query("UPDATE email_settings SET last_success_at = now() WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(())
}
