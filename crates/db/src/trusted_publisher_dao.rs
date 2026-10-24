//! Repository-scoped workload trusted publishers.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{PgConnection, PgPool, Row, Transaction};

use crate::model::Repository;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPublisherMatch {
    pub id: i64,
    pub definition_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPublisher {
    pub id: i64,
    pub repository_id: i64,
    pub realm_id: i64,
    pub name: String,
    pub description: String,
    pub includes: JsonValue,
    pub excludes: JsonValue,
    pub conditions: JsonValue,
    pub actions: Vec<String>,
    pub definition_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct NewTrustedPublisher<'a> {
    pub repository_id: i64,
    pub realm_id: i64,
    pub name: &'a str,
    pub description: &'a str,
    pub includes: &'a [String],
    pub excludes: &'a [String],
    pub conditions: &'a JsonValue,
    pub actions: &'a [String],
}

fn digest(publisher: &TrustedPublisher) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(
        serde_json::to_vec(&(
            publisher.id,
            publisher.repository_id,
            publisher.realm_id,
            &publisher.name,
            &publisher.description,
            &publisher.includes,
            &publisher.excludes,
            &publisher.conditions,
            &publisher.actions,
        ))
        .expect("trusted publisher definition serializes"),
    )
    .into()
}

fn from_row(row: &sqlx::postgres::PgRow) -> sqlx::Result<TrustedPublisher> {
    let mut publisher = TrustedPublisher {
        id: row.try_get("id")?,
        repository_id: row.try_get("repository_id")?,
        realm_id: row.try_get("realm_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        includes: row.try_get("includes")?,
        excludes: row.try_get("excludes")?,
        conditions: row.try_get("conditions")?,
        actions: row.try_get("actions")?,
        definition_sha256: [0; 32],
    };
    publisher.definition_sha256 = digest(&publisher);
    Ok(publisher)
}

pub async fn list_for_repository(
    pool: &PgPool,
    repository_id: i64,
) -> sqlx::Result<Vec<TrustedPublisher>> {
    let rows = sqlx::query(
        r#"
        SELECT id, repository_id, realm_id, name, description, includes,
               excludes, conditions, actions
        FROM trusted_publisher
        WHERE repository_id = $1
        ORDER BY name, id
        "#,
    )
    .bind(repository_id)
    .fetch_all(pool)
    .await?;
    rows.iter().map(from_row).collect()
}

pub async fn find_for_repository(
    pool: &PgPool,
    repository_id: i64,
    id: i64,
) -> sqlx::Result<Option<TrustedPublisher>> {
    let row = sqlx::query(
        r#"
        SELECT id, repository_id, realm_id, name, description, includes,
               excludes, conditions, actions
        FROM trusted_publisher
        WHERE repository_id = $1 AND id = $2
        "#,
    )
    .bind(repository_id)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn list_for_realm(
    pool: &PgPool,
    realm_id: i64,
) -> sqlx::Result<Vec<TrustedPublisher>> {
    let rows = sqlx::query(
        r#"
        SELECT id, repository_id, realm_id, name, description, includes,
               excludes, conditions, actions
        FROM trusted_publisher
        WHERE realm_id = $1
        ORDER BY id
        "#,
    )
    .bind(realm_id)
    .fetch_all(pool)
    .await?;
    rows.iter().map(from_row).collect()
}

pub async fn create(
    pool: &PgPool,
    new: NewTrustedPublisher<'_>,
) -> sqlx::Result<TrustedPublisher> {
    let row = sqlx::query(
        r#"
        INSERT INTO trusted_publisher (
            repository_id, realm_id, name, description, includes, excludes,
            conditions, actions
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, repository_id, realm_id, name, description, includes,
                  excludes, conditions, actions
        "#,
    )
    .bind(new.repository_id)
    .bind(new.realm_id)
    .bind(new.name)
    .bind(new.description)
    .bind(serde_json::to_value(new.includes).expect("includes serialize"))
    .bind(serde_json::to_value(new.excludes).expect("excludes serialize"))
    .bind(new.conditions)
    .bind(new.actions)
    .fetch_one(pool)
    .await?;
    from_row(&row)
}

pub async fn update(
    pool: &PgPool,
    repository_id: i64,
    id: i64,
    new: NewTrustedPublisher<'_>,
) -> sqlx::Result<Option<TrustedPublisher>> {
    let row = sqlx::query(
        r#"
        UPDATE trusted_publisher
        SET realm_id = $3, name = $4, description = $5, includes = $6,
            excludes = $7, conditions = $8, actions = $9, updated_at = now()
        WHERE repository_id = $1 AND id = $2
        RETURNING id, repository_id, realm_id, name, description, includes,
                  excludes, conditions, actions
        "#,
    )
    .bind(repository_id)
    .bind(id)
    .bind(new.realm_id)
    .bind(new.name)
    .bind(new.description)
    .bind(serde_json::to_value(new.includes).expect("includes serialize"))
    .bind(serde_json::to_value(new.excludes).expect("excludes serialize"))
    .bind(new.conditions)
    .bind(new.actions)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn delete(pool: &PgPool, repository_id: i64, id: i64) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "DELETE FROM trusted_publisher WHERE repository_id = $1 AND id = $2",
    )
    .bind(repository_id)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() != 0)
}

pub async fn find_live_matches(
    pool: &PgPool,
    matches: &[TrustedPublisherMatch],
    repository_id: i64,
) -> sqlx::Result<Vec<TrustedPublisher>> {
    if matches.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = matches.iter().map(|matched| matched.id).collect();
    let rows = sqlx::query(
        r#"
        SELECT id, repository_id, realm_id, name, description, includes,
               excludes, conditions, actions
        FROM trusted_publisher
        WHERE id = ANY($1) AND repository_id = $2
        "#,
    )
    .bind(&ids)
    .bind(repository_id)
    .fetch_all(pool)
    .await?;
    let wanted: std::collections::HashMap<_, _> = matches
        .iter()
        .map(|matched| (matched.id, matched.definition_sha256))
        .collect();
    rows.iter()
        .map(from_row)
        .collect::<sqlx::Result<Vec<_>>>()
        .map(|rows| {
            rows.into_iter()
                .filter(|publisher| {
                    wanted.get(&publisher.id) == Some(&publisher.definition_sha256)
                })
                .collect()
        })
}

pub async fn lock_matches(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    matches: &[TrustedPublisherMatch],
) -> sqlx::Result<bool> {
    Ok(lock_matches_with_rows(tx, matches).await?.1)
}

pub async fn lock_matches_with_rows(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    matches: &[TrustedPublisherMatch],
) -> sqlx::Result<(Vec<TrustedPublisher>, bool)> {
    if matches.is_empty() {
        return Ok((Vec::new(), true));
    }
    let ids: Vec<i64> = matches.iter().map(|matched| matched.id).collect();
    let rows = sqlx::query(
        r#"
        SELECT id, repository_id, realm_id, name, description, includes,
               excludes, conditions, actions
        FROM trusted_publisher
        WHERE id = ANY($1)
        ORDER BY id
        FOR SHARE
        "#,
    )
    .bind(&ids)
    .fetch_all(&mut **tx)
    .await?;
    let current = rows
        .iter()
        .map(from_row)
        .collect::<sqlx::Result<Vec<_>>>()?;
    let live: Vec<_> = current
        .into_iter()
        .filter(|publisher| {
            matches.iter().any(|matched| {
                publisher.id == matched.id
                    && publisher.definition_sha256 == matched.definition_sha256
            })
        })
        .collect();
    let all_live = live.len() == matches.len();
    Ok((live, all_live))
}

pub async fn load_key_matches(
    conn: &mut PgConnection,
    key_id: i64,
) -> sqlx::Result<Vec<TrustedPublisherMatch>> {
    let rows = sqlx::query(
        r#"
        SELECT trusted_publisher_id, definition_sha256
        FROM workload_api_key_trusted_publisher
        WHERE workload_api_key_id = $1
        ORDER BY trusted_publisher_id
        "#,
    )
    .bind(key_id)
    .fetch_all(conn)
    .await?;
    rows.iter()
        .map(|row| {
            let bytes: Vec<u8> = row.try_get("definition_sha256")?;
            Ok(TrustedPublisherMatch {
                id: row.try_get("trusted_publisher_id")?,
                definition_sha256: bytes.try_into().map_err(
                    |bytes: Vec<u8>| sqlx::Error::ColumnDecode {
                        index: "definition_sha256".into(),
                        source: format!("expected 32 bytes, got {}", bytes.len()).into(),
                    },
                )?,
            })
        })
        .collect()
}

pub async fn store_key_matches(
    conn: &mut PgConnection,
    key_id: i64,
    matches: &[TrustedPublisherMatch],
) -> sqlx::Result<()> {
    for matched in matches {
        sqlx::query(
            r#"
            INSERT INTO workload_api_key_trusted_publisher
                (workload_api_key_id, trusted_publisher_id, definition_sha256)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(key_id)
        .bind(matched.id)
        .bind(matched.definition_sha256.as_slice())
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

pub async fn hosted_repository(pool: &PgPool, repository_id: i64) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM repository WHERE id = $1 AND kind = 'hosted')",
    )
    .bind(repository_id)
    .fetch_one(pool)
    .await
}

pub fn validate_repository(repository: &Repository) -> bool {
    repository.kind() == crate::model::RepoKind::Hosted
}
