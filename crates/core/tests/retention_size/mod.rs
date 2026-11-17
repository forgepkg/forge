//! What `retention_metrics.rs` and `retention_metrics_off.rs` share: a
//! repository a retention run deletes from, and the statements the run sent
//! to the database, to count its size reads (#549).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration as StdDuration;

use chrono::Duration;
use forge_core::repo::NoopCacheInvalidator;
use forge_core::retention::worker::{RetentionConfig, RetentionWorker};
use forge_core::Format;
use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::retention_dao::{self, RunSummary};
use serde_json::{json, Value};
use sqlx::PgPool;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

use crate::common::unique;

/// The size of each seeded version's asset.
pub const ASSET_SIZE: u64 = 100;

/// The statements sqlx ran, read from its `sqlx::query` events.
#[derive(Clone, Default)]
pub struct Statements(Arc<Mutex<Vec<String>>>);

impl Statements {
    /// Make a recorder the process's `tracing` subscriber (once per test
    /// binary) and return it.
    pub fn install() -> Statements {
        static INSTALLED: OnceLock<Statements> = OnceLock::new();
        INSTALLED
            .get_or_init(|| {
                let statements = Statements::default();
                let subscriber = tracing_subscriber::registry().with(
                    statements.clone().with_filter(
                        tracing_subscriber::filter::Targets::new()
                            .with_target("sqlx::query", tracing::Level::DEBUG),
                    ),
                );
                tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");
                statements
            })
            .clone()
    }

    /// How many statements ran so far.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// The repository size reads among the statements that ran since
    /// `mark` (an earlier [`Self::len`]): the statements that select one
    /// `SUM` of sizes, as `repository_size` of packages, images and files
    /// each does (evaluation sums per version, in a subquery).
    pub fn size_reads_since(&self, mark: usize) -> Vec<String> {
        self.0.lock().unwrap()[mark..]
            .iter()
            .filter(|sql| sql.trim_start().starts_with("SELECT COALESCE(SUM("))
            .cloned()
            .collect()
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Statements {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        /// The statement: `db.statement` when sqlx shortened it into
        /// `summary`, `summary` otherwise.
        #[derive(Default)]
        struct Sql {
            summary: String,
            statement: String,
        }
        impl tracing::field::Visit for Sql {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "summary" => self.summary = value.to_string(),
                    "db.statement" => self.statement = value.to_string(),
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.record_str(field, &format!("{value:?}"));
            }
        }
        let mut sql = Sql::default();
        event.record(&mut sql);
        self.0
            .lock()
            .unwrap()
            .push(format!("{} {}", sql.summary, sql.statement));
    }
}

/// A hosted NuGet repository `name` with two versions of `lib`, 60 days old,
/// under a policy that deletes versions older than 30 days but keeps the
/// newest one, with `extra` merged into the policy. Returns its id.
pub async fn seed(pool: &PgPool, name: &str, extra: Value) -> i64 {
    let repo = repository_dao::insert_repository(pool, NewRepository::hosted(name.to_string()))
        .await
        .unwrap();
    for version in ["1.0.0", "2.0.0"] {
        // A blob of its own per version, unlike any other test binary's.
        let sha = format!("{:064x}", (0x549_u128 << 64) | u128::from(rand_tag()));
        blob_dao::upsert_pending(pool, &sha, ASSET_SIZE as i64, &format!("k/{sha}"))
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
        tx.commit().await.unwrap();
        let component = component_dao::insert_component(
            pool,
            NewComponent {
                repository_id: repo.id,
                name: "lib".into(),
                original_id: "lib".into(),
                version: version.into(),
                version_original: version.into(),
                listed: true,
            },
        )
        .await
        .unwrap();
        asset_dao::insert_asset(
            pool,
            NewAsset {
                component_id: component.id,
                path: format!("lib.{version}.nupkg"),
                content_type: "application/octet-stream".into(),
                blob_sha256: sha,
                size: ASSET_SIZE as i64,
                sha512_base64: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE component SET created_at = now() - interval '60 days' WHERE id = $1")
            .bind(component.id)
            .execute(pool)
            .await
            .unwrap();
    }
    let mut policy = json!({
        "version": 1,
        "rules": [{
            "id": "old",
            "action": "hard_delete",
            "criteria": { "keep_last_n": 1, "older_than_days": 30 }
        }]
    });
    policy
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    retention_dao::write_policy(pool, repo.id, Some(&policy))
        .await
        .unwrap();
    repo.id
}

/// A blob tag no other process of this test run uses.
fn rand_tag() -> u64 {
    (u64::from(std::process::id()) << 32) | unique()
}

/// Run the repository's retention once, as the worker's tick does.
pub async fn run(pool: &PgPool, repository_id: i64) -> RunSummary {
    let format =
        forge_core::format::SpecFormat::new(Arc::new(forge_format_nuget::Nuget::default()));
    let worker = RetentionWorker::new(
        pool.clone(),
        Arc::new(format) as Arc<dyn Format>,
        Arc::new(NoopCacheInvalidator),
        RetentionConfig {
            poll_interval: StdDuration::from_millis(10),
            default_run_interval: Duration::seconds(1),
            lease: Duration::seconds(60),
            delete_grace: Duration::seconds(60),
        },
    );
    worker
        .tick_repo(repository_id)
        .await
        .expect("the run")
        .expect("a claimed repository")
}
