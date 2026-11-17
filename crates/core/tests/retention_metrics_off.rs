//! With the metrics off (the default), a retention run never reads the
//! repository's size: the read only feeds `forge.retention.freed` (#549).
//!
//! A test binary of its own: the metrics are a process's, and this one never
//! turns them on. `retention_metrics.rs` is the same run with them on.
//! Postgres only.

mod common;
mod retention_size;

use common::{pool, unique};
use retention_size::Statements;
use serde_json::json;

#[tokio::test]
async fn a_run_reads_no_repository_size_without_the_metrics() {
    let statements = Statements::install();
    assert!(!forge_telemetry::enabled(), "this binary has no metrics");
    let pool = pool().await;
    let repo = retention_size::seed(&pool, &format!("rsize-off-{}", unique()), json!({})).await;

    let mark = statements.len();
    let summary = retention_size::run(&pool, repo).await;

    // The run did its work, and the recorder saw it.
    assert_eq!(summary.deleted, 1);
    assert!(
        statements.len() > mark,
        "the run's statements were recorded"
    );
    assert_eq!(
        statements.size_reads_since(mark),
        Vec::<String>::new(),
        "no size read around a run without the metrics"
    );
}
