//! With the metrics off (the default), the connection pool emits no event
//! per acquire and no layer waits for one (#549): `telemetry.rs` has the
//! acquire times with the metrics on.
//!
//! A test binary of its own: the metrics are a process's, and this one never
//! turns them on. Requires Docker (Postgres via the shared harness), or
//! `FORGE_TEST_DATABASE_URL`.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use forge_server::telemetry::ACQUIRE_TARGET;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, Registry};

/// Counts the events of [`ACQUIRE_TARGET`].
#[derive(Clone, Default)]
struct AcquireEvents(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> Layer<S> for AcquireEvents {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == ACQUIRE_TARGET {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[tokio::test]
async fn the_pool_emits_no_acquire_event_without_the_metrics() {
    assert!(!forge_telemetry::enabled(), "this binary has no metrics");
    // What `main` would add to the subscriber: nothing.
    assert!(forge_server::telemetry::acquire_times::<Registry>().is_none());

    // A subscriber that wants every acquire event, down to TRACE: a pool
    // that emitted one would reach it.
    let events = AcquireEvents::default();
    let subscriber = tracing_subscriber::registry().with(
        events.clone().with_filter(
            tracing_subscriber::filter::Targets::new()
                .with_target(ACQUIRE_TARGET, tracing::Level::TRACE),
        ),
    );
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    // The server's pool, as `main` builds it.
    let pool = common::sized_pool(2, Duration::from_secs(10)).await;
    for _ in 0..5 {
        let mut conn = pool.acquire().await.expect("acquire");
        sqlx::query("SELECT 1")
            .execute(&mut *conn)
            .await
            .expect("query");
    }
    assert_eq!(
        events.0.load(Ordering::SeqCst),
        0,
        "no acquire event with the metrics off"
    );

    // The counter does see such events: a pool told to emit them, as the
    // server's is with the metrics on, emits one per acquire.
    let options: sqlx::postgres::PgConnectOptions = pool.connect_options().as_ref().clone();
    let loud = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_time_level(log::LevelFilter::Trace)
        .connect_with(options)
        .await
        .expect("connect");
    for _ in 0..3 {
        loud.acquire().await.expect("acquire");
    }
    // The connect acquires too.
    assert!(events.0.load(Ordering::SeqCst) >= 3);
}
