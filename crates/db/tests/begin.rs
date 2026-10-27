//! `forge_db::begin` is safe against cancellation (#570): a caller dropped
//! while Postgres's answer to its `BEGIN` is on the way leaves no connection
//! inside a transaction, as sqlx's own `Pool::begin` does.
//!
//! A relay between the pool and Postgres holds the answer back, so the caller
//! is dropped exactly then. Requires Docker (see `common`).

mod common;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};

/// A TCP relay to Postgres that notes a `BEGIN` going up, and holds back
/// what comes down while `hold` is set.
struct Relay {
    hold: watch::Sender<bool>,
    begun: Notify,
}

/// Start a relay to the database at `url`; returns the URL through it.
async fn relay(url: &str) -> (String, Arc<Relay>) {
    let mut url = url::Url::parse(url).expect("database url");
    let upstream = format!(
        "{}:{}",
        url.host_str().expect("database host"),
        url.port().unwrap_or(5432)
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    url.set_host(Some("127.0.0.1")).unwrap();
    url.set_port(Some(listener.local_addr().unwrap().port()))
        .unwrap();
    // In plain text, for the relay to see the `BEGIN`.
    url.query_pairs_mut().append_pair("sslmode", "disable");
    let relay = Arc::new(Relay {
        hold: watch::channel(false).0,
        begun: Notify::new(),
    });
    let shared = relay.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let server = TcpStream::connect(&upstream).await.unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            let up = shared.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; 8192];
                while let Ok(n @ 1..) = client_read.read(&mut buf).await {
                    if buf[..n].windows(5).any(|w| w == b"BEGIN") {
                        up.begun.notify_one();
                    }
                    if server_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            let mut hold = shared.hold.subscribe();
            tokio::spawn(async move {
                let mut buf = vec![0; 8192];
                while let Ok(n @ 1..) = server_read.read(&mut buf).await {
                    if hold.wait_for(|held| !held).await.is_err()
                        || client_write.write_all(&buf[..n]).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (url.to_string(), relay)
}

/// Whether a caller of `begin`, dropped while the answer to its `BEGIN` is
/// held back, leaves the pool's connection inside a transaction once it is
/// back in the pool.
async fn leaves_a_transaction<F, Fut>(begin: F) -> bool
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = sqlx::Result<Transaction<'static, Postgres>>> + Send + 'static,
{
    let (url, relay) = relay(&common::url().await).await;
    // One connection, handed out without a test query: `begin` sends its
    // `BEGIN` at once.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect(&url)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    // The pool pings a connection given back before it is idle again.
    tokio::time::timeout(Duration::from_secs(10), async {
        while pool.num_idle() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the connection is idle");

    relay.hold.send_replace(true);
    let caller = tokio::spawn(begin(pool.clone()));
    tokio::time::timeout(Duration::from_secs(10), relay.begun.notified())
        .await
        .expect("the BEGIN goes up");
    caller.abort();
    let _ = caller.await;
    relay.hold.send_replace(false);

    // Once the connection is back in the pool, look at it from another.
    let _back = tokio::time::timeout(Duration::from_secs(10), pool.acquire())
        .await
        .expect("the connection comes back")
        .unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM pg_stat_activity WHERE pid = $1")
        .bind(pid)
        .fetch_one(&common::pool().await)
        .await
        .unwrap();
    state == "idle in transaction"
}

#[tokio::test]
async fn a_caller_dropped_mid_begin_leaves_no_transaction_open() {
    // sqlx's own `Pool::begin` does: the caller is dropped in that window.
    // (Should a sqlx release fix it, `forge_db::begin` may go.)
    assert!(
        leaves_a_transaction(|pool| async move { pool.begin().await }).await,
        "sqlx's Pool::begin left no transaction open"
    );
    assert!(!leaves_a_transaction(|pool| async move { forge_db::begin(&pool).await }).await);
}
