//! The login throttle's Postgres store of the networks a username signed in
//! from ([`forge_core::auth::PgKnownNetworks`]).

mod common;

use std::net::IpAddr;
use std::time::Duration;

use forge_core::auth::{KnownNetworkStore, PgKnownNetworks};

#[tokio::test]
async fn networks_are_recorded_read_back_and_pruned() {
    let pool = common::pool().await;
    let store = PgKnownNetworks::new(pool.clone());
    let user: [u8; 32] = *uuid::Uuid::new_v4()
        .as_bytes()
        .repeat(2)
        .first_chunk()
        .unwrap();
    let office: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: IpAddr = "2001:db8:1:2::".parse().unwrap();

    store.remember(user, office).await;
    store.remember(user, v6).await;
    store.remember(user, office).await;
    let mut recent = store.recent(user, Duration::from_secs(3600)).await;
    recent.sort();
    assert_eq!(recent.len(), 2);
    assert!(recent.iter().all(|(_, age)| *age < Duration::from_secs(60)));
    let nets: Vec<IpAddr> = recent.iter().map(|(net, _)| *net).collect();
    assert!(nets.contains(&office) && nets.contains(&v6));
    assert!(store
        .recent([0u8; 32], Duration::from_secs(3600))
        .await
        .is_empty());

    // Older than the window: not returned, and pruned.
    sqlx::query(
        "UPDATE login_known_network SET last_success_at = now() - interval '40 days' \
         WHERE username_sha256 = $1 AND network = $2",
    )
    .bind(&user[..])
    .bind(office.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let recent = store
        .recent(user, Duration::from_secs(30 * 24 * 3600))
        .await;
    assert_eq!(
        recent.iter().map(|(net, _)| *net).collect::<Vec<_>>(),
        vec![v6]
    );
    let pruned = forge_db::login_network_dao::prune(
        &pool,
        chrono::Utc::now() - chrono::Duration::days(30),
        1000,
    )
    .await
    .unwrap();
    assert!(pruned >= 1);
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM login_known_network WHERE username_sha256 = $1")
            .bind(&user[..])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(left, 1);
}
