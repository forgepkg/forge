//! The geolocation databases of the traffic statistics, downloaded from
//! MaxMind: GeoLite2-Country and GeoLite2-ASN, with the account ID and
//! license key an administrator sets (Admin → Traffic → Settings).
//!
//! * The license key is sealed in `forge_setting`
//!   ([`forge_db::secret_dao::MAXMIND_LICENSE_KEY_SETTING`]); the account ID
//!   and the downloads' outcome are kept next to it ([`STATE_SETTING`]).
//! * One instance downloads (the others see its claim on the state) and puts
//!   the databases in the bucket ([`GeoKind::key`]); every instance loads them
//!   from there ([`forge_traffic::geo::refresh`]).
//! * A download stores its databases only while the state is still the one
//!   it claimed ([`Claim`]): credentials forgotten (**Turn off**) or set
//!   again while it ran discard it ([`update`]).
//! * The databases are downloaded again every [`REFRESH_AFTER`] (MaxMind
//!   publishes GeoLite2 twice a week, and its license asks for current
//!   databases), at most every [`RETRY_AFTER`] after a failure.

use std::io::Read;

use chrono::{DateTime, Duration, Utc};
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_db::authz_dao;
use forge_db::secret_dao::{self, MAXMIND_LICENSE_KEY_SETTING};
use forge_traffic::GeoKind;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// The `forge_setting` key of the [`MaxmindState`].
pub const STATE_SETTING: &str = "traffic_maxmind";

/// The editions downloaded, by the database they fill.
pub const EDITIONS: [(GeoKind, &str); 2] = [
    (GeoKind::Country, "GeoLite2-Country"),
    (GeoKind::Asn, "GeoLite2-ASN"),
];

/// How old the databases may get before they are downloaded again.
pub const REFRESH_AFTER: Duration = Duration::days(3);
/// How long after an attempt the next one waits: a failure is not retried
/// every hour (MaxMind limits the downloads a day).
pub const RETRY_AFTER: Duration = Duration::hours(6);
/// The largest archive accepted, and the largest database in it.
const MAX_ARCHIVE_BYTES: usize = 256 << 20;
const MAX_DATABASE_BYTES: u64 = 512 << 20;
/// A download's deadline.
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// The longest error kept.
const MAX_ERROR_BYTES: usize = 500;

/// The MaxMind account and how its downloads went, kept in `forge_setting`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MaxmindState {
    /// The MaxMind account ID; `None` without credentials.
    pub account_id: Option<String>,
    /// When an instance last started a download.
    pub last_attempt: Option<DateTime<Utc>>,
    /// When the databases were last downloaded and stored.
    pub last_success: Option<DateTime<Utc>>,
    /// Why the last download failed, until one succeeds.
    pub last_error: Option<String>,
}

/// The stored state and its raw value (for a compare-and-swap).
pub async fn read_state(pool: &sqlx::PgPool) -> sqlx::Result<(MaxmindState, Option<String>)> {
    let raw = authz_dao::get_setting(pool, STATE_SETTING).await?;
    let state = match &raw {
        None => MaxmindState::default(),
        Some(raw) => serde_json::from_str(raw).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
    };
    Ok((state, raw))
}

fn encode(state: &MaxmindState) -> sqlx::Result<String> {
    serde_json::to_string(state).map_err(|e| sqlx::Error::Encode(Box::new(e)))
}

async fn write_state(pool: &sqlx::PgPool, state: &MaxmindState) -> sqlx::Result<()> {
    authz_dao::set_setting(pool, STATE_SETTING, &encode(state)?).await
}

/// A claimed download attempt: the state as [`claim`] stored it. Its
/// `last_attempt` tells it from every other state the row held or will hold,
/// the same account's set again included ([`set_credentials`] clears it), so
/// a swap from it succeeds only while no instance forgot the credentials,
/// set them again or claimed a later attempt.
#[derive(Debug, Clone)]
pub struct Claim {
    state: MaxmindState,
    raw: String,
}

/// The stored license key, opened; `None` when there is none.
pub async fn license_key(state: &AppState) -> anyhow::Result<Option<PlaintextSecret>> {
    let Some(value) = authz_dao::get_setting(&state.pool, MAXMIND_LICENSE_KEY_SETTING).await?
    else {
        return Ok(None);
    };
    Ok(Some(
        secret_dao::open_secret_setting(&state.envelope, MAXMIND_LICENSE_KEY_SETTING, &value)
            .await?,
    ))
}

/// Whether a license key is stored.
pub async fn has_license_key(pool: &sqlx::PgPool) -> sqlx::Result<bool> {
    Ok(authz_dao::get_setting(pool, MAXMIND_LICENSE_KEY_SETTING)
        .await?
        .is_some())
}

/// Store the account ID and, when given, the license key (sealed). The
/// downloads' outcome is cleared: the next check downloads with these.
pub async fn set_credentials(
    state: &AppState,
    account_id: &str,
    license_key: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(key) = license_key {
        let current = authz_dao::get_setting(&state.pool, MAXMIND_LICENSE_KEY_SETTING).await?;
        let stored = secret_dao::store_secret_setting(
            &state.pool,
            &state.envelope,
            MAXMIND_LICENSE_KEY_SETTING,
            &PlaintextSecret::from(key.to_string()),
            current.as_deref(),
        )
        .await?;
        if stored.is_none() {
            anyhow::bail!("the license key changed while it was being saved; try again");
        }
    }
    write_state(
        &state.pool,
        &MaxmindState {
            account_id: Some(account_id.to_string()),
            ..MaxmindState::default()
        },
    )
    .await?;
    Ok(())
}

/// Forget the credentials and delete the databases from the bucket (every
/// instance unloads them with its next refresh). A download in flight, on
/// any instance, stores nothing afterwards: its claim on the state is gone
/// ([`update`]). One that is storing its databases right now holds the
/// state's row, so the state is deleted, and the databases after it, once it
/// is done.
pub async fn forget(state: &AppState) -> anyhow::Result<()> {
    authz_dao::delete_setting(&state.pool, MAXMIND_LICENSE_KEY_SETTING).await?;
    authz_dao::delete_setting(&state.pool, STATE_SETTING).await?;
    for kind in GeoKind::ALL {
        state.traffic.objects.delete(kind.key()).await?;
        state.traffic.geo.unload(kind);
    }
    Ok(())
}

/// The HTTP client for MaxMind: bounded time, redirects followed (the
/// download answers with one to its storage; the credentials are not sent
/// along to another host).
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent(concat!("forge/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("the MaxMind HTTP client builds")
}

fn clip(mut text: String) -> String {
    if text.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// The `.mmdb` file in the `.tar.gz` archive `archive`.
fn extract(archive: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries()? {
        let entry = entry?;
        let is_database = entry.path()?.extension().is_some_and(|ext| ext == "mmdb");
        if !is_database {
            continue;
        }
        let size = entry.header().size()?;
        if size > MAX_DATABASE_BYTES {
            anyhow::bail!("the database in the archive is larger than {MAX_DATABASE_BYTES} bytes");
        }
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        entry.take(MAX_DATABASE_BYTES).read_to_end(&mut bytes)?;
        return Ok(bytes);
    }
    anyhow::bail!("the archive holds no .mmdb file")
}

/// Download `edition` with the account `account_id` and `license_key`.
async fn download(
    http: &reqwest::Client,
    base: &str,
    account_id: &str,
    license_key: &PlaintextSecret,
    edition: &str,
) -> anyhow::Result<Vec<u8>> {
    let url = format!("{base}/geoip/databases/{edition}/download?suffix=tar.gz");
    let response = http
        .get(&url)
        .basic_auth(account_id, Some(license_key.expose_secret()))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach {base}: {e}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("MaxMind refused the account ID or the license key (401)");
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("MaxMind answered {status} for {edition}: {}", clip(body));
    }
    let mut archive = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        if archive.len() + chunk.len() > MAX_ARCHIVE_BYTES {
            anyhow::bail!("the {edition} archive is larger than {MAX_ARCHIVE_BYTES} bytes");
        }
        archive.extend_from_slice(&chunk);
    }
    tokio::task::spawn_blocking(move || extract(&archive)).await?
}

/// Download both databases and check them, then store them in the bucket
/// and load them here, and record the outcome: all of it only while the
/// state is still `claim`'s.
///
/// **Turn off** (or new credentials) during the download therefore discards
/// it, on whichever instance it happened: the swap is on the stored state,
/// not on what this process remembers. The swap to the successful state
/// comes first, in a transaction that stays open while the databases are put
/// and loaded. It holds the state's row, so [`forget`] and
/// [`set_credentials`] wait for it and delete or replace what it stored;
/// nothing is put behind their back.
pub async fn update(state: &AppState, claim: &Claim) -> anyhow::Result<()> {
    let result = async {
        let account_id = claim
            .state
            .account_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no MaxMind account ID is set"))?;
        let key = license_key(state)
            .await?
            .ok_or_else(|| anyhow::anyhow!("no MaxMind license key is set"))?;
        let http = http_client();
        let base = state.config.traffic.maxmind_base();
        let mut databases = Vec::with_capacity(EDITIONS.len());
        for (kind, edition) in EDITIONS {
            let bytes = download(&http, base, account_id, &key, edition).await?;
            forge_traffic::geo::check(kind, bytes.clone())
                .map_err(|e| anyhow::anyhow!("the {edition} download is no database: {e}"))?;
            databases.push((kind, bytes));
        }
        let succeeded = MaxmindState {
            last_success: Some(Utc::now()),
            last_error: None,
            ..claim.state.clone()
        };
        let mut tx = state.pool.begin().await?;
        if !authz_dao::replace_setting(&mut *tx, STATE_SETTING, &claim.raw, &encode(&succeeded)?)
            .await?
        {
            return anyhow::Ok(false);
        }
        for (kind, bytes) in databases {
            state.traffic.objects.put(kind.key(), bytes).await?;
        }
        forge_traffic::geo::refresh(&*state.traffic.objects, &state.traffic.geo).await?;
        tx.commit().await?;
        anyhow::Ok(true)
    }
    .await;
    match result {
        Ok(true) => {
            tracing::info!("downloaded the MaxMind geolocation databases");
            Ok(())
        }
        Ok(false) => {
            tracing::info!(
                "discarded the MaxMind download: the credentials were removed or changed, or \
                 a later download was started, while it ran"
            );
            Ok(())
        }
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot download the MaxMind databases");
            // Recorded only over the claimed state: never over credentials
            // removed or set since, nor over a state that cannot be read.
            let failed = MaxmindState {
                last_error: Some(clip(format!("{e:#}"))),
                ..claim.state.clone()
            };
            let recorded = match encode(&failed) {
                Ok(json) => {
                    authz_dao::replace_setting(&state.pool, STATE_SETTING, &claim.raw, &json).await
                }
                Err(e) => Err(e),
            };
            match recorded {
                Ok(true) => {}
                Ok(false) => tracing::info!(
                    "the MaxMind download's failure is not recorded: the state changed while \
                     it ran"
                ),
                Err(e) => {
                    forge_db::observe_error(&e);
                    tracing::warn!(error = %e, "cannot record the MaxMind download");
                }
            }
            Err(e)
        }
    }
}

/// Claim an attempt: record `now` as the last attempt, unless another
/// instance changed the state since `raw` was read. Returns the claim when
/// this instance won.
pub async fn claim(
    pool: &sqlx::PgPool,
    stored: &MaxmindState,
    raw: Option<&str>,
    now: DateTime<Utc>,
) -> sqlx::Result<Option<Claim>> {
    let state = MaxmindState {
        last_attempt: Some(now),
        ..stored.clone()
    };
    let json = encode(&state)?;
    let won = match raw {
        Some(raw) => authz_dao::replace_setting(pool, STATE_SETTING, raw, &json).await?,
        None => authz_dao::insert_setting_if_absent(pool, STATE_SETTING, &json).await?,
    };
    Ok(won.then_some(Claim { state, raw: json }))
}

/// Whether the databases are due for a download: credentials are set, the
/// last download is older than [`REFRESH_AFTER`] (or a database is missing),
/// and the last attempt is older than [`RETRY_AFTER`].
pub fn due(stored: &MaxmindState, has_key: bool, missing: bool, now: DateTime<Utc>) -> bool {
    let stale = missing || stored.last_success.is_none_or(|t| now - t >= REFRESH_AFTER);
    let rested = stored.last_attempt.is_none_or(|t| now - t >= RETRY_AFTER);
    stored.account_id.is_some() && has_key && stale && rested
}

/// The worker's check: download the databases if they are due and this
/// instance claims the download.
pub async fn update_if_due(state: &AppState) -> anyhow::Result<()> {
    let (stored, raw) = read_state(&state.pool).await?;
    if stored.account_id.is_none() {
        return Ok(());
    }
    let has_key = has_license_key(&state.pool).await?;
    let listed = state.traffic.objects.list("traffic/v1/geoip/").await?;
    let missing = GeoKind::ALL
        .iter()
        .any(|k| !listed.iter().any(|o| o.key == k.key()));
    let now = Utc::now();
    if !due(&stored, has_key, missing, now) {
        return Ok(());
    }
    let Some(claim) = claim(&state.pool, &stored, raw.as_deref(), now).await? else {
        return Ok(());
    };
    update(state, &claim).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(name: &str, body: &[u8]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, body).unwrap();
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn the_database_is_taken_from_its_archive() {
        let a = archive("GeoLite2-ASN_20261030/GeoLite2-ASN.mmdb", b"database");
        assert_eq!(extract(&a).unwrap(), b"database");
        let none = archive("GeoLite2-ASN_20261030/LICENSE.txt", b"text");
        assert!(extract(&none).unwrap_err().to_string().contains("no .mmdb"));
        assert!(extract(b"not gzip").is_err());
    }

    #[test]
    fn downloads_are_due_when_old_and_rested() {
        let now = Utc::now();
        let set = MaxmindState {
            account_id: Some("1".into()),
            ..MaxmindState::default()
        };
        assert!(due(&set, true, false, now), "never downloaded");
        assert!(!due(&set, false, false, now), "no license key");
        assert!(
            !due(&MaxmindState::default(), true, true, now),
            "no account"
        );
        let fresh = MaxmindState {
            last_success: Some(now - Duration::hours(1)),
            last_attempt: Some(now - Duration::hours(1)),
            ..set.clone()
        };
        assert!(!due(&fresh, true, false, now));
        let old = MaxmindState {
            last_success: Some(now - Duration::days(4)),
            last_attempt: Some(now - Duration::days(4)),
            ..set.clone()
        };
        assert!(due(&old, true, false, now));
        let failed_recently = MaxmindState {
            last_attempt: Some(now - Duration::hours(1)),
            last_error: Some("401".into()),
            ..set
        };
        assert!(
            !due(&failed_recently, true, true, now),
            "rests after a failure"
        );
    }
}
