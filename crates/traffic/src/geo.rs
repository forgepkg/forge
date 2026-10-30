//! The country and autonomous system of a client address, from MaxMind
//! databases (`.mmdb`: GeoLite2 or GeoIP2).
//!
//! Two databases, each optional: one with countries (a Country or City
//! edition) and one with autonomous systems (an ASN or ISP edition). They
//! are kept in Forge's bucket ([`GeoKind::key`]), where Forge's download from
//! MaxMind puts them or an operator does, and every instance loads them from
//! there ([`refresh`]): a database replaced in the bucket is loaded again,
//! one removed is unloaded.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, TimeZone, Utc};
use maxminddb::{geoip2, Reader};
use serde::Serialize;

use crate::objects::Objects;

/// The two databases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoKind {
    Country,
    Asn,
}

impl GeoKind {
    pub const ALL: [GeoKind; 2] = [GeoKind::Country, GeoKind::Asn];

    /// Where the database is kept in the bucket.
    pub fn key(self) -> &'static str {
        match self {
            GeoKind::Country => "traffic/v1/geoip/country.mmdb",
            GeoKind::Asn => "traffic/v1/geoip/asn.mmdb",
        }
    }

    /// Whether a database of `database_type` (its metadata's) answers this
    /// kind: a Country or City edition for countries, an ASN or ISP edition
    /// for autonomous systems.
    fn accepts(self, database_type: &str) -> bool {
        let t = database_type.to_ascii_lowercase();
        match self {
            GeoKind::Country => t.contains("country") || t.contains("city"),
            GeoKind::Asn => t.contains("asn") || t.contains("isp"),
        }
    }
}

/// What a loaded database is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DbInfo {
    /// Its edition, as its metadata names it (`GeoLite2-Country`).
    pub database_type: String,
    /// When MaxMind built it.
    pub built_at: Option<DateTime<Utc>>,
    pub size: u64,
    /// The bucket object's ETag it was loaded from.
    #[serde(skip)]
    pub etag: String,
}

struct Db {
    reader: Reader<Vec<u8>>,
    info: DbInfo,
}

/// Where an address is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// ISO 3166-1 alpha-2; `""` unknown.
    pub country: String,
    /// `0` unknown.
    pub asn: u32,
    /// `""` unknown.
    pub as_org: String,
}

/// The loaded databases.
#[derive(Default)]
pub struct Geo {
    country: RwLock<Option<Arc<Db>>>,
    asn: RwLock<Option<Arc<Db>>>,
}

impl std::fmt::Debug for Geo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Geo")
            .field("country", &self.info(GeoKind::Country))
            .field("asn", &self.info(GeoKind::Asn))
            .finish()
    }
}

/// `bytes` as a database of `kind`, checked: it parses, and its edition
/// answers `kind`.
fn open(kind: GeoKind, bytes: Vec<u8>, etag: String) -> anyhow::Result<Db> {
    let size = bytes.len() as u64;
    let reader = Reader::from_source(bytes)?;
    let meta = reader.metadata();
    let database_type = meta.database_type.clone();
    if !kind.accepts(&database_type) {
        anyhow::bail!(
            "{database_type} is not a {} database",
            match kind {
                GeoKind::Country => "country (Country or City)",
                GeoKind::Asn => "autonomous system (ASN or ISP)",
            }
        );
    }
    let built_at = i64::try_from(meta.build_epoch)
        .ok()
        .and_then(|secs| Utc.timestamp_opt(secs, 0).single());
    Ok(Db {
        reader,
        info: DbInfo {
            database_type,
            built_at,
            size,
            etag,
        },
    })
}

/// Check that `bytes` is a database of `kind`; what it is.
pub fn check(kind: GeoKind, bytes: Vec<u8>) -> anyhow::Result<DbInfo> {
    Ok(open(kind, bytes, String::new())?.info)
}

impl Geo {
    fn slot(&self, kind: GeoKind) -> &RwLock<Option<Arc<Db>>> {
        match kind {
            GeoKind::Country => &self.country,
            GeoKind::Asn => &self.asn,
        }
    }

    fn get(&self, kind: GeoKind) -> Option<Arc<Db>> {
        self.slot(kind)
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set(&self, kind: GeoKind, db: Option<Arc<Db>>) {
        *self
            .slot(kind)
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = db;
    }

    /// Load `bytes`, the bucket object of ETag `etag`, as the database of
    /// `kind`.
    pub fn load(&self, kind: GeoKind, bytes: Vec<u8>, etag: String) -> anyhow::Result<DbInfo> {
        let db = open(kind, bytes, etag)?;
        let info = db.info.clone();
        self.set(kind, Some(Arc::new(db)));
        Ok(info)
    }

    /// Unload the database of `kind`.
    pub fn unload(&self, kind: GeoKind) {
        self.set(kind, None);
    }

    /// What is loaded as the database of `kind`.
    pub fn info(&self, kind: GeoKind) -> Option<DbInfo> {
        self.get(kind).map(|db| db.info.clone())
    }

    /// Whether any database is loaded.
    pub fn any(&self) -> bool {
        GeoKind::ALL.iter().any(|k| self.get(*k).is_some())
    }

    /// Where `ip` is, as far as the loaded databases know.
    pub fn locate(&self, ip: IpAddr) -> Location {
        let ip = ip.to_canonical();
        let mut location = Location::default();
        if let Some(db) = self.get(GeoKind::Country) {
            if let Ok(Some(c)) = db
                .reader
                .lookup(ip)
                .and_then(|r| r.decode::<geoip2::Country>())
            {
                location.country = c
                    .country
                    .iso_code
                    .or(c.registered_country.iso_code)
                    .unwrap_or_default()
                    .to_string();
            }
        }
        if let Some(db) = self.get(GeoKind::Asn) {
            if let Ok(Some(a)) = db.reader.lookup(ip).and_then(|r| r.decode::<geoip2::Asn>()) {
                location.asn = a.autonomous_system_number.unwrap_or(0);
                location.as_org = a
                    .autonomous_system_organization
                    .unwrap_or_default()
                    .to_string();
            }
        }
        location
    }
}

/// Load the databases kept in the bucket that changed since they were
/// loaded, and unload the ones removed. A database that cannot be read is
/// logged and left as it was.
pub async fn refresh(objects: &dyn Objects, geo: &Geo) -> anyhow::Result<()> {
    let listed = objects.list("traffic/v1/geoip/").await?;
    for kind in GeoKind::ALL {
        let Some(object) = listed.iter().find(|o| o.key == kind.key()) else {
            if geo.info(kind).is_some() {
                tracing::info!(?kind, "the geolocation database was removed; unloading it");
                geo.unload(kind);
            }
            continue;
        };
        let etag = object.etag.clone().unwrap_or_default();
        if geo
            .info(kind)
            .is_some_and(|i| i.etag == etag && !etag.is_empty())
        {
            continue;
        }
        let Some(bytes) = objects.get(kind.key()).await? else {
            continue;
        };
        match geo.load(kind, bytes.to_vec(), etag) {
            Ok(info) => tracing::info!(
                database = %info.database_type,
                built_at = ?info.built_at,
                "loaded the geolocation database"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                key = kind.key(),
                "cannot load the geolocation database"
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::MemoryObjects;
    use crate::testing::{asn_db, country_db};

    #[test]
    fn databases_locate_addresses() {
        let geo = Geo::default();
        assert_eq!(
            geo.locate("192.0.2.1".parse().unwrap()),
            Location::default()
        );
        geo.load(
            GeoKind::Country,
            country_db(&[("192.0.2.0/24", "DE")]),
            "1".into(),
        )
        .unwrap();
        geo.load(
            GeoKind::Asn,
            asn_db(&[("192.0.2.0/24", 64_500, "Example AS")]),
            "1".into(),
        )
        .unwrap();
        assert_eq!(
            geo.locate("192.0.2.77".parse().unwrap()),
            Location {
                country: "DE".into(),
                asn: 64_500,
                as_org: "Example AS".into()
            }
        );
        assert_eq!(
            geo.locate("::ffff:192.0.2.77".parse().unwrap()).country,
            "DE",
            "a mapped address is its IPv4 address"
        );
        assert_eq!(
            geo.locate("198.51.100.1".parse().unwrap()),
            Location::default()
        );
        assert_eq!(
            geo.locate("2001:db8::1".parse().unwrap()),
            Location::default(),
            "an IPv6 address in an IPv4 database is unknown"
        );
        assert_eq!(
            geo.info(GeoKind::Asn).unwrap().database_type,
            "GeoLite2-ASN"
        );
    }

    #[test]
    fn a_database_of_the_other_kind_is_refused() {
        let geo = Geo::default();
        let err = geo
            .load(
                GeoKind::Country,
                asn_db(&[("192.0.2.0/24", 1, "x")]),
                "1".into(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("not a country"), "{err}");
        assert!(geo
            .load(GeoKind::Asn, b"no database".to_vec(), "1".into())
            .is_err());
        assert!(!geo.any());
    }

    #[tokio::test]
    async fn refresh_follows_the_bucket() {
        let objects = MemoryObjects::default();
        let geo = Geo::default();
        objects
            .put(
                GeoKind::Country.key(),
                country_db(&[("192.0.2.0/24", "DE")]),
            )
            .await
            .unwrap();
        refresh(&objects, &geo).await.unwrap();
        assert_eq!(geo.locate("192.0.2.1".parse().unwrap()).country, "DE");

        objects
            .put(
                GeoKind::Country.key(),
                country_db(&[("192.0.2.0/24", "FR")]),
            )
            .await
            .unwrap();
        refresh(&objects, &geo).await.unwrap();
        assert_eq!(
            geo.locate("192.0.2.1".parse().unwrap()).country,
            "FR",
            "replaced"
        );

        objects.delete(GeoKind::Country.key()).await.unwrap();
        refresh(&objects, &geo).await.unwrap();
        assert!(!geo.any(), "removed");
    }
}
