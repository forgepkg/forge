//! The counts and the rows of the Parquet files.
//!
//! The files are plain Parquet, readable by any tool (DuckDB, pandas). A
//! column the record API cannot leave empty holds `""` or `0` for none: the
//! derived reader takes no `Option` field. Times are Unix seconds (`start`)
//! or milliseconds (`time_ms`), in UTC.

use std::sync::Arc;

use bytes::Bytes;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;
use parquet::record::{RecordReader, RecordWriter};
use parquet_derive::{ParquetRecordReader, ParquetRecordWriter};

/// The upper bounds of the latency histogram, in milliseconds: a request is
/// counted in the first bucket whose bound it does not exceed, or in the
/// last, above all of them.
pub const LATENCY_BOUNDS_MS: [u64; 13] = [
    5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000,
];

/// The buckets of the latency histogram: one per bound, and one above.
pub const LATENCY_BUCKETS: usize = LATENCY_BOUNDS_MS.len() + 1;

/// What requests are counted under within a time bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BucketKey {
    /// The surface (`forge_telemetry::http::Surface`), narrowed to the
    /// format for a repository's requests.
    pub surface: String,
    /// The repository the request addressed; `""` for none.
    pub repository: String,
    /// The request method.
    pub method: String,
    /// The response status.
    pub status: u16,
}

/// The counts of a [`BucketKey`] in a time bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    pub requests: u64,
    /// Response body bytes sent.
    pub bytes: u64,
    /// Time to the response headers, summed, in microseconds.
    pub duration_us: u64,
    /// The latency histogram ([`LATENCY_BOUNDS_MS`]).
    pub latency: [u64; LATENCY_BUCKETS],
}

impl Counts {
    /// Count one request.
    pub fn observe(&mut self, duration: std::time::Duration, bytes: u64) {
        self.requests += 1;
        self.bytes += bytes;
        let us = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.duration_us = self.duration_us.saturating_add(us);
        let bucket = LATENCY_BOUNDS_MS
            .iter()
            .position(|&bound| us <= bound * 1_000)
            .unwrap_or(LATENCY_BOUNDS_MS.len());
        self.latency[bucket] += 1;
    }

    /// Add `other`'s counts.
    pub fn add(&mut self, other: &Counts) {
        self.requests += other.requests;
        self.bytes += other.bytes;
        self.duration_us = self.duration_us.saturating_add(other.duration_us);
        for (mine, theirs) in self.latency.iter_mut().zip(other.latency) {
            *mine += theirs;
        }
    }
}

/// A row of a `buckets` file: a key's counts in the bucket starting at
/// `start` (a minute or an hour).
#[derive(Debug, Clone, Default, PartialEq, Eq, ParquetRecordWriter, ParquetRecordReader)]
pub(crate) struct BucketRow {
    pub start: i64,
    pub surface: String,
    pub repository: String,
    pub method: String,
    pub status: i32,
    pub requests: i64,
    pub bytes: i64,
    pub duration_us: i64,
    pub le_5ms: i64,
    pub le_10ms: i64,
    pub le_25ms: i64,
    pub le_50ms: i64,
    pub le_100ms: i64,
    pub le_250ms: i64,
    pub le_500ms: i64,
    pub le_1s: i64,
    pub le_2500ms: i64,
    pub le_5s: i64,
    pub le_10s: i64,
    pub le_30s: i64,
    pub le_60s: i64,
    pub over_60s: i64,
}

fn signed(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn unsigned(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

impl BucketRow {
    pub fn new(start: i64, key: &BucketKey, counts: &Counts) -> BucketRow {
        let l = counts.latency.map(signed);
        BucketRow {
            start,
            surface: key.surface.clone(),
            repository: key.repository.clone(),
            method: key.method.clone(),
            status: i32::from(key.status),
            requests: signed(counts.requests),
            bytes: signed(counts.bytes),
            duration_us: signed(counts.duration_us),
            le_5ms: l[0],
            le_10ms: l[1],
            le_25ms: l[2],
            le_50ms: l[3],
            le_100ms: l[4],
            le_250ms: l[5],
            le_500ms: l[6],
            le_1s: l[7],
            le_2500ms: l[8],
            le_5s: l[9],
            le_10s: l[10],
            le_30s: l[11],
            le_60s: l[12],
            over_60s: l[13],
        }
    }

    pub fn counts(&self) -> Counts {
        Counts {
            requests: unsigned(self.requests),
            bytes: unsigned(self.bytes),
            duration_us: unsigned(self.duration_us),
            latency: [
                self.le_5ms,
                self.le_10ms,
                self.le_25ms,
                self.le_50ms,
                self.le_100ms,
                self.le_250ms,
                self.le_500ms,
                self.le_1s,
                self.le_2500ms,
                self.le_5s,
                self.le_10s,
                self.le_30s,
                self.le_60s,
                self.over_60s,
            ]
            .map(unsigned),
        }
    }
}

/// A row of a `clients` file: a client network's counts in the bucket
/// starting at `start`, as one of the bucket's top clients.
#[derive(Debug, Clone, Default, PartialEq, Eq, ParquetRecordWriter, ParquetRecordReader)]
pub(crate) struct ClientRow {
    pub start: i64,
    /// The network the requests are counted under.
    pub network: String,
    /// The last address of the network seen.
    pub address: String,
    pub requests: i64,
    pub bytes: i64,
    /// 4xx answers, the next three included.
    pub client_errors: i64,
    /// 401 and 403 answers.
    pub denied: i64,
    pub not_found: i64,
    /// 429 answers.
    pub throttled: i64,
    /// 5xx answers.
    pub server_errors: i64,
    /// The last user agent seen; `""` for none.
    pub user_agent: String,
    /// The last account kind seen ([`crate::Account::kind`]).
    pub account: String,
    /// The last account's user; `0` for none.
    pub user_id: i64,
}

/// A row of a `requests` file: one request of the request log.
#[derive(Debug, Clone, Default, PartialEq, Eq, ParquetRecordWriter, ParquetRecordReader)]
pub(crate) struct LogRow {
    /// When the response was sent, in Unix milliseconds.
    pub time_ms: i64,
    /// The client network; `""` with client addresses switched off.
    pub network: String,
    /// The client address; `""` with client addresses switched off.
    pub address: String,
    pub method: String,
    /// The path, without the query and with secrets replaced
    /// (`forge-server`'s `recorded_path`).
    pub path: String,
    pub surface: String,
    /// `""` for none.
    pub repository: String,
    pub status: i32,
    pub bytes: i64,
    /// Time to the response headers, in microseconds.
    pub duration_us: i64,
    /// `""` for none.
    pub user_agent: String,
    pub account: String,
    /// `0` for none.
    pub user_id: i64,
}

/// `rows` as a Parquet file, in one row group.
pub(crate) fn encode<T>(rows: &[T]) -> anyhow::Result<Vec<u8>>
where
    for<'a> &'a [T]: RecordWriter<T>,
{
    let schema = rows.schema()?;
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_created_by(format!("forge {}", env!("CARGO_PKG_VERSION")))
        .build();
    let mut writer = SerializedFileWriter::new(Vec::new(), schema, Arc::new(props))?;
    let mut group = writer.next_row_group()?;
    rows.write_to_row_group(&mut group)?;
    group.close()?;
    Ok(writer.into_inner()?)
}

/// The rows of the Parquet file `bytes`.
pub(crate) fn decode<T>(bytes: Bytes) -> anyhow::Result<Vec<T>>
where
    Vec<T>: RecordReader<T>,
{
    let reader = SerializedFileReader::new(bytes)?;
    let mut rows = Vec::new();
    for i in 0..reader.num_row_groups() {
        let mut group = reader.get_row_group(i)?;
        let n = usize::try_from(group.metadata().num_rows()).unwrap_or(0);
        if n > 0 {
            rows.read_from_row_group(&mut *group, n)?;
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn latency_lands_in_its_bucket() {
        let mut c = Counts::default();
        c.observe(Duration::from_micros(4_999), 1);
        c.observe(Duration::from_millis(5), 1);
        c.observe(Duration::from_micros(5_001), 1);
        c.observe(Duration::from_secs(61), 1);
        assert_eq!(c.latency[0], 2, "up to and including 5 ms");
        assert_eq!(c.latency[1], 1);
        assert_eq!(c.latency[LATENCY_BUCKETS - 1], 1, "above the last bound");
        assert_eq!(c.requests, 4);
        assert_eq!(c.bytes, 4);
    }

    #[test]
    fn rows_round_trip_through_parquet() {
        let key = BucketKey {
            surface: "nuget".into(),
            repository: "nuget-hosted".into(),
            method: "GET".into(),
            status: 200,
        };
        let mut counts = Counts::default();
        counts.observe(Duration::from_millis(30), 1234);
        counts.observe(Duration::from_millis(3), 10);
        let rows = vec![
            BucketRow::new(1_700_000_040, &key, &counts),
            BucketRow::new(1_700_000_100, &key, &Counts::default()),
        ];
        let back: Vec<BucketRow> = decode(encode(&rows).unwrap().into()).unwrap();
        assert_eq!(back, rows);
        assert_eq!(back[0].counts(), counts);

        let log = vec![LogRow {
            time_ms: 1_700_000_040_123,
            network: "2001:db8::/64".into(),
            address: "2001:db8::7".into(),
            method: "GET".into(),
            path: "/v2/".into(),
            status: 401,
            ..LogRow::default()
        }];
        let back: Vec<LogRow> = decode(encode(&log).unwrap().into()).unwrap();
        assert_eq!(back, log);

        let none: Vec<ClientRow> = decode(encode::<ClientRow>(&[]).unwrap().into()).unwrap();
        assert!(none.is_empty());
    }
}
