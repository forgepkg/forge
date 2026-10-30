//! The rows of the Parquet files.
//!
//! The files are plain Parquet, readable by any tool (DuckDB, pandas). A
//! column the record API cannot leave empty holds `""` or `0` for none: the
//! derived reader takes no `Option` field.

use std::sync::Arc;

use bytes::Bytes;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;
use parquet::record::{RecordReader, RecordWriter};
use parquet_derive::{ParquetRecordReader, ParquetRecordWriter};

/// A row of a day file: the requests one client network made to one
/// repository on one day, as one instance answered them.
#[derive(Debug, Clone, Default, PartialEq, Eq, ParquetRecordWriter, ParquetRecordReader)]
pub(crate) struct DayRow {
    /// The start of the day (UTC), in Unix seconds.
    pub day: i64,
    /// The repository the requests addressed; `""` for requests that
    /// addressed none (the web UI, the APIs, sign-in).
    pub repository: String,
    /// The client network: the address, or an IPv6 address's /64; `""` with
    /// client addresses switched off, `other` past the day's bound.
    pub network: String,
    /// The last address of the network seen; `""` with addresses off.
    pub address: String,
    /// The ISO 3166-1 code of the country the network is in; `""` unknown.
    pub country: String,
    /// The autonomous system the network belongs to; `0` unknown.
    pub asn: i64,
    /// The organisation of the autonomous system; `""` unknown.
    pub as_org: String,
    pub requests: i64,
    /// Response body bytes sent.
    pub bytes: i64,
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

    #[test]
    fn rows_round_trip_through_parquet() {
        let rows = vec![
            DayRow {
                day: 1_793_318_400,
                repository: "npm-proxy".into(),
                network: "2001:db8::/64".into(),
                address: "2001:db8::7".into(),
                country: "DE".into(),
                asn: 64_500,
                as_org: "Example AS".into(),
                requests: 12,
                bytes: 3_400,
            },
            DayRow::default(),
        ];
        let back: Vec<DayRow> = decode(encode(&rows).unwrap().into()).unwrap();
        assert_eq!(back, rows);
        let none: Vec<DayRow> = decode(encode::<DayRow>(&[]).unwrap().into()).unwrap();
        assert!(none.is_empty());
    }
}
