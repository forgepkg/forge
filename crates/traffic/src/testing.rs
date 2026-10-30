//! Small MaxMind databases for tests: an IPv4 search tree over a few
//! networks, their records and the metadata, in the MaxMind DB format
//! (<https://maxmind.github.io/MaxMind-DB/>), as GeoLite2 editions name
//! them.

use std::net::Ipv4Addr;

/// A value of the MaxMind DB data section.
enum Value<'a> {
    Str(&'a str),
    U16(u16),
    U32(u32),
    U64(u64),
    Map(Vec<(&'a str, Value<'a>)>),
    Array(Vec<Value<'a>>),
}

/// The control byte(s) of a value of `kind` (1–15) and `size`.
fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
    let (first, extra): (u8, Vec<u8>) = match size {
        0..=28 => (size as u8, vec![]),
        29..=284 => (29, vec![(size - 29) as u8]),
        _ => {
            let n = size - 285;
            (30, vec![(n >> 8) as u8, n as u8])
        }
    };
    if kind <= 7 {
        out.push((kind << 5) | first);
    } else {
        out.push(first);
        out.push(kind - 7);
    }
    out.extend(extra);
}

fn uint(out: &mut Vec<u8>, kind: u8, n: u64) {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    control(out, kind, bytes.len() - skip);
    out.extend(&bytes[skip..]);
}

fn encode(out: &mut Vec<u8>, value: &Value<'_>) {
    match value {
        Value::Str(s) => {
            control(out, 2, s.len());
            out.extend(s.as_bytes());
        }
        Value::U16(n) => uint(out, 5, u64::from(*n)),
        Value::U32(n) => uint(out, 6, u64::from(*n)),
        Value::U64(n) => uint(out, 9, *n),
        Value::Map(entries) => {
            control(out, 7, entries.len());
            for (k, v) in entries {
                encode(out, &Value::Str(k));
                encode(out, v);
            }
        }
        Value::Array(items) => {
            control(out, 11, items.len());
            for item in items {
                encode(out, item);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Record {
    Empty,
    Node(usize),
    Data(usize),
}

/// A database of `database_type` mapping each network (`a.b.c.d/len`) to
/// its record.
fn database(database_type: &str, networks: Vec<(&str, Value<'_>)>) -> Vec<u8> {
    let mut nodes: Vec<[Record; 2]> = vec![[Record::Empty; 2]];
    let mut data = Vec::new();
    for (network, record) in networks {
        let (addr, len) = network.split_once('/').expect("a.b.c.d/len");
        let addr = u32::from(addr.parse::<Ipv4Addr>().expect("an IPv4 network"));
        let len: usize = len.parse().expect("a prefix length");
        assert!((1..=32).contains(&len), "prefix length");
        let offset = data.len();
        encode(&mut data, &record);
        let mut node = 0;
        for depth in 0..len {
            let bit = ((addr >> (31 - depth)) & 1) as usize;
            if depth == len - 1 {
                nodes[node][bit] = Record::Data(offset);
            } else {
                node = match nodes[node][bit] {
                    Record::Node(next) => next,
                    _ => {
                        nodes.push([Record::Empty; 2]);
                        let next = nodes.len() - 1;
                        nodes[node][bit] = Record::Node(next);
                        next
                    }
                };
            }
        }
    }
    let node_count = nodes.len();
    let mut out = Vec::new();
    for node in &nodes {
        for record in node {
            let value = match *record {
                Record::Empty => node_count,
                Record::Node(n) => n,
                Record::Data(offset) => node_count + 16 + offset,
            } as u32;
            out.extend(&value.to_be_bytes()[1..]);
        }
    }
    out.extend([0u8; 16]);
    out.extend(data);
    out.extend(b"\xAB\xCD\xEFMaxMind.com");
    encode(
        &mut out,
        &Value::Map(vec![
            ("binary_format_major_version", Value::U16(2)),
            ("binary_format_minor_version", Value::U16(0)),
            ("build_epoch", Value::U64(1_793_318_400)),
            ("database_type", Value::Str(database_type)),
            ("description", Value::Map(vec![("en", Value::Str("Test"))])),
            ("ip_version", Value::U16(4)),
            ("languages", Value::Array(vec![Value::Str("en")])),
            ("node_count", Value::U32(node_count as u32)),
            ("record_size", Value::U16(24)),
        ]),
    );
    out
}

/// A `GeoLite2-Country` database of `(network, ISO code)`.
pub fn country_db(networks: &[(&str, &str)]) -> Vec<u8> {
    database(
        "GeoLite2-Country",
        networks
            .iter()
            .map(|(net, code)| {
                (
                    *net,
                    Value::Map(vec![(
                        "country",
                        Value::Map(vec![("iso_code", Value::Str(code))]),
                    )]),
                )
            })
            .collect(),
    )
}

/// A `GeoLite2-ASN` database of `(network, number, organisation)`.
pub fn asn_db(networks: &[(&str, u32, &str)]) -> Vec<u8> {
    database(
        "GeoLite2-ASN",
        networks
            .iter()
            .map(|(net, asn, org)| {
                (
                    *net,
                    Value::Map(vec![
                        ("autonomous_system_number", Value::U32(*asn)),
                        ("autonomous_system_organization", Value::Str(org)),
                    ]),
                )
            })
            .collect(),
    )
}
