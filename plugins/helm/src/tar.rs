//! Just enough of tar to find one file in a chart archive: ustar and GNU
//! headers, GNU long names, and PAX `path` records.

use std::io::{self, Read};

const BLOCK: usize = 512;

/// The longest name or PAX header read.
const MAX_HEADER_DATA: u64 = 64 * 1024;

/// Read entries from `archive` until one whose path `wanted` accepts; return
/// its path and contents. A matching entry larger than `max_size` is an
/// error; `None` when the archive ends first.
pub fn find_file(
    mut archive: impl Read,
    wanted: impl Fn(&str) -> bool,
    max_size: u64,
) -> io::Result<Option<(String, Vec<u8>)>> {
    let mut long_name: Option<String> = None;
    let mut header = [0u8; BLOCK];
    loop {
        if !read_block(&mut archive, &mut header)? || header.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        let size = parse_size(&header[124..136])?;
        let padded = size.div_ceil(BLOCK as u64) * BLOCK as u64;
        let typeflag = header[156];
        match typeflag {
            // GNU long name / PAX extended header: the next entry's path.
            b'L' | b'x' => {
                if size > MAX_HEADER_DATA {
                    return Err(invalid("oversized tar extension header"));
                }
                let data = read_exact(&mut archive, size)?;
                skip(&mut archive, padded - size)?;
                long_name = if typeflag == b'L' {
                    Some(c_string(&data))
                } else {
                    pax_path(&data).or(long_name)
                };
            }
            _ => {
                let path = long_name.take().unwrap_or_else(|| header_path(&header));
                let regular = matches!(typeflag, b'0' | 0 | b'7');
                if regular && wanted(&path) {
                    if size > max_size {
                        return Err(invalid(&format!("{path} is larger than {max_size} bytes")));
                    }
                    let data = read_exact(&mut archive, size)?;
                    return Ok(Some((path, data)));
                }
                skip(&mut archive, padded)?;
            }
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Fill `block`; `false` at a clean end of the stream.
fn read_block(r: &mut impl Read, block: &mut [u8; BLOCK]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < BLOCK {
        match r.read(&mut block[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(invalid("truncated tar header")),
            n => filled += n,
        }
    }
    Ok(true)
}

fn read_exact(r: &mut impl Read, len: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    r.take(len).read_to_end(&mut data)?;
    if data.len() as u64 != len {
        return Err(invalid("truncated tar entry"));
    }
    Ok(data)
}

fn skip(r: &mut impl Read, len: u64) -> io::Result<()> {
    let skipped = io::copy(&mut r.take(len), &mut io::sink())?;
    if skipped != len {
        return Err(invalid("truncated tar entry"));
    }
    Ok(())
}

/// An octal size field, or GNU base-256 for large sizes.
fn parse_size(field: &[u8]) -> io::Result<u64> {
    if field[0] & 0x80 != 0 {
        let mut n: u64 = 0;
        for &b in &field[1..] {
            n = n
                .checked_mul(256)
                .and_then(|n| n.checked_add(u64::from(b)))
                .ok_or_else(|| invalid("tar size overflows"))?;
        }
        return Ok(n);
    }
    let text = c_string(field);
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| invalid("bad tar size field"))
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// `prefix/name` of a ustar header, or just `name`.
fn header_path(header: &[u8; BLOCK]) -> String {
    let name = c_string(&header[0..100]);
    if &header[257..262] == b"ustar" {
        let prefix = c_string(&header[345..500]);
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

/// The `path` record of a PAX header (`"<len> path=<value>\n"` records).
fn pax_path(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    text.lines().find_map(|record| {
        let (_, kv) = record.split_once(' ')?;
        kv.strip_prefix("path=").map(str::to_string)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ustar archive of `(path, contents)` entries.
    pub(crate) fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, data) in entries {
            let mut header = [0u8; BLOCK];
            header[..path.len()].copy_from_slice(path.as_bytes());
            let size = format!("{:011o}\0", data.len());
            header[124..136].copy_from_slice(size.as_bytes());
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        }
        out.extend_from_slice(&[0u8; 2 * BLOCK]);
        out
    }

    #[test]
    fn finds_the_wanted_entry() {
        let tar = archive(&[
            ("demo/values.yaml", b"replicas: 1\n"),
            ("demo/Chart.yaml", b"name: demo\n"),
        ]);
        let found = find_file(&tar[..], |p| p.ends_with("Chart.yaml"), 1024).unwrap();
        assert_eq!(
            found,
            Some(("demo/Chart.yaml".into(), b"name: demo\n".to_vec()))
        );
        assert_eq!(find_file(&tar[..], |p| p == "missing", 1024).unwrap(), None);
        assert!(find_file(&tar[..], |p| p.ends_with("Chart.yaml"), 4).is_err());
        assert!(find_file(&tar[..700], |p| p == "missing", 1024).is_err());
    }

    #[test]
    fn reads_pax_paths() {
        assert_eq!(
            pax_path(b"30 path=demo/Chart.yaml\n20 mtime=1.5\n").as_deref(),
            Some("demo/Chart.yaml")
        );
    }
}
