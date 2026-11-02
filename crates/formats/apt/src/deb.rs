//! Reading a binary package (`.deb`, deb(5)): an `ar` archive holding
//! `debian-binary`, then `control.tar[.gz|.xz|.zst]`, then the data. Only
//! the `control` file of the control member is read; the data is never
//! touched, and every member is read within bounds, so a package that
//! inflates without end fails fast.

use std::io::{self, Read, Seek, SeekFrom};

use crate::control::MAX_CONTROL_BYTES;

/// The largest control member read (compressed).
pub const MAX_CONTROL_MEMBER_BYTES: u64 = 64 * 1024 * 1024;

/// The most the control member may inflate to.
pub const MAX_CONTROL_TAR_BYTES: u64 = 256 * 1024 * 1024;

/// The most members looked at before the control member.
const MAX_MEMBERS: usize = 16;

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_HEADER: usize = 60;

/// Why a package was refused.
#[derive(Debug)]
pub enum DebError {
    /// Not a binary package, or a damaged one: the text says why.
    Invalid(String),
    /// Reading the staged package failed.
    Io(io::Error),
}

impl std::fmt::Display for DebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebError::Invalid(m) => f.write_str(m),
            DebError::Io(e) => write!(f, "reading the package failed: {e}"),
        }
    }
}

impl From<io::Error> for DebError {
    fn from(e: io::Error) -> Self {
        DebError::Io(e)
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DebError> {
    Err(DebError::Invalid(message.into()))
}

/// One member of the archive: its name and where its data is.
struct Member {
    name: String,
    offset: u64,
    size: u64,
}

/// Read the next member header at the reader's position (even-aligned), or
/// `None` at the end of the archive.
fn next_member<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Option<Member>, DebError> {
    let mut header = [0u8; AR_HEADER];
    let mut filled = 0;
    while filled < AR_HEADER {
        match reader.read(&mut header[filled..])? {
            0 if filled == 0 => return Ok(None),
            0 => return invalid("not a Debian package: the archive ends inside a member header"),
            n => filled += n,
        }
    }
    if &header[58..60] != b"`\n" {
        return invalid("not a Debian package: a damaged ar member header");
    }
    let field = |range: std::ops::Range<usize>| {
        std::str::from_utf8(&header[range])
            .map(str::trim_end)
            .unwrap_or("")
            .to_string()
    };
    let name = field(0..16);
    // GNU ar ends names with `/`.
    let name = name.strip_suffix('/').unwrap_or(&name).to_string();
    let Ok(size) = field(48..58).parse::<u64>() else {
        return invalid("not a Debian package: an ar member without a size");
    };
    let offset = reader.stream_position()?;
    Ok(Some(Member { name, offset, size }))
}

/// The bytes of the `control` file of the package `reader` holds.
pub fn control_file<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Vec<u8>, DebError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    if reader.read_exact(&mut magic).is_err() || &magic != AR_MAGIC {
        return invalid("not a Debian package (.deb): no ar archive");
    }
    let mut seen_binary = false;
    for _ in 0..MAX_MEMBERS {
        let Some(member) = next_member(reader)? else {
            break;
        };
        let next = member.offset + member.size + (member.size & 1);
        match member.name.as_str() {
            "debian-binary" => {
                if member.size > 64 {
                    return invalid("not a Debian package: debian-binary is too long");
                }
                let mut version = Vec::new();
                Read::take(&mut *reader, member.size).read_to_end(&mut version)?;
                if !version.starts_with(b"2.") {
                    return invalid(format!(
                        "unsupported package format {:?} (debian-binary)",
                        String::from_utf8_lossy(&version).trim()
                    ));
                }
                seen_binary = true;
            }
            // Reserved for internal use: skipped, as dpkg does.
            name if name.starts_with('_') => {}
            name if name == "control.tar" || name.starts_with("control.tar.") => {
                if !seen_binary {
                    return invalid("not a Debian package: debian-binary is not the first member");
                }
                if member.size > MAX_CONTROL_MEMBER_BYTES {
                    return invalid("the package's control member is too large");
                }
                let compressed = Read::take(&mut *reader, member.size);
                let tar: Box<dyn Read + '_> = match &name["control.tar".len()..] {
                    "" => Box::new(compressed),
                    ".gz" => Box::new(flate2::read::GzDecoder::new(compressed)),
                    ".xz" => Box::new(lzma_rust2::XzReader::new(compressed, true)),
                    ".zst" => {
                        Box::new(ruzstd::decoding::StreamingDecoder::new(compressed).map_err(
                            |e| DebError::Invalid(format!("the control member is not zstd: {e}")),
                        )?)
                    }
                    other => {
                        return invalid(format!(
                            "the control member is compressed with an unsupported method ({other})"
                        ))
                    }
                };
                return control_in_tar(tar.take(MAX_CONTROL_TAR_BYTES));
            }
            other => {
                return invalid(format!(
                    "not a Debian package: member {other:?} comes before the control member"
                ))
            }
        }
        reader.seek(SeekFrom::Start(next))?;
    }
    invalid("not a Debian package: no control member")
}

/// The `control` file inside a control tarball.
fn control_in_tar(tar: impl Read) -> Result<Vec<u8>, DebError> {
    let mut archive = tar::Archive::new(tar);
    let entries = archive
        .entries()
        .map_err(|e| DebError::Invalid(format!("the control member is not a tar archive: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| {
            DebError::Invalid(format!("the control member is not a tar archive: {e}"))
        })?;
        let path = entry.path_bytes().into_owned();
        let path = path.strip_prefix(b"./").unwrap_or(&path);
        if path != b"control" {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return invalid("the package's control is not a file");
        }
        if entry.size() > MAX_CONTROL_BYTES as u64 {
            return invalid("the package's control file is too large");
        }
        let mut control = Vec::new();
        entry
            .by_ref()
            .take(MAX_CONTROL_BYTES as u64)
            .read_to_end(&mut control)
            .map_err(|e| DebError::Invalid(format!("the control file could not be read: {e}")))?;
        return Ok(control);
    }
    invalid("the package has no control file")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    /// A `.deb` of `control`, its control member compressed by `method`
    /// (`""`, `gz`, `xz`), with a small data member.
    pub(crate) fn deb(control: &str, method: &str) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(control.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "./control", control.as_bytes())
            .unwrap();
        let tar = tar.into_inner().unwrap();
        let (name, member) = match method {
            "" => ("control.tar".to_string(), tar),
            "gz" => {
                let mut gz =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gz.write_all(&tar).unwrap();
                ("control.tar.gz".to_string(), gz.finish().unwrap())
            }
            "xz" => {
                let mut xz =
                    lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))
                        .unwrap();
                xz.write_all(&tar).unwrap();
                ("control.tar.xz".to_string(), xz.finish().unwrap())
            }
            other => panic!("{other}"),
        };
        ar(&[
            ("debian-binary", b"2.0\n".to_vec()),
            (&name, member),
            ("data.tar", vec![0u8; 1024]),
        ])
    }

    pub(crate) fn ar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = AR_MAGIC.to_vec();
        for (name, data) in members {
            out.extend_from_slice(
                format!(
                    "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    name,
                    0,
                    0,
                    0,
                    100644,
                    data.len()
                )
                .as_bytes(),
            );
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    const CONTROL: &str = "Package: hello\nVersion: 1.0-1\nArchitecture: amd64\nDescription: hi\n";

    #[test]
    fn reads_the_control_file_of_every_compression() {
        for method in ["", "gz", "xz"] {
            let deb = deb(CONTROL, method);
            assert_eq!(
                control_file(&mut Cursor::new(deb)).unwrap(),
                CONTROL.as_bytes(),
                "{method}"
            );
        }
    }

    #[test]
    fn refuses_what_is_not_a_package() {
        for bad in [
            b"not an archive".to_vec(),
            ar(&[("debian-binary", b"2.0\n".to_vec())]),
            ar(&[
                ("debian-binary", b"3.0\n".to_vec()),
                ("control.tar", vec![]),
            ]),
            ar(&[("data.tar", vec![0; 10]), ("control.tar", vec![])]),
            ar(&[("control.tar", vec![])]),
            ar(&[
                ("debian-binary", b"2.0\n".to_vec()),
                ("control.tar.bz2", vec![1]),
            ]),
            ar(&[
                ("debian-binary", b"2.0\n".to_vec()),
                ("control.tar.gz", vec![1, 2, 3]),
            ]),
            // A truncated header.
            b"!<arch>\ndebian-binary   ".to_vec(),
        ] {
            assert!(
                matches!(
                    control_file(&mut Cursor::new(&bad)),
                    Err(DebError::Invalid(_))
                ),
                "{:?}",
                String::from_utf8_lossy(&bad)
            );
        }
    }

    #[test]
    fn a_control_tar_without_control_is_refused() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        tar.append_data(&mut header, "./md5sums", &b"abc"[..])
            .unwrap();
        let deb = ar(&[
            ("debian-binary", b"2.0\n".to_vec()),
            ("control.tar", tar.into_inner().unwrap()),
        ]);
        let err = control_file(&mut Cursor::new(deb)).unwrap_err();
        assert!(err.to_string().contains("no control file"), "{err}");
    }
}
