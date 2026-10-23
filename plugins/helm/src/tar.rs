//! A tar reader that sees a chart archive the way Helm does.
//!
//! Helm reads a chart with Go's `archive/tar`, so an entry's name, its type
//! and where its data ends are whatever that reader makes of the headers.
//! Forge must make the same of them, or the two disagree about which file
//! is the chart's `Chart.yaml`. [`Archive`] follows Go's `Reader.Next` for
//! every archive it accepts: ustar, PAX, GNU and STAR headers and their
//! checksums, PAX `path` and `size` records (of the last extended header
//! before an entry), GNU long names and long link names, global PAX headers
//! as entries of their own, entry types without data, and Go's end of
//! archive. It refuses what it does not model: sparse files, entry types
//! charts do not use, and a few archives Go reads (a stream that ends inside
//! padding, an extension header over [`MAX_HEADER_DATA`], a negative size).

use std::io::{self, Read};

/// The size of a header, and the unit data is padded to.
const BLOCK: usize = 512;

/// The longest PAX header or GNU long name read. Go reads up to 1 MiB; the
/// names in a chart are far shorter.
const MAX_HEADER_DATA: u64 = 64 * 1024;

/// An entry of an archive, as Go's `tar.Reader.Next` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its name (`Header.Name`): the header's own, joined to a ustar prefix,
    /// or taken from a PAX `path` record or a GNU long name. Bytes, as in a
    /// Go string.
    pub name: Vec<u8>,
    /// Its type flag. An old-style regular entry (`\0`) reads as `0`, or as
    /// a directory (`5`) when its name ends with `/`, as in Go.
    pub typeflag: u8,
    /// Its mode field (`Header.Mode`).
    pub mode: i64,
    /// The length of its data: 0 for the types that have none (links,
    /// devices, directories, FIFOs), whatever the header says.
    pub size: u64,
}

impl Entry {
    /// Whether Go's `Header.FileInfo().IsDir()` holds: a directory by its
    /// type, or by the file type bits of its mode, whatever its type.
    pub fn is_dir(&self) -> bool {
        // Go converts the mode to a 32-bit `fs.FileMode`.
        self.typeflag == b'5' || (self.mode as u32) & !0o7777 == 0o040000
    }
}

/// The entries of a tar stream, one at a time.
pub struct Archive<R> {
    reader: R,
    /// The current entry's data not read yet.
    unread: u64,
    /// The padding after the current entry's data.
    padding: u64,
    /// Whether the end of the archive was reached.
    ended: bool,
}

impl<R: Read> Archive<R> {
    /// Read the archive in `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            unread: 0,
            padding: 0,
            ended: false,
        }
    }

    /// The next entry, after skipping what is left of the current one;
    /// `None` at the end of the archive. Extended headers and GNU long names
    /// apply to the entry after them and are not entries; a global PAX
    /// header (`g`) is one, as in Go, and ends what came before it.
    pub fn next_entry(&mut self) -> io::Result<Option<Entry>> {
        if self.ended {
            return Ok(None);
        }
        skip(&mut self.reader, self.unread + self.padding)?;
        self.unread = 0;
        self.padding = 0;
        // What extension headers say about the entry after them. Go keeps
        // the last extended header, and the last long name.
        let mut pax: Option<Pax> = None;
        let mut long_name: Vec<u8> = Vec::new();
        loop {
            let Some(header) = self.read_header()? else {
                self.ended = true;
                return Ok(None);
            };
            match header.typeflag {
                b'x' | b'g' => {
                    let records = Pax::parse(&self.special_data(&header)?)?;
                    if header.typeflag == b'g' {
                        let path = records.path.filter(|p| !p.is_empty());
                        return Ok(Some(Entry {
                            name: path.unwrap_or(header.name),
                            typeflag: b'g',
                            mode: 0,
                            size: 0,
                        }));
                    }
                    pax = Some(records);
                }
                b'L' | b'K' => {
                    let data = self.special_data(&header)?;
                    // A long link name only names a link's target.
                    if header.typeflag == b'L' {
                        long_name = c_string(&data).to_vec();
                    }
                }
                b'S' => return Err(invalid("the archive holds a GNU sparse file")),
                typeflag => {
                    let mut name = header.name;
                    let mut size = header.size;
                    if let Some(pax) = pax {
                        pax.check()?;
                        if let Some(path) = pax.path.filter(|p| !p.is_empty()) {
                            name = path;
                        }
                        if let Some(value) = pax.size.filter(|s| !s.is_empty()) {
                            size = decimal(&value).ok_or_else(|| invalid("bad PAX size record"))?;
                        }
                    }
                    // A GNU long name wins over a PAX path, in either order.
                    if !long_name.is_empty() {
                        name = long_name;
                    }
                    let typeflag = match typeflag {
                        0 if name.ends_with(b"/") => b'5',
                        0 => b'0',
                        other => other,
                    };
                    if !matches!(typeflag, b'0'..=b'7') {
                        return Err(invalid(&format!(
                            "the archive holds an entry of type {:?}",
                            char::from(typeflag)
                        )));
                    }
                    let size = u64::try_from(size).map_err(|_| invalid("negative tar size"))?;
                    // Links, devices, directories and FIFOs have no data,
                    // whatever their size says.
                    let size = if matches!(typeflag, b'1'..=b'6') {
                        0
                    } else {
                        size
                    };
                    self.unread = size;
                    self.padding = padding(size);
                    return Ok(Some(Entry {
                        name,
                        typeflag,
                        mode: header.mode,
                        size,
                    }));
                }
            }
        }
    }

    /// The current entry's data. An entry larger than `max` bytes is an
    /// error.
    pub fn read_data(&mut self, max: u64) -> io::Result<Vec<u8>> {
        if self.unread > max {
            return Err(invalid(&format!("larger than {max} bytes")));
        }
        let data = read_exact(&mut self.reader, self.unread)?;
        self.unread = 0;
        Ok(data)
    }

    /// The next header; `None` at the end of the archive: the end of the
    /// stream before a header or after one zero block, or two zero blocks.
    /// A zero block followed by anything else is an error, as in Go.
    fn read_header(&mut self) -> io::Result<Option<Header>> {
        let mut block = [0u8; BLOCK];
        if !read_block(&mut self.reader, &mut block)? {
            return Ok(None);
        }
        if block.iter().all(|&b| b == 0) {
            if !read_block(&mut self.reader, &mut block)? || block.iter().all(|&b| b == 0) {
                return Ok(None);
            }
            return Err(invalid("a zero block in the middle of the archive"));
        }
        let header = Header::parse(&block)?;
        if header.size < 0 {
            return Err(invalid("negative tar size"));
        }
        Ok(Some(header))
    }

    /// The data of an extension header, and its padding skipped.
    fn special_data(&mut self, header: &Header) -> io::Result<Vec<u8>> {
        let size = header.size as u64;
        if size > MAX_HEADER_DATA {
            return Err(invalid("oversized tar extension header"));
        }
        let data = read_exact(&mut self.reader, size)?;
        skip(&mut self.reader, padding(size))?;
        Ok(data)
    }
}

/// The fields of a header block that Go's reader uses.
struct Header {
    /// The name, joined to the prefix of the header's format.
    name: Vec<u8>,
    /// The type flag, as written.
    typeflag: u8,
    /// The size field, which an extended header may replace.
    size: i64,
    /// The mode field.
    mode: i64,
}

/// The header formats Go tells apart by their magic.
#[derive(PartialEq)]
enum Format {
    /// No magic: no prefix, no user or device fields.
    V7,
    /// `ustar\0`, which PAX archives use too: a 155-byte prefix.
    Ustar,
    /// `ustar  \0`: times where ustar has its prefix.
    Gnu,
    /// `ustar\0` and `tar\0` at the end: a 131-byte prefix, then times.
    Star,
}

impl Header {
    /// Parse a header block as Go's `Reader.readHeader` does.
    fn parse(block: &[u8; BLOCK]) -> io::Result<Self> {
        let format = format(block).ok_or_else(|| invalid("bad tar header checksum"))?;
        let mut fields = Numbers::default();
        let mode = fields.numeric(&block[100..108]);
        fields.numeric(&block[108..116]); // uid
        fields.numeric(&block[116..124]); // gid
        let size = fields.numeric(&block[124..136]);
        fields.numeric(&block[136..148]); // mtime
        if format != Format::V7 {
            fields.numeric(&block[329..337]); // devmajor
            fields.numeric(&block[337..345]); // devminor
        }
        let prefix = match format {
            Format::V7 => &[],
            Format::Ustar => c_string(&block[345..500]),
            Format::Star => {
                fields.numeric(&block[476..488]); // atime
                fields.numeric(&block[488..500]); // ctime
                c_string(&block[345..476])
            }
            // A GNU header has times where ustar has its prefix. Go reads
            // them as a prefix after all when they are no times (old Go
            // versions wrote GNU headers with a prefix) and it is ASCII.
            Format::Gnu => {
                let mut times = Numbers::default();
                if block[345] != 0 {
                    times.numeric(&block[345..357]);
                }
                if block[357] != 0 {
                    times.numeric(&block[357..369]);
                }
                let prefix = c_string(&block[345..500]);
                if times.failed && prefix.is_ascii() {
                    prefix
                } else {
                    &[]
                }
            }
        };
        if fields.failed {
            return Err(invalid("bad tar header field"));
        }
        let name = c_string(&block[0..100]);
        Ok(Self {
            name: if prefix.is_empty() {
                name.to_vec()
            } else {
                [prefix, b"/", name].concat()
            },
            typeflag: block[156],
            size,
            mode,
        })
    }
}

/// The format of a header block; `None` when its checksum is wrong. Go
/// accepts the unsigned sum of the bytes and the signed one (Sun tar).
fn format(block: &[u8; BLOCK]) -> Option<Format> {
    let mut fields = Numbers::default();
    let stored = fields.octal(&block[148..156]);
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &b) in block.iter().enumerate() {
        // The checksum field counts as spaces.
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += i64::from(b);
        signed += i64::from(b as i8);
    }
    if fields.failed || (stored != unsigned && stored != signed) {
        return None;
    }
    let (magic, version, trailer) = (&block[257..263], &block[263..265], &block[508..512]);
    Some(if magic == b"ustar\0" && trailer == b"tar\0" {
        Format::Star
    } else if magic == b"ustar\0" {
        Format::Ustar
    } else if magic == b"ustar " && version == b" \0" {
        Format::Gnu
    } else {
        Format::V7
    })
}

/// Go's reader of numeric header fields; `failed` is set by any field it
/// cannot read, like Go's `parser.err`.
#[derive(Default)]
struct Numbers {
    failed: bool,
}

impl Numbers {
    /// An octal field, or GNU base-256 (two's complement) when its first
    /// bit is set (Go's `parseNumeric`).
    fn numeric(&mut self, field: &[u8]) -> i64 {
        if field[0] & 0x80 == 0 {
            return self.octal(field);
        }
        let inverse = if field[0] & 0x40 != 0 { 0xff } else { 0 };
        let mut n: u64 = 0;
        for (i, &b) in field.iter().enumerate() {
            let mut b = b ^ inverse;
            if i == 0 {
                b &= 0x7f;
            }
            if n >> 56 > 0 {
                self.failed = true;
                return 0;
            }
            n = n << 8 | u64::from(b);
        }
        if n >> 63 > 0 {
            self.failed = true;
            return 0;
        }
        if inverse == 0xff {
            !(n as i64)
        } else {
            n as i64
        }
    }

    /// An octal field: NULs and spaces trimmed from both ends, then the
    /// digits up to the first NUL (Go's `parseOctal`).
    fn octal(&mut self, field: &[u8]) -> i64 {
        let padding = |b: &u8| *b == b' ' || *b == 0;
        let start = field.iter().position(|b| !padding(b));
        let end = field.iter().rposition(|b| !padding(b));
        let (Some(start), Some(end)) = (start, end) else {
            return 0;
        };
        let mut n: u64 = 0;
        for &b in c_string(&field[start..=end]) {
            let next = match b {
                b'0'..=b'7' => n
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(u64::from(b - b'0'))),
                _ => None,
            };
            let Some(next) = next else {
                self.failed = true;
                return 0;
            };
            n = next;
        }
        n as i64
    }
}

/// The records of a PAX extended header that bear on an entry. A key given
/// twice keeps its last value, as in Go.
#[derive(Default)]
struct Pax {
    /// `path`: the entry's name.
    path: Option<Vec<u8>>,
    /// `size`: the length of the entry's data.
    size: Option<Vec<u8>>,
    /// `uid`.
    uid: Option<Vec<u8>>,
    /// `gid`.
    gid: Option<Vec<u8>>,
    /// `atime`, `mtime` and `ctime`.
    times: [Option<Vec<u8>>; 3],
}

impl Pax {
    /// Parse the records of a PAX header (`"<length> <key>=<value>\n"`,
    /// Go's `parsePAX`). GNU sparse records, which describe a sparse file's
    /// layout and may rename it, are refused.
    fn parse(mut data: &[u8]) -> io::Result<Self> {
        let bad = || invalid("bad PAX record");
        let mut pax = Self::default();
        while !data.is_empty() {
            // The length, of the whole record, ends at the first space.
            let space = data.iter().position(|&b| b == b' ').ok_or_else(bad)?;
            let length = decimal(&data[..space]).ok_or_else(bad)?;
            if length < 5 || length > data.len() as i64 {
                return Err(bad());
            }
            let length = length as usize;
            if length <= space + 1 || data[length - 1] != b'\n' {
                return Err(bad());
            }
            let record = &data[space + 1..length - 1];
            data = &data[length..];
            let equals = record.iter().position(|&b| b == b'=').ok_or_else(bad)?;
            let (key, value) = (&record[..equals], record[equals + 1..].to_vec());
            let field = match key {
                b"" => return Err(bad()),
                b"path" | b"linkpath" | b"uname" | b"gname" if value.contains(&0) => {
                    return Err(bad())
                }
                _ if key.contains(&0) => return Err(bad()),
                _ if key.starts_with(b"GNU.sparse.") => {
                    return Err(invalid("the archive holds a GNU sparse file"))
                }
                b"path" => &mut pax.path,
                b"size" => &mut pax.size,
                b"uid" => &mut pax.uid,
                b"gid" => &mut pax.gid,
                b"atime" => &mut pax.times[0],
                b"mtime" => &mut pax.times[1],
                b"ctime" => &mut pax.times[2],
                _ => continue,
            };
            *field = Some(value);
        }
        Ok(pax)
    }

    /// Refuse the records Go cannot apply to an entry (`mergePAX`). Empty
    /// values are ignored, as in Go.
    fn check(&self) -> io::Result<()> {
        let bad = || invalid("bad PAX record");
        for id in [&self.uid, &self.gid].into_iter().flatten() {
            if !id.is_empty() {
                decimal(id).ok_or_else(bad)?;
            }
        }
        // Seconds, and an optional fraction.
        for time in self.times.iter().flatten().filter(|t| !t.is_empty()) {
            let (seconds, fraction) = match time.iter().position(|&b| b == b'.') {
                Some(dot) => (&time[..dot], &time[dot + 1..]),
                None => (&time[..], &[][..]),
            };
            decimal(seconds).ok_or_else(bad)?;
            if !fraction.iter().all(u8::is_ascii_digit) {
                return Err(bad());
            }
        }
        Ok(())
    }
}

/// A decimal integer with an optional sign, as Go's `strconv.ParseInt(s,
/// 10, 64)` reads it.
fn decimal(text: &[u8]) -> Option<i64> {
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    if digits.is_empty() {
        return None;
    }
    let mut n: i64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = i64::from(b - b'0');
        n = n.checked_mul(10)?;
        n = if negative {
            n.checked_sub(digit)?
        } else {
            n.checked_add(digit)?
        };
    }
    Some(n)
}

/// An error for an archive Forge does not read.
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// The padding after `size` bytes of data, to the end of their last block.
fn padding(size: u64) -> u64 {
    size.next_multiple_of(BLOCK as u64) - size
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

/// The next `len` bytes; an error when the stream ends first.
fn read_exact(r: &mut impl Read, len: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    r.take(len).read_to_end(&mut data)?;
    if data.len() as u64 != len {
        return Err(invalid("truncated tar entry"));
    }
    Ok(data)
}

/// Skip `len` bytes; an error when the stream ends first.
fn skip(r: &mut impl Read, len: u64) -> io::Result<()> {
    let skipped = io::copy(&mut r.take(len), &mut io::sink())?;
    if skipped != len {
        return Err(invalid("truncated tar entry"));
    }
    Ok(())
}

/// The bytes up to the first NUL (Go's `parseString`).
fn c_string(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ustar header (mode 0644) with a valid checksum.
    pub(crate) fn header(name: &[u8], typeflag: u8, size: u64) -> [u8; BLOCK] {
        let mut header = [0u8; BLOCK];
        header[..name.len()].copy_from_slice(name);
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        seal(&mut header);
        header
    }

    /// Write the checksum of `header`, after changing it.
    pub(crate) fn seal(header: &mut [u8; BLOCK]) {
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    /// `header` followed by `data`, padded to whole blocks.
    pub(crate) fn entry(header: [u8; BLOCK], data: &[u8]) -> Vec<u8> {
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(BLOCK), 0);
        out
    }

    /// A regular file.
    pub(crate) fn file(path: &str, data: &[u8]) -> Vec<u8> {
        entry(header(path.as_bytes(), b'0', data.len() as u64), data)
    }

    /// A GNU long name (`L`) or long link name (`K`).
    pub(crate) fn long(typeflag: u8, name: &str) -> Vec<u8> {
        let data = [name.as_bytes(), b"\0"].concat();
        entry(header(b"././@LongLink", typeflag, data.len() as u64), &data)
    }

    /// A PAX header of type `typeflag` (`x` or `g`) holding `records`.
    pub(crate) fn pax(typeflag: u8, records: &[(&str, &str)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (key, value) in records {
            let body = format!(" {key}={value}\n");
            // The length counts its own digits.
            let mut length = body.len();
            while length != length.to_string().len() + body.len() {
                length = length.to_string().len() + body.len();
            }
            data.extend_from_slice(format!("{length}{body}").as_bytes());
        }
        entry(
            header(b"PaxHeaders.0/x", typeflag, data.len() as u64),
            &data,
        )
    }

    /// The end of an archive: two zero blocks.
    pub(crate) const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

    /// A minimal ustar archive of `(path, contents)` entries.
    pub(crate) fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = entries
            .iter()
            .flat_map(|(path, data)| file(path, data))
            .collect();
        out.extend_from_slice(&END);
        out
    }

    /// Every entry of `tar`: its name, type and data.
    fn entries(tar: &[u8]) -> io::Result<Vec<(String, u8, Vec<u8>)>> {
        let mut archive = Archive::new(tar);
        let mut out = Vec::new();
        while let Some(entry) = archive.next_entry()? {
            let data = archive.read_data(u64::MAX)?;
            assert_eq!(data.len() as u64, entry.size);
            let name = String::from_utf8_lossy(&entry.name).into_owned();
            out.push((name, entry.typeflag, data));
        }
        Ok(out)
    }

    /// The names of the entries of `tar`.
    fn names(tar: &[u8]) -> Vec<String> {
        entries(tar)
            .unwrap()
            .into_iter()
            .map(|(n, _, _)| n)
            .collect()
    }

    #[test]
    fn reads_entries_and_their_data() {
        let tar = archive(&[
            ("demo/values.yaml", b"replicas: 1\n"),
            ("demo/Chart.yaml", b"name: demo\n"),
        ]);
        assert_eq!(
            entries(&tar).unwrap(),
            [
                ("demo/values.yaml".into(), b'0', b"replicas: 1\n".to_vec()),
                ("demo/Chart.yaml".into(), b'0', b"name: demo\n".to_vec()),
            ]
        );
        // Data not read is skipped.
        let mut archive = Archive::new(&tar[..]);
        archive.next_entry().unwrap();
        assert!(archive.read_data(4).is_err());
        let second = archive.next_entry().unwrap().unwrap();
        assert_eq!(second.name, b"demo/Chart.yaml");
        assert_eq!(archive.next_entry().unwrap(), None);
        assert_eq!(archive.next_entry().unwrap(), None);
        // Truncated: in the data, in the padding, in a header.
        assert!(entries(&tar[..520]).is_err());
        assert!(entries(&tar[..700]).is_err());
        assert!(entries(&tar[..1030]).is_err());
    }

    #[test]
    fn ends_like_go() {
        let one = file("demo/a", b"a");
        // The stream ends before a header, or after one zero block.
        assert_eq!(names(&one), ["demo/a"]);
        assert_eq!(names(&[&one[..], &[0; BLOCK]].concat()), ["demo/a"]);
        // Two zero blocks end the archive; what follows is not read.
        let after = [&one[..], &END, &file("demo/b", b"b")].concat();
        assert_eq!(names(&after), ["demo/a"]);
        // A zero block followed by a header is an error, not the end.
        let hidden = [&one[..], &[0; BLOCK], &file("demo/b", b"b")].concat();
        assert!(entries(&hidden).is_err());
    }

    #[test]
    fn checks_header_checksums() {
        let mut bad = header(b"demo/a", b'0', 0);
        bad[0] = b'x';
        assert!(entries(&[&bad[..], &END].concat()).is_err());
        // Go accepts the signed sum too (Sun tar).
        let mut signed = header("demo/é".as_bytes(), b'0', 0);
        let sum: i64 = signed
            .iter()
            .enumerate()
            .map(|(i, &b)| if (148..156).contains(&i) { b' ' } else { b })
            .map(|b| i64::from(b as i8))
            .sum();
        signed[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert_eq!(names(&[&signed[..], &END].concat()), ["demo/é"]);
    }

    #[test]
    fn reads_numeric_fields_like_go() {
        // Leading NULs and spaces are padding, not the end of the number.
        let mut padded = header(b"demo/a", b'0', 0);
        padded[124..136].copy_from_slice(b"\0 0000000003");
        seal(&mut padded);
        let tar = [&entry(padded, b"abc")[..], &END].concat();
        assert_eq!(entries(&tar).unwrap()[0].2, b"abc");
        // GNU base-256.
        let mut binary = header(b"demo/a", b'0', 0);
        binary[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        seal(&mut binary);
        let tar = [&entry(binary, b"abc")[..], &END].concat();
        assert_eq!(entries(&tar).unwrap()[0].2, b"abc");
        // What Go cannot read: a sign, a digit that is not octal, a mode
        // in hexadecimal.
        for (field, value) in [
            (124..136, &b"+0000000003\0"[..]),
            (124..136, b"0000000009\0\0"),
            (100..108, b"0x644\0\0\0"),
        ] {
            let mut bad = header(b"demo/a", b'0', 3);
            bad[field].copy_from_slice(value);
            seal(&mut bad);
            assert!(entries(&[&entry(bad, b"abc")[..], &END].concat()).is_err());
        }
    }

    #[test]
    fn joins_a_ustar_prefix_but_not_gnu_times() {
        let mut ustar = header(b"Chart.yaml", b'0', 0);
        ustar[345..349].copy_from_slice(b"demo");
        seal(&mut ustar);
        assert_eq!(names(&[&ustar[..], &END].concat()), ["demo/Chart.yaml"]);

        // A GNU header has times where ustar has its prefix.
        let gnu = |times: &[u8]| {
            let mut gnu = header(b"demo/Chart.yaml", b'0', 0);
            gnu[257..265].copy_from_slice(b"ustar  \0");
            gnu[345..345 + times.len()].copy_from_slice(times);
            seal(&mut gnu);
            names(&[&gnu[..], &END].concat())
        };
        assert_eq!(gnu(b"14567012345\0"), ["demo/Chart.yaml"]);
        // Junk that reads as octal times stays times.
        assert_eq!(gnu(b"7\0junk"), ["demo/Chart.yaml"]);
        // Junk that does not is a prefix to Go (old Go versions wrote one),
        // when it is ASCII.
        assert_eq!(gnu(b"evil"), ["evil/demo/Chart.yaml"]);
        assert_eq!(gnu("évil".as_bytes()), ["demo/Chart.yaml"]);

        // STAR: a shorter prefix, then times.
        let mut star = header(b"Chart.yaml", b'0', 0);
        star[345..349].copy_from_slice(b"demo");
        star[508..512].copy_from_slice(b"tar\0");
        seal(&mut star);
        assert_eq!(names(&[&star[..], &END].concat()), ["demo/Chart.yaml"]);

        // V7, without a magic: no prefix.
        let mut v7 = header(b"demo/Chart.yaml", b'0', 0);
        v7[257..265].fill(0);
        v7[345..349].copy_from_slice(b"evil");
        seal(&mut v7);
        assert_eq!(names(&[&v7[..], &END].concat()), ["demo/Chart.yaml"]);
    }

    #[test]
    fn applies_pax_records_like_go() {
        // A PAX path renames the next entry only.
        let tar = [
            &pax(b'x', &[("mtime", "1.5"), ("path", "demo/values.yaml")])[..],
            &file("x", b"a: 1\n"),
            &file("demo/b", b""),
            &END,
        ]
        .concat();
        assert_eq!(names(&tar), ["demo/values.yaml", "demo/b"]);
        // A key given twice keeps its last value; an empty one keeps the
        // header's name.
        let twice = [
            &pax(b'x', &[("path", "demo/a"), ("path", "demo/b")])[..],
            &file("x", b""),
            &pax(b'x', &[("path", "")]),
            &file("demo/c", b""),
            &END,
        ]
        .concat();
        assert_eq!(names(&twice), ["demo/b", "demo/c"]);
        // Only the last extended header before an entry counts.
        let last = [
            &pax(b'x', &[("path", "demo/a")])[..],
            &pax(b'x', &[("mtime", "1")]),
            &file("demo/b", b""),
            &END,
        ]
        .concat();
        assert_eq!(names(&last), ["demo/b"]);

        // A PAX size moves the end of the entry's data: what its header
        // calls data is the next entry.
        let chart = file("demo/Chart.yaml", b"name: demo\n");
        let sized = [
            &pax(b'x', &[("size", "0")])[..],
            &entry(header(b"demo/a", b'0', chart.len() as u64), &chart),
            &END,
        ]
        .concat();
        assert_eq!(names(&sized), ["demo/a", "demo/Chart.yaml"]);

        // Records Go cannot apply, and sparse files.
        for records in [
            &[("size", "x")][..],
            &[("uid", "1x")],
            &[("mtime", "1.x")],
            &[("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0")],
            &[("GNU.sparse.name", "demo/Chart.yaml")],
        ] {
            let tar = [&pax(b'x', records)[..], &file("demo/a", b""), &END].concat();
            assert!(entries(&tar).is_err(), "{records:?}");
        }
        // A record longer than the header.
        let malformed = [
            &entry(header(b"x", b'x', 11), b"13 path=ab\n")[..],
            &file("demo/a", b""),
            &END,
        ]
        .concat();
        assert!(entries(&malformed).is_err());
    }

    #[test]
    fn applies_gnu_long_names_like_go() {
        // A long name renames the next entry; a long link name does not,
        // and does not take the long name before it.
        let tar = [
            &long(b'L', "demo/values.yaml")[..],
            &file("x", b""),
            &long(b'L', "demo/Chart.yaml"),
            &long(b'K', "demo/target"),
            &file("demo/a", b""),
            &END,
        ]
        .concat();
        assert_eq!(names(&tar), ["demo/values.yaml", "demo/Chart.yaml"]);
        // A long name wins over a PAX path, before it or after it.
        for (first, second) in [
            (long(b'L', "demo/long"), pax(b'x', &[("path", "demo/pax")])),
            (pax(b'x', &[("path", "demo/pax")]), long(b'L', "demo/long")),
        ] {
            let tar = [&first[..], &second, &file("x", b""), &END].concat();
            assert_eq!(names(&tar), ["demo/long"]);
        }
    }

    #[test]
    fn a_global_header_is_an_entry_of_its_own() {
        // It ends what came before it: the long name applies to no entry.
        let tar = [
            &long(b'L', "demo/Chart.yaml")[..],
            &pax(b'g', &[("comment", "abc")]),
            &file("demo/a", b""),
            &END,
        ]
        .concat();
        let entries = entries(&tar).unwrap();
        assert_eq!(entries[0].1, b'g');
        assert_eq!(entries[1].0, "demo/a");
    }

    #[test]
    fn types_without_data_have_none() {
        // A symlink's size does not make the next header its data.
        let chart = file("demo/Chart.yaml", b"name: demo\n");
        for typeflag in *b"123456" {
            let tar = [
                &header(b"demo/link", typeflag, chart.len() as u64)[..],
                &chart,
                &END,
            ]
            .concat();
            assert_eq!(names(&tar), ["demo/link", "demo/Chart.yaml"]);
        }
        // An old-style regular entry named with a `/` is a directory.
        let tar = [
            &header(b"demo/", 0, chart.len() as u64)[..],
            &entry(header(b"demo/a", 0, 1), b"a"),
            &chart,
            &END,
        ]
        .concat();
        let entries = entries(&tar).unwrap();
        assert_eq!((entries[0].1, entries[1].1), (b'5', b'0'));
        assert_eq!(entries[2].0, "demo/Chart.yaml");
    }

    #[test]
    fn a_directory_by_its_mode() {
        let mut dir = header(b"demo/Chart.yaml", b'0', 0);
        dir[100..108].copy_from_slice(b"0040755\0");
        seal(&mut dir);
        let tar = [&dir[..], &END].concat();
        let mut archive = Archive::new(&tar[..]);
        assert!(archive.next_entry().unwrap().unwrap().is_dir());
        let tar = [&header(b"demo/a", b'0', 0)[..], &END].concat();
        let mut archive = Archive::new(&tar[..]);
        assert!(!archive.next_entry().unwrap().unwrap().is_dir());
    }

    #[test]
    fn refuses_what_it_does_not_model() {
        for typeflag in *b"SDMVA" {
            let tar = [&header(b"demo/a", typeflag, 0)[..], &END].concat();
            assert!(entries(&tar).is_err(), "{}", char::from(typeflag));
        }
        let mut negative = header(b"demo/a", b'0', 0);
        negative[124..136].copy_from_slice(&[0xff; 12]);
        seal(&mut negative);
        assert!(entries(&[&negative[..], &END].concat()).is_err());
    }
}
