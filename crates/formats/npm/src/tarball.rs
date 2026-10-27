//! Reading a package tarball the way npm installs it.
//!
//! npm (pacote) unpacks a tarball with node-tar and `strip: 1`: the first
//! component of every path is dropped, whatever it is called (`package/` by
//! convention), so the package's `package.json` is the entry
//! `<first>/package.json`. When several entries map to it, the last one wins
//! on disk, so the last one is read. A file is any entry node-tar unpacks as
//! one: a regular file (`0`, or NUL in the old form) or a contiguous file
//! (`7`). A directory is one of type `5`, or of type `0` whose path ends in
//! `/`, as old tars wrote them; it has no body to node-tar. The whole archive
//! is read, every gzip member of it, bounded in what it unpacks to.
//!
//! Where node-tar would read the archive otherwise than its headers lay it
//! out, the tarball is refused rather than read one way (#554): a header
//! node-tar rejects (it then reads the block after it as the next header, so
//! the body `tar` skips holds entries only npm sees), a PAX record it would
//! skip or read otherwise, data after the end of the archive (node-tar reads
//! on after one zero block), and a file some client could unpack to
//! `package.json` otherwise than by node-tar's strip on Linux (`\`, `.` or
//! empty components, another case). `npm pack` writes none of these.

use std::io::{self, BufRead, Read};

use serde_json::{Map, Value};

/// The most a tarball may unpack to by default: 1 GiB.
pub const DEFAULT_MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

/// The largest `package.json` read.
pub const MAX_PACKAGE_JSON_BYTES: u64 = 8 * 1024 * 1024;

/// The largest GNU long name or PAX extended header read. They name a path
/// of a few hundred bytes; the cap is the chart reader's.
const MAX_HEADER_ENTRY_BYTES: u64 = 64 * 1024;

/// What a tarball holds, as far as the registry cares.
#[derive(Debug, Clone, PartialEq)]
pub struct Tarball {
    /// The `package.json` npm installs, as an object.
    pub package_json: Map<String, Value>,
    /// Its `name`.
    pub name: String,
    /// Its `version`, as written.
    pub version: String,
    /// Files in the archive (`dist.fileCount`).
    pub file_count: u64,
    /// Their unpacked size (`dist.unpackedSize`).
    pub unpacked_size: u64,
}

/// A gzip stream inflated as npm inflates it (minizlib, on Node's zlib):
/// member after member, until the input ends or a member is followed by a
/// zero byte, the padding old tarballs carry (`npm` once padded them to
/// 10 KiB). Node's zlib ignores what follows that byte; here it must be zeros
/// to the end.
struct Gunzip<R: BufRead> {
    member: Option<flate2::bufread::GzDecoder<R>>,
}

impl<R: BufRead> Read for Gunzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(member) = self.member.as_mut() else {
                return Ok(0);
            };
            let n = member.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            let mut input = self.member.take().expect("a member").into_inner();
            match input.fill_buf()?.first() {
                None => return Ok(0),
                Some(0) => loop {
                    let padding = input.fill_buf()?;
                    if padding.is_empty() {
                        return Ok(0);
                    }
                    if padding.iter().any(|b| *b != 0) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "data after the gzip stream's padding",
                        ));
                    }
                    let len = padding.len();
                    input.consume(len);
                },
                Some(_) => self.member = Some(flate2::bufread::GzDecoder::new(input)),
            }
        }
    }
}

/// `path` without a leading Windows drive (`c:`), which node-tar strips as a
/// root of the path before the first component is (`strip-absolute-path.js`
/// parses with Windows' rules, also on Linux).
fn without_drive(path: &[u8]) -> Option<&[u8]> {
    match path {
        [letter, b':', rest @ ..] if letter.is_ascii_alphabetic() => Some(rest),
        _ => None,
    }
}

/// Whether npm unpacks the file `path` to the package's `package.json`:
/// `<first>/package.json`, as node-tar strips the first component
/// (`strip: 1`) and resolves the rest (a trailing `/` included) on Linux and
/// macOS. The first component is a plain name: not empty, `.` or `..`, no
/// `\` and no drive, which node-tar or Windows read otherwise.
fn is_manifest(path: &[u8]) -> bool {
    let Some(slash) = path.iter().position(|b| *b == b'/') else {
        return false;
    };
    let (first, rest) = (&path[..slash], &path[slash + 1..]);
    let plain = !first.is_empty()
        && first != b"."
        && first != b".."
        && !first.contains(&b'\\')
        && without_drive(first).is_none();
    let end = rest.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
    plain && &rest[..end] == b"package.json"
}

/// Whether `path` starts with what node-tar's `stripAbsolutePath` takes for
/// a root and strips (Windows' rules, also on Linux): a `/` or `\`, which
/// begins a UNC (`\\server\share\`) or device (`\\?\C:\`) root too, or a
/// drive (`c:`).
fn rooted(path: &[u8]) -> bool {
    matches!(path, [b'/' | b'\\', ..]) || without_drive(path).is_some()
}

/// Whether some client could unpack the file `path` to `package.json`
/// although [`is_manifest`] says no: node-tar resolves `.` and empty
/// components after the strip, takes `..` and a drive or a leading `/` for a
/// root before it, Windows also splits at `\` and drops trailing dots and
/// spaces, and macOS and Windows ignore case.
///
/// node-tar also strips every root it finds at the start of the path, before
/// the first component is stripped (node-tar 6 and 7.4, npm 10) or after it
/// (7.5, npm 11.20 and later): `\\srv\share\package.json`, `C:C:package.json`
/// and `package/c:package.json` are all unpacked to `package.json`. Such a
/// rooted path naming a `package.json` (with drives before the name, as in
/// `c:c:package.json`) is taken for one whatever the root holds.
fn may_be_manifest(path: &[u8]) -> bool {
    let named = |part: &[u8]| {
        let end = part
            .iter()
            .rposition(|b| *b != b'.' && !b.is_ascii_whitespace())
            .map_or(0, |i| i + 1);
        part[..end].eq_ignore_ascii_case(b"package.json")
    };
    let after_first = path
        .iter()
        .position(|b| *b == b'/')
        .map(|slash| &path[slash + 1..]);
    if [Some(path), after_first].into_iter().flatten().any(rooted) {
        let mut last = path
            .split(|b| *b == b'/' || *b == b'\\')
            .rfind(|part| !part.is_empty() && *part != b".")
            .unwrap_or_default();
        while let Some(rest) = without_drive(last) {
            last = rest;
        }
        if named(last) {
            return true;
        }
    }
    [Some(path), without_drive(path)]
        .into_iter()
        .flatten()
        .any(|path| {
            [&b"/"[..], b"/\\"].into_iter().any(|separators| {
                let parts: Vec<&[u8]> = path
                    .split(|b| separators.contains(b))
                    .filter(|part| !part.is_empty() && *part != b".")
                    .collect();
                parts.len() <= 2 && parts.last().is_some_and(|last| named(last))
            })
        })
}

/// The name field of `header` alone, up to its first NUL: without the ustar
/// prefix, as node-tar reads it when it decides whether a `0` entry is a
/// directory.
fn name_field(header: &tar::Header) -> &[u8] {
    let name = &header.as_old().name;
    &name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())]
}

/// Whether `bytes` hold a line break as JavaScript's `.` sees one (`\n`,
/// `\r`, U+2028, U+2029).
fn has_line_break(bytes: &[u8]) -> bool {
    bytes.iter().any(|b| *b == b'\n' || *b == b'\r')
        || bytes
            .windows(3)
            .any(|w| w == [0xE2, 0x80, 0xA8] || w == [0xE2, 0x80, 0xA9])
}

/// Whether node-tar reads the string `field` as `tar` does, up to its first
/// NUL: node-tar's `replace(/\0.*/, '')` keeps what follows a line break
/// after that NUL.
fn reads_to_nul(field: &[u8]) -> bool {
    field
        .iter()
        .position(|b| *b == 0)
        .is_none_or(|nul| !has_line_break(&field[nul..]))
}

/// The base-256 number `field` holds as node-tar reads it
/// (`lib/large-numbers.js`): positive after `0x80`, two's complement after
/// `0xff`. `None` where node-tar throws: another first byte, or a number
/// past JavaScript's safe integers.
fn base256(field: &[u8]) -> Option<i128> {
    const SAFE: i128 = (1 << 53) - 1;
    let unsigned = |bytes: &[u8]| bytes.iter().fold(0i128, |n, b| n << 8 | i128::from(*b));
    let value = match field.first()? {
        0x80 => unsigned(&field[1..]),
        0xff => unsigned(field) - (1i128 << (8 * field.len())),
        _ => return None,
    };
    (-SAFE..=SAFE).contains(&value).then_some(value)
}

/// The octal number `field` holds as node-tar reads it (`decSmallNumber`,
/// `parseInt(_, 8)`): the leading octal digits after whitespace and a sign.
/// `None` for no digits, where node-tar reads `null`.
fn octal(field: &[u8]) -> Option<i128> {
    let text = field.trim_ascii_start();
    let (sign, text) = match text.first() {
        Some(b'-') => (-1, &text[1..]),
        Some(b'+') => (1, &text[1..]),
        _ => (1, text),
    };
    let digits = text
        .iter()
        .take_while(|b| (b'0'..=b'7').contains(b))
        .count();
    (digits > 0).then(|| {
        sign * text[..digits]
            .iter()
            .fold(0i128, |n, d| n * 8 + i128::from(d - b'0'))
    })
}

/// A number field as node-tar reads it: base-256 when its first byte has the
/// high bit, else octal.
fn number(field: &[u8]) -> Option<i128> {
    if field[0] & 0x80 != 0 {
        base256(field)
    } else {
        octal(field)
    }
}

/// Refuse the header `header` of an entry of `size` bytes where node-tar
/// reads it otherwise than `tar` (`lib/header.js`, `lib/parse.js`): node-tar
/// rejects a header with a warning, skips its 512 bytes alone and reads the
/// next block as a header, so a body `tar` skips would hold entries only npm
/// sees. `extended_path`: a GNU long name or PAX header names the entry.
fn check_header(header: &tar::Header, size: u64, extended_path: bool) -> Result<(), String> {
    let b = header.as_bytes();
    let refuse = |why: &str| {
        Err(format!(
            "the tarball has a header npm reads otherwise: {why}"
        ))
    };
    let ustar = &b[257..265] == b"ustar\x0000";
    // What node-tar decodes besides the size: mode, uid, gid and mtime; a
    // ustar header's device numbers, and its atime and ctime where the
    // prefix leaves them room. A base-256 number it cannot read throws.
    let mut fields = vec![(100, 8), (108, 8), (116, 8), (136, 12)];
    if ustar {
        fields.extend([(329, 8), (337, 8)]);
        if b[475] == 0 {
            fields.extend([(476, 12), (488, 12)]);
        }
    }
    if fields
        .into_iter()
        .any(|(at, len)| b[at] & 0x80 != 0 && base256(&b[at..at + len]).is_none())
    {
        return refuse("a base-256 number");
    }
    if number(&b[124..136]) != Some(i128::from(size)) {
        return refuse("its size");
    }
    // node-tar reads the checksum field over 12 bytes, into the type and the
    // link name, and sums the header unsigned as `tar` does.
    let sum = 8 * 0x20
        + b[..148]
            .iter()
            .chain(&b[156..])
            .map(|byte| i128::from(*byte))
            .sum::<i128>();
    if number(&b[148..160]) != Some(sum) {
        return refuse("its checksum");
    }
    let prefix = if ustar {
        Some(&b[345..if b[475] == 0 { 475 } else { 500 }])
    } else {
        None
    };
    let name = &b[..100];
    let link = &b[157..257];
    if !reads_to_nul(name) || !reads_to_nul(link) || prefix.is_some_and(|p| !reads_to_nul(p)) {
        return refuse("a string with a line break after its end");
    }
    // A prefix node-tar joins with `/` although `tar` reads it empty.
    if ustar && b[475] != 0 && b[345] == 0 {
        return refuse("an empty prefix");
    }
    if !extended_path && header.path_bytes().is_empty() {
        return refuse("an empty path");
    }
    let is_link = matches!(b[156], b'1' | b'2');
    if is_link == (link[0] == 0) {
        return refuse(if is_link {
            "a link without a target"
        } else {
            "a link target on an entry that is no link"
        });
    }
    Ok(())
}

/// Read the data of `entry`, a GNU long name or a PAX extended header of
/// `size` bytes, refusing one larger than [`MAX_HEADER_ENTRY_BYTES`].
fn header_entry(entry: &mut impl Read, size: u64, what: &str) -> Result<Vec<u8>, String> {
    if size > MAX_HEADER_ENTRY_BYTES {
        return Err(format!(
            "the tarball's {what} is larger than {MAX_HEADER_ENTRY_BYTES} bytes"
        ));
    }
    let mut data = Vec::with_capacity(size as usize);
    entry
        .read_to_end(&mut data)
        .map_err(|e| format!("unreadable {what}: {e}"))?;
    Ok(data)
}

/// The `path` and `size` records of the PAX header `data` (the last of each).
///
/// The records are read as the format defines them, each `<length>
/// <key>=<value>\n` of the length it states in plain decimal, and also as
/// node-tar reads them ([`node_tar_pax`]). A header is refused when the
/// records are not of the lengths they state, when a path is one node-tar
/// ignores (empty) or reads as a number (digits alone), when a size is not
/// plain digits, and when node-tar finds another path or size in it: a value
/// holding a line break or bytes that are not UTF-8 node-tar reads otherwise.
/// Other records may hold anything (GNU tar and bsdtar write a file's
/// extended attributes raw, `SCHILY.xattr.<name>`), as npm installs them.
fn pax(data: &[u8]) -> Result<(Option<Vec<u8>>, Option<u64>), String> {
    let refuse = |why: &str| format!("the tarball's PAX header has {why}");
    let (mut path, mut size) = (None, None);
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|b| *b == b' ' || *b == b'\n')
            .filter(|at| rest[*at] == b' ')
            .ok_or_else(|| refuse("a record without a length"))?;
        let length = &rest[..space];
        let plain =
            !length.is_empty() && length[0] != b'0' && length.iter().all(|b| b.is_ascii_digit());
        let length = std::str::from_utf8(length)
            .ok()
            .filter(|_| plain)
            .and_then(|l| l.parse::<usize>().ok())
            .filter(|l| *l > space + 1 && *l <= rest.len() && rest[*l - 1] == b'\n')
            .ok_or_else(|| refuse("a record whose length is not its own"))?;
        let record = &rest[space + 1..length - 1];
        rest = &rest[length..];
        let eq = record
            .iter()
            .position(|b| *b == b'=')
            .ok_or_else(|| refuse("a record without a value"))?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        let digits = !value.is_empty() && value.iter().all(|b| b.is_ascii_digit());
        match key {
            b"path" if value.is_empty() || digits || value.contains(&0) => {
                return Err(refuse("a path npm reads otherwise"));
            }
            b"path" => path = Some(value.to_vec()),
            b"size" => {
                size = Some(
                    std::str::from_utf8(value)
                        .ok()
                        .filter(|_| digits)
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| refuse("an unreadable size"))?,
                );
            }
            _ => {}
        }
    }
    let (npm_path, npm_size) = node_tar_pax(data);
    if npm_path.as_ref().map(String::as_bytes) != path.as_deref() || npm_size != size.map(Ok) {
        return Err(refuse("a record npm reads otherwise"));
    }
    Ok((path, size))
}

/// The `path` and `size` node-tar takes from the PAX header `data`
/// (`lib/parse.js`, `lib/pax.js`): it decodes the data as UTF-8 with
/// replacement characters, splits it at line breaks, and reads a line as a
/// record when `parseInt` finds the line's own length plus one at its start;
/// the key is what follows as many characters as that number and a space
/// take, up to the first `=`. A size that is not plain digits is `Err` (no
/// size node-tar is sure to read alike).
fn node_tar_pax(data: &[u8]) -> (Option<String>, Option<Result<u64, ()>>) {
    // JavaScript's white space and line terminators, which `parseInt` skips.
    let js_space = |c: char| {
        matches!(
            c,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    };
    let text = String::from_utf8_lossy(data);
    let text = text.strip_suffix('\n').unwrap_or(&text);
    let (mut path, mut size) = (None, None);
    for line in text.split('\n') {
        // `parseInt(line, 10)`.
        let number = line.trim_start_matches(js_space);
        let (negative, number) = match number.as_bytes().first() {
            Some(b'-') => (true, &number[1..]),
            Some(b'+') => (false, &number[1..]),
            _ => (false, number),
        };
        let digits = number.bytes().take_while(u8::is_ascii_digit).count();
        let Some(n) = number[..digits].parse::<u128>().ok().filter(|_| !negative) else {
            continue;
        };
        if n != line.len() as u128 + 1 {
            continue;
        }
        // `line.slice((n + ' ').length)`, in UTF-16 code units: a slice
        // that splits a character leaves no key node-tar reads.
        let skip = n.to_string().len() + 1;
        let (mut units, mut at) = (0, None);
        for (i, c) in line.char_indices() {
            if units >= skip {
                at = (units == skip).then_some(i);
                break;
            }
            units += c.len_utf16();
        }
        let Some(at) = at else {
            continue;
        };
        let Some((key, value)) = line[at..].split_once('=') else {
            continue;
        };
        // `.replace(/\0.*/, '')`: `.` stops at a line terminator.
        let value = match value.find('\0') {
            Some(nul) => {
                let after = &value[nul + 1..];
                let kept = after
                    .find(['\r', '\u{2028}', '\u{2029}'])
                    .map_or("", |end| &after[end..]);
                format!("{}{kept}", &value[..nul])
            }
            None => value.to_owned(),
        };
        match key {
            "path" => path = Some(value),
            "size" => {
                let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
                size = Some(value.parse().ok().filter(|_| digits).ok_or(()));
            }
            _ => {}
        }
    }
    (path, size)
}

/// Read the gzip-compressed tarball in `tgz`, refusing one that unpacks to
/// more than `max_unpacked` bytes or holds no `package.json` npm would read.
///
/// The entries are read raw: `tar` would read a GNU long name or a PAX
/// extended header whole, unbounded, before it hands back the entry it
/// names. They are read here instead, bounded ([`header_entry`]) and counted
/// against `max_unpacked` like any entry, and the path they give the next
/// entry is applied as npm (node-tar) applies it: the later one wins, old
/// forms included. A PAX `size` that is not the size of every header it
/// applies to (node-tar applies it up to the next entry that is no GNU long
/// name or PAX header) is refused (an npm tarball is far below the 8 GiB a
/// header holds, so the record only ever disagrees), as are a global one, a
/// GNU sparse entry, a directory whose header gives it a body, and the
/// headers [`check_header`] refuses: each would lay the archive out
/// otherwise than its headers do.
pub fn read(tgz: impl Read, max_unpacked: u64) -> Result<Tarball, String> {
    // npm (minizlib) reads every gzip member.
    let gz = Gunzip {
        member: Some(flate2::bufread::GzDecoder::new(io::BufReader::new(tgz))),
    };
    let mut archive = tar::Archive::new(gz);
    let entries = archive
        .entries()
        .map_err(|e| format!("not a gzip-compressed tar archive: {e}"))?
        .raw(true);
    let mut package_json: Option<Vec<u8>> = None;
    let mut file_count = 0u64;
    let mut unpacked = 0u64;
    // What a GNU long name or a PAX header says of the next entry.
    let mut next_path: Option<Vec<u8>> = None;
    let mut next_size: Option<u64> = None;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("unreadable tar entry: {e}"))?;
        let size = entry.header().entry_size().unwrap_or(0);
        unpacked = unpacked.saturating_add(size);
        if unpacked > max_unpacked {
            return Err(format!(
                "the tarball unpacks to more than {max_unpacked} bytes"
            ));
        }
        check_header(entry.header(), size, next_path.is_some())?;
        if next_size.is_some_and(|pax| pax != size) {
            return Err("the tarball's PAX header gives an entry another size than its own".into());
        }
        let kind = entry.header().entry_type();
        // The entries node-tar reads as describing the next one.
        match kind.as_byte() {
            // A GNU long name (`N` in its old form) names the next entry.
            b'L' | b'N' => {
                let mut name = header_entry(&mut entry, size, "GNU long name")?;
                if !reads_to_nul(&name) {
                    return Err("the tarball has a GNU long name npm reads otherwise".into());
                }
                name.truncate(name.iter().position(|b| *b == 0).unwrap_or(name.len()));
                if name.is_empty() {
                    return Err("the tarball has an empty GNU long name".into());
                }
                next_path = Some(name);
                continue;
            }
            // A PAX extended header (`X` in its old form) names the next
            // entry and may give its size.
            b'x' | b'X' => {
                let (path, size) = pax(&header_entry(&mut entry, size, "PAX header")?)?;
                next_path = path.or(next_path);
                next_size = size.or(next_size);
                continue;
            }
            // A PAX global header: node-tar takes no path from it, but a
            // size for every later entry.
            b'g' => {
                if pax(&header_entry(&mut entry, size, "PAX global header")?)?
                    .1
                    .is_some()
                {
                    return Err("the tarball's PAX global header gives entries a size".into());
                }
                continue;
            }
            // A long link name names no path npm reads.
            b'K' => continue,
            b'S' => return Err("the tarball holds a GNU sparse entry".into()),
            _ => {}
        }
        next_size = None;
        let named = next_path.take();
        // node-tar takes a `0` entry whose path ends in `/` for a directory:
        // the path a GNU long name or a PAX header gives, else the header's
        // name field alone. A directory has no body to node-tar, whatever its
        // header says, so the next header follows its own; `tar` skips the
        // size the header says, and would read other entries than npm does.
        let slash = named
            .as_deref()
            .unwrap_or_else(|| name_field(entry.header()))
            .ends_with(b"/");
        if kind.is_dir() || (kind.is_file() && slash) {
            if size != 0 {
                return Err("the tarball holds a directory entry with a body".into());
            }
            continue;
        }
        let path = named.unwrap_or_else(|| entry.path_bytes().into_owned());
        if !(kind.is_file() || kind.is_contiguous()) {
            continue;
        }
        file_count += 1;
        if is_manifest(&path) {
            if size > MAX_PACKAGE_JSON_BYTES {
                return Err(format!(
                    "package.json is larger than {MAX_PACKAGE_JSON_BYTES} bytes"
                ));
            }
            let mut data = Vec::with_capacity(size as usize);
            (&mut entry)
                .take(MAX_PACKAGE_JSON_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(|e| format!("unreadable package.json: {e}"))?;
            package_json = Some(data);
        } else if may_be_manifest(&path) {
            return Err(format!(
                "the tarball holds {:?}, which a client may unpack to package.json",
                String::from_utf8_lossy(&path)
            ));
        }
        // The rest of the entry's data is skipped by the archive reader,
        // which still inflates it: what the size bound above is for.
    }
    // `tar` ends the archive at its first zero block, node-tar only at two
    // in a row: what follows must be zeros alone, inflated within the bound
    // (but no part of `dist.unpackedSize`).
    let mut rest = archive.into_inner();
    let mut block = [0u8; 8192];
    let mut trailing = 0u64;
    loop {
        let n = rest
            .read(&mut block)
            .map_err(|e| format!("unreadable tarball: {e}"))?;
        if n == 0 {
            break;
        }
        trailing = trailing.saturating_add(n as u64);
        if unpacked.saturating_add(trailing) > max_unpacked {
            return Err(format!(
                "the tarball unpacks to more than {max_unpacked} bytes"
            ));
        }
        if block[..n].iter().any(|b| *b != 0) {
            return Err("the tarball holds data after the end of its archive".into());
        }
    }
    let data = package_json.ok_or("the tarball holds no package/package.json")?;
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&data);
    let package_json: Map<String, Value> = match serde_json::from_slice(data) {
        Ok(Value::Object(map)) => map,
        Ok(_) => return Err("package.json is not a JSON object".into()),
        Err(e) => return Err(format!("package.json is not valid JSON: {e}")),
    };
    let field = |key: &str| {
        package_json
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("package.json has no {key:?}"))
    };
    let name = field("name")?;
    let version = field("version")?;
    Ok(Tarball {
        package_json,
        name,
        version,
        file_count,
        unpacked_size: unpacked,
    })
}

/// Build a gzip-compressed tarball of `entries` (path, contents), for tests.
#[doc(hidden)]
pub fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, path, *data)
            .expect("append tar entry");
    }
    let tar = builder.into_inner().expect("finish tar");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).expect("gzip");
    gz.finish().expect("finish gzip")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_package_json_npm_installs() {
        let tgz = build(&[
            ("package/package.json", br#"{"name":"a","version":"1.0.0"}"#),
            ("package/index.js", b"module.exports = 1"),
            ("package/lib/package.json", br#"{"name":"nested"}"#),
        ]);
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.version.as_str()), ("a", "1.0.0"));
        assert_eq!(t.file_count, 3);

        // Any top-level directory; the last entry wins.
        let tgz = build(&[
            (
                "node-uuid/package.json",
                br#"{"name":"first","version":"1.0.0"}"#,
            ),
            (
                "./package/package.json",
                "\u{feff}{\"name\":\"last\",\"version\":\"2.0.0\"}".as_bytes(),
            ),
        ]);
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.version.as_str()), ("last", "2.0.0"));
    }

    #[test]
    fn refuses_what_npm_would_not_install() {
        let none = build(&[("package.json", br#"{"name":"a","version":"1.0.0"}"#)]);
        assert!(read(&none[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        let not_json = build(&[("package/package.json", b"name: a")]);
        assert!(read(&not_json[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        let no_version = build(&[("package/package.json", br#"{"name":"a"}"#)]);
        assert!(read(&no_version[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        assert!(read(&b"not gzip"[..], DEFAULT_MAX_UNPACKED_BYTES).is_err());
        let big = build(&[
            ("package/package.json", br#"{"name":"a","version":"1.0.0"}"#),
            ("package/blob", &[0u8; 4096]),
        ]);
        let err = read(&big[..], 1024).unwrap_err();
        assert!(err.contains("unpacks to more than"), "{err}");
    }

    /// Append an entry of `kind` named `name` (its name field, as is) to the
    /// uncompressed `tar`: a header that says `size`, then `data` (which may
    /// be shorter).
    fn raw_entry(tar: &mut Vec<u8>, name: &str, kind: u8, size: u64, data: &[u8]) {
        let mut header = tar::Header::new_ustar();
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_size(size);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::new(kind));
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(data);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }

    /// `tar` ended and gzip-compressed.
    fn finish(mut tar: Vec<u8>) -> Vec<u8> {
        tar.extend_from_slice(&[0; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).expect("gzip");
        gz.finish().expect("finish gzip")
    }

    /// A PAX record, `<length> <key>=<value>\n`, its length counting itself.
    fn pax_record(key: &str, value: &str) -> String {
        let rest = format!(" {key}={value}\n");
        let mut len = rest.len();
        while rest.len() + len.to_string().len() != len {
            len = rest.len() + len.to_string().len();
        }
        format!("{len}{rest}")
    }

    /// A PAX record whose value is `value`, any bytes.
    fn pax_bytes(key: &str, value: &[u8]) -> Vec<u8> {
        let rest = [format!(" {key}=").as_bytes(), value, b"\n"].concat();
        let mut len = rest.len();
        while rest.len() + len.to_string().len() != len {
            len = rest.len() + len.to_string().len();
        }
        [len.to_string().into_bytes(), rest].concat()
    }

    const PACKAGE_JSON: &[u8] = br#"{"name":"a","version":"1.0.0"}"#;

    #[test]
    fn reads_every_entry_npm_unpacks_as_a_file() {
        // A regular file, in its current and its old form, and a contiguous
        // file: the later one is the package.json npm installs.
        let later = br#"{"name":"b","version":"2.0.0"}"#;
        for kind in *b"0\x007" {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            raw_entry(&mut tar, "package/package.json", kind, 30, later);
            let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
            assert_eq!((t.name.as_str(), t.file_count), ("b", 2), "{kind}");
        }

        // What npm does not unpack as a file is neither read nor counted.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        raw_entry(&mut tar, "package/package.json", b'6', 30, later);
        let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("a", 1));
    }

    #[test]
    fn directories_are_read_as_npm_reads_them() {
        // A directory is neither read nor counted: of type `5`, or of type
        // `0` (or NUL) whose path ends in `/`, the path its name field, a
        // GNU long name or a PAX header gives. `package/package.json/` is
        // then no manifest.
        let pax_dir = pax_record("path", "package/package.json/");
        let dirs: [&[(&str, u8, &[u8])]; 5] = [
            &[("package/package.json", b'5', b"")],
            &[("package/package.json/", b'0', b"")],
            &[("package/package.json/", b'\0', b"")],
            &[
                ("././@LongLink", b'L', b"package/package.json/\0"),
                ("package/x", b'0', b""),
            ],
            &[
                ("PaxHeaders/x", b'x', pax_dir.as_bytes()),
                ("package/x", b'0', b""),
            ],
        ];
        for entries in dirs {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            for (name, kind, data) in entries {
                raw_entry(&mut tar, name, *kind, data.len() as u64, data);
            }
            let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES)
                .unwrap_or_else(|e| panic!("{entries:?}: {e}"));
            assert_eq!((t.name.as_str(), t.file_count), ("a", 1), "{entries:?}");
        }

        // A contiguous file stays a file, its path ending in `/` or not: npm
        // unpacks it to `package.json`.
        let mut tar = Vec::new();
        let later = br#"{"name":"b","version":"2.0.0"}"#;
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        raw_entry(&mut tar, "package/package.json/", b'7', 30, later);
        let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("b", 2));
    }

    #[test]
    fn refuses_a_directory_with_a_body() {
        // node-tar reads a directory as having no body and the header after
        // its own as the next entry, where `tar` skips the size the header
        // says. A directory's body can so hold a package.json with an
        // install script, and an entry npm skips over the package.json
        // `tar` reads next: npm and Forge would read different manifests.
        let evil = br#"{"name":"a","version":"1.0.0","scripts":{"install":"x"}}"#;
        let mut body = Vec::new();
        raw_entry(
            &mut body,
            "package/package.json",
            b'0',
            evil.len() as u64,
            evil,
        );
        raw_entry(&mut body, "package/skip", b'V', 1024, &[]);
        for (name, kind) in [
            ("package/lib", b'5'),
            ("package/lib/", b'0'),
            ("package/lib/", b'\0'),
        ] {
            let mut tar = Vec::new();
            raw_entry(&mut tar, name, kind, body.len() as u64, &body);
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("directory entry with a body"), "{name}: {err}");
        }
    }

    #[test]
    fn long_names_and_pax_headers_are_read_bounded() {
        let huge = 8 * 1024 * 1024 * 1024;
        for kind in *b"LNxXg" {
            // An 8 GiB header entry (cut short: it is never read): past the
            // unpack bound, and past the header cap under a bigger one.
            let mut tar = Vec::new();
            raw_entry(&mut tar, "././@LongLink", kind, huge, &[0; 512]);
            let tgz = finish(tar);
            let err = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("unpacks to more than"), "{err}");
            let err = read(&tgz[..], 2 * huge).unwrap_err();
            assert!(err.contains("larger than 65536 bytes"), "{err}");

            // One byte over the cap, all there.
            let mut tar = Vec::new();
            let over = vec![b'a'; MAX_HEADER_ENTRY_BYTES as usize + 1];
            raw_entry(&mut tar, "././@LongLink", kind, over.len() as u64, &over);
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("larger than 65536 bytes"), "{err}");
        }
    }

    #[test]
    fn long_names_and_pax_paths_name_the_next_entry_as_npm_reads_it() {
        // What `tar` writes for a path over 100 bytes: a GNU long name.
        let long = format!("package/{}/index.js", "d".repeat(150));
        let tgz = build(&[
            (long.as_str(), b"module.exports = 1"),
            ("package/package.json", PACKAGE_JSON),
        ]);
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("a", 2));

        let pax_path = pax_record("path", "package/package.json");
        let other = pax_record("path", "package/other.json");
        let named: [&[(&str, u8, &[u8])]; 5] = [
            // A GNU long name, in its current and its old form.
            &[("././@LongLink", b'L', b"package/package.json\0")],
            &[("././@LongLink", b'N', b"package/package.json")],
            // A PAX path, in its current and its old form.
            &[("PaxHeaders/x", b'x', pax_path.as_bytes())],
            &[("PaxHeaders/x", b'X', pax_path.as_bytes())],
            // The later of the two wins, and a long link names nothing.
            &[
                ("PaxHeaders/x", b'x', other.as_bytes()),
                ("././@LongLink", b'L', b"package/package.json"),
                ("././@LongLink", b'K', b"target"),
            ],
        ];
        for headers in named {
            let mut tar = Vec::new();
            for (name, kind, data) in headers {
                raw_entry(&mut tar, name, *kind, data.len() as u64, data);
            }
            raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
            let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES)
                .unwrap_or_else(|e| panic!("{headers:?}: {e}"));
            assert_eq!((t.name.as_str(), t.file_count), ("a", 1), "{headers:?}");
        }

        // A name applies to the next entry only.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "././@LongLink", b'L', 20, b"package/package.json");
        raw_entry(&mut tar, "package/dir", b'5', 0, &[]);
        raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
        let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
        assert!(err.contains("no package/package.json"), "{err}");
    }

    #[test]
    fn refuses_an_archive_laid_out_otherwise_than_its_headers() {
        let size_of = |n: usize| pax_record("size", &n.to_string());
        let same = size_of(PACKAGE_JSON.len());
        let mut tar = Vec::new();
        raw_entry(
            &mut tar,
            "PaxHeaders/x",
            b'x',
            same.len() as u64,
            same.as_bytes(),
        );
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        assert!(read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).is_ok());

        let refused: [(&str, u8, String, &str); 4] = [
            ("PaxHeaders/x", b'x', size_of(8 * 1024), "another size"),
            (
                "PaxHeaders/x",
                b'x',
                pax_record("size", "lots"),
                "unreadable size",
            ),
            ("PaxHeaders/g", b'g', same.clone(), "global header"),
            ("package/sparse", b'S', String::new(), "sparse"),
        ];
        for (name, kind, data, why) in refused {
            let mut tar = Vec::new();
            raw_entry(&mut tar, name, kind, data.len() as u64, data.as_bytes());
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains(why), "{name}: {err}");
        }
    }

    /// Append an entry like [`raw_entry`] with all of `data`, its header
    /// changed by `change` before its checksum is set.
    fn changed_entry(
        tar: &mut Vec<u8>,
        name: &[u8],
        kind: u8,
        data: &[u8],
        change: impl FnOnce(&mut [u8; 512]),
    ) {
        let mut header = tar::Header::new_ustar();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::new(kind));
        change(header.as_mut_bytes());
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(data);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }

    #[test]
    fn refuses_a_header_npm_rejects() {
        // node-tar rejects these headers and reads the block after each as
        // the next header, so the body `tar` skips could hold a package.json
        // only npm installs (#554).
        let size_past_8_bytes = |b: &mut [u8; 512]| {
            let mut field = [0u8; 12];
            field[0] = 0x80;
            field[3] = 1;
            field[11] = 30;
            b[124..136].copy_from_slice(&field);
        };
        type Change = Box<dyn FnOnce(&mut [u8; 512])>;
        let refused: [(&[u8], u8, Change, &str); 7] = [
            (
                b"package/x",
                b'0',
                Box::new(|b| b[157..163].copy_from_slice(b"target")),
                "a link target on an entry that is no link",
            ),
            (
                b"package/x",
                b'2',
                Box::new(|_| {}),
                "a link without a target",
            ),
            (b"", b'0', Box::new(|_| {}), "an empty path"),
            (
                b"package/x",
                b'0',
                Box::new(|b| b[100] = 0x81),
                "a base-256 number",
            ),
            // `tar` reads the last 8 bytes of a base-256 size, node-tar all.
            (b"package/x", b'0', Box::new(size_past_8_bytes), "its size"),
            // node-tar reads `package/x\n/`, a directory.
            (
                b"package/x\0x\n/",
                b'0',
                Box::new(|_| {}),
                "a string with a line break after its end",
            ),
            // node-tar joins an empty prefix: `/package/x`.
            (
                b"package/x",
                b'0',
                Box::new(|b| b[475] = b'A'),
                "an empty prefix",
            ),
        ];
        for (name, kind, change, why) in refused {
            let mut tar = Vec::new();
            changed_entry(&mut tar, name, kind, PACKAGE_JSON, change);
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }

        // A checksum of 8 digits with no end runs into the type flag, which
        // node-tar reads with it.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        let sum = tar::Header::from_byte_slice(&tar[..512]).cksum().unwrap();
        tar[148..156].copy_from_slice(format!("{sum:08o}").as_bytes());
        let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
        assert!(err.contains("its checksum"), "{err}");

        // A base-256 size both read alike is read.
        let mut tar = Vec::new();
        changed_entry(&mut tar, b"package/package.json", b'0', PACKAGE_JSON, |b| {
            let mut field = [0u8; 12];
            field[0] = 0x80;
            field[11] = 30;
            b[124..136].copy_from_slice(&field);
        });
        let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!(t.name, "a");
    }

    #[test]
    fn refuses_data_after_the_end_of_the_archive() {
        // `tar` ends the archive at a zero block, node-tar reads on after one.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        tar.extend_from_slice(&[0; 512]);
        raw_entry(
            &mut tar,
            "package/package.json",
            b'0',
            30,
            br#"{"name":"b","version":"2.0.0"}"#,
        );
        let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
        assert!(err.contains("data after the end"), "{err}");

        // Zeros after it are counted against the bound, not in the size.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        tar.extend_from_slice(&[0; 4096]);
        let tgz = finish(tar);
        assert_eq!(
            read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES)
                .unwrap()
                .unpacked_size,
            30
        );
        let err = read(&tgz[..], 1024).unwrap_err();
        assert!(err.contains("unpacks to more than"), "{err}");
    }

    #[test]
    fn reads_every_gzip_member() {
        // npm inflates every member of the gzip stream; the later package.json
        // is the one it installs.
        let gz = |tar: &[u8]| {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            std::io::Write::write_all(&mut gz, tar).expect("gzip");
            gz.finish().expect("finish gzip")
        };
        let mut first = Vec::new();
        raw_entry(&mut first, "package/package.json", b'0', 30, PACKAGE_JSON);
        let mut second = Vec::new();
        raw_entry(
            &mut second,
            "package/package.json",
            b'0',
            30,
            br#"{"name":"b","version":"2.0.0"}"#,
        );
        second.extend_from_slice(&[0; 1024]);
        let tgz = [gz(&first), gz(&second)].concat();
        let t = read(&tgz[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("b", 2));

        // Zeros after the stream are padding, as old npm wrote it (grunt
        // 0.1.0); anything else after the padding is refused.
        let whole = [first, vec![0; 1024]].concat();
        let padded = [gz(&whole), vec![0; 3000]].concat();
        let t = read(&padded[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!(t.name, "a");
        let err = read(&[padded, vec![1]].concat()[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
        assert!(err.contains("after the gzip stream's padding"), "{err}");
    }

    #[test]
    fn pax_records_are_read_as_npm_reads_them() {
        let path = pax_record("path", "package/package.json");
        let hidden = |line: &str| [b"x\n", line.as_bytes()].concat();
        let refused: [(Vec<u8>, &str); 11] = [
            // node-tar reads the key ` path` after a length with a sign or a
            // leading zero.
            (format!("+{path}").into_bytes(), "length is not its own"),
            (format!("0{path}").into_bytes(), "length is not its own"),
            (
                b"99 path=package/package.json\n".to_vec(),
                "length is not its own",
            ),
            // node-tar skips an empty line, where `tar` stops.
            (format!("\n{path}").into_bytes(), "without a length"),
            (b"9 a=\xff\xfe\n".to_vec(), "length is not its own"),
            // node-tar decodes a path that is not UTF-8 with replacement
            // characters, so its length is no longer its own, and splits one
            // holding a line break: it skips both.
            (
                pax_bytes("path", b"package/\xffpackage.json"),
                "npm reads otherwise",
            ),
            (
                pax_bytes("path", b"package/a\nb.json"),
                "npm reads otherwise",
            ),
            // A line break in another record's value starts a line node-tar
            // reads as a record of its own, `parseInt` skipping a sign.
            (
                pax_bytes("SCHILY.xattr.user.a", &hidden(path.trim_end())),
                "npm reads otherwise",
            ),
            (
                pax_bytes(
                    "SCHILY.xattr.user.a",
                    &hidden("+29path=package/package.json"),
                ),
                "npm reads otherwise",
            ),
            // An empty path node-tar ignores, digits alone it reads as a number.
            (
                pax_record("path", "").into_bytes(),
                "a path npm reads otherwise",
            ),
            (
                pax_record("path", "123").into_bytes(),
                "a path npm reads otherwise",
            ),
        ];
        for (data, why) in refused {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "PaxHeaders/x", b'x', data.len() as u64, &data);
            raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }

        // Other records, as GNU tar and bsdtar write them, pass by: a time,
        // and extended attributes raw, bytes that are not UTF-8 and line
        // breaks included, which node-tar skips.
        for other in [
            pax_record("mtime", "1700000000.5").into_bytes(),
            pax_bytes("SCHILY.xattr.com.apple.provenance", b"\x01\x02\x00\xff"),
            pax_bytes("SCHILY.xattr.user.b", b"\xf0\x90\x80A"),
            pax_bytes("SCHILY.xattr.user.c", b"\x00\n\xfe\n12 x=y\n"),
        ] {
            let data = [other, path.clone().into_bytes()].concat();
            let mut tar = Vec::new();
            raw_entry(&mut tar, "PaxHeaders/x", b'x', data.len() as u64, &data);
            raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
            let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES)
                .unwrap_or_else(|e| panic!("{:?}: {e}", String::from_utf8_lossy(&data)));
            assert_eq!(t.name, "a");
        }
    }

    #[test]
    fn a_pax_size_applies_up_to_the_next_entry() {
        // node-tar gives a GNU long name after a PAX header that header's size.
        let size = pax_record("size", "30");
        let mut tar = Vec::new();
        raw_entry(
            &mut tar,
            "PaxHeaders/x",
            b'x',
            size.len() as u64,
            size.as_bytes(),
        );
        raw_entry(
            &mut tar,
            "././@LongLink",
            b'L',
            21,
            b"package/package.json\0",
        );
        raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
        let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
        assert!(err.contains("another size"), "{err}");
    }

    #[test]
    fn refuses_a_gnu_long_name_npm_reads_otherwise() {
        for (name, why) in [
            (
                &b"package/package.json\0x\ny"[..],
                "GNU long name npm reads otherwise",
            ),
            (b"\0", "empty GNU long name"),
        ] {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "././@LongLink", b'L', name.len() as u64, name);
            raw_entry(&mut tar, "package/x", b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn takes_the_manifest_only_where_npm_does() {
        // node-tar strips exactly the first component and resolves the rest;
        // a path some client unpacks to package.json otherwise is refused.
        for path in [
            "./package.json",
            "/package.json",
            "../package.json",
            "package.json",
            "./package/package.json",
            "package//package.json",
            "package/./package.json",
            "package\\package.json",
            "pa\\ck/package.json",
            "package/PACKAGE.JSON",
            "package/package.json.",
            "package/package.json ",
            "c:package.json",
            "c:x/package.json",
        ] {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            raw_entry(&mut tar, path, b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("may unpack to package.json"), "{path}: {err}");
        }

        // node-tar strips Windows roots (drives, UNC and device roots) at the
        // start of the path, before the first component is stripped (6, 7.4)
        // or after it (7.5): each is the package.json npm installs.
        for path in [
            "package/c:package.json",
            "package/C:/package.json",
            "package/C:\\package.json",
            "package/c:c:package.json",
            "package/c:./package.json",
            "package/\\\\srv\\share\\package.json",
            "package/\\/srv/share/package.json",
            "package/\\\\?\\C:\\package.json",
            "./c:package.json",
            "\\\\srv\\share\\package.json",
            "\\/srv/share/package.json",
            "/\\\\srv\\share\\package.json",
            "C:C:package.json",
            "\\\\?\\C:\\package.json",
            "//?/C:/package.json",
            "package/c:PACKAGE.JSON.",
        ] {
            let mut tar = Vec::new();
            raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
            raw_entry(&mut tar, path, b'0', 30, PACKAGE_JSON);
            let err = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap_err();
            assert!(err.contains("may unpack to package.json"), "{path}: {err}");
        }

        // A drive or a backslash elsewhere names a file of its own, as does a
        // rooted path to another file.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "package/package.json", b'0', 30, PACKAGE_JSON);
        for path in [
            "package/lib/c:package.json",
            "package/lib\\package.json",
            "package/c:index.js",
            "package/c:package.json.js",
        ] {
            raw_entry(&mut tar, path, b'0', 9, br#"{"a":"b"}"#);
        }
        let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("a", 5));

        // The first component is any plain name; a deeper package.json is
        // just a file.
        let mut tar = Vec::new();
        raw_entry(&mut tar, "pkg/package.json", b'0', 30, PACKAGE_JSON);
        raw_entry(&mut tar, "pkg/lib/package.json", b'0', 9, br#"{"a":"b"}"#);
        let t = read(&finish(tar)[..], DEFAULT_MAX_UNPACKED_BYTES).unwrap();
        assert_eq!((t.name.as_str(), t.file_count), ("a", 2));
    }
}
