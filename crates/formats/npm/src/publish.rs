//! The body of `npm publish`: a packument document carrying the tarball
//! base64-encoded in `_attachments.<file>.data`.
//!
//! [`Extractor`] reads the body as it arrives, chunk by chunk, and splits it
//! in two without ever holding the tarball in memory: the decoded tarball,
//! handed to the caller as it is decoded (to be staged on disk), and the
//! document with the attachment's `data` replaced by `""`, small enough to
//! parse. It is a push parser (no I/O of its own), so it runs on the async
//! task that reads the request body.
//!
//! The document is copied token by token, without the whitespace between
//! tokens. The extractor delimits strings, objects and arrays itself and
//! leaves numbers and literals to the JSON parser the caller runs on the
//! document afterwards, which also catches anything else malformed.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;

/// The deepest nesting accepted.
const MAX_DEPTH: usize = 64;

/// Base64 decoded in blocks of this many characters (a multiple of 4).
const DECODE_BLOCK: usize = 64 * 1024;

/// Keys longer than this are not decoded: no key the extractor looks for is.
const MAX_MATCHED_KEY: usize = 64;

/// npm's base64 (Node's `Buffer#toString('base64')`), padded or not.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Why a publish body is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The body is not a JSON document of the expected shape.
    Malformed(String),
    /// The document, without the tarball, is larger than allowed.
    DocumentTooLarge(usize),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::Malformed(m) => write!(f, "malformed publish document: {m}"),
            ExtractError::DocumentTooLarge(limit) => write!(
                f,
                "the publish document is larger than {limit} bytes (without its tarball)"
            ),
        }
    }
}

impl std::error::Error for ExtractError {}

/// What the extractor made of a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The document, its attachment's `data` replaced by `""`.
    pub document: Vec<u8>,
    /// The attachment whose data was extracted: its name (the key under
    /// `_attachments`) and the number of bytes decoded.
    pub attachment: Option<(String, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    Object,
    Array,
}

#[derive(Debug)]
struct Frame {
    container: Container,
    /// The key of the member being read (objects), decoded when short.
    key: Option<String>,
    /// Whether no member or element has been read yet.
    empty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Key,
    Value,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A value is expected.
    Value,
    /// A key (or the end of an empty object) is expected.
    Key,
    /// The `:` after a key is expected.
    Colon,
    /// A `,` or the end of the container is expected (or the end of the
    /// body, at the top level).
    After,
    /// Inside a string; `escaped` after a backslash, `unicode` counting the
    /// hex digits of a `\u` escape still to come.
    Str {
        role: Role,
        escaped: bool,
        unicode: u8,
    },
    /// Inside a number or a literal (`true`, `false`, `null`).
    Literal,
    /// The top-level value is complete.
    Done,
}

/// Splits a publish body into its document and its tarball; see the module
/// documentation.
pub struct Extractor {
    max_document: usize,
    document: Vec<u8>,
    stack: Vec<Frame>,
    state: State,
    key: Vec<u8>,
    /// Base64 characters of the data not decoded yet.
    pending: Vec<u8>,
    /// The `\u` escape being read inside the data.
    unicode: Vec<u8>,
    attachment: Option<(String, u64)>,
    offset: u64,
}

impl Extractor {
    /// An extractor refusing a document over `max_document` bytes.
    pub fn new(max_document: usize) -> Self {
        Extractor {
            max_document,
            document: Vec::new(),
            stack: Vec::new(),
            state: State::Value,
            key: Vec::new(),
            pending: Vec::new(),
            unicode: Vec::new(),
            attachment: None,
            offset: 0,
        }
    }

    /// Whether the extractor is inside the attachment's data, or past it.
    pub fn found_attachment(&self) -> bool {
        self.attachment.is_some()
    }

    fn malformed(&self, what: &str) -> ExtractError {
        ExtractError::Malformed(format!("{what} at byte {}", self.offset))
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        if self.document.len() + bytes.len() > self.max_document {
            return Err(ExtractError::DocumentTooLarge(self.max_document));
        }
        self.document.extend_from_slice(bytes);
        Ok(())
    }

    /// Whether a string value starting now is an attachment's data:
    /// `_attachments.<name>.data` at the top level.
    fn at_data(&self) -> bool {
        matches!(
            self.stack.as_slice(),
            [root, attachments, attachment]
                if root.container == Container::Object
                    && root.key.as_deref() == Some("_attachments")
                    && attachments.container == Container::Object
                    && attachment.container == Container::Object
                    && attachment.key.as_deref() == Some("data")
        )
    }

    /// The state after a value ends.
    fn value_done(&mut self) -> State {
        if self.stack.is_empty() {
            State::Done
        } else {
            State::After
        }
    }

    /// Decode the complete base64 blocks of the data (all of it at its
    /// end), appending the bytes to `out`.
    fn decode(&mut self, out: &mut Vec<u8>, last: bool) -> Result<(), ExtractError> {
        let take = if last {
            self.pending.len()
        } else {
            self.pending.len() - self.pending.len() % 4
        };
        if take == 0 {
            return Ok(());
        }
        let start = out.len();
        BASE64
            .decode_vec(&self.pending[..take], out)
            .map_err(|e| self.malformed(&format!("invalid base64 in the attachment ({e})")))?;
        if let Some((_, len)) = &mut self.attachment {
            *len += (out.len() - start) as u64;
        }
        self.pending.drain(..take);
        Ok(())
    }

    /// Read `chunk`, appending the tarball bytes it decodes to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), ExtractError> {
        let mut i = 0;
        while i < chunk.len() {
            let b = chunk[i];
            match self.state {
                State::Str {
                    role,
                    escaped,
                    unicode,
                } => {
                    if role == Role::Data {
                        // Copy a run of plain base64 characters at once.
                        if !escaped && unicode == 0 && b != b'"' && b != b'\\' {
                            let run = chunk[i..]
                                .iter()
                                .position(|&c| c == b'"' || c == b'\\')
                                .unwrap_or(chunk.len() - i);
                            self.pending.extend_from_slice(&chunk[i..i + run]);
                            if self.pending.len() >= DECODE_BLOCK {
                                self.decode(out, false)?;
                            }
                            i += run;
                            self.offset += run as u64;
                            continue;
                        }
                        self.data_byte(b, escaped, unicode, out)?;
                    } else {
                        self.string_byte(b, role, escaped, unicode)?;
                    }
                }
                State::Literal => {
                    if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                        self.state = self.value_done();
                        // Re-read this byte in the new state.
                        continue;
                    }
                    self.emit(&[b])?;
                }
                _ if matches!(b, b' ' | b'\t' | b'\r' | b'\n') => {}
                State::Done => return Err(self.malformed("data after the document")),
                State::Value => self.value_start(b)?,
                State::Key => match b {
                    b'"' => {
                        self.emit(b"\"")?;
                        self.key.clear();
                        self.state = State::Str {
                            role: Role::Key,
                            escaped: false,
                            unicode: 0,
                        };
                    }
                    b'}' if self.stack.last().is_some_and(|f| f.empty) => {
                        self.close(b, Container::Object)?
                    }
                    _ => return Err(self.malformed("expected a key")),
                },
                State::Colon => {
                    if b != b':' {
                        return Err(self.malformed("expected ':'"));
                    }
                    self.emit(b":")?;
                    self.state = State::Value;
                }
                State::After => match (b, self.stack.last().map(|f| f.container)) {
                    (b',', Some(container)) => {
                        self.emit(b",")?;
                        self.state = match container {
                            Container::Object => State::Key,
                            Container::Array => State::Value,
                        };
                    }
                    (b'}', Some(Container::Object)) => self.close(b, Container::Object)?,
                    (b']', Some(Container::Array)) => self.close(b, Container::Array)?,
                    _ => return Err(self.malformed("expected ',' or the end of a container")),
                },
            }
            i += 1;
            self.offset += 1;
        }
        Ok(())
    }

    fn value_start(&mut self, b: u8) -> Result<(), ExtractError> {
        if b == b']' {
            // Only an empty array may end where a value is expected.
            return match self.stack.last() {
                Some(frame) if frame.container == Container::Array && frame.empty => {
                    self.close(b, Container::Array)
                }
                _ => Err(self.malformed("expected a value")),
            };
        }
        if let Some(frame) = self.stack.last_mut() {
            frame.empty = false;
        }
        match b {
            b'{' | b'[' => {
                if self.stack.len() >= MAX_DEPTH {
                    return Err(self.malformed("nested too deeply"));
                }
                self.emit(&[b])?;
                let container = if b == b'{' {
                    Container::Object
                } else {
                    Container::Array
                };
                self.stack.push(Frame {
                    container,
                    key: None,
                    empty: true,
                });
                self.state = match container {
                    Container::Object => State::Key,
                    Container::Array => State::Value,
                };
            }
            b'"' => {
                let role = if self.at_data() {
                    if self.attachment.is_some() {
                        return Err(self.malformed("a publish carries one tarball"));
                    }
                    let name = self.stack[1].key.clone().unwrap_or_default();
                    self.attachment = Some((name, 0));
                    Role::Data
                } else {
                    Role::Value
                };
                self.emit(b"\"")?;
                self.state = State::Str {
                    role,
                    escaped: false,
                    unicode: 0,
                };
            }
            b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                self.emit(&[b])?;
                self.state = State::Literal;
            }
            _ => return Err(self.malformed("expected a value")),
        }
        Ok(())
    }

    fn close(&mut self, b: u8, container: Container) -> Result<(), ExtractError> {
        match self.stack.pop() {
            Some(frame) if frame.container == container => {}
            _ => return Err(self.malformed("unbalanced brackets")),
        }
        self.emit(&[b])?;
        self.state = self.value_done();
        Ok(())
    }

    /// A byte of a key or of a string value: copied as it is.
    fn string_byte(
        &mut self,
        b: u8,
        role: Role,
        escaped: bool,
        unicode: u8,
    ) -> Result<(), ExtractError> {
        if b < 0x20 {
            return Err(self.malformed("a control character in a string"));
        }
        self.emit(&[b])?;
        if role == Role::Key && self.key.len() <= MAX_MATCHED_KEY {
            self.key.push(b);
        }
        let (escaped, unicode) = match (escaped, unicode, b) {
            (false, _, b'"') if unicode == 0 => {
                if role == Role::Key {
                    let key = self.decoded_key();
                    if let Some(frame) = self.stack.last_mut() {
                        frame.key = key;
                    }
                    self.state = State::Colon;
                } else {
                    self.state = self.value_done();
                }
                return Ok(());
            }
            (false, 0, b'\\') => (true, 0),
            (true, _, b'u') => (false, 4),
            (true, _, _) => (false, 0),
            (false, n, _) if n > 0 => {
                if !b.is_ascii_hexdigit() {
                    return Err(self.malformed("a bad \\u escape"));
                }
                (false, n - 1)
            }
            (false, _, _) => (false, 0),
        };
        self.state = State::Str {
            role,
            escaped,
            unicode,
        };
        Ok(())
    }

    /// The key just read, decoded, unless it is too long to be one the
    /// extractor looks for.
    fn decoded_key(&self) -> Option<String> {
        if self.key.len() > MAX_MATCHED_KEY {
            return None;
        }
        // `self.key` ends with the closing quote.
        let mut quoted = Vec::with_capacity(self.key.len() + 1);
        quoted.push(b'"');
        quoted.extend_from_slice(&self.key);
        serde_json::from_slice::<String>(&quoted).ok()
    }

    /// A byte of the attachment's data that is not a plain base64 character.
    fn data_byte(
        &mut self,
        b: u8,
        escaped: bool,
        unicode: u8,
        out: &mut Vec<u8>,
    ) -> Result<(), ExtractError> {
        if unicode > 0 {
            if !b.is_ascii_hexdigit() {
                return Err(self.malformed("a bad \\u escape"));
            }
            self.unicode.push(b);
            if unicode == 1 {
                let code = std::str::from_utf8(&self.unicode).ok().and_then(|hex| {
                    u8::from_str_radix(hex, 16)
                        .ok()
                        .filter(|_| hex.starts_with("00"))
                });
                self.unicode.clear();
                match code {
                    Some(c) if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=') => {
                        self.pending.push(c)
                    }
                    Some(b'\n' | b'\r') => {}
                    _ => return Err(self.malformed("a non-base64 character in the attachment")),
                }
            }
            self.state = State::Str {
                role: Role::Data,
                escaped: false,
                unicode: unicode - 1,
            };
            return Ok(());
        }
        if escaped {
            let unicode = match b {
                b'/' => {
                    self.pending.push(b'/');
                    0
                }
                // Line breaks some encoders wrap base64 with.
                b'n' | b'r' => 0,
                b'u' => 4,
                _ => return Err(self.malformed("a non-base64 escape in the attachment")),
            };
            self.state = State::Str {
                role: Role::Data,
                escaped: false,
                unicode,
            };
            return Ok(());
        }
        match b {
            b'\\' => {
                self.state = State::Str {
                    role: Role::Data,
                    escaped: true,
                    unicode: 0,
                };
            }
            b'"' => {
                self.decode(out, true)?;
                self.emit(b"\"")?;
                self.state = self.value_done();
            }
            _ => unreachable!("plain characters are copied in runs"),
        }
        Ok(())
    }

    /// The body is complete: the document, and the attachment found.
    pub fn finish(self) -> Result<Extracted, ExtractError> {
        match self.state {
            State::Done => {}
            // A top-level number ends with the body.
            State::Literal if self.stack.is_empty() => {}
            _ => return Err(self.malformed("the document ends early")),
        }
        Ok(Extracted {
            document: self.document,
            attachment: self.attachment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// The document, the attachment's data and the attachment's name and
    /// length.
    type Run = (Value, Vec<u8>, Option<(String, u64)>);

    /// Run the extractor over `body` in chunks of `size`.
    fn run(body: &[u8], size: usize) -> Result<Run, ExtractError> {
        let mut x = Extractor::new(1024 * 1024);
        let mut out = Vec::new();
        for chunk in body.chunks(size) {
            x.feed(chunk, &mut out)?;
        }
        let extracted = x.finish()?;
        let doc = serde_json::from_slice(&extracted.document).expect("valid document");
        Ok((doc, out, extracted.attachment))
    }

    fn body(tarball: &[u8]) -> Vec<u8> {
        let data = base64::engine::general_purpose::STANDARD.encode(tarball);
        serde_json::to_vec_pretty(&json!({
            "_id": "@acme/a",
            "name": "@acme/a",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"name": "@acme/a", "version": "1.0.0", "data": "kept", "n": [1, 2.5, -3e2, true, false, null, {}, []]}},
            "access": null,
            "_attachments": {"@acme/a-1.0.0.tgz": {"content_type": "application/octet-stream", "data": data, "length": tarball.len()}},
            "readme": "say \"hi\" \\ \u{e9} \u{1F600}"
        }))
        .unwrap()
    }

    #[test]
    fn splits_the_document_from_the_tarball() {
        let tarball: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let body = body(&tarball);
        for size in [1, 3, 7, 4096, body.len()] {
            let (doc, out, attachment) = run(&body, size).unwrap();
            assert_eq!(out, tarball, "chunk size {size}");
            assert_eq!(
                attachment,
                Some(("@acme/a-1.0.0.tgz".to_string(), tarball.len() as u64))
            );
            assert_eq!(doc["_attachments"]["@acme/a-1.0.0.tgz"]["data"], "");
            assert_eq!(doc["_attachments"]["@acme/a-1.0.0.tgz"]["length"], 200_000);
            assert_eq!(doc["versions"]["1.0.0"]["data"], "kept");
            assert_eq!(
                doc["versions"]["1.0.0"]["n"],
                json!([1, 2.5, -3e2, true, false, null, {}, []])
            );
            assert_eq!(doc["readme"], "say \"hi\" \\ \u{e9} \u{1F600}");
        }
    }

    #[test]
    fn reads_escaped_and_wrapped_base64() {
        let tarball = b"\xff\xfe\xfd hello world, this is a tarball".to_vec();
        let data = base64::engine::general_purpose::STANDARD.encode(&tarball);
        let wrapped: String = data
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                let mut s = String::new();
                if i > 0 && i % 8 == 0 {
                    s.push_str("\\n");
                }
                if c == '/' {
                    s.push_str("\\/");
                } else if c == 'A' {
                    s.push_str("\\u0041");
                } else {
                    s.push(c);
                }
                s.chars().collect::<Vec<_>>()
            })
            .collect();
        let body = format!(r#"{{"_attachments":{{"x.tgz":{{"data":"{wrapped}"}}}}}}"#);
        let (_, out, _) = run(body.as_bytes(), 5).unwrap();
        assert_eq!(out, tarball);
    }

    #[test]
    fn a_document_without_an_attachment() {
        let (doc, out, attachment) =
            run(br#"{"name":"a","versions":{},"_attachments":{}}"#, 2).unwrap();
        assert!(out.is_empty());
        assert_eq!(attachment, None);
        assert_eq!(doc["name"], "a");
        // `data` elsewhere is a string like any other.
        let (doc, out, attachment) = run(
            br#"{"data":"QUJD","x":{"_attachments":{"a":{"data":"QUJD"}}}}"#,
            2,
        )
        .unwrap();
        assert!(out.is_empty() && attachment.is_none());
        assert_eq!(doc["data"], "QUJD");
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        for bad in [
            &br#"{"a":1"#[..],
            br#"{"a" 1}"#,
            br#"{"a":1,}"#,
            br#"{"a":1]"#,
            br#"[1,2}"#,
            br#"{"a":1} {}"#,
            br#"{a:1}"#,
            br#"{"_attachments":{"x":{"data":"QUJD!"}}}"#,
            br#"{"_attachments":{"x":{"data":"QU\tJD"}}}"#,
            br#"{"_attachments":{"x":{"data":"QUJD"},"y":{"data":"QUJD"}}}"#,
            b"{\"a\":\"line\nbreak\"}",
        ] {
            let result = run(bad, 3);
            assert!(
                matches!(result, Err(ExtractError::Malformed(_))),
                "{:?}: {result:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(run(deep.as_bytes(), 10).is_err());
        let mut x = Extractor::new(10);
        assert_eq!(
            x.feed(br#"{"description":"far too long"}"#, &mut Vec::new()),
            Err(ExtractError::DocumentTooLarge(10))
        );
    }
}
