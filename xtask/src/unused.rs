//! `cargo xtask unused`: what nothing uses, and neither rustc nor clippy
//! reports.
//!
//! rustc warns about a private item nothing calls, but not about a `pub` one:
//! it compiles one crate at a time, and another crate may call it. Nor does
//! Cargo say when a dependency is no longer imported. This check reads the
//! workspace's manifests and Rust sources as text and reports:
//!
//! * a `pub` item (a function, type, trait, constant or static) whose name
//!   appears nowhere else in the workspace's Rust sources, so that nothing,
//!   not even a test, uses it;
//! * a dependency that its member's sources never name: no `name::…`,
//!   `use name` or `extern crate name`, the name's `-` read as `_` or dropped
//!   (`md-5` is imported as `md5`);
//! * a dev-dependency that repeats one of its member's dependencies without
//!   adding a feature, since the tests have the dependencies anyway;
//! * an entry of `[workspace.dependencies]` that no member inherits.
//!
//! Being a text search, it errs towards silence: a name mentioned anywhere
//! else, in a comment, a string or as an unrelated local, counts as used. A
//! dependency the code needs without naming it (one that turns on a feature
//! of another) is listed, with the reason, in its member's manifest:
//!
//! ```toml
//! [package.metadata.unused]
//! # <why the code needs it without naming it>
//! ignore = ["name"]
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

/// The workspace manifest: its members and `[workspace.dependencies]`.
const ROOT_MANIFEST: &str = "Cargo.toml";
/// The table of a member's manifest that lists the dependencies to keep.
const METADATA: &str = "package.metadata.unused";

/// `cargo xtask unused`.
pub fn unused(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: cargo xtask unused".into());
    }
    let root = read(ROOT_MANIFEST)?;
    let mut members = Vec::new();
    for dir in workspace_members(&root) {
        let manifest = format!("{dir}/Cargo.toml");
        let mut sources = Vec::new();
        rust_sources(Path::new(&dir), &mut sources)?;
        members.push(Member {
            text: read(&manifest)?,
            manifest,
            sources,
        });
    }

    let mut findings = unused_items(members.iter().flat_map(|m| &m.sources));
    for member in &members {
        findings.extend(member_findings(member));
    }
    findings.extend(uninherited(&root, members.iter().map(|m| m.text.as_str())));

    if findings.is_empty() {
        println!(
            "{} member(s): every pub item and every dependency is used.",
            members.len()
        );
        return Ok(());
    }
    for finding in &findings {
        eprintln!("{finding}");
    }
    Err(format!(
        "{} finding(s): remove what nothing uses (a dependency the code needs \
         without naming it goes under [{METADATA}] ignore, see xtask/src/unused.rs)",
        findings.len()
    ))
}

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("unused: read {path}: {e}"))
}

/// A workspace member: its manifest and its Rust sources.
struct Member {
    manifest: String,
    text: String,
    /// `(path, text)` of every `.rs` file under the member's directory.
    sources: Vec<(String, String)>,
}

/// Every `.rs` file under `dir`, but not under a `target` directory.
fn rust_sources(dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("unused: list {}: {e}", dir.display()))?;
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "target") {
                rust_sources(&path, out)?;
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path.to_string_lossy().into_owned();
            out.push((name.clone(), read(&name)?));
        }
    }
    Ok(())
}

// ── pub items ──────────────────────────────────────────────────────────────

/// The `pub` items whose name no other place in `sources` mentions.
fn unused_items<'a>(sources: impl Iterator<Item = &'a (String, String)> + Clone) -> Vec<String> {
    let mut mentions: HashMap<&str, usize> = HashMap::new();
    for (_, text) in sources.clone() {
        for word in words(text) {
            *mentions.entry(word).or_default() += 1;
        }
    }
    let mut out = Vec::new();
    for (path, text) in sources {
        for (line, kind, name) in pub_items(&code_only(text)) {
            if mentions.get(name.as_str()).copied().unwrap_or(0) <= 1 {
                out.push(format!(
                    "{path}:{line}: pub {kind} `{name}`: nothing else in the workspace names it"
                ));
            }
        }
    }
    out
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The identifier-like words of `text`, comments and strings included.
fn words(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || loop {
        let start = rest.find(is_ident_start)?;
        // A word does not start inside another (`2nd`, `x86_64`).
        let before = rest[..start].chars().next_back();
        let len = rest[start..]
            .find(|c| !is_ident(c))
            .unwrap_or(rest.len() - start);
        let word = &rest[start..start + len];
        rest = &rest[start + len..];
        if !before.is_some_and(|c| c.is_ascii_digit()) {
            return Some(word);
        }
    })
}

/// `text` with its comments and string and character literals blanked out
/// (newlines kept), so that code in a doc comment or a test's string is not
/// read as a definition.
fn code_only(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, c: char| out.push(if c == '\n' { '\n' } else { ' ' });
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev_ident = i > 0 && is_ident(chars[i - 1]);
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                blank(&mut out, chars[i]);
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, chars[i]);
                    i += 1;
                }
            }
        } else if let Some(hashes) = (!prev_ident).then(|| raw_string_start(&chars, i)).flatten() {
            // r"…", r#"…"#, br"…": no escapes; ends at `"` and the hashes.
            let open = hashes + 2 + usize::from(c == 'b');
            for &c in &chars[i..i + open] {
                blank(&mut out, c);
            }
            i += open;
            while i < chars.len() {
                if chars[i] == '"'
                    && chars[i + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&c| c == '#')
                        .count()
                        == hashes
                {
                    for &c in &chars[i..(i + 1 + hashes).min(chars.len())] {
                        blank(&mut out, c);
                    }
                    i += 1 + hashes;
                    break;
                }
                blank(&mut out, chars[i]);
                i += 1;
            }
        } else if c == '"' {
            blank(&mut out, c);
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    blank(&mut out, chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    blank(&mut out, chars[i]);
                    i += 1;
                }
            }
            if i < chars.len() {
                blank(&mut out, chars[i]);
                i += 1;
            }
        } else if c == '\'' && (next == Some('\\') || chars.get(i + 2) == Some(&'\'')) {
            // A character literal ('x', '\n', '\''), not a lifetime ('a).
            blank(&mut out, c);
            i += 1;
            if chars.get(i) == Some(&'\\') {
                blank(&mut out, '\\');
                i += 1;
            }
            while i < chars.len() {
                let done = chars[i] == '\'';
                blank(&mut out, chars[i]);
                i += 1;
                if done {
                    break;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// The number of `#` of a raw string literal starting at `chars[i]` (`r"`,
/// `r#"`, `br"`), if one does.
fn raw_string_start(chars: &[char], i: usize) -> Option<usize> {
    let mut j = i;
    if chars.get(j) == Some(&'b') {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = chars[j..].iter().take_while(|&&c| c == '#').count();
    (chars.get(j + hashes) == Some(&'"')).then_some(hashes)
}

/// The `pub` items `code` defines (comments and strings blanked out):
/// `(line, kind, name)`, lines counted from 1.
fn pub_items(code: &str) -> Vec<(usize, &'static str, String)> {
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("pub") else {
            continue;
        };
        let rest = if let Some(scoped) = rest.strip_prefix('(') {
            // pub(crate), pub(super), pub(in path)
            match scoped.find(')') {
                Some(end) => &scoped[end + 1..],
                None => continue,
            }
        } else if rest.starts_with(char::is_whitespace) {
            rest
        } else {
            continue; // `public`, `pub_items`
        };
        let mut tokens = rest.split_whitespace().peekable();
        let mut kind = None;
        while let Some(token) = tokens.next() {
            match token {
                // `extern "C"`: the ABI string is blanked out already.
                "async" | "unsafe" | "extern" => {}
                "const"
                    if tokens
                        .peek()
                        .is_some_and(|t| matches!(*t, "fn" | "async" | "unsafe" | "extern")) => {}
                "fn" | "struct" | "enum" | "union" | "trait" | "type" | "const" | "static" => {
                    kind = Some(token);
                    break;
                }
                _ => break,
            }
        }
        let Some(kind) = kind else { continue };
        let mut name = tokens.next();
        if kind == "static" && name == Some("mut") {
            name = tokens.next();
        }
        let Some(name) = name else { continue };
        let name = name.strip_prefix("r#").unwrap_or(name);
        let len = name.find(|c| !is_ident(c)).unwrap_or(name.len());
        if len > 0 && name.starts_with(is_ident_start) {
            let kind = match kind {
                "fn" => "fn",
                "struct" => "struct",
                "enum" => "enum",
                "union" => "union",
                "trait" => "trait",
                "type" => "type",
                "const" => "const",
                _ => "static",
            };
            out.push((n + 1, kind, name[..len].to_string()));
        }
    }
    out
}

// ── Dependencies ───────────────────────────────────────────────────────────

/// A `key = value` of a manifest, the value without comments and with its
/// lines joined; `line` counts from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    table: String,
    key: String,
    value: String,
    line: usize,
}

/// The entries of `manifest`, in order, each with the table it is in.
fn entries(manifest: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut table = String::new();
    let mut lines = manifest.lines().enumerate();
    while let Some((n, line)) = lines.next() {
        let line = strip_comment(line);
        let trimmed = line.trim();
        if let Some(header) = trimmed.strip_prefix('[') {
            table = header
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_string();
            continue;
        }
        let Some((key, value)) = split_once_outside_quotes(trimmed, '=') else {
            continue;
        };
        let mut value = value.trim().to_string();
        while depth(&value) > 0 {
            let Some((_, more)) = lines.next() else { break };
            value.push(' ');
            value.push_str(strip_comment(more).trim());
        }
        out.push(Entry {
            table: table.clone(),
            key: key.trim().trim_matches('"').to_string(),
            value,
            line: n + 1,
        });
    }
    out
}

/// `line` up to a `#` that is not in a string.
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '#') => return &line[..i],
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if c == q => quote = None,
            _ => {}
        }
    }
    line
}

/// How many `{`/`[` of `value` are still open (outside strings).
fn depth(value: &str) -> i32 {
    let mut quote = None;
    let mut depth = 0;
    for c in value.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if c == q => quote = None,
            (None, '{' | '[') => depth += 1,
            (None, '}' | ']') => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// `s` split at the first `sep` that is outside strings and brackets.
fn split_once_outside_quotes(s: &str, sep: char) -> Option<(&str, &str)> {
    split_outside_quotes(s, sep, 1)
        .first()
        .filter(|first| first.len() < s.len())
        .map(|first| (*first, &s[first.len() + 1..]))
}

/// `s` split at each `sep` outside strings and brackets, at most `max`
/// times (0: no limit).
fn split_outside_quotes(s: &str, sep: char, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut quote, mut depth, mut start) = (None, 0, 0);
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if c == q => quote = None,
            (None, '{' | '[') => depth += 1,
            (None, '}' | ']') => depth -= 1,
            (None, _) if c == sep && depth == 0 && (max == 0 || out.len() < max) => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// A dependency's spec as `key → value` (`"1"` is `version = "1"`), values
/// without whitespace outside strings, and its features apart.
fn spec(value: &str) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let value = value.trim();
    let mut fields = BTreeMap::new();
    let mut features = BTreeSet::new();
    let Some(inner) = value.strip_prefix('{').and_then(|v| v.strip_suffix('}')) else {
        fields.insert("version".to_string(), value.to_string());
        return (fields, features);
    };
    for field in split_outside_quotes(inner, ',', 0) {
        let Some((key, value)) = split_once_outside_quotes(field, '=') else {
            continue;
        };
        let key = key.trim().to_string();
        let value: String = value.trim().to_string();
        if key == "features" {
            features.extend(string_list(&value));
        } else {
            fields.insert(key, without_space(&value));
        }
    }
    (fields, features)
}

/// The strings of an array value, `["a", "b"]`.
fn string_list(value: &str) -> Vec<String> {
    let list = value.trim().trim_start_matches('[').trim_end_matches(']');
    split_outside_quotes(list, ',', 0)
        .into_iter()
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn without_space(value: &str) -> String {
    let mut quote = None;
    value
        .chars()
        .filter(|&c| {
            match (quote, c) {
                (None, '"' | '\'') => quote = Some(c),
                (Some(q), _) if c == q => quote = None,
                _ => {}
            }
            quote.is_some() || !c.is_whitespace()
        })
        .collect()
}

/// Whether `table` lists dependencies: `dependencies`, `dev-dependencies`,
/// `build-dependencies`, or one of them for a target only.
fn is_dependency_table(table: &str) -> bool {
    let last = table.rsplit('.').next().unwrap_or(table);
    matches!(
        last,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    ) && (!table.contains('.') || table.starts_with("target."))
}

/// What is wrong with the dependencies of `member`.
fn member_findings(member: &Member) -> Vec<String> {
    let entries = entries(&member.text);
    let ignored: BTreeSet<String> = entries
        .iter()
        .filter(|e| e.table == METADATA && e.key == "ignore")
        .flat_map(|e| string_list(&e.value))
        .collect();
    let deps: Vec<&Entry> = entries
        .iter()
        .filter(|e| is_dependency_table(&e.table))
        .collect();
    let sources: Vec<&str> = member
        .sources
        .iter()
        .map(|(_, text)| text.as_str())
        .collect();
    let mut out = Vec::new();
    let mut reported = BTreeSet::new();
    for dep in &deps {
        if ignored.contains(&dep.key) || reported.contains(&dep.key) {
            continue;
        }
        let named = idents(&dep.key)
            .iter()
            .any(|ident| sources.iter().any(|source| names_crate(source, ident)));
        if !named {
            reported.insert(dep.key.clone());
            out.push(format!(
                "{}:{}: [{}] `{}`: no source of the crate names it",
                member.manifest, dep.line, dep.table, dep.key
            ));
        }
    }
    for dev in deps.iter().filter(|e| e.table == "dev-dependencies") {
        let Some(normal) = deps
            .iter()
            .find(|e| e.table == "dependencies" && e.key == dev.key)
        else {
            continue;
        };
        let (normal_fields, normal_features) = spec(&normal.value);
        let (dev_fields, dev_features) = spec(&dev.value);
        if normal_fields == dev_fields && dev_features.is_subset(&normal_features) {
            out.push(format!(
                "{}:{}: [dev-dependencies] `{}` repeats [dependencies] `{}` (line {}): \
                 the tests have it already",
                member.manifest, dev.line, dev.key, normal.key, normal.line
            ));
        }
    }
    out
}

/// The names the code may import dependency `key` as: `-` as `_`, or
/// dropped (`md-5` is `md5`).
fn idents(key: &str) -> Vec<String> {
    let mut out = vec![key.replace('-', "_")];
    if key.contains('-') {
        out.push(key.replace('-', ""));
    }
    out
}

/// Whether `source` names the crate `ident`: a path (`ident::…`), a `use`
/// or an `extern crate`.
fn names_crate(source: &str, ident: &str) -> bool {
    let mut from = 0;
    while let Some(at) = source[from..].find(ident) {
        let start = from + at;
        let end = start + ident.len();
        from = end;
        let before = source[..start].chars().next_back();
        let after = source[end..].chars().next();
        if before.is_some_and(is_ident) || after.is_some_and(is_ident) {
            continue;
        }
        if source[end..].starts_with("::") {
            return true;
        }
        let preceding = source[..start].trim_end();
        let word_start = preceding.rfind(|c| !is_ident(c)).map_or(0, |i| i + 1);
        if matches!(&preceding[word_start..], "use" | "crate") {
            return true;
        }
    }
    false
}

/// The `[workspace.dependencies]` of `root` that no member inherits.
fn uninherited<'a>(root: &str, members: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut inherited = BTreeSet::new();
    for manifest in members {
        for entry in entries(manifest) {
            if is_dependency_table(&entry.table)
                && spec(&entry.value)
                    .0
                    .get("workspace")
                    .is_some_and(|v| v == "true")
            {
                inherited.insert(entry.key);
            }
        }
    }
    entries(root)
        .into_iter()
        .filter(|e| e.table == "workspace.dependencies" && !inherited.contains(&e.key))
        .map(|e| {
            format!(
                "{ROOT_MANIFEST}:{}: [workspace.dependencies] `{}`: no member inherits it",
                e.line, e.key
            )
        })
        .collect()
}

/// The member directories `[workspace] members` lists.
fn workspace_members(root: &str) -> Vec<String> {
    entries(root)
        .into_iter()
        .find(|e| e.table == "workspace" && e.key == "members")
        .map(|e| string_list(&e.value))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(path: &str, text: &str) -> (String, String) {
        (path.to_string(), text.to_string())
    }

    #[test]
    fn a_pub_item_nothing_else_names_is_reported() {
        let sources = [
            src(
                "a.rs",
                "pub fn used() {}\npub(crate) async fn lonely() {}\npub struct Kept;\n",
            ),
            src("b.rs", "fn main() { a::used(); let _ = Kept; }\n"),
        ];
        assert_eq!(
            unused_items(sources.iter()),
            ["a.rs:2: pub fn `lonely`: nothing else in the workspace names it"]
        );
    }

    #[test]
    fn a_mention_in_a_comment_or_string_counts_as_a_use() {
        let sources = [
            src("a.rs", "pub const LIMIT: u32 = 1;\npub fn helper() {}\n"),
            src("b.rs", "// see LIMIT\nconst S: &str = \"helper\";\n"),
        ];
        assert!(unused_items(sources.iter()).is_empty());
    }

    #[test]
    fn definitions_in_comments_and_strings_are_not_items() {
        let code = code_only(concat!(
            "/// ```\n/// pub fn in_doc() {}\n/// ```\n",
            "const A: &str = \"pub fn in_string() {}\";\n",
            "const B: &str = r#\"pub fn in_raw() {}\"#;\n",
            "/* pub fn in_block() {} */\n",
            "fn f<'a>(c: char) -> bool { c == '\"' }\n",
            "pub fn real() {}\n",
        ));
        let names: Vec<_> = pub_items(&code)
            .into_iter()
            .map(|(line, _, name)| (line, name))
            .collect();
        assert_eq!(names, [(8, "real".to_string())]);
    }

    #[test]
    fn every_kind_of_pub_item_is_read() {
        let code = "pub const fn a() {}\npub const B: u8 = 0;\npub static mut C: u8 = 0;\n\
                    pub(super) unsafe fn d() {}\npub enum E {}\npub trait F {}\npub type G = u8;\n\
                    pub mod h {}\npub use i::J;\npub struct r#K;\npublic();\n";
        let items: Vec<_> = pub_items(code)
            .into_iter()
            .map(|(_, kind, name)| (kind, name))
            .collect();
        let expected = [
            ("fn", "a"),
            ("const", "B"),
            ("static", "C"),
            ("fn", "d"),
            ("enum", "E"),
            ("trait", "F"),
            ("type", "G"),
            ("struct", "K"),
        ];
        assert_eq!(items, expected.map(|(kind, name)| (kind, name.to_string())));
    }

    #[test]
    fn manifest_entries_span_lines_and_drop_comments() {
        let manifest = "[package]\nname = \"x\" # the name\n\n[dependencies]\n\
                        a = { version = \"1\", features = [\n    \"b\", # why\n    \"c\",\n] }\n\
                        [target.'cfg(unix)'.dependencies]\nd = \"2\"\n";
        let deps: Vec<_> = entries(manifest)
            .into_iter()
            .filter(|e| is_dependency_table(&e.table))
            .map(|e| (e.key, e.line))
            .collect();
        assert_eq!(deps, [("a".to_string(), 5), ("d".to_string(), 10)]);
        let a = &entries(manifest)[1];
        let (fields, features) = spec(&a.value);
        assert_eq!(fields.get("version").map(String::as_str), Some("\"1\""));
        assert_eq!(features.into_iter().collect::<Vec<_>>(), ["b", "c"]);
    }

    #[test]
    fn a_crate_is_named_by_a_path_a_use_or_an_extern_crate() {
        assert!(names_crate("let v = serde_json::json!({});", "serde_json"));
        assert!(names_crate("use tokio;", "tokio"));
        assert!(names_crate("pub use  rand ;", "rand"));
        assert!(names_crate("extern crate alloc;", "alloc"));
        assert!(!names_crate("let url = base.url;", "url"));
        assert!(!names_crate("my_tokio::spawn()", "tokio"));
        assert!(idents("md-5")
            .iter()
            .any(|i| names_crate("md5::compute(b)", i)));
    }

    fn member(manifest: &str, source: &str) -> Member {
        Member {
            manifest: "m/Cargo.toml".into(),
            text: manifest.into(),
            sources: vec![src("m/src/lib.rs", source)],
        }
    }

    #[test]
    fn an_unnamed_dependency_is_reported_unless_ignored() {
        let manifest = "[package.metadata.unused]\nignore = [\"feature-only\"]\n\n\
                        [dependencies]\nserde = \"1\"\nhex = \"0.4\"\nfeature-only = \"1\"\n\
                        [dev-dependencies]\ntempfile = \"3\"\n";
        let source = "use serde::Serialize;\n";
        assert_eq!(
            member_findings(&member(manifest, source)),
            [
                "m/Cargo.toml:6: [dependencies] `hex`: no source of the crate names it",
                "m/Cargo.toml:9: [dev-dependencies] `tempfile`: no source of the crate names it",
            ]
        );
    }

    #[test]
    fn a_dev_dependency_that_adds_nothing_is_reported() {
        let manifest = "[dependencies]\n\
                        a = { workspace = true, features = [\"x\", \"y\"] }\n\
                        b = { path = \"../b\" }\nc = \"1\"\n\
                        [dev-dependencies]\n\
                        a = { workspace = true, features = [\"y\"] }\n\
                        b = { path = \"../b\", features = [\"testing\"] }\n\
                        c = { version = \"1\" }\n";
        let source = "use a; use b; use c;";
        assert_eq!(
            member_findings(&member(manifest, source)),
            [
                "m/Cargo.toml:6: [dev-dependencies] `a` repeats [dependencies] `a` (line 2): \
                 the tests have it already",
                "m/Cargo.toml:8: [dev-dependencies] `c` repeats [dependencies] `c` (line 4): \
                 the tests have it already",
            ]
        );
    }

    #[test]
    fn workspace_members_and_their_inherited_dependencies() {
        let root = "[workspace]\nmembers = [\n    \"crates/a\", # first\n    \"xtask\",\n]\n\n\
                    [workspace.dependencies]\nserde = \"1\"\nunused-one = \"2\"\n";
        assert_eq!(workspace_members(root), ["crates/a", "xtask"]);
        let member = "[dependencies]\nserde = { workspace = true }\n";
        assert_eq!(
            uninherited(root, [member].into_iter()),
            ["Cargo.toml:9: [workspace.dependencies] `unused-one`: no member inherits it"]
        );
    }
}
