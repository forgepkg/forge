//! Uploads of several files: `POST /raw/<repo>/<directory>/` with a
//! `multipart/form-data` body, whose file parts are stored under
//! `directory`, each at its part's file name. Nexus' field names for its
//! component upload work too: `raw.directory` (or `directory`) names a
//! subdirectory, and `<field>.filename` (`raw.asset1.filename`) the name of
//! the file part `<field>`. The host receives the form
//! ([`Query::Form`]) and stores every file, or none ([`Query::Store`]).

use std::collections::{BTreeMap, HashSet};

use forge_plugin_api::files;
use forge_plugin_api::{
    Action, Answer, FileSource, FormContent, FormPart, Loaded, NewFile, Query, Response,
    StoreStatus, StoredFile,
};

/// The next step of a form upload into `directory`: store the form's files
/// once it is received, answer once they are stored.
pub fn render(directory: &str, data: &[Loaded]) -> Action {
    match data.last().map(|loaded| &loaded.answer) {
        Some(Answer::Form(parts)) => match place(directory, parts) {
            Ok(files) => Action::Load(vec![Query::Store(files)]),
            Err(message) => Action::Respond(Response::text(400, &message)),
        },
        Some(Answer::Stored(files)) => Action::Respond(stored(files)),
        _ => Action::Respond(Response::text(500, "raw: the form was not received")),
    }
}

/// Where each file of a form goes, or why the form is refused.
pub fn place(directory: &str, parts: &[FormPart]) -> Result<Vec<NewFile>, String> {
    let mut texts: BTreeMap<&str, &str> = BTreeMap::new();
    let mut uploads = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        match &part.content {
            FormContent::File(file) => uploads.push((index, part.field.as_str(), file)),
            FormContent::Text(value) => {
                texts.insert(part.field.as_str(), value.as_str());
            }
        }
    }
    if uploads.is_empty() {
        return Err("the form holds no file".into());
    }

    // The fields: a subdirectory, and the names of file parts.
    let mut subdirectory = "";
    let fields: HashSet<&str> = uploads.iter().map(|(_, field, _)| *field).collect();
    for (name, value) in &texts {
        match *name {
            "directory" | "raw.directory" => subdirectory = value,
            other
                if other
                    .strip_suffix(".filename")
                    .is_some_and(|field| fields.contains(field)) => {}
            other => {
                return Err(format!(
                    "unknown form field {other:?} (file parts, directory and <file field>.filename are accepted)"
                ))
            }
        }
    }
    let base = files::normalize_directory(subdirectory).map_err(|e| format!("directory: {e}"))?;
    let directory = format!("{directory}{base}");

    let mut seen = HashSet::new();
    let mut placed = Vec::with_capacity(uploads.len());
    for (index, field, file) in uploads {
        let name = texts
            .get(format!("{field}.filename").as_str())
            .copied()
            .unwrap_or(&file.name);
        let target =
            files::join(&directory, name).map_err(|e| format!("file name {name:?}: {e}"))?;
        if !seen.insert(target.clone()) {
            return Err(format!("the form holds {target} twice"));
        }
        placed.push(NewFile {
            path: target,
            source: FileSource::Part(u32::try_from(index).unwrap_or(u32::MAX)),
            content_type: file.content_type.clone(),
        });
    }
    Ok(placed)
}

/// The answer to a stored form: what became of each file, 201 when one was
/// new.
fn stored(files: &[StoredFile]) -> Response {
    let created = files.iter().any(|f| f.status == StoreStatus::Created);
    let files: Vec<serde_json::Value> = files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path,
                "size": f.size,
                "sha256": f.sha256,
                "status": match f.status {
                    StoreStatus::Created => "created",
                    StoreStatus::Replaced => "replaced",
                    StoreStatus::Unchanged => "unchanged",
                },
            })
        })
        .collect();
    Response::new(
        if created { 201 } else { 200 },
        "application/json",
        serde_json::json!({ "files": files }).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_plugin_api::FormFile;

    fn file(field: &str, name: &str) -> FormPart {
        FormPart {
            field: field.into(),
            content: FormContent::File(FormFile {
                name: name.into(),
                content_type: Some("application/gzip".into()),
                size: 3,
            }),
        }
    }

    fn text(field: &str, value: &str) -> FormPart {
        FormPart {
            field: field.into(),
            content: FormContent::Text(value.into()),
        }
    }

    #[test]
    fn files_go_under_the_directory_by_their_names() {
        let placed = place("pdfium/", &[file("file", "a.tgz"), file("file", "b.tgz")]).unwrap();
        let paths: Vec<_> = placed.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["pdfium/a.tgz", "pdfium/b.tgz"]);
        assert_eq!(placed[1].source, FileSource::Part(1));
        assert_eq!(placed[0].content_type.as_deref(), Some("application/gzip"));
    }

    #[test]
    fn nexus_fields_name_the_directory_and_the_files() {
        let parts = [
            text("raw.directory", "7350"),
            file("raw.asset1", "upload.bin"),
            text("raw.asset1.filename", "pdfium-linux-x64.tgz"),
            file("raw.asset2", "pdfium-win-x64.tgz"),
        ];
        let placed = place("pdfium/", &parts).unwrap();
        let placed: Vec<_> = placed
            .iter()
            .map(|f| (f.path.as_str(), &f.source))
            .collect();
        assert_eq!(
            placed,
            [
                ("pdfium/7350/pdfium-linux-x64.tgz", &FileSource::Part(1)),
                ("pdfium/7350/pdfium-win-x64.tgz", &FileSource::Part(3)),
            ]
        );
    }

    #[test]
    fn bad_forms_are_refused() {
        assert_eq!(
            place("", &[text("directory", "x")]).unwrap_err(),
            "the form holds no file"
        );
        assert!(place("", &[file("f", "a"), text("other", "x")])
            .unwrap_err()
            .starts_with("unknown form field \"other\""));
        // A name for a part that is not there is unknown too.
        assert!(place("", &[file("f", "a"), text("g.filename", "x")]).is_err());
        assert!(place("", &[file("f", "a"), text("directory", "../x")])
            .unwrap_err()
            .starts_with("directory: "));
        assert!(place("", &[file("f", "../a")])
            .unwrap_err()
            .starts_with("file name \"../a\": "));
        assert_eq!(
            place("d/", &[file("f", "a"), file("g", "a")]).unwrap_err(),
            "the form holds d/a twice"
        );
    }
}
