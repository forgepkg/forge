//! The raw protocol against canned answers: what each request asks of the
//! host, round by round, and what it answers.

use forge_format_raw::Raw;
use forge_plugin_api::testing::{repository, serve};
use forge_plugin_api::{
    Action, Answer, DirectoryEntry, DirectoryPage, DirectoryQuery, FileInfo, FileSource,
    FormContent, FormFile, FormPart, NewFile, Query, RepositoryKind, Request, StoreStatus,
    StoredFile,
};

fn file(path: &str) -> FileInfo {
    FileInfo {
        path: path.into(),
        size: 3,
        content_type: "application/gzip".into(),
        sha256: "ab".repeat(32),
        sha512: String::new(),
        sha1: "cd".repeat(20),
        md5: "ef".repeat(16),
        modified: "2026-10-01T12:00:00.250Z".into(),
        last_downloaded: None,
    }
}

fn hosted() -> forge_plugin_api::Repository {
    repository(RepositoryKind::Hosted, "/raw")
}

#[test]
fn a_stored_file_is_served_by_the_host() {
    let served = serve(
        &Raw,
        &hosted(),
        &Request::new("GET", "/a/x.tgz"),
        |q| match q {
            Query::File(p) if p == "a/x.tgz" => Answer::File(Some(file(p))),
            other => panic!("unexpected {other:?}"),
        },
    );
    assert_eq!(served.outcome, Action::ServeFile("a/x.tgz".into()));
}

#[test]
fn a_sidecar_is_computed_from_its_file() {
    let served = serve(
        &Raw,
        &hosted(),
        &Request::new("GET", "/a/x.tgz.sha1"),
        |q| match q {
            Query::File(p) if p == "a/x.tgz.sha1" => Answer::File(None),
            Query::File(p) if p == "a/x.tgz" => Answer::File(Some(file(p))),
            other => panic!("unexpected {other:?}"),
        },
    );
    assert_eq!(served.response().status, 200);
    assert_eq!(served.text(), format!("{}  x.tgz\n", "cd".repeat(20)));
    assert_eq!(
        served.header("etag").unwrap(),
        format!("\"{}-sha1\"", "ab".repeat(32))
    );
    assert_eq!(
        served.header("last-modified"),
        Some("Thu, 01 Oct 2026 12:00:00 GMT")
    );
    assert_eq!(
        served.header("content-disposition"),
        Some("attachment; filename=\"x.tgz.sha1\"")
    );
    // A stored file of the sidecar's name is served as it is.
    let served = serve(
        &Raw,
        &hosted(),
        &Request::new("GET", "/a/x.tgz.sha1"),
        |q| match q {
            Query::File(p) => Answer::File(Some(file(p))),
            other => panic!("unexpected {other:?}"),
        },
    );
    assert_eq!(served.outcome, Action::ServeFile("a/x.tgz.sha1".into()));
    // The client's copy is current.
    let req = Request::new("GET", "/a/x.tgz.md5")
        .with_header("if-none-match", &format!("\"{}-md5\"", "ab".repeat(32)));
    let served = serve(&Raw, &hosted(), &req, |q| match q {
        Query::File(p) if p == "a/x.tgz" => Answer::File(Some(file(p))),
        Query::File(_) => Answer::File(None),
        other => panic!("unexpected {other:?}"),
    });
    assert_eq!(served.response().status, 304);
    assert!(served.response().body.is_empty());
}

#[test]
fn a_proxy_fetches_what_it_has_not_cached() {
    let proxy = repository(RepositoryKind::Proxy, "/raw");
    let served = serve(&Raw, &proxy, &Request::new("GET", "/x.bin"), |q| match q {
        Query::File(_) => Answer::File(None),
        Query::FetchFile(p) => Answer::File(Some(file(p))),
        other => panic!("unexpected {other:?}"),
    });
    assert_eq!(served.outcome, Action::ServeFile("x.bin".into()));
    assert_eq!(
        served.queries,
        [
            Query::File("x.bin".into()),
            Query::FetchFile("x.bin".into())
        ]
    );
}

#[test]
fn a_directory_named_without_its_slash_redirects() {
    let directory = |answer: Option<DirectoryPage>| {
        move |q: &Query| match q {
            Query::File(_) => Answer::File(None),
            Query::Directory(d) => {
                assert_eq!(
                    d,
                    &DirectoryQuery {
                        directory: "pdfium/".into(),
                        after: None,
                        limit: 1
                    }
                );
                Answer::Directory(answer.clone())
            }
            other => panic!("unexpected {other:?}"),
        }
    };
    let page = DirectoryPage {
        entries: vec![DirectoryEntry::Directory("pdfium/7350/".into())],
        next: None,
    };
    let served = serve(
        &Raw,
        &hosted(),
        &Request::new("GET", "/pdfium"),
        directory(Some(page)),
    );
    assert_eq!(served.response().status, 301);
    assert_eq!(served.header("location"), Some("/raw/repo/pdfium/"));
    // A hosted repository asks no upstream.
    assert!(!served
        .queries
        .iter()
        .any(|q| matches!(q, Query::FetchFile(_))));
    let served = serve(
        &Raw,
        &hosted(),
        &Request::new("GET", "/pdfium"),
        directory(None),
    );
    assert_eq!(served.response().status, 404);
}

#[test]
fn the_repository_url_without_its_slash_redirects() {
    let served = serve(&Raw, &hosted(), &Request::new("GET", ""), |q| {
        panic!("unexpected {q:?}")
    });
    assert_eq!(served.response().status, 301);
    assert_eq!(served.header("location"), Some("/raw/repo/"));
    let served = serve(&Raw, &hosted(), &Request::new("PUT", ""), |q| {
        panic!("unexpected {q:?}")
    });
    assert_eq!(served.response().status, 404);
}

#[test]
fn listings_render_the_page_the_host_loaded() {
    let req = Request::new("GET", "/a/?limit=1&format=json");
    let served = serve(&Raw, &hosted(), &req, |q| match q {
        Query::Directory(d) => {
            assert_eq!(d.directory, "a/");
            assert_eq!(d.limit, 1);
            Answer::Directory(Some(DirectoryPage {
                entries: vec![DirectoryEntry::File(file("a/x.tgz"))],
                next: Some("x.tgz".into()),
            }))
        }
        other => panic!("unexpected {other:?}"),
    });
    let response = served.response();
    assert_eq!(response.status, 200);
    assert_eq!(served.header("content-type"), Some("application/json"));
    assert_eq!(
        served.header("link"),
        Some("</raw/repo/a/?after=x.tgz&limit=1&format=json>; rel=\"next\"")
    );
    let page: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(page["entries"][0]["name"], "x.tgz");
    assert_eq!(page["next"], "x.tgz");
    // A directory that does not exist.
    let served = serve(&Raw, &hosted(), &Request::new("GET", "/b/"), |_| {
        Answer::Directory(None)
    });
    assert_eq!(served.response().status, 404);
}

#[test]
fn uploads_and_deletes_go_through_the_host() {
    let req = Request::new("PUT", "/a/x.tgz").with_header("content-type", "application/gzip");
    let served = serve(&Raw, &hosted(), &req, |q| match q {
        Query::Store(files) => {
            assert_eq!(
                files,
                &[NewFile {
                    path: "a/x.tgz".into(),
                    source: FileSource::Body,
                    content_type: Some("application/gzip".into()),
                }]
            );
            Answer::Stored(vec![StoredFile {
                path: "a/x.tgz".into(),
                size: 3,
                sha256: "ab".into(),
                status: StoreStatus::Created,
            }])
        }
        other => panic!("unexpected {other:?}"),
    });
    assert_eq!(served.response().status, 201);

    let served = serve(&Raw, &hosted(), &Request::new("POST", "/a/"), |q| match q {
        Query::Form => Answer::Form(vec![
            FormPart {
                field: "raw.directory".into(),
                content: FormContent::Text("7350".into()),
            },
            FormPart {
                field: "file".into(),
                content: FormContent::File(FormFile {
                    name: "x.tgz".into(),
                    content_type: None,
                    size: 3,
                }),
            },
        ]),
        Query::Store(files) => {
            assert_eq!(files[0].path, "a/7350/x.tgz");
            assert_eq!(files[0].source, FileSource::Part(1));
            Answer::Stored(vec![StoredFile {
                path: files[0].path.clone(),
                size: 3,
                sha256: "ab".into(),
                status: StoreStatus::Unchanged,
            }])
        }
        other => panic!("unexpected {other:?}"),
    });
    assert_eq!(served.response().status, 200);
    let body: serde_json::Value = serde_json::from_slice(&served.response().body).unwrap();
    assert_eq!(body["files"][0]["status"], "unchanged");

    let served = serve(&Raw, &hosted(), &Request::new("DELETE", "/a/x.tgz"), |q| {
        assert_eq!(q, &Query::Remove("a/x.tgz".into()));
        Answer::Removed(false)
    });
    assert_eq!(served.response().status, 404);
}

#[test]
fn bad_paths_and_methods_are_refused() {
    for (method, path, status) in [
        ("GET", "/a/../b", 400),
        ("GET", "/a//b", 400),
        ("GET", "/a%2fb", 400),
        ("PUT", "/a/", 400),
        ("POST", "/a", 400),
        ("DELETE", "/a/", 400),
        ("PATCH", "/a", 405),
        ("GET", "/?limit=x", 400),
        ("GET", "/?after=..", 400),
    ] {
        let served = serve(&Raw, &hosted(), &Request::new(method, path), |q| {
            panic!("{method} {path}: unexpected {q:?}")
        });
        assert_eq!(served.response().status, status, "{method} {path}");
    }
}
