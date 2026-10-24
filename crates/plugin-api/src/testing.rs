//! Running a plugin's protocol without a server (feature `testing`).
//!
//! [`serve`] does what the host's dispatcher does with a request: it calls
//! [`FormatPlugin::handle`], answers the queries the plugin asks for with
//! `answer`, and calls [`FormatPlugin::render`] round by round, under the
//! host's bounds. What only the host can do (a download, a publish, a
//! change, serving a file) comes back as the action, for the test to
//! inspect.
//!
//! [`converse`] does the same for the upstream side of a proxy
//! ([`FormatPlugin::upstream`]): it answers every fetch the plugin asks for
//! with `fetch`, as the host's proxy read path would.
//!
//! ```ignore
//! let served = serve(&MyFormat, &repository(RepositoryKind::Hosted), &Request::new("GET", "/index.json"), |query| match query {
//!     Query::Search(_) => Answer::Search(SearchResult { total: 0, hits: vec![] }),
//!     other => panic!("unexpected {other:?}"),
//! });
//! assert_eq!(served.response().status, 200);
//! ```

use crate::{Action, Answer, FormatPlugin, Loaded, Query, Repository, RepositoryKind};
use crate::{Fetch, FetchResult, Fetched, FormatError, Remote, UpstreamAnswer, UpstreamOp};
use crate::{Request, Response, UpstreamStep};

/// The most rounds of queries one request may load (as the host).
pub const MAX_ROUNDS: usize = 4;

/// The most query answers one request may load (as the host).
pub const MAX_QUERIES: usize = 2048;

/// A repository named `repo` of `kind`, served at
/// `https://forge.example.com/repository/repo`.
pub fn repository(kind: RepositoryKind) -> Repository {
    Repository {
        name: "repo".into(),
        kind,
        base_url: "https://forge.example.com/repository/repo".into(),
        inline: false,
        reserved_prefixes: Vec::new(),
    }
}

/// What came of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The plugin's response, or the host action it asked for.
    pub outcome: Action,
    /// Every query the plugin asked for, in order.
    pub queries: Vec<Query>,
}

impl Served {
    /// The response; panics when the plugin asked for a host action.
    pub fn response(&self) -> &Response {
        match &self.outcome {
            Action::Respond(response) => response,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    /// The response body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.response().body).into_owned()
    }

    /// The value of response header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.response()
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Serve `req` to `plugin` for `repo`, answering its queries with `answer`.
pub fn serve(
    plugin: &dyn FormatPlugin,
    repo: &Repository,
    req: &Request,
    mut answer: impl FnMut(&Query) -> Answer,
) -> Served {
    let queries = Vec::new();
    let pending = match plugin.handle(repo, req) {
        Action::Load(pending) => pending,
        outcome => return Served { outcome, queries },
    };
    serve_loads(plugin, repo, req, &mut answer, pending, queries)
}

/// [`serve`] for a request with a body ([`Action::ReadBody`]): the plugin is
/// asked again with `body`, as the host does once it read it.
pub fn serve_with_body(
    plugin: &dyn FormatPlugin,
    repo: &Repository,
    req: &Request,
    body: &[u8],
    answer: impl FnMut(&Query) -> Answer,
) -> Served {
    match plugin.handle(repo, req) {
        Action::ReadBody(_) => {}
        outcome => {
            return Served {
                outcome,
                queries: Vec::new(),
            }
        }
    }
    serve(plugin, repo, &req.clone().with_body(body.to_vec()), answer)
}

fn serve_loads(
    plugin: &dyn FormatPlugin,
    repo: &Repository,
    req: &Request,
    answer: &mut impl FnMut(&Query) -> Answer,
    mut pending: Vec<Query>,
    mut queries: Vec<Query>,
) -> Served {
    let mut data: Vec<Loaded> = Vec::new();
    for _ in 0..MAX_ROUNDS {
        if data.len() + pending.len() > MAX_QUERIES {
            break;
        }
        for query in pending {
            let answered = answer(&query);
            queries.push(query.clone());
            data.push(Loaded {
                query,
                answer: answered,
            });
        }
        match plugin.render(repo, req, &data) {
            Action::Load(more) => pending = more,
            outcome => return Served { outcome, queries },
        }
    }
    Served {
        outcome: Action::Respond(Response::text(
            500,
            "the response needs more data than one request may load",
        )),
        queries,
    }
}

/// The most rounds of one upstream conversation (as the host).
pub const MAX_UPSTREAM_ROUNDS: usize = 4;

/// The most fetches of one upstream conversation (as the host).
pub const MAX_UPSTREAM_FETCHES: usize = 256;

/// The most rounds of one upstream conversation of an images format (as
/// the host): an upstream's tag list may take a page per round.
pub const MAX_IMAGE_UPSTREAM_ROUNDS: usize = 12;

/// What came of an upstream conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversed {
    /// The plugin's answer.
    pub answer: UpstreamAnswer,
    /// Every fetch the plugin asked for, in order.
    pub fetches: Vec<Fetch>,
}

/// Run `op` against `remote` through `plugin`'s upstream side, answering
/// its fetches with `fetch`. Errs with what the plugin returned, or when it
/// needs more rounds or fetches than the host allows. Every fetch reaches
/// `fetch`: the host also refuses the ones on origins its upstream does not
/// point at ([`Fetch`]), which a test checks by the URLs in
/// [`Conversed::fetches`].
pub fn converse(
    plugin: &dyn FormatPlugin,
    remote: &Remote,
    op: &UpstreamOp,
    mut fetch: impl FnMut(&Fetch) -> Fetched,
) -> Result<Conversed, FormatError> {
    converse_answered(plugin, remote, op, |want| FetchResult {
        fetch: want.clone(),
        outcome: fetch(want),
        status: None,
        headers: Vec::new(),
    })
}

/// [`converse`], with `fetch` answering each fetch whole: its outcome, and
/// for an images format the status and `link` headers of the upstream's
/// answer. An images format's conversation may take
/// [`MAX_IMAGE_UPSTREAM_ROUNDS`] rounds.
pub fn converse_answered(
    plugin: &dyn FormatPlugin,
    remote: &Remote,
    op: &UpstreamOp,
    mut fetch: impl FnMut(&Fetch) -> FetchResult,
) -> Result<Conversed, FormatError> {
    let rounds = if plugin.descriptor().storage == crate::Storage::Images {
        MAX_IMAGE_UPSTREAM_ROUNDS
    } else {
        MAX_UPSTREAM_ROUNDS
    };
    let mut fetched: Vec<FetchResult> = Vec::new();
    for _ in 0..rounds {
        match plugin.upstream(remote, op, &fetched)? {
            UpstreamStep::Done(answer) => {
                return Ok(Conversed {
                    answer,
                    fetches: fetched.into_iter().map(|f| f.fetch).collect(),
                })
            }
            UpstreamStep::Fetch(wanted) => {
                if wanted.is_empty() || fetched.len() + wanted.len() > MAX_UPSTREAM_FETCHES {
                    return Err(FormatError::Internal(format!(
                        "asked for {} fetches after {}",
                        wanted.len(),
                        fetched.len()
                    )));
                }
                for want in wanted {
                    let mut answered = fetch(&want);
                    answered.fetch = want;
                    fetched.push(answered);
                }
            }
        }
    }
    Err(FormatError::Internal(format!(
        "needed more than {rounds} rounds"
    )))
}
