//! Running a plugin's protocol without a server (feature `testing`).
//!
//! [`serve`] does what the host's dispatcher does with a request: it calls
//! [`FormatPlugin::handle`], answers the queries the plugin asks for with
//! `answer`, and calls [`FormatPlugin::render`] round by round, under the
//! host's bounds. What only the host can do (a download, a publish, a
//! change) comes back as the action, for the test to inspect.
//!
//! ```ignore
//! let served = serve(&MyFormat, &repository(RepositoryKind::Hosted), &Request::new("GET", "/index.json"), |query| match query {
//!     Query::Search(_) => Answer::Search(SearchResult { total: 0, hits: vec![] }),
//!     other => panic!("unexpected {other:?}"),
//! });
//! assert_eq!(served.response().status, 200);
//! ```

use crate::{Action, Answer, FormatPlugin, Loaded, Query, Rendered, Repository, RepositoryKind};
use crate::{Request, Response};

/// The most rounds of queries one request may load (as the host).
pub const MAX_ROUNDS: usize = 4;

/// The most query answers one request may load (as the host).
pub const MAX_QUERIES: usize = 2048;

/// A repository named `repo` of `kind`, served at
/// `https://forge.example.com{mount}/repo`.
pub fn repository(kind: RepositoryKind, mount: &str) -> Repository {
    Repository {
        name: "repo".into(),
        kind,
        base_url: format!("https://forge.example.com{mount}/repo"),
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
    let mut queries = Vec::new();
    let mut pending = match plugin.handle(repo, req) {
        Action::Load(pending) => pending,
        outcome => return Served { outcome, queries },
    };
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
            Rendered::Respond(response) => {
                return Served {
                    outcome: Action::Respond(response),
                    queries,
                }
            }
            Rendered::Load(more) => pending = more,
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
