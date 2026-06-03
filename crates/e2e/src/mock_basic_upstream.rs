//! In-process mock **HTTP Basic** upstream identity provider for the slice-12.3
//! credential-forwarding e2e scenarios (the verdaccio-nexus-auth-proxy pattern).
//!
//! A tiny axum app on an ephemeral loopback port that plays the upstream Nexus
//! status/whoami endpoint:
//!
//! * It accepts an `Authorization: Basic …` header and checks the decoded
//!   `username:password` against a fixed credential table.
//! * Valid credentials → `200` with a small JSON body advertising the user's
//!   groups (so the `groups_path` / `required_groups` / `admin_group` gate can be
//!   exercised). Invalid credentials → `401`. No/garbled header → `401`.
//! * Every request increments a hit counter so a test can assert the upstream was
//!   forwarded to **exactly N times** (cache-hit ⇒ no extra hit; TTL-expiry /
//!   reauth ⇒ a fresh hit).
//! * A `down` switch makes every request answer `503` (an outage from forge's
//!   point of view ⇒ `Unavailable` ⇒ fail-closed, nothing cached), so the
//!   fail-closed scenario can be driven deterministically.
//!
//! The forge server reaches this over its **SSRF-guarded** client, so the stack
//! must set `allow_private_upstream = true` (the loopback address is otherwise
//! blocked) — [`MockBasicUpstream::upstream_basic_block`] does that.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use serde_json::json;
use tokio::task::JoinHandle;

/// One known upstream credential plus the groups the whoami body advertises.
#[derive(Clone)]
struct Account {
    password: String,
    groups: Vec<String>,
}

/// Shared mock state: the credential table, the request hit counter, and the
/// `down` (outage) switch.
struct Inner {
    /// `username -> account`.
    accounts: HashMap<String, Account>,
    /// Total number of forwarded requests this mock has *received* (every call,
    /// regardless of verdict). Tests assert exact counts against this.
    hits: AtomicUsize,
    /// When set, every request answers `503` (simulated upstream outage).
    down: AtomicBool,
}

/// A running in-process mock Basic-auth upstream.
pub struct MockBasicUpstream {
    base: String,
    inner: Arc<Inner>,
    handle: JoinHandle<()>,
}

impl Drop for MockBasicUpstream {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Clone)]
struct Ctx {
    inner: Arc<Inner>,
}

impl MockBasicUpstream {
    /// Boot the mock on an ephemeral loopback port. `accounts` is a list of
    /// `(username, password, groups)` the upstream will accept.
    pub async fn start(accounts: Vec<(&str, &str, Vec<&str>)>) -> Self {
        let table: HashMap<String, Account> = accounts
            .into_iter()
            .map(|(u, p, g)| {
                (
                    u.to_string(),
                    Account {
                        password: p.to_string(),
                        groups: g.into_iter().map(str::to_string).collect(),
                    },
                )
            })
            .collect();

        let inner = Arc::new(Inner {
            accounts: table,
            hits: AtomicUsize::new(0),
            down: AtomicBool::new(false),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock basic upstream");
        let addr = listener.local_addr().expect("upstream addr");
        let base = format!("http://{addr}");

        let ctx = Ctx {
            inner: inner.clone(),
        };
        let app = Router::new().route("/status", get(status)).with_state(ctx);

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        Self {
            base,
            inner,
            handle,
        }
    }

    /// The whoami/status URL forge forwards Basic credentials to.
    pub fn status_url(&self) -> String {
        format!("{}/status", self.base)
    }

    /// Number of requests this upstream has received (every forward, any verdict).
    pub fn hits(&self) -> usize {
        self.inner.hits.load(Ordering::SeqCst)
    }

    /// Flip the outage switch: when `true`, every request answers `503`.
    pub fn set_down(&self, down: bool) {
        self.inner.down.store(down, Ordering::SeqCst);
    }

    /// The `[auth]` + `[auth.upstream_basic]` TOML block pointing forge at this
    /// mock. `providers` is the ordered chain (e.g.
    /// `["local-password", "upstream-basic"]`). `positive_ttl_secs` /
    /// `negative_ttl_secs` tune the validated-credential cache. When `groups`
    /// wiring is requested (`required_groups` / `admin_group`), the `groups_path`
    /// is set to `roles` so the mock's `{"roles": [...]}` body is parsed.
    #[allow(clippy::too_many_arguments)]
    pub fn upstream_basic_block(
        &self,
        providers: &[&str],
        positive_ttl_secs: u64,
        negative_ttl_secs: u64,
        required_groups: &[&str],
        admin_group: &str,
    ) -> String {
        let provider_list = providers
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let required = required_groups
            .iter()
            .map(|g| format!("{g:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        // Only parse groups when a gate/admin-mapping needs them (config rejects
        // required_groups without groups_path).
        let groups_path = if required_groups.is_empty() && admin_group.is_empty() {
            String::new()
        } else {
            "groups_path = \"roles\"\n".to_string()
        };
        format!(
            r#"
providers = [{provider_list}]

[auth.upstream_basic]
enabled = true
url = "{url}"
method = "GET"
success_status = [200]
reject_status = [401, 403]
allow_private_upstream = true
auto_provision = true
required_groups = [{required}]
{groups_path}admin_group = "{admin_group}"

[auth.upstream_basic.cache]
positive_ttl_secs = {positive_ttl_secs}
negative_ttl_secs = {negative_ttl_secs}
key_pepper = "e2e-credforward-pepper-high-entropy"
"#,
            url = self.status_url(),
        )
    }
}

/// `GET /status` — the Nexus whoami stand-in. Counts the hit, honours the `down`
/// switch, then validates the Basic header against the credential table.
async fn status(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    ctx.inner.hits.fetch_add(1, Ordering::SeqCst);

    if ctx.inner.down.load(Ordering::SeqCst) {
        // Outage: forge treats a 5xx as Unavailable (fail-closed, cache nothing).
        return (StatusCode::SERVICE_UNAVAILABLE, "upstream down").into_response();
    }

    let Some((user, pass)) = decode_basic(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match ctx.inner.accounts.get(&user) {
        Some(acct) if acct.password == pass => Json(json!({
            "userId": user,
            "roles": acct.groups,
        }))
        .into_response(),
        // Wrong password or unknown user → definitive rejection.
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Decode an `Authorization: Basic base64(user:pass)` header into its parts.
fn decode_basic(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}
