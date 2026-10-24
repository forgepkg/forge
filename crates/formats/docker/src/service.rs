//! The registry service: request routing, caller resolution and
//! authorization, shared by the pull, push and token handlers.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::{AuthMethod, Principal};
use forge_core::authz::Level;
use forge_core::net::upstream::UpstreamHttp;
use forge_core::repo::PublishPolicy;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};
use forge_storage::{BlobStore, Cas};
use sqlx::PgPool;

use crate::error::{Code, OciError, OciResult};
use crate::path::{self, Endpoint};
use crate::reference;
use crate::token::{self, Claims, TokenKeys};

/// Tunables of the registry (the server's `[docker]` section and friends).
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// `server.public_base_url`, without a trailing `/`.
    pub public_base_url: String,
    /// Largest blob (layer) a proxy downloads from its upstream.
    pub max_blob_bytes: u64,
    /// Largest blob a push to a hosted repository may carry when the
    /// repository has no upload limit of its own
    /// ([`Repository::max_upload_bytes`]).
    pub default_max_upload_bytes: u64,
    /// Lifetime of a registry Bearer token.
    pub token_ttl_seconds: u64,
    /// Outbox grace of released blob references.
    pub delete_grace: chrono::Duration,
    /// `groups.max_nesting_depth`.
    pub max_group_depth: u32,
    /// `docker.unreferenced_blob_ttl_seconds`: a blob link no manifest names
    /// is released after this long unused.
    pub unreferenced_blob_ttl: chrono::Duration,
}

impl RegistryConfig {
    /// How often a pull (or `HEAD`) of a blob records a use of its link: a
    /// tenth of the unreferenced-blob TTL, at most hourly. A link a client
    /// confirmed then stays at least nine tenths of the TTL, whereas an
    /// hourly record with the smallest TTL (an hour) could leave it none.
    pub fn link_touch_interval(&self) -> chrono::Duration {
        (self.unreferenced_blob_ttl / 10).min(chrono::Duration::hours(1))
    }
}

/// Builds the request-scoped policy that records a workload's publishes
/// (the trusted-publishing ledger) in the manifest transaction.
pub trait PublishRecorder: Send + Sync {
    fn for_repository(&self, repository: &Repository) -> Arc<dyn PublishPolicy>;
}

/// Whether the workload principal of a registry token still stands. The
/// server answers it from its realms: like a workload key, a token stands
/// only while its realm is enabled with the configuration it was verified
/// under, and, when it was minted with a workload key, while that key has
/// not ended.
#[async_trait::async_trait]
pub trait WorkloadCheck: Send + Sync {
    async fn still_valid(&self, principal: &Principal) -> Result<bool, String>;
}

/// The Docker / OCI registry: everything under `/v2`.
#[derive(Clone)]
pub struct Registry {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub pool: PgPool,
    pub cas: Cas,
    pub store: BlobStore,
    pub cache: Cache,
    pub authz: Authz,
    pub http: UpstreamHttp,
    pub envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    pub config: RegistryConfig,
    pub keys: TokenKeys,
    pub recorder: Option<Arc<dyn PublishRecorder>>,
    pub workloads: Option<Arc<dyn WorkloadCheck>>,
}

/// Parts the registry is built from.
pub struct RegistryParts {
    pub pool: PgPool,
    pub cas: Cas,
    pub store: BlobStore,
    pub cache: Cache,
    pub authz: Authz,
    pub http: UpstreamHttp,
    pub envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    pub config: RegistryConfig,
    pub keys: TokenKeys,
    pub recorder: Option<Arc<dyn PublishRecorder>>,
    pub workloads: Option<Arc<dyn WorkloadCheck>>,
}

impl Registry {
    pub fn new(parts: RegistryParts) -> Self {
        Registry {
            inner: Arc::new(Inner {
                pool: parts.pool,
                cas: parts.cas,
                store: parts.store,
                cache: parts.cache,
                authz: parts.authz,
                http: parts.http,
                envelope: parts.envelope,
                config: parts.config,
                keys: parts.keys,
                recorder: parts.recorder,
                workloads: parts.workloads,
            }),
        }
    }

    pub fn config(&self) -> &RegistryConfig {
        &self.inner.config
    }

    /// Answer one `/v2` request. `principal` is what the authentication
    /// middleware resolved (registry Bearer tokens are resolved here).
    pub async fn handle(&self, principal: Principal, req: Request<Body>) -> Response {
        let mut response = match self.route(principal, req).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        };
        let headers = response.headers_mut();
        headers.insert(
            "docker-distribution-api-version",
            HeaderValue::from_static("registry/2.0"),
        );
        harden(headers);
        response
    }

    async fn route(&self, principal: Principal, req: Request<Body>) -> OciResult<Response> {
        let Some(endpoint) = path::parse(req.uri().path()) else {
            return Err(OciError::new(
                StatusCode::NOT_FOUND,
                Code::NameUnknown,
                "not a registry endpoint",
            ));
        };
        let site = self.site(request_host(&req)).await?;
        let caller = self.caller(principal, req.headers(), &site).await?;
        match endpoint {
            Endpoint::Base => self.version_check(&caller, &site),
            Endpoint::Token => {
                if req.method() != Method::GET {
                    return Err(OciError::unsupported(
                        "the token service answers GET with Basic credentials",
                    ));
                }
                self.token(&caller, &site, req.uri().query().unwrap_or_default())
                    .await
            }
            Endpoint::Catalog => Err(OciError::new(
                StatusCode::NOT_FOUND,
                Code::Unsupported,
                "the catalog API is not supported; browse images in the web UI",
            )),
            endpoint => self.repository_request(caller, site, endpoint, req).await,
        }
    }

    async fn repository_request(
        &self,
        caller: Caller,
        site: Site,
        endpoint: Endpoint,
        req: Request<Body>,
    ) -> OciResult<Response> {
        let name = endpoint.name().unwrap_or_default().to_string();
        let action = action_of(&endpoint, req.method());
        let target = match self.resolve(&site, &name).await? {
            Some(target) => target,
            None => {
                // An unknown repository is answered like one the caller may
                // not use; only a global admin learns that it does not exist.
                if self.inner.authz.is_global_admin(&caller.principal).await {
                    return Err(OciError::name_unknown(&name));
                }
                return Err(self.refusal(&caller, &site, &name, action, Decision::Deny));
            }
        };
        let write_target = if action == Level::Read {
            let decision = self.decide(&caller, &target, Level::Read).await;
            if decision != Decision::Allow {
                return Err(self.refusal(&caller, &site, &name, action, decision));
            }
            None
        } else {
            Some(self.write_target(&caller, &site, &target, action).await?)
        };
        // An offline hosted or group repository serves nothing; an offline
        // proxy serves what it cached.
        let serving = write_target.as_ref().unwrap_or(&target);
        if !serving.repo.online && serving.repo.kind() != RepoKind::Proxy
            || !target.repo.online && target.repo.kind() == RepoKind::Group
        {
            return Err(OciError::unavailable("repository is offline"));
        }
        let ctx = RequestCtx {
            caller,
            site,
            target,
            write_target,
        };
        let method = req.method().clone();
        let response = match (&endpoint, &method) {
            (Endpoint::Manifest { reference, .. }, &Method::GET | &Method::HEAD) => {
                self.get_manifest(&ctx, reference, method == Method::HEAD, req.headers())
                    .await
            }
            (Endpoint::Manifest { reference, .. }, &Method::PUT) => {
                self.put_manifest(&ctx, reference, req).await
            }
            (Endpoint::Manifest { reference, .. }, &Method::DELETE) => {
                self.delete_manifest(&ctx, reference).await
            }
            (Endpoint::Blob { digest, .. }, &Method::GET | &Method::HEAD) => {
                self.get_blob(&ctx, digest, method == Method::HEAD, req.headers())
                    .await
            }
            (Endpoint::Blob { digest, .. }, &Method::DELETE) => {
                self.delete_blob(&ctx, digest).await
            }
            (Endpoint::UploadStart { .. }, &Method::POST) => self.start_upload(&ctx, req).await,
            (Endpoint::Upload { id, .. }, &Method::GET) => self.upload_status(&ctx, id).await,
            (Endpoint::Upload { id, .. }, &Method::PATCH) => self.patch_upload(&ctx, id, req).await,
            (Endpoint::Upload { id, .. }, &Method::PUT) => self.finish_upload(&ctx, id, req).await,
            (Endpoint::Upload { id, .. }, &Method::DELETE) => self.cancel_upload(&ctx, id).await,
            (Endpoint::TagsList { .. }, &Method::GET) => {
                self.tags_list(&ctx, req.uri().query().unwrap_or_default())
                    .await
            }
            (Endpoint::Referrers { digest, .. }, &Method::GET) => {
                self.referrers(&ctx, digest, req.uri().query().unwrap_or_default())
                    .await
            }
            _ => Err(OciError::unsupported("method not allowed on this endpoint")),
        };
        if action != Level::Read {
            let status = match &response {
                Ok(r) => r.status().as_u16(),
                Err(e) => e.status.as_u16(),
            };
            tracing::info!(
                target: "forge::audit",
                %method,
                repo = %ctx.serving().repo.name,
                image = %ctx.target.image,
                endpoint = %endpoint_label(&endpoint),
                status,
                principal = %ctx.caller.principal.audit_label(),
                "image mutation"
            );
        }
        response
    }

    // ── Site and caller ─────────────────────────────────────────────────────

    /// Which host the request reached and the token realm and service that
    /// go with it. A host that names a docker repository (`config.host`)
    /// serves that repository at the registry root.
    async fn site(&self, host: Option<String>) -> OciResult<Site> {
        let public = &self.inner.config.public_base_url;
        let (scheme, public_host) = registry_origin(public);
        let host = host.map(|h| h.to_ascii_lowercase());
        let host_repo = match &host {
            Some(h) if *h != public_host => {
                let bare = strip_port(h);
                oci_dao::find_repository_by_host(&self.inner.pool, bare).await?
            }
            _ => None,
        };
        let (service, realm) = match (&host, &host_repo) {
            (Some(h), Some(_)) => (h.clone(), format!("{scheme}://{h}/v2/token")),
            _ => (
                public_host.clone(),
                format!("{scheme}://{public_host}/v2/token"),
            ),
        };
        Ok(Site {
            service,
            realm,
            issuer: token::issuer(public),
            host_repo,
        })
    }

    /// The effective caller: a registry Bearer token's principal, else the
    /// middleware's.
    async fn caller(
        &self,
        principal: Principal,
        headers: &HeaderMap,
        site: &Site,
    ) -> OciResult<Caller> {
        let Some(bearer) = bearer_token(headers) else {
            return Ok(Caller {
                principal,
                claims: None,
            });
        };
        if !token::looks_like_registry_token(bearer) {
            // Another bearer (a workload identity token the middleware has
            // already resolved, or nothing it knows).
            return Ok(Caller {
                principal,
                claims: None,
            });
        }
        let invalid = || {
            OciError::new(
                StatusCode::UNAUTHORIZED,
                Code::Unauthorized,
                "invalid or expired registry token",
            )
            .with_header(
                header::WWW_AUTHENTICATE,
                site.challenge(None, Some("invalid_token")),
            )
        };
        let claims = token::verify(&self.inner.keys, bearer, &site.issuer, &site.service)
            .ok_or_else(invalid)?;
        let principal = claims.fp.to_principal(principal).ok_or_else(invalid)?;
        let principal = self
            .refresh_principal(principal)
            .await?
            .ok_or_else(invalid)?;
        Ok(Caller {
            principal,
            claims: Some(claims),
        })
    }

    /// Re-read what a token's principal rests on: a user's account must still
    /// be active (and the API token it was minted from live); a workload's
    /// realm and key must still stand ([`WorkloadCheck`]). Cached briefly per
    /// process.
    async fn refresh_principal(&self, principal: Principal) -> OciResult<Option<Principal>> {
        if let Principal::Workload {
            realm_id,
            config_sha256,
            key_id,
            ..
        } = principal
        {
            let Some(check) = self.inner.workloads.clone() else {
                return Ok(Some(principal));
            };
            let key = format!(
                "{realm_id}:{}:{}",
                hex::encode(config_sha256),
                key_id.map_or_else(|| "token".to_string(), |id| id.to_string())
            );
            let live: Result<bool, String> = self
                .inner
                .cache
                .get_or_try_insert_local(
                    "oci:workload",
                    &key,
                    std::time::Duration::from_secs(10),
                    || async move { check.still_valid(&principal).await },
                )
                .await;
            return match live {
                Ok(true) => Ok(Some(principal)),
                Ok(false) => Ok(None),
                Err(e) => Err(OciError::internal("workload lookup", e)),
            };
        }
        let Principal::User {
            user_id,
            token_id,
            method,
            ..
        } = principal
        else {
            return Ok(Some(principal));
        };
        let key = format!("{user_id}:{}", token_id.unwrap_or(0));
        let pool = self.inner.pool.clone();
        let state: Result<bool, String> = self
            .inner
            .cache
            .get_or_try_insert_local(
                "oci:principal",
                &key,
                std::time::Duration::from_secs(10),
                || async move {
                    oci_dao::live_principal(&pool, user_id, token_id)
                        .await
                        .map_err(|e| e.to_string())
                },
            )
            .await;
        match state {
            Ok(true) => Ok(Some(Principal::User {
                user_id,
                token_id,
                method,
            })),
            Ok(false) => Ok(None),
            Err(e) => Err(OciError::internal("principal lookup", e)),
        }
    }

    // ── Names and authorization ─────────────────────────────────────────────

    /// The repository and image a `<name>` addresses: on a repository's own
    /// host the whole name is the image; otherwise the first component names
    /// the Forge repository and the rest the image. `None` for an unknown (or
    /// non-docker) repository.
    pub(crate) async fn resolve(&self, site: &Site, name: &str) -> OciResult<Option<Target>> {
        if !reference::valid_name(name) {
            return Err(OciError::name_invalid(name));
        }
        if let Some(repo) = &site.host_repo {
            return Ok(Some(Target {
                repo: repo.clone(),
                image: name.to_string(),
                name: name.to_string(),
            }));
        }
        let Some((repo_name, image)) = name.split_once('/') else {
            return Err(OciError::name_invalid(name).with_detail(serde_json::json!({
                "name": name,
                "hint": "use <forge-repository>/<image>",
            })));
        };
        let repo = repository_dao::find_repository_by_name(&self.inner.pool, repo_name).await?;
        Ok(repo.filter(Repository::is_docker).map(|repo| Target {
            repo,
            image: image.to_string(),
            name: name.to_string(),
        }))
    }

    /// Whether the caller may `action` the target's image: the repository
    /// permission and its content selectors, then a registry token's scope
    /// (checked against the name the client used).
    pub(crate) async fn decide(&self, caller: &Caller, target: &Target, action: Level) -> Decision {
        if !self
            .rbac_allows(&caller.principal, &target.repo, &target.image, action)
            .await
        {
            return Decision::Deny;
        }
        match &caller.claims {
            Some(claims) if !claims_allow(claims, &target.name, action) => Decision::NeedsScope,
            _ => Decision::Allow,
        }
    }

    /// The RBAC part of [`Self::decide`].
    pub(crate) async fn rbac_allows(
        &self,
        principal: &Principal,
        repo: &Repository,
        image: &str,
        action: Level,
    ) -> bool {
        let authz = &self.inner.authz;
        let allowed = match action {
            Level::Read => authz.can_read(principal, repo).await,
            Level::Write => authz.can_write(principal, repo).await,
            Level::Delete => authz.can_delete(principal, repo).await,
        };
        allowed
            && authz
                .package_filter_for(principal, repo, action)
                .await
                .allows(image)
    }

    /// Where a push or delete addressed to `target` lands (the repository
    /// itself, or a group's writable member), after checking the caller may
    /// do it there.
    async fn write_target(
        &self,
        caller: &Caller,
        site: &Site,
        target: &Target,
        action: Level,
    ) -> OciResult<Target> {
        if !mutation_credential(&caller.principal) {
            return Err(self.refusal(caller, site, &target.name, action, Decision::Deny));
        }
        let landing = match target.repo.kind() {
            RepoKind::Hosted => target.clone(),
            RepoKind::Proxy | RepoKind::Group => {
                let decision = self.decide(caller, target, Level::Read).await;
                if decision != Decision::Allow {
                    return Err(self.refusal(caller, site, &target.name, Level::Read, decision));
                }
                let member = match target.repo.kind() {
                    RepoKind::Group => self.writable_member(&target.repo).await?,
                    _ => None,
                };
                match member {
                    Some(member) => Target {
                        repo: member,
                        image: target.image.clone(),
                        name: target.name.clone(),
                    },
                    None if target.repo.kind() == RepoKind::Proxy => {
                        return Err(OciError::unsupported(
                            "a proxy repository is read-only; push to a hosted repository",
                        ))
                    }
                    None => {
                        return Err(OciError::unsupported(
                            "this group has no writable member; push to a hosted repository",
                        ))
                    }
                }
            }
        };
        let decision = if self
            .rbac_allows(&caller.principal, &landing.repo, &landing.image, action)
            .await
        {
            match &caller.claims {
                Some(claims) if !claims_allow(claims, &target.name, action) => Decision::NeedsScope,
                _ => Decision::Allow,
            }
        } else {
            Decision::Deny
        };
        if decision != Decision::Allow {
            return Err(self.refusal(caller, site, &target.name, action, decision));
        }
        Ok(landing)
    }

    /// A group's writable member, if configured and a hosted docker member.
    pub(crate) async fn writable_member(
        &self,
        group: &Repository,
    ) -> OciResult<Option<Repository>> {
        let Some(id) = group.writable_member_id() else {
            return Ok(None);
        };
        let members = repository_dao::group_members(&self.inner.pool, group.id).await?;
        Ok(members
            .into_iter()
            .map(|(member, _)| member)
            .find(|m| m.id == id && m.is_docker() && m.kind() == RepoKind::Hosted))
    }

    /// The refusal of `action` on `name`: a challenge (401) when credentials
    /// or a token for the scope could help, `DENIED` (403) for an
    /// authenticated caller the permission is missing for.
    pub(crate) fn refusal(
        &self,
        caller: &Caller,
        site: &Site,
        name: &str,
        action: Level,
        decision: Decision,
    ) -> OciError {
        let authenticated = mutation_credential(&caller.principal);
        let error = caller.claims.as_ref().map(|_| "insufficient_scope");
        match decision {
            Decision::NeedsScope => self.challenge_error(site, name, action, error),
            Decision::Deny if !authenticated => self.challenge_error(site, name, action, error),
            _ => OciError::denied("requested access to the resource is denied")
                .with_detail(serde_json::json!({ "name": name, "action": scope_actions(action) })),
        }
    }

    fn challenge_error(
        &self,
        site: &Site,
        name: &str,
        action: Level,
        error: Option<&str>,
    ) -> OciError {
        let scope = format!("repository:{name}:{}", scope_actions(action));
        OciError::new(
            StatusCode::UNAUTHORIZED,
            Code::Unauthorized,
            "authentication required",
        )
        .with_detail(serde_json::json!({ "name": name, "action": scope_actions(action) }))
        .with_header(
            header::WWW_AUTHENTICATE,
            site.challenge(Some(&scope), error),
        )
    }

    fn version_check(&self, caller: &Caller, site: &Site) -> OciResult<Response> {
        let signed_in = caller.claims.is_some()
            || matches!(
                caller.principal,
                Principal::User { method, .. } if method != AuthMethod::Session
            )
            || matches!(caller.principal, Principal::Workload { .. });
        if signed_in {
            return Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                "{}",
            )
                .into_response());
        }
        Err(OciError::new(
            StatusCode::UNAUTHORIZED,
            Code::Unauthorized,
            "authentication required",
        )
        .with_header(header::WWW_AUTHENTICATE, site.challenge(None, None)))
    }
}

/// The scheme and `host[:port]` of `public_base_url`: where the registry
/// lives. Docker clients always talk to `/v2/` at the root of a host, so a
/// path in the URL plays no part.
pub fn registry_origin(public_base_url: &str) -> (&'static str, String) {
    let scheme = if public_base_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let host = url::Url::parse(public_base_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    (scheme, host)
}

/// The host a request reached (`Host`, or the HTTP/2 authority).
fn request_host(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .filter(|h| !h.is_empty())
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .split_once(']')
            .map_or(host, |(h, _)| h.trim_start_matches('['));
    }
    host.rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host, |(h, _)| h)
}

/// The `Authorization: Bearer` value, if any.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// Whether the principal is a credential a push may come from: an API
/// token, a password (Basic or a token minted from one) or a workload — but
/// never a browser session, which a cross-site page could ride.
pub(crate) fn mutation_credential(principal: &Principal) -> bool {
    match principal {
        Principal::User { method, .. } => *method != AuthMethod::Session,
        Principal::Workload { .. } => true,
        _ => false,
    }
}

/// The token-scope actions a request of an access level needs.
fn scope_actions(action: Level) -> &'static str {
    match action {
        Level::Read => "pull",
        Level::Write => "pull,push",
        Level::Delete => "delete",
    }
}

fn claims_allow(claims: &Claims, name: &str, action: Level) -> bool {
    match action {
        Level::Read => claims.grants(name, "pull"),
        Level::Write => claims.grants(name, "push"),
        Level::Delete => claims.grants(name, "delete"),
    }
}

/// The access level a request needs.
fn action_of(endpoint: &Endpoint, method: &Method) -> Level {
    match (endpoint, method) {
        (Endpoint::UploadStart { .. } | Endpoint::Upload { .. }, _) => Level::Write,
        (_, &Method::PUT | &Method::POST | &Method::PATCH) => Level::Write,
        (_, &Method::DELETE) => Level::Delete,
        _ => Level::Read,
    }
}

fn endpoint_label(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Manifest { reference, .. } => format!("manifests/{reference}"),
        Endpoint::Blob { digest, .. } => format!("blobs/{digest}"),
        Endpoint::UploadStart { .. } => "blobs/uploads/".into(),
        Endpoint::Upload { id, .. } => format!("blobs/uploads/{id}"),
        Endpoint::TagsList { .. } => "tags/list".into(),
        Endpoint::Referrers { digest, .. } => format!("referrers/{digest}"),
        Endpoint::Base | Endpoint::Token | Endpoint::Catalog => String::new(),
    }
}

/// Browser hardening of registry responses: content (layers, manifests,
/// artifacts) is never rendered, sniffed or framed.
fn harden(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

/// An authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Allow,
    /// RBAC allows it, but the registry token presented does not cover it:
    /// the client should fetch a token for this scope.
    NeedsScope,
    Deny,
}

/// The host a request reached and its token realm.
#[derive(Debug, Clone)]
pub(crate) struct Site {
    /// Token `service` and audience: the host the registry was reached on.
    pub service: String,
    /// The token endpoint URL.
    pub realm: String,
    pub issuer: String,
    /// The repository this host serves (host-based routing).
    pub host_repo: Option<Repository>,
}

impl Site {
    /// A `WWW-Authenticate: Bearer` challenge.
    pub fn challenge(&self, scope: Option<&str>, error: Option<&str>) -> HeaderValue {
        let mut value = format!(
            "Bearer realm=\"{}\",service=\"{}\"",
            self.realm, self.service
        );
        if let Some(scope) = scope {
            value.push_str(&format!(",scope=\"{scope}\""));
        }
        if let Some(error) = error {
            value.push_str(&format!(",error=\"{error}\""));
        }
        HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
    }
}

/// The resolved caller of a request.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    pub principal: Principal,
    /// The registry token presented, if any.
    pub claims: Option<Claims>,
}

/// A repository and image a request addresses.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub repo: Repository,
    pub image: String,
    /// The `<name>` as the client wrote it (what `Location` headers and
    /// token scopes use).
    pub name: String,
}

/// Everything a repository endpoint handler needs.
pub(crate) struct RequestCtx {
    pub caller: Caller,
    pub site: Site,
    /// The repository the request addressed.
    pub target: Target,
    /// Where a push or delete lands (`None` for pulls).
    pub write_target: Option<Target>,
}

impl RequestCtx {
    /// The repository writes go to (the addressed one for pulls).
    pub fn serving(&self) -> &Target {
        self.write_target.as_ref().unwrap_or(&self.target)
    }
}

/// The `Location` path of a resource of `name`.
pub(crate) fn location(name: &str, rest: &str) -> String {
    format!("/v2/{name}/{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ports_are_stripped() {
        assert_eq!(strip_port("docker.example.com:443"), "docker.example.com");
        assert_eq!(strip_port("docker.example.com"), "docker.example.com");
        assert_eq!(strip_port("[::1]:5000"), "::1");
    }

    #[test]
    fn actions_by_endpoint() {
        let m = Endpoint::Manifest {
            name: "a/b".into(),
            reference: "x".into(),
        };
        assert_eq!(action_of(&m, &Method::GET), Level::Read);
        assert_eq!(action_of(&m, &Method::HEAD), Level::Read);
        assert_eq!(action_of(&m, &Method::PUT), Level::Write);
        assert_eq!(action_of(&m, &Method::DELETE), Level::Delete);
        let u = Endpoint::Upload {
            name: "a/b".into(),
            id: "x".into(),
        };
        assert_eq!(action_of(&u, &Method::GET), Level::Write);
        assert_eq!(action_of(&u, &Method::DELETE), Level::Write);
    }

    #[test]
    fn bearer_values() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(bearer_token(&h), Some("abc"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&h), None);
    }

    #[test]
    fn sessions_never_mutate() {
        assert!(!mutation_credential(&Principal::User {
            user_id: 1,
            token_id: None,
            method: AuthMethod::Session
        }));
        assert!(mutation_credential(&Principal::User {
            user_id: 1,
            token_id: None,
            method: AuthMethod::Password
        }));
        assert!(!mutation_credential(&Principal::Unauthenticated));
    }
}
