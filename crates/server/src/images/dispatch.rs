//! A `/v2` request: the host's part of it, then the conversation with the
//! images format.
//!
//! The host answers `/v2/` (the version check), `/v2/token` (the token
//! service, [`super::auth`]) and `/v2/_catalog` (refused) itself. Any other
//! path goes to the format ([`FormatPlugin::image_path`]), which splits off
//! the name the client wrote and says what the request needs; the host
//! resolves the name (by path, `<repository>/<image>`, or on a repository's
//! own host, `config.host`), authorizes it (RBAC and package selectors on
//! the image, a registry token's scope), picks where a change lands (a
//! group's writable member) and refuses an offline repository. Then the
//! format's `handle` and `render` decide the response, round by round,
//! with the image queries this module answers from the store and the
//! actions it performs (serving a blob or a manifest). What the host
//! refuses, the format answers in its words
//! ([`FormatPlugin::image_error`]), with the host's challenge.
//!
//! Every answer carries `Docker-Distribution-API-Version` and the
//! registry's hardening; a response the format renders keeps only the
//! headers in [`PASSED_RESPONSE_HEADERS`], `location` and `link` only
//! within `/v2/`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_core::auth::{AuthMethod, Principal};
use forge_core::authz::Level;
use forge_db::model::{RepoKind, Repository};
use forge_db::{oci_dao, repository_dao};
use forge_plugin::api::images::{
    ImageAnswer, ImageError, ImageName, ImagePath, ImageQuery, Permission, Reference,
};
use forge_plugin::api::{self as protocol, Action, Answer, Loaded, Query};
use forge_plugin::FormatPlugin;

use super::digest::ContentDigest;
use super::pull::{BlobHit, ManifestHit};
use super::token::{self, Claims};
use super::{Failure, ImgResult, Registry};

/// The most rounds of queries one request may load.
const MAX_ROUNDS: usize = 4;

/// Request headers the format sees. Never credentials or cookies.
pub const PASSED_REQUEST_HEADERS: &[&str] =
    &["accept", "content-range", "content-type", "user-agent"];

/// Response headers the format may set. `location` and `link` only within
/// `/v2/`.
pub const PASSED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "docker-content-digest",
    "docker-upload-uuid",
    "link",
    "location",
    "oci-filters-applied",
    "oci-subject",
    "oci-tag",
    "range",
    "retry-after",
];

impl Registry {
    /// Answer one `/v2` request. `principal` is what the authentication
    /// middleware resolved (registry Bearer tokens are resolved here).
    pub async fn handle(&self, principal: Principal, req: Request<Body>) -> Response {
        let mut response = match self.route(principal, req).await {
            Ok(response) => response,
            Err(failure) => self.failure_response(failure),
        };
        let headers = response.headers_mut();
        headers.insert(
            "docker-distribution-api-version",
            HeaderValue::from_static("registry/2.0"),
        );
        harden(headers);
        response
    }

    /// What the host refused or failed, as the format answers it, with the
    /// host's own headers (a challenge).
    pub fn failure_response(&self, failure: Failure) -> Response {
        let mut response = self.respond(self.plugin().image_error(&failure.error));
        for (name, value) in failure.headers {
            response.headers_mut().insert(name, value);
        }
        response
    }

    /// A response the format rendered ([`rendered`]).
    pub(crate) fn respond(&self, response: protocol::Response) -> Response {
        rendered(response)
    }

    async fn route(&self, principal: Principal, req: Request<Body>) -> ImgResult<Response> {
        let mount = self.plugin().descriptor().mount;
        let rest = req
            .uri()
            .path()
            .strip_prefix(mount)
            .unwrap_or_default()
            .to_string();
        // The host's own endpoints; anything else is the format's to split.
        let path = match rest.as_str() {
            "" | "/" | "/token" | "/_catalog" => None,
            _ => Some(self.plugin().image_path(req.method().as_str(), &rest)?),
        };
        let site = self.site(request_host(&req)).await?;
        let caller = self.caller(principal, req.headers(), &site).await?;
        match (rest.as_str(), path) {
            (_, Some(path)) => self.repository_request(caller, site, path, req).await,
            ("/token", None) => {
                if req.method() != Method::GET {
                    return Err(Failure::unsupported(
                        405,
                        "the token service answers GET with Basic credentials",
                    ));
                }
                self.token(&caller, &site, req.uri().query().unwrap_or_default())
                    .await
            }
            ("/_catalog", None) => Err(Failure::unsupported(
                404,
                "the catalog API is not supported; browse images in the web UI",
            )),
            _ => self.version_check(&caller, &site),
        }
    }

    async fn repository_request(
        &self,
        caller: Caller,
        site: Site,
        path: ImagePath,
        req: Request<Body>,
    ) -> ImgResult<Response> {
        let name = path.name;
        let permission = path.permission;
        let action = rbac(permission);
        let target = match self.resolve(&site, &name).await? {
            Some(target) => target,
            None => {
                // An unknown repository is answered like one the caller may
                // not use; only a global admin learns that it does not exist.
                if self.inner.authz.is_global_admin(&caller.principal).await {
                    return Err(Failure::new(ImageError::NameUnknown { name }));
                }
                return Err(self.refusal(&caller, &site, &name, permission, Decision::Deny));
            }
        };
        let write_target = if action == Level::Read {
            let decision = self.decide(&caller, &target, Level::Read).await;
            if decision != Decision::Allow {
                return Err(self.refusal(&caller, &site, &name, permission, decision));
            }
            None
        } else {
            Some(
                self.write_target(&caller, &site, &target, permission)
                    .await?,
            )
        };
        // An offline hosted or group repository serves nothing; an offline
        // proxy serves what it cached.
        let serving = write_target.as_ref().unwrap_or(&target);
        if !serving.repo.online && serving.repo.kind() != RepoKind::Proxy
            || !target.repo.online && target.repo.kind() == RepoKind::Group
        {
            return Err(Failure::new(ImageError::Offline));
        }
        let ctx = RequestCtx {
            caller,
            site,
            target,
            write_target,
        };
        let method = req.method().clone();
        let request = protocol::Request {
            method: method.as_str().to_string(),
            path: path.endpoint.clone(),
            query: req.uri().query().unwrap_or_default().to_string(),
            headers: req
                .headers()
                .iter()
                .filter(|(name, _)| PASSED_REQUEST_HEADERS.contains(&name.as_str()))
                .filter_map(|(name, value)| {
                    Some((name.to_string(), value.to_str().ok()?.to_string()))
                })
                .collect(),
            image: Some(ImageName {
                image: ctx.target.image.clone(),
                name: ctx.target.name.clone(),
            }),
        };
        let conversation = Conversation {
            reg: self,
            ctx: &ctx,
            permission,
            head: method == Method::HEAD,
            headers: req.headers().clone(),
            body: Mutex::new(Some(req.into_body())),
            manifests: Mutex::new(HashMap::new()),
            blobs: Mutex::new(HashMap::new()),
        };
        let response = conversation.run(request).await;
        if action != Level::Read {
            tracing::info!(
                target: "forge::audit",
                %method,
                repo = %ctx.serving().repo.name,
                image = %ctx.target.image,
                endpoint = %path.endpoint.trim_start_matches('/'),
                status = response.status().as_u16(),
                principal = %ctx.caller.principal.audit_label(),
                "image mutation"
            );
        }
        Ok(response)
    }

    // ── Site and caller ─────────────────────────────────────────────────────

    /// Which host the request reached and the token realm and service that
    /// go with it. A host that names a repository of the images format
    /// (`config.host`) serves that repository at the registry root.
    pub(crate) async fn site(&self, host: Option<String>) -> ImgResult<Site> {
        let public = &self.inner.config.public_base_url;
        let (scheme, public_host) = registry_origin(public);
        let host = host.map(|h| h.to_ascii_lowercase());
        let host_repo = match &host {
            Some(h) if *h != public_host => {
                let bare = strip_port(h);
                oci_dao::find_repository_by_host(&self.inner.pool, bare, self.format()).await?
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
    ) -> ImgResult<Caller> {
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
            Failure::new(ImageError::InvalidToken).with_header(
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
    /// realm and key must still stand ([`super::WorkloadCheck`]). Cached
    /// briefly per process.
    async fn refresh_principal(&self, principal: Principal) -> ImgResult<Option<Principal>> {
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
                Err(e) => Err(Failure::internal("workload lookup", e)),
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
            Err(e) => Err(Failure::internal("principal lookup", e)),
        }
    }

    // ── Names and authorization ─────────────────────────────────────────────

    /// The repository and image a `<name>` addresses: on a repository's own
    /// host the whole name is the image; otherwise the first component names
    /// the Forge repository and the rest the image. `None` for an unknown
    /// repository, or one of another format. The name is in the format's
    /// grammar already.
    pub(crate) async fn resolve(&self, site: &Site, name: &str) -> ImgResult<Option<Target>> {
        if let Some(repo) = &site.host_repo {
            return Ok(Some(Target {
                repo: repo.clone(),
                image: name.to_string(),
                name: name.to_string(),
            }));
        }
        let Some((repo_name, image)) = name.split_once('/') else {
            return Err(Failure::new(ImageError::NameInvalid {
                name: name.to_string(),
                hint: Some("use <forge-repository>/<image>".into()),
            }));
        };
        let repo = repository_dao::find_repository_by_name(&self.inner.pool, repo_name).await?;
        Ok(repo.filter(|r| self.serves(r)).map(|repo| Target {
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
        permission: Permission,
    ) -> ImgResult<Target> {
        let action = rbac(permission);
        if !mutation_credential(&caller.principal) {
            return Err(self.refusal(caller, site, &target.name, permission, Decision::Deny));
        }
        let landing = match target.repo.kind() {
            RepoKind::Hosted => target.clone(),
            RepoKind::Proxy | RepoKind::Group => {
                let decision = self.decide(caller, target, Level::Read).await;
                if decision != Decision::Allow {
                    return Err(self.refusal(
                        caller,
                        site,
                        &target.name,
                        Permission::Read,
                        decision,
                    ));
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
                        return Err(Failure::unsupported(
                            405,
                            "a proxy repository is read-only; push to a hosted repository",
                        ))
                    }
                    None => {
                        return Err(Failure::unsupported(
                            405,
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
            return Err(self.refusal(caller, site, &target.name, permission, decision));
        }
        Ok(landing)
    }

    /// A group's writable member, if configured and a hosted member of the
    /// images format.
    pub(crate) async fn writable_member(
        &self,
        group: &Repository,
    ) -> ImgResult<Option<Repository>> {
        let Some(id) = group.writable_member_id() else {
            return Ok(None);
        };
        let members = repository_dao::group_members(&self.inner.pool, group.id).await?;
        Ok(members
            .into_iter()
            .map(|(member, _)| member)
            .find(|m| m.id == id && self.serves(m) && m.kind() == RepoKind::Hosted))
    }

    /// The refusal of `permission` on `name`: a challenge (401) when
    /// credentials or a token for the scope could help, a denial (403) for
    /// an authenticated caller the permission is missing for.
    pub(crate) fn refusal(
        &self,
        caller: &Caller,
        site: &Site,
        name: &str,
        permission: Permission,
        decision: Decision,
    ) -> Failure {
        let authenticated = mutation_credential(&caller.principal);
        let error = caller.claims.as_ref().map(|_| "insufficient_scope");
        match decision {
            Decision::NeedsScope => challenge(site, name, permission, error),
            Decision::Deny if !authenticated => challenge(site, name, permission, error),
            _ => Failure::new(ImageError::Denied {
                name: name.to_string(),
                permission,
            }),
        }
    }

    fn version_check(&self, caller: &Caller, site: &Site) -> ImgResult<Response> {
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
        Err(
            Failure::new(ImageError::AuthenticationRequired { scope: None })
                .with_header(header::WWW_AUTHENTICATE, site.challenge(None, None)),
        )
    }
}

/// A challenge for a token with the scope `permission` on `name`.
fn challenge(site: &Site, name: &str, permission: Permission, error: Option<&str>) -> Failure {
    let scope = format!("repository:{name}:{}", scope_actions(permission));
    Failure::new(ImageError::AuthenticationRequired {
        scope: Some((name.to_string(), permission)),
    })
    .with_header(
        header::WWW_AUTHENTICATE,
        site.challenge(Some(&scope), error),
    )
}

/// One request's conversation with the format: the queries it asks for,
/// answered from the store, and the actions it ends with.
struct Conversation<'a> {
    reg: &'a Registry,
    ctx: &'a RequestCtx,
    /// What the request was authorized for.
    permission: Permission,
    head: bool,
    /// The request's headers, for a blob's `Range` and a manifest's type.
    headers: HeaderMap,
    /// The request body, until a query reads it.
    body: Mutex<Option<Body>>,
    /// The manifests queries found, for serving one of them.
    manifests: Mutex<HashMap<Reference, ManifestHit>>,
    /// The blobs queries found, by digest, for serving one of them.
    blobs: Mutex<HashMap<String, BlobHit>>,
}

impl Conversation<'_> {
    /// Run a protocol call of the format off the async workers. A format
    /// that panics answers 500.
    async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn FormatPlugin) -> R + Send + 'static,
    ) -> Result<R, Response> {
        let plugin = Arc::clone(&self.reg.inner.plugin);
        tokio::task::spawn_blocking(move || f(plugin.as_ref()))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "images format failed");
                self.reg
                    .failure_response(Failure::new(ImageError::Internal))
            })
    }

    async fn run(&self, request: protocol::Request) -> Response {
        let handled = {
            let (target, request) = (self.target(), request.clone());
            self.call(move |plugin| plugin.handle(&target, &request))
                .await
        };
        let mut action = match handled {
            Ok(action) => action,
            Err(response) => return response,
        };
        let mut data: Vec<Loaded> = Vec::new();
        for _ in 0..MAX_ROUNDS {
            let Action::Load(queries) = action else {
                return self.act(action).await;
            };
            if let Err(response) = self.check_round(&queries) {
                return response;
            }
            for query in queries {
                let Query::Image(image_query) = &query else {
                    return self.misused("a query of another storage");
                };
                let answer = match self.answer(image_query).await {
                    Ok(answer) => answer,
                    Err(response) => return response,
                };
                data.push(Loaded {
                    query,
                    answer: Answer::Image(answer),
                });
            }
            let (target, req) = (self.target(), request.clone());
            let rendered = self
                .call(move |plugin| {
                    let rendered = plugin.render(&target, &req, &data);
                    (rendered, data)
                })
                .await;
            match rendered {
                Ok((next, loaded)) => {
                    data = loaded;
                    action = next;
                }
                Err(response) => return response,
            }
        }
        if !matches!(action, Action::Load(_)) {
            return self.act(action).await;
        }
        tracing::warn!("images format asked for more rounds than one request may load");
        self.reg
            .failure_response(Failure::new(ImageError::Internal))
    }

    /// The repository as the format sees it: the one the request addressed.
    fn target(&self) -> protocol::Repository {
        let repo = &self.ctx.target.repo;
        protocol::Repository {
            name: repo.name.clone(),
            kind: match repo.kind() {
                RepoKind::Hosted => protocol::RepositoryKind::Hosted,
                RepoKind::Proxy => protocol::RepositoryKind::Proxy,
                RepoKind::Group => protocol::RepositoryKind::Group,
            },
            base_url: format!(
                "{}{}",
                self.reg.inner.config.public_base_url,
                self.reg.plugin().descriptor().mount
            ),
            inline: false,
        }
    }

    /// The format asked for something the contract does not allow: a bug in
    /// it, answered with a server error.
    fn misused(&self, what: &str) -> Response {
        tracing::error!(repo = %self.ctx.target.repo.name, "images format asked for {what}");
        self.reg
            .failure_response(Failure::new(ImageError::Internal))
    }

    /// Whether a round of queries keeps to the contract: image queries, of
    /// the request's image, and a change alone in its round, on a request
    /// authorized for it.
    fn check_round(&self, queries: &[Query]) -> Result<(), Response> {
        if queries.is_empty() {
            return Err(self.misused("an empty round"));
        }
        if queries.len() > 1 && queries.iter().any(Query::is_change) {
            return Err(self.misused("a change with other queries in its round"));
        }
        for query in queries {
            let Query::Image(query) = query else {
                return Err(self.misused("a query of another storage"));
            };
            if query
                .image()
                .is_some_and(|image| image != self.ctx.target.image)
            {
                return Err(self.misused("a query of another image"));
            }
            let needs = match query {
                ImageQuery::DeleteManifest { .. } | ImageQuery::DeleteBlob { .. } => {
                    Some(Permission::Delete)
                }
                query if query.is_change() => Some(Permission::Write),
                _ => None,
            };
            if needs.is_some_and(|needs| needs != self.permission)
                || needs.is_some() && self.ctx.write_target.is_none()
            {
                return Err(self.misused("a change the request was not authorized for"));
            }
        }
        Ok(())
    }

    /// The request body, for the one query that reads it.
    fn take_body(&self) -> Result<Body, Response> {
        self.body
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| self.misused("the request body twice"))
    }

    /// A digest the format named, as the store verifies content against it.
    fn digest(&self, digest: &str) -> Result<ContentDigest, Response> {
        ContentDigest::named(digest).map_err(|failure| self.reg.failure_response(failure))
    }

    /// The answer to one query, or the response that ends the request
    /// instead.
    async fn answer(&self, query: &ImageQuery) -> Result<ImageAnswer, Response> {
        let reg = self.reg;
        let ctx = self.ctx;
        let t = &ctx.target;
        let landing = ctx.serving();
        let principal = &ctx.caller.principal;
        let error = |failure: Failure| failure.error;
        Ok(match query {
            ImageQuery::Manifest { reference, .. } => {
                if let Reference::Digest(digest) = reference {
                    self.digest(digest)?;
                }
                let found = reg
                    .manifest_from(&ctx.caller, &t.repo, &t.image, reference, 0)
                    .await;
                if let Ok(Some(hit)) = &found {
                    self.manifests
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(reference.clone(), hit.clone());
                }
                ImageAnswer::Manifest(found.map(|hit| hit.map(|h| h.info())).map_err(error))
            }
            ImageQuery::Blob { digest, .. } => {
                let digest = self.digest(digest)?;
                let found = reg
                    .blob_from(&ctx.caller, &t.repo, &t.image, &digest, 0)
                    .await;
                if let Ok(Some(hit)) = &found {
                    self.blobs
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(digest.to_string(), hit.clone());
                }
                ImageAnswer::Blob(found.map(|hit| hit.map(|h| h.info())).map_err(error))
            }
            ImageQuery::Tags { last, n, .. } => ImageAnswer::Tags(
                reg.tags_from(
                    &ctx.caller,
                    &t.repo,
                    &t.image,
                    last.as_deref(),
                    *n as usize,
                    0,
                )
                .await
                .map_err(error),
            ),
            ImageQuery::Referrers {
                digest,
                artifact_type,
                ..
            } => {
                let digest = self.digest(digest)?;
                let found = reg
                    .referrers_from(&ctx.caller, &t.repo, &t.image, &digest, 0)
                    .await
                    .map(|mut found| {
                        if let Some(filter) = artifact_type {
                            found.retain(|r| r.artifact_type.as_deref() == Some(filter.as_str()));
                        }
                        found
                    });
                ImageAnswer::Referrers(found.map_err(error))
            }
            ImageQuery::StartUpload { mount, .. } => {
                let mount = match mount {
                    Some(mount) => Some((self.digest(&mount.digest)?, mount.from.as_deref())),
                    None => None,
                };
                ImageAnswer::Started(reg.start_upload(ctx, landing, mount).await.map_err(error))
            }
            ImageQuery::UploadStatus(id) => {
                ImageAnswer::Upload(reg.upload_status(landing, id).await.map_err(error))
            }
            ImageQuery::AppendUpload { id, range } => {
                let body = self.take_body()?;
                ImageAnswer::Upload(
                    reg.append_upload(landing, id, *range, body)
                        .await
                        .map_err(error),
                )
            }
            ImageQuery::FinishUpload { id, digest, range } => {
                let digest = self.digest(digest)?;
                let body = self.take_body()?;
                ImageAnswer::Blob(
                    reg.finish_upload(landing, id, &digest, *range, body)
                        .await
                        .map(Some)
                        .map_err(error),
                )
            }
            ImageQuery::CancelUpload(id) => {
                ImageAnswer::Done(reg.cancel_upload(landing, id).await.map_err(error))
            }
            ImageQuery::PutManifest {
                reference, tags, ..
            } => {
                if let Reference::Digest(digest) = reference {
                    self.digest(digest)?;
                }
                let body = self.take_body()?;
                let content_type = self
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                ImageAnswer::Stored(
                    reg.put_manifest(principal, landing, reference, tags, content_type, body)
                        .await
                        .map_err(error),
                )
            }
            ImageQuery::DeleteManifest { reference, .. } => {
                if let Reference::Digest(digest) = reference {
                    self.digest(digest)?;
                }
                ImageAnswer::Done(
                    reg.delete_manifest(principal, landing, reference)
                        .await
                        .map_err(error),
                )
            }
            ImageQuery::DeleteBlob { digest, .. } => {
                let digest = self.digest(digest)?;
                ImageAnswer::Done(
                    reg.delete_blob(principal, landing, &digest)
                        .await
                        .map_err(error),
                )
            }
        })
    }

    /// Do what the format decided, other than loading data.
    async fn act(&self, action: Action) -> Response {
        match action {
            Action::Respond(response) => self.reg.respond(response),
            Action::ServeBlob { digest, .. } => {
                let found = self
                    .blobs
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&digest)
                    .cloned();
                match found {
                    Some(hit) if self.permission == Permission::Read => self
                        .reg
                        .serve_blob(&hit, self.head, &self.headers)
                        .await
                        .unwrap_or_else(|failure| self.reg.failure_response(failure)),
                    _ => self.misused("serving a blob no query found"),
                }
            }
            Action::ServeManifest { reference, .. } => {
                let found = self
                    .manifests
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&reference)
                    .cloned();
                match found {
                    Some(hit) if self.permission == Permission::Read => self
                        .reg
                        .serve_manifest(&hit, self.head)
                        .await
                        .unwrap_or_else(|failure| self.reg.failure_response(failure)),
                    _ => self.misused("serving a manifest no query found"),
                }
            }
            _ => self.misused("an action of another storage"),
        }
    }
}

/// A response the images format rendered, keeping only the headers it may
/// set: [`PASSED_RESPONSE_HEADERS`], `location` and `link` only within
/// `/v2/`.
pub(crate) fn rendered(rendered: protocol::Response) -> Response {
    let status = StatusCode::from_u16(rendered.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    // The format's `content-type`, none of the host's.
    let mut response = Response::new(Body::from(rendered.body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in &rendered.headers {
        let name = name.to_ascii_lowercase();
        if !PASSED_RESPONSE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let inside = match name.as_str() {
            "location" => value.starts_with("/v2/"),
            "link" => value.trim_start().starts_with("</v2/"),
            _ => true,
        };
        if !inside {
            tracing::warn!(header = %name, "images format: a header outside the registry dropped");
            continue;
        }
        let (Ok(name), Ok(value)) = (
            header::HeaderName::try_from(name),
            HeaderValue::from_str(value),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
    response
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

/// The RBAC action a permission is.
pub(crate) fn rbac(permission: Permission) -> Level {
    match permission {
        Permission::Read => Level::Read,
        Permission::Write => Level::Write,
        Permission::Delete => Level::Delete,
    }
}

/// The token-scope actions a permission needs.
fn scope_actions(permission: Permission) -> &'static str {
    match permission {
        Permission::Read => "pull",
        Permission::Write => "pull,push",
        Permission::Delete => "delete",
    }
}

fn claims_allow(claims: &Claims, name: &str, action: Level) -> bool {
    match action {
        Level::Read => claims.grants(name, "pull"),
        Level::Write => claims.grants(name, "push"),
        Level::Delete => claims.grants(name, "delete"),
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
    /// The `<name>` as the client wrote it (what token scopes use).
    pub name: String,
}

/// Everything a repository request needs.
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
