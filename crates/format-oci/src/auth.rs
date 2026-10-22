//! The token service (`GET /v2/token`): Docker's Bearer token protocol, the
//! way Nexus' "Docker Bearer Token Realm" implements it.
//!
//! `docker login` sends Basic credentials (an API token, or a password where
//! the server allows password Basic or a credential-forwarding realm) here;
//! the authentication middleware has already validated them. The answer is
//! a short-lived JWT granting, per requested `repository:<name>:<actions>`
//! scope, only the actions the caller may perform right now.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_core::auth::Principal;
use forge_core::authz::Action;
use forge_db::model::RepoKind;

use crate::error::{Code, OciError, OciResult};
use crate::service::{mutation_credential, Caller, Registry, Site};
use crate::token::{self, Access, Claims, TokenPrincipal};

impl Registry {
    pub(crate) async fn token(
        &self,
        caller: &Caller,
        site: &Site,
        query: &str,
    ) -> OciResult<Response> {
        // A registry token is never a credential for another one: it would
        // let a short-lived token renew itself forever.
        let principal = if caller.claims.is_some() {
            Principal::Unauthenticated
        } else {
            caller.principal
        };
        let mut scopes = Vec::new();
        let mut account = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "scope" => {
                    for scope in token::parse_scopes(&value) {
                        if !token::add_scope(&mut scopes, scope) {
                            return Err(OciError::new(
                                StatusCode::BAD_REQUEST,
                                Code::Unsupported,
                                format!(
                                    "a token request may name at most {} repositories",
                                    token::MAX_SCOPES
                                ),
                            ));
                        }
                    }
                }
                "account" => account = Some(value.into_owned()),
                _ => {}
            }
        }
        let token_principal = TokenPrincipal::of(&principal);
        if account.is_some() && token_principal == TokenPrincipal::Anonymous {
            // `docker login` must fail without valid credentials.
            return Err(OciError::new(
                StatusCode::UNAUTHORIZED,
                Code::Unauthorized,
                "authentication required",
            )
            .with_header(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"Forge\""),
            ));
        }

        let mut access = Vec::new();
        for scope in scopes {
            let granted = self
                .granted(&principal, site, &scope.name, &scope.actions)
                .await;
            access.push(Access {
                kind: "repository".into(),
                name: scope.name,
                actions: granted,
            });
        }

        let now = chrono::Utc::now();
        let ttl = self.inner.config.token_ttl_seconds.max(60) as i64;
        let claims = Claims {
            iss: site.issuer.clone(),
            aud: site.service.clone(),
            sub: match &token_principal {
                TokenPrincipal::Anonymous => "anonymous".into(),
                TokenPrincipal::User { uid, .. } => format!("user:{uid}"),
                TokenPrincipal::Workload { realm, role, .. } => format!("workload:{realm}:{role}"),
            },
            iat: now.timestamp(),
            nbf: now.timestamp() - 5,
            exp: now.timestamp() + ttl,
            jti: uuid::Uuid::new_v4().to_string(),
            access,
            fp: token_principal,
        };
        let jwt = token::issue(&self.inner.keys, &claims)
            .map_err(|e| OciError::internal("token signing", e))?;
        if matches!(claims.fp, TokenPrincipal::Anonymous) {
            tracing::debug!(scopes = ?claims.access, "registry: anonymous token issued");
        } else {
            tracing::info!(
                target: "forge::audit",
                principal = %principal.audit_label(),
                scopes = %serde_json::to_string(&claims.access).unwrap_or_default(),
                "registry token issued"
            );
        }
        let body = serde_json::json!({
            "token": jwt,
            "access_token": jwt,
            "expires_in": ttl,
            "issued_at": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body.to_string(),
        )
            .into_response())
    }

    /// The subset of `requested` actions the principal may perform on the
    /// repository `name`. An unknown repository grants nothing.
    async fn granted(
        &self,
        principal: &Principal,
        site: &Site,
        name: &str,
        requested: &[String],
    ) -> Vec<String> {
        let Ok(Some(target)) = self.resolve(site, name).await else {
            return Vec::new();
        };
        let wants = |a: &str| requested.iter().any(|r| r == a || r == "*");
        let mut granted = Vec::new();
        let readable = self
            .rbac_allows(principal, &target.repo, &target.image, Action::Read)
            .await;
        if wants("pull") && readable {
            granted.push("pull".to_string());
        }
        if (wants("push") || wants("delete")) && mutation_credential(principal) {
            let landing = match target.repo.kind() {
                RepoKind::Hosted => Some(target.repo.clone()),
                RepoKind::Group if readable => {
                    self.writable_member(&target.repo).await.ok().flatten()
                }
                _ => None,
            };
            if let Some(landing) = landing {
                if wants("push")
                    && self
                        .rbac_allows(principal, &landing, &target.image, Action::Write)
                        .await
                {
                    granted.push("push".to_string());
                }
                if wants("delete")
                    && self
                        .rbac_allows(principal, &landing, &target.image, Action::Delete)
                        .await
                {
                    granted.push("delete".to_string());
                }
            }
        }
        granted
    }
}
