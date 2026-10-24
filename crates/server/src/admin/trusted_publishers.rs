//! Trusted publishers bound to a hosted repository.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::SelectorPatterns;
use forge_db::auth_realm_dao;
use forge_db::model::{RepoKind, Repository};
use forge_db::repository_dao;
use forge_db::trusted_publisher_dao::{self, NewTrustedPublisher, TrustedPublisher};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

use crate::auth::{validate_trusted_publisher_conditions, ClaimCondition, KIND_WORKLOAD_IDENTITY};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct TrustedPublisherView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub realm_id: i64,
    pub realm: String,
    pub issuer: String,
    pub packages: Packages,
    pub conditions: JsonValue,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPublisherBody {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub realm: String,
    #[serde(default)]
    pub packages: Packages,
    pub conditions: Vec<ClaimCondition>,
    pub actions: Vec<String>,
}

fn bad_request(message: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, message.into()).into_response()
}

async fn hosted_repository(state: &AppState, name: &str) -> Result<Repository, Response> {
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(repo)) if repo.kind() == RepoKind::Hosted => Ok(repo),
        Ok(Some(_)) => Err(bad_request(
            "trusted publishers can only be configured on hosted repositories",
        )),
        Ok(None) => Err((StatusCode::NOT_FOUND, "repository not found").into_response()),
        Err(error) => Err(super::db_error(error)),
    }
}

async fn realm_and_conditions(
    state: &AppState,
    realm_name: &str,
    conditions: Vec<ClaimCondition>,
) -> Result<(i64, Vec<ClaimCondition>), Response> {
    let realm = match auth_realm_dao::find_realm_by_name(&state.pool, realm_name.trim()).await {
        Ok(Some(realm)) if realm.kind == KIND_WORKLOAD_IDENTITY => realm,
        Ok(Some(_)) => return Err(bad_request("realm must be a workload_identity realm")),
        Ok(None) => return Err(bad_request("workload identity realm not found")),
        Err(error) => return Err(super::db_error(error)),
    };
    let Some(issuer) = realm.config.get("issuer").and_then(JsonValue::as_str) else {
        return Err(bad_request("workload identity realm has no issuer"));
    };
    let identity_claims: Vec<String> = realm
        .config
        .get("identity_claims")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(str::to_string)
        .collect();
    let conditions = validate_trusted_publisher_conditions(issuer, &identity_claims, conditions)
        .map_err(bad_request)?;
    Ok((realm.id, conditions))
}

fn validate_body(body: &mut TrustedPublisherBody) -> Result<(), Response> {
    body.name = body.name.trim().to_string();
    if body.name.is_empty() {
        return Err(bad_request("trusted publisher name is required"));
    }
    if let Err(error) = (SelectorPatterns {
        includes: body.packages.includes.clone(),
        excludes: body.packages.excludes.clone(),
    })
    .compile_check()
    {
        return Err(bad_request(format!(
            "invalid content-selector glob: {error}"
        )));
    }
    if body.actions.iter().any(|action| action != "write" && action != "delete")
        || !body.actions.iter().any(|action| action == "write")
    {
        return Err(bad_request(
            "actions must include \"write\" and may also include \"delete\"",
        ));
    }
    body.actions.sort();
    body.actions.dedup();
    Ok(())
}

fn new_publisher<'a>(
    repository_id: i64,
    realm_id: i64,
    body: &'a TrustedPublisherBody,
    conditions: &'a JsonValue,
) -> NewTrustedPublisher<'a> {
    NewTrustedPublisher {
        repository_id,
        realm_id,
        name: &body.name,
        description: &body.description,
        includes: &body.packages.includes,
        excludes: &body.packages.excludes,
        conditions,
        actions: &body.actions,
    }
}

async fn view(
    state: &AppState,
    publisher: TrustedPublisher,
) -> Result<TrustedPublisherView, Response> {
    let realm = auth_realm_dao::find_realm_by_id(&state.pool, publisher.realm_id)
        .await
        .map_err(super::db_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "trusted publisher realm not found").into_response())?;
    let issuer = realm
        .config
        .get("issuer")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(TrustedPublisherView {
        id: publisher.id,
        name: publisher.name,
        description: publisher.description,
        realm_id: publisher.realm_id,
        realm: realm.name,
        issuer,
        packages: Packages {
            includes: serde_json::from_value(publisher.includes)
                .map_err(|error| bad_request(format!("invalid stored includes: {error}")))?,
            excludes: serde_json::from_value(publisher.excludes)
                .map_err(|error| bad_request(format!("invalid stored excludes: {error}")))?,
        },
        conditions: publisher.conditions,
        actions: publisher.actions,
    })
}

/// `GET /admin/repositories/{name}/trusted-publishers`
pub async fn list(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match hosted_repository(&state, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    match trusted_publisher_dao::list_for_repository(&state.pool, repo.id).await {
        Ok(publishers) => {
            let mut views = Vec::with_capacity(publishers.len());
            for publisher in publishers {
                match view(&state, publisher).await {
                    Ok(publisher) => views.push(publisher),
                    Err(response) => return response,
                }
            }
            Json(views).into_response()
        }
        Err(error) => super::db_error(error),
    }
}

/// `POST /admin/repositories/{name}/trusted-publishers`
pub async fn create(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mut body): Json<TrustedPublisherBody>,
) -> Response {
    let repo = match hosted_repository(&state, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    if let Err(response) = validate_body(&mut body) {
        return response;
    }
    let (realm_id, conditions) =
        match realm_and_conditions(&state, &body.realm, body.conditions.clone()).await {
            Ok(result) => result,
            Err(response) => return response,
        };
    let conditions = json!(conditions);
    match trusted_publisher_dao::create(
        &state.pool,
        new_publisher(repo.id, realm_id, &body, &conditions),
    )
    .await
    {
        Ok(publisher) => match view(&state, publisher).await {
            Ok(publisher) => (StatusCode::CREATED, Json(publisher)).into_response(),
            Err(response) => response,
        },
        Err(error) if unique_violation(&error) => {
            (StatusCode::CONFLICT, "trusted publisher name already exists").into_response()
        }
        Err(error) => super::db_error(error),
    }
}

/// `PUT /admin/repositories/{name}/trusted-publishers/{id}`
pub async fn update(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
    Json(mut body): Json<TrustedPublisherBody>,
) -> Response {
    let repo = match hosted_repository(&state, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    if let Err(response) = validate_body(&mut body) {
        return response;
    }
    let (realm_id, conditions) =
        match realm_and_conditions(&state, &body.realm, body.conditions.clone()).await {
            Ok(result) => result,
            Err(response) => return response,
        };
    let conditions = json!(conditions);
    match trusted_publisher_dao::update(
        &state.pool,
        repo.id,
        id,
        new_publisher(repo.id, realm_id, &body, &conditions),
    )
    .await
    {
        Ok(Some(publisher)) => match view(&state, publisher).await {
            Ok(publisher) => Json(publisher).into_response(),
            Err(response) => response,
        },
        Ok(None) => (StatusCode::NOT_FOUND, "trusted publisher not found").into_response(),
        Err(error) if unique_violation(&error) => {
            (StatusCode::CONFLICT, "trusted publisher name already exists").into_response()
        }
        Err(error) => super::db_error(error),
    }
}

/// `DELETE /admin/repositories/{name}/trusted-publishers/{id}`
pub async fn delete(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
) -> Response {
    let repo = match hosted_repository(&state, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    match trusted_publisher_dao::delete(&state.pool, repo.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "trusted publisher not found").into_response(),
        Err(error) => super::db_error(error),
    }
}

fn unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
