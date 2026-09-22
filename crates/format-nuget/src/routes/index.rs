//! Service index (`GET {base}/index.json`), spec §6 + Appendix A.
//!
//! Advertises the absolute resource `@id`s a client uses to self-configure.
//! `PackagePublish/2.0.0` is advertised for **hosted** repos only; proxy and
//! group repos expose read resources only.

use axum::extract::State;
use axum::response::Json;
use forge_core::repo::RepoKind;
use serde_json::{json, Value};

use crate::routes::RouteContext;

/// Build the service-index JSON for the given context.
pub fn service_index_json(ctx: &RouteContext) -> Value {
    let base = ctx.base();

    let mut resources = vec![
        json!({ "@id": format!("{base}/query"), "@type": "SearchQueryService/3.5.0" }),
        // Common alias many clients still probe for.
        json!({ "@id": format!("{base}/query"), "@type": "SearchQueryService/3.0.0-rc" }),
        // Every registration variant points at the same hive: older clients
        // (VS2015, nuget.exe 3.x/4.x, packages.config resolvers) look up the
        // unversioned / 3.0.0 / 3.4.0 types and find no registration otherwise.
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.0.0-beta" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.0.0-rc" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.4.0" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.6.0" }),
        json!({ "@id": format!("{base}/flat/"), "@type": "PackageBaseAddress/3.0.0" }),
    ];

    if ctx.kind == RepoKind::Hosted {
        resources.push(json!({
            "@id": format!("{base}/package"),
            "@type": "PackagePublish/2.0.0"
        }));
    }

    json!({
        "version": "3.0.0",
        "resources": resources,
    })
}

/// Handler: `GET`/`HEAD` `/index.json`.
pub async fn service_index(State(ctx): State<RouteContext>) -> Json<Value> {
    Json(service_index_json(&ctx))
}
