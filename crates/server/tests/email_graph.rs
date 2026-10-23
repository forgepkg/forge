//! The Microsoft Graph email transport (#320), against a mock Entra token
//! endpoint and a mock Graph (`wiremock`): a client secret and a federated
//! credential (a client assertion signed with forge's issuer keys) both get a
//! token and send through `sendMail`, a token is reused until it expires,
//! and the test send reports Entra's and Graph's errors.

mod common;

use jsonwebtoken::Algorithm;
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TENANT: &str = "contoso.onmicrosoft.com";
const CLIENT_ID: &str = "00000000-1111-2222-3333-444444444444";
const SENDER: &str = "forge@contoso.com";

async fn admin(
    srv: &common::TestServer,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    let req = srv
        .client()
        .request(method, format!("{}{path}", srv.base_url))
        .basic_auth(&u, Some(&p));
    match body {
        Some(body) => req.json(&body),
        None => req,
    }
    .send()
    .await
    .unwrap()
}

/// A server on a database of its own (email settings are install-wide),
/// sending Graph mail to `microsoft`.
async fn server(microsoft: &MockServer) -> common::TestServer {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    srv.state
        .mailer
        .use_microsoft_endpoints(forge_server::email::MicrosoftEndpoints {
            login: microsoft.uri(),
            graph: microsoft.uri(),
        });
    srv
}

fn graph_settings(transport: Value) -> Value {
    let mut t = json!({"kind": "microsoft_graph", "tenant_id": TENANT, "client_id": CLIENT_ID});
    t.as_object_mut()
        .unwrap()
        .extend(transport.as_object().unwrap().clone());
    json!({
        "from_address": SENDER,
        "from_name": "Forge",
        "reply_to": "help@contoso.com",
        "transport": t,
    })
}

fn token_path() -> String {
    format!("/{TENANT}/oauth2/v2.0/token")
}

fn send_path(sender: &str) -> String {
    format!("/v1.0/users/{sender}/sendMail")
}

fn form(request: &Request) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}

async fn requests_to(server: &MockServer, path: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("recorded")
        .into_iter()
        .filter(|r| r.url.path() == path)
        .collect()
}

async fn test_send(srv: &common::TestServer, to: &str) -> (reqwest::StatusCode, Value) {
    let resp = admin(
        srv,
        reqwest::Method::POST,
        "/admin/settings/email/test",
        Some(json!({"to": to})),
    )
    .await;
    let status = resp.status();
    (status, resp.json().await.unwrap())
}

/// With a client secret: one token for two sends, the message as Graph
/// expects it, and the secret never returned.
#[tokio::test]
async fn sends_through_graph_with_a_client_secret() {
    let microsoft = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer", "expires_in": 3599, "access_token": "token-1",
        })))
        .expect(1)
        .mount(&microsoft)
        .await;
    Mock::given(method("POST"))
        .and(path(send_path(SENDER)))
        .and(header("authorization", "Bearer token-1"))
        .respond_with(ResponseTemplate::new(202))
        .expect(2)
        .mount(&microsoft)
        .await;
    let srv = server(&microsoft).await;

    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(graph_settings(json!({"client_secret": "graph-s3cret"}))),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["transport"]["client_secret_set"], json!(true));
    assert!(!view.to_string().contains("graph-s3cret"));
    assert!(view.get("federated_credential").is_none());

    for to in ["someone@example.com", "other@example.com"] {
        let (status, body) = test_send(&srv, to).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["sent"], json!(true));
    }

    let token = &requests_to(&microsoft, &token_path()).await[0];
    let form = form(token);
    assert_eq!(form["grant_type"], "client_credentials");
    assert_eq!(form["client_id"], CLIENT_ID);
    assert_eq!(form["client_secret"], "graph-s3cret");
    assert_eq!(form["scope"], "https://graph.microsoft.com/.default");
    assert!(!form.contains_key("client_assertion"));

    let sent = &requests_to(&microsoft, &send_path(SENDER)).await[0];
    let body: Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(body["saveToSentItems"], json!(false));
    let message = &body["message"];
    assert_eq!(message["subject"], "Forge test email");
    assert_eq!(message["body"]["contentType"], "HTML");
    assert!(message["body"]["content"]
        .as_str()
        .unwrap()
        .contains("href=\"http://test.local\""));
    assert_eq!(
        message["toRecipients"],
        json!([{"emailAddress": {"address": "someone@example.com"}}])
    );
    assert_eq!(
        message["from"],
        json!({"emailAddress": {"address": SENDER, "name": "Forge"}})
    );
    assert_eq!(
        message["replyTo"],
        json!([{"emailAddress": {"address": "help@contoso.com"}}])
    );

    // The secret is kept for the same app, and asked for again for another.
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(graph_settings(json!({"sender": "ops@contoso.com"}))),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(graph_settings(
            json!({"tenant_id": "fabrikam.onmicrosoft.com"}),
        )),
    )
    .await;
    assert_eq!(resp.status(), 400);
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("transport.client_secret is required"));
}

/// With a federated credential: saving publishes forge's issuer keys and
/// shows what to register; the token request carries an assertion that
/// verifies against forge's JWKS, and no secret.
#[tokio::test]
async fn a_federated_app_signs_in_with_forges_issuer_keys() {
    let microsoft = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer", "expires_in": 3599, "access_token": "token-f",
        })))
        .mount(&microsoft)
        .await;
    let mailbox = "9a8b7c6d-0000-1111-2222-333344445555";
    Mock::given(method("POST"))
        .and(path(send_path(mailbox)))
        .and(header("authorization", "Bearer token-f"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&microsoft)
        .await;
    let srv = server(&microsoft).await;
    let client = srv.client();

    // Nothing is published before a federated app needs it.
    let jwks = client
        .get(format!("{}/.well-known/jwks.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(jwks.status(), 404);

    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(graph_settings(json!({
            "client_authentication": "federated_credential",
            "sender": mailbox,
        }))),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let view: Value = resp.json().await.unwrap();
    let subject = format!("{CLIENT_ID}@https://login.microsoftonline.com/{TENANT}/v2.0");
    assert_eq!(
        view["federated_credential"],
        json!({
            "issuer": "http://test.local",
            "subject": subject,
            "audience": "api://AzureADTokenExchange",
        })
    );
    assert_eq!(view["transport"]["client_secret_set"], json!(false));
    let jwks: Value = client
        .get(format!("{}/.well-known/jwks.json", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .expect("the issuer keys are published on save");

    let (status, body) = test_send(&srv, "someone@example.com").await;
    assert_eq!(status, 200, "{body}");

    let form = form(&requests_to(&microsoft, &token_path()).await[0]);
    assert!(!form.contains_key("client_secret"), "{form:?}");
    assert_eq!(form["client_id"], CLIENT_ID);
    assert_eq!(
        form["client_assertion_type"],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    let assertion = &form["client_assertion"];
    let kid = jsonwebtoken::decode_header(assertion)
        .unwrap()
        .kid
        .expect("kid");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == json!(kid))
        .expect("signing key published");
    let key = jsonwebtoken::DecodingKey::from_rsa_components(
        jwk["n"].as_str().unwrap(),
        jwk["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    validation.set_issuer(&["http://test.local"]);
    validation.set_audience(&["api://AzureADTokenExchange"]);
    validation.sub = Some(subject);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    jsonwebtoken::decode::<Value>(assertion, &key, &validation)
        .expect("the assertion verifies against forge's JWKS");
}

/// Entra's refusal of the app and Graph's refusal of the message reach the
/// test send (502) and the settings page, with their codes.
#[tokio::test]
async fn the_test_send_reports_entras_and_graphs_errors() {
    let microsoft = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided.",
        })))
        .up_to_n_times(1)
        .mount(&microsoft)
        .await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer", "expires_in": 3599, "access_token": "token-2",
        })))
        .mount(&microsoft)
        .await;
    Mock::given(method("POST"))
        .and(path(send_path(SENDER)))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": "ErrorAccessDenied",
                "message": "Access is denied. Check credentials and try again.",
            }
        })))
        .mount(&microsoft)
        .await;
    let srv = server(&microsoft).await;
    let resp = admin(
        &srv,
        reqwest::Method::PUT,
        "/admin/settings/email",
        Some(graph_settings(json!({"client_secret": "wrong"}))),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let (status, body) = test_send(&srv, "someone@example.com").await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["sent"], json!(false));
    let error = body["error"].as_str().unwrap();
    assert!(
        error.contains("401 invalid_client") && error.contains("AADSTS7000215"),
        "{error}"
    );

    let (status, body) = test_send(&srv, "someone@example.com").await;
    assert_eq!(status, 502, "{body}");
    let error = body["error"].as_str().unwrap();
    assert!(
        error.contains("403 ErrorAccessDenied") && error.contains("Access is denied"),
        "{error}"
    );
    let view: Value = admin(&srv, reqwest::Method::GET, "/admin/settings/email", None)
        .await
        .json()
        .await
        .unwrap();
    assert!(
        view["last_failure"]["error"]
            .as_str()
            .unwrap()
            .contains("ErrorAccessDenied"),
        "{view}"
    );
}
