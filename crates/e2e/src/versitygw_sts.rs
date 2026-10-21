//! A versitygw whose STS trusts a [`MockOidc`] issuer, for the short-lived S3
//! credentials scenarios (#60, `s3.credentials = "web_identity"`).
//!
//! One container runs versitygw's standalone IAM service (the IAM and STS
//! APIs) and an S3 gateway that resolves every access key through it, over a
//! unix socket inside the container. The IAM service fetches the issuer's
//! discovery document and JWKS from the test process, which it reaches as
//! [`HOST_ALIAS`], so the issuer must be started with
//! [`MockOidc::start_workload_only_on_host`]. With a local Docker daemon the
//! alias is the Docker host gateway; with a remote one (GitLab's
//! Docker-in-Docker service, `DOCKER_HOST=tcp://docker:2375`) it is this
//! machine's address on the route to the daemon.
//!
//! [`VersitygwSts::start`] registers the issuer as an OpenID Connect provider
//! for [`CLIENT_ID`] and creates a role its tokens may assume, with full S3
//! access. `AssumeRoleWithWebIdentity` exchanges a token whose `aud` is
//! [`CLIENT_ID`] for temporary keys of that role; like AWS STS, it needs the
//! role's ARN ([`VersitygwSts::role_arn`]).

use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use testcontainers::core::{Host, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use crate::MockOidc;

/// The name the container reaches the test host by.
pub const HOST_ALIAS: &str = "host.docker.internal";
/// The OIDC client id the STS trusts tokens for (their `aud`).
pub const CLIENT_ID: &str = "forge-s3";
/// versitygw's root access key (CI-only credentials).
pub const ROOT_ACCESS: &str = "forge-e2e-root";
/// versitygw's root secret key (CI-only credentials).
pub const ROOT_SECRET: &str = "forge-e2e-root-secret";

const IMAGE: &str = "versity/versitygw";
/// The standalone IAM service, and with it STS, first shipped in v1.8.0.
const TAG: &str = "v1.9.0";
const S3_PORT: u16 = 7070;
const IAM_PORT: u16 = 7071;
const ROLE_NAME: &str = "forge";

/// A running versitygw with its IAM service (removed when dropped).
pub struct VersitygwSts {
    s3_endpoint: String,
    sts_endpoint: String,
    role_arn: String,
    _container: ContainerAsync<GenericImage>,
}

impl VersitygwSts {
    /// Start versitygw with an STS that trusts `issuer`'s tokens for
    /// [`CLIENT_ID`], and the role they assume.
    pub async fn start(issuer: &MockOidc) -> Self {
        // The gateway starts once the IAM service listens on its private
        // socket; the loop gives up (and the container exits) if the IAM
        // service does.
        let script = format!(
            "set -e\n\
             mkdir -p /tmp/iam /tmp/data\n\
             versitygw --port :{IAM_PORT} --health /healthz \
             --access {ROOT_ACCESS} --secret {ROOT_SECRET} \
             iam --dir /tmp/iam --private-ports /tmp/iam.sock \
             --oidc-allow-private-endpoints --oidc-allow-insecure-transport &\n\
             iam=$!\n\
             while [ ! -S /tmp/iam.sock ]; do kill -0 $iam; sleep 0.1; done\n\
             exec versitygw --port :{S3_PORT} --health /healthz \
             --access {ROOT_ACCESS} --secret {ROOT_SECRET} \
             --iam-standalone-endpoint /tmp/iam.sock posix /tmp/data\n"
        );
        let container = GenericImage::new(IMAGE, TAG)
            .with_entrypoint("/bin/sh")
            .with_exposed_port(S3_PORT.tcp())
            .with_exposed_port(IAM_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Admin/S3 service listening on"))
            .with_host(HOST_ALIAS, host_for_containers())
            .with_cmd(["-c", &script])
            .start()
            .await
            .expect("start versitygw testcontainer (is Docker running?)");
        let host = container.get_host().await.expect("host");
        let s3_port = container
            .get_host_port_ipv4(S3_PORT)
            .await
            .expect("mapped S3 port");
        let iam_port = container
            .get_host_port_ipv4(IAM_PORT)
            .await
            .expect("mapped IAM port");
        let s3_endpoint = format!("http://{host}:{s3_port}");
        let sts_endpoint = format!("http://{host}:{iam_port}");
        for endpoint in [&s3_endpoint, &sts_endpoint] {
            wait_until_healthy(endpoint).await;
        }
        let role_arn = trust(&sts_endpoint, issuer).await;
        Self {
            s3_endpoint,
            sts_endpoint,
            role_arn,
            _container: container,
        }
    }

    /// The S3 endpoint.
    pub fn s3_endpoint(&self) -> &str {
        &self.s3_endpoint
    }

    /// The STS (and IAM) endpoint.
    pub fn sts_endpoint(&self) -> &str {
        &self.sts_endpoint
    }

    /// The role `issuer`'s tokens assume.
    pub fn role_arn(&self) -> &str {
        &self.role_arn
    }
}

async fn wait_until_healthy(endpoint: &str) {
    let url = format!("{endpoint}/healthz");
    let client = reqwest::Client::new();
    for _ in 0..60 {
        if client
            .get(&url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("versitygw never became healthy at {url}");
}

/// Register `issuer` as an OpenID Connect provider for [`CLIENT_ID`] and
/// create a role its tokens may assume, with full S3 access. Returns the
/// role's ARN.
async fn trust(iam_endpoint: &str, issuer: &MockOidc) -> String {
    let created = iam(
        iam_endpoint,
        &[
            ("Action", "CreateOpenIDConnectProvider"),
            ("Url", issuer.issuer()),
            ("ClientIDList.member.1", CLIENT_ID),
        ],
    )
    .await;
    let provider_arn = xml_text(&created, "OpenIDConnectProviderArn");
    let trust_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Federated": provider_arn },
            "Action": "sts:AssumeRoleWithWebIdentity",
        }],
    })
    .to_string();
    let created = iam(
        iam_endpoint,
        &[
            ("Action", "CreateRole"),
            ("RoleName", ROLE_NAME),
            ("AssumeRolePolicyDocument", &trust_policy),
        ],
    )
    .await;
    let role_arn = xml_text(&created, "Arn");
    let s3_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }],
    })
    .to_string();
    iam(
        iam_endpoint,
        &[
            ("Action", "PutRolePolicy"),
            ("RoleName", ROLE_NAME),
            ("PolicyName", "s3"),
            ("PolicyDocument", &s3_policy),
        ],
    )
    .await;
    role_arn
}

/// Call the IAM API as the root user and return the response body.
async fn iam(endpoint: &str, params: &[(&str, &str)]) -> String {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("Version", "2010-05-08")
        .extend_pairs(params)
        .finish();
    let url = format!("{endpoint}/");
    let content_type = "application/x-www-form-urlencoded";
    let identity = Credentials::new(ROOT_ACCESS, ROOT_SECRET, None, None, "forge-e2e").into();
    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("iam")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .expect("signing params")
        .into();
    let signable = SignableRequest::new(
        "POST",
        &url,
        [("content-type", content_type)].into_iter(),
        SignableBody::Bytes(body.as_bytes()),
    )
    .expect("signable IAM request");
    let (instructions, _) = sign(signable, &signing_params)
        .expect("sign IAM request")
        .into_parts();
    let mut request = reqwest::Client::new()
        .post(&url)
        .header("content-type", content_type)
        .body(body);
    for (name, value) in instructions.headers() {
        request = request.header(name, value);
    }
    let response = request.send().await.expect("IAM request");
    let status = response.status();
    let text = response.text().await.expect("IAM response");
    assert!(status.is_success(), "IAM {params:?}: {status} {text}");
    text
}

/// The text of the first `<tag>` element in `xml`.
fn xml_text(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("no <{tag}> in {xml}"))
        + open.len();
    let end = start
        + xml[start..]
            .find(&format!("</{tag}>"))
            .unwrap_or_else(|| panic!("no </{tag}> in {xml}"));
    xml[start..end].to_string()
}

/// How a container reaches this process: the host gateway of a local Docker
/// daemon, or this machine's address on the route to a remote one.
fn host_for_containers() -> Host {
    let remote = std::env::var("DOCKER_HOST").ok().and_then(|host| {
        let authority = host.strip_prefix("tcp://")?.split('/').next()?.to_string();
        Some(if authority.contains(':') {
            authority
        } else {
            format!("{authority}:2375")
        })
    });
    match remote.as_deref().and_then(local_address_towards) {
        Some(ip) if !ip.is_loopback() => Host::Addr(ip),
        _ => Host::HostGateway,
    }
}

/// The local address the route to `daemon` (`host:port`) leaves from (a
/// connected UDP socket sends nothing).
fn local_address_towards(daemon: &str) -> Option<IpAddr> {
    let target = daemon.to_socket_addrs().ok()?.next()?;
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .ok()?;
    socket.connect(target).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// A token the STS accepts, signed by `issuer`.
pub async fn web_identity_token(issuer: &MockOidc) -> String {
    issuer
        .sign_token(issuer.wif_claims(
            "system:serviceaccount:forge:forge",
            CLIENT_ID,
            serde_json::json!({}),
        ))
        .await
}
