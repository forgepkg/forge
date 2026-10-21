//! A MinIO container whose STS trusts a [`MockOidc`] issuer, for the
//! short-lived S3 credentials scenarios (#60, `s3.credentials =
//! "web_identity"`).
//!
//! MinIO fetches the issuer's discovery document and JWKS from the test
//! process, which it reaches as [`HOST_ALIAS`], so the issuer must be started
//! with [`MockOidc::start_workload_only_on_host`]. With a local Docker daemon
//! the alias is the Docker host gateway; with a remote one (GitLab's
//! Docker-in-Docker service, `DOCKER_HOST=tcp://docker:2375`) it is this
//! machine's address on the route to the daemon.
//! A token whose `aud` is [`CLIENT_ID`] and whose `policy` claim names a MinIO
//! policy (e.g. `readwrite`) is exchanged by `AssumeRoleWithWebIdentity` for
//! temporary keys with that policy: MinIO's claim-based policies, which take
//! no `RoleArn`.

use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use testcontainers::core::{Host, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use crate::MockOidc;

/// The name the container reaches the test host by.
pub const HOST_ALIAS: &str = "host.docker.internal";
/// The OIDC client id MinIO trusts tokens for (their `aud`).
pub const CLIENT_ID: &str = "forge-s3";
/// MinIO's root user (CI-only credentials).
pub const ROOT_USER: &str = "forge-e2e-root";
/// MinIO's root password (CI-only credentials).
pub const ROOT_PASSWORD: &str = "forge-e2e-root-password";

const IMAGE: &str = "minio/minio";
/// The last community release published as an image.
const TAG: &str = "RELEASE.2025-09-07T16-13-09Z";
const PORT: u16 = 9000;

/// A running MinIO (removed when dropped).
pub struct Minio {
    endpoint: String,
    _container: ContainerAsync<GenericImage>,
}

impl Minio {
    /// Start MinIO with OpenID Connect STS trusting `issuer`'s tokens for
    /// [`CLIENT_ID`].
    pub async fn start(issuer: &MockOidc) -> Self {
        let config_url = format!("{}/.well-known/openid-configuration", issuer.issuer());
        let container = GenericImage::new(IMAGE, TAG)
            .with_exposed_port(PORT.tcp())
            .with_wait_for(WaitFor::message_on_stdout("API: "))
            .with_host(HOST_ALIAS, host_for_containers())
            .with_env_var("MINIO_ROOT_USER", ROOT_USER)
            .with_env_var("MINIO_ROOT_PASSWORD", ROOT_PASSWORD)
            .with_env_var("MINIO_IDENTITY_OPENID_CONFIG_URL", config_url)
            .with_env_var("MINIO_IDENTITY_OPENID_CLIENT_ID", CLIENT_ID)
            .with_env_var("MINIO_IDENTITY_OPENID_CLAIM_NAME", "policy")
            .with_cmd(["server", "/data"])
            .start()
            .await
            .expect("start minio testcontainer (is Docker running?)");
        let host = container.get_host().await.expect("host");
        let port = container
            .get_host_port_ipv4(PORT)
            .await
            .expect("mapped port");
        let minio = Self {
            endpoint: format!("http://{host}:{port}"),
            _container: container,
        };
        minio.wait_until_ready().await;
        minio
    }

    /// The S3 (and STS) endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn wait_until_ready(&self) {
        let url = format!("{}/minio/health/ready", self.endpoint);
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
        panic!("minio never became ready at {url}");
    }
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

/// A token MinIO's STS accepts for `policy`, signed by `issuer`.
pub async fn web_identity_token(issuer: &MockOidc, policy: &str) -> String {
    issuer
        .sign_token(issuer.wif_claims(
            "system:serviceaccount:forge:forge",
            CLIENT_ID,
            serde_json::json!({ "policy": policy }),
        ))
        .await
}
