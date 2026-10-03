//! The HTTP server loop.
//!
//! `axum::serve` builds its hyper connection builder without a timer, so
//! hyper's header-read timeout never runs and a client can hold a connection
//! (and its task) open indefinitely by trickling request headers
//! ("slowloris"). [`serve`] accepts connections itself and serves each with a
//! timer-backed builder that enforces [`ServeOptions::header_read_timeout`];
//! per-request body-idle and response timeouts are router layers
//! ([`crate::app::build_router`]).

use std::future::Future;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// Connection-level limits.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// How long a client may take to send a request's headers (HTTP/1);
    /// `None` disables the limit.
    pub header_read_timeout: Option<Duration>,
}

impl ServeOptions {
    /// The options a [`crate::config::Config`] asks for.
    pub fn from_config(config: &crate::config::Config) -> Self {
        let secs = config.server.header_read_timeout_seconds;
        ServeOptions {
            header_read_timeout: (secs > 0).then(|| Duration::from_secs(secs)),
        }
    }
}

/// Serve `app` on `listener` until `shutdown` resolves, then stop accepting
/// and wait for in-flight connections to finish. Each request carries the
/// peer address as [`ConnectInfo<SocketAddr>`], like
/// `into_make_service_with_connect_info`.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // E.g. EMFILE: back off instead of spinning.
                    tracing::warn!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let service = app
            .clone()
            .map_request(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                req.map(Body::new)
            });
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(options.header_read_timeout);
        let connection = builder
            .serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(service))
            .into_owned();
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::trace!(%error, %peer, "connection ended with an error");
            }
        });
    }
    drop(listener);
    graceful.shutdown().await;
}
