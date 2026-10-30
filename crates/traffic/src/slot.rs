//! What the layers of a request learn about it, for its count: the client
//! address and the repository it addressed.
//!
//! The outermost middleware opens a [`Slot`] around the request
//! ([`Slot::scope`]); code running in the request's task fills it in with
//! [`note_client`] and [`note_repository`] without the values being threaded
//! through every handler. Outside a slot (a worker, a test calling a handler
//! directly) noting does nothing.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

tokio::task_local! {
    static SLOT: Arc<Mutex<Noted>>;
}

/// What was noted about a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Noted {
    /// The client address: the socket peer, or the one a trusted proxy
    /// forwarded.
    pub client: Option<IpAddr>,
    /// The network the address is counted under (the address itself, an
    /// IPv6 address's /64), as text.
    pub network: Option<String>,
    /// The repository the request addressed, once it was found.
    pub repository: Option<String>,
}

/// The slot of one request.
#[derive(Debug, Clone, Default)]
pub struct Slot(Arc<Mutex<Noted>>);

impl Slot {
    /// An empty slot.
    pub fn new() -> Slot {
        Slot::default()
    }

    /// Run `fut` with this slot open: what it notes lands here.
    pub async fn scope<F: Future>(&self, fut: F) -> F::Output {
        SLOT.scope(self.0.clone(), fut).await
    }

    /// What was noted so far.
    pub fn take(&self) -> Noted {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

fn note(f: impl FnOnce(&mut Noted)) {
    let _ = SLOT.try_with(|slot| f(&mut slot.lock().unwrap_or_else(PoisonError::into_inner)));
}

/// Note the request's client `address`, counted under `network`.
pub fn note_client(address: IpAddr, network: String) {
    note(|n| {
        n.client = Some(address);
        n.network = Some(network);
    });
}

/// Note the repository the request addresses, once it is known to exist.
pub fn note_repository(name: &str) {
    note(|n| n.repository = Some(name.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notes_land_in_the_open_slot_only() {
        note_repository("outside");
        let slot = Slot::new();
        slot.scope(async {
            note_client("192.0.2.7".parse().unwrap(), "192.0.2.7".into());
            tokio::task::yield_now().await;
            note_repository("nuget");
        })
        .await;
        let noted = slot.take();
        assert_eq!(noted.repository.as_deref(), Some("nuget"));
        assert_eq!(noted.network.as_deref(), Some("192.0.2.7"));
        assert_eq!(slot.take(), Noted::default(), "taken once");
    }
}
