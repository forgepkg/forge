//! Password-login failure throttling (per client IP + username).
//!
//! Both password entry points — the browser `POST /auth/login` and the wire
//! HTTP Basic password path ([`super::token::BasicAuthSource`]) — reserve an
//! attempt here with [`LoginThrottle::begin`] before running the provider
//! chain and report its verdict on the returned [`LoginAttempt`]. Once a
//! `(client IP, username)` pair has accumulated `max_failures` failures inside
//! a fixed `window`, further attempts for that pair are refused without
//! touching the chain (no argon2 work, nothing forwarded upstream) until the
//! window lapses. A success clears the pair.
//!
//! Keying on the pair (not the username alone) means an attacker cannot lock a
//! victim out from another address, while a single address still cannot brute
//! force a username. An IPv6 client is keyed by its **/64**: one host
//! routinely owns a whole /64, so per-address keys would hand it 2^64 fresh
//! budgets. The state is **per instance and in memory** — a cheap first line
//! of defense, not a cluster-wide guarantee.
//!
//! ## Per-username soft backoff
//! A guesser spread over many networks never trips a pair's lockout, so
//! failures are also counted per **username** across all addresses. Past a
//! threshold (default three pair budgets per window) attempts for that
//! username are spaced out — each waits for the next slot, the spacing
//! doubling with every further failure up to a cap, and an attempt whose wait
//! would exceed [`DEFAULT_MAX_WAIT`] is refused as busy — so the account can no
//! longer be guessed at full speed. A success clears it.
//!
//! Slots are shared by everyone presenting the username, so a guesser who
//! keeps claiming them could otherwise keep the owner out. Two rules prevent
//! that: an attempt from a network the username signed in from successfully
//! in the last [`KNOWN_NETWORK_TTL`] (the owner's office, VPN or CI runners)
//! skips the backoff, and an attempt whose pair is already locked is refused
//! without claiming a slot.
//!
//! With a [`KnownNetworkStore`] (the server uses [`PgKnownNetworks`]) those
//! networks are also recorded in Postgres, at most once an hour per network,
//! and read back while a username is being backed off (at most once every
//! [`KNOWN_NETWORK_RELOAD`] per username): a sign-in seen by another instance,
//! or before a restart, still exempts the owner. Lockouts and failure counts
//! stay per instance.
//!
//! ## Reservation, not check-then-record
//! An attempt is counted against the pair's budget atomically *before* the
//! chain runs: at most `max_failures - failures` attempts of a pair are in
//! flight at once. A separate "is it locked?" check followed by a later
//! "record the failure" would let N concurrent guesses all pass the check
//! before any of them recorded its failure. An attempt beyond the in-flight
//! budget **waits** (bounded by [`DEFAULT_MAX_WAIT`]) for a slot instead of
//! being refused, so a client that legitimately sends many parallel requests
//! with the right password (a NuGet restore over Basic) is serialized, never
//! locked out. Verdicts: [`LoginAttempt::failed`] counts the failure,
//! [`LoginAttempt::succeeded`] clears the pair, and
//! [`LoginAttempt::released`] — an outage, which is not the caller's fault —
//! or a dropped attempt (the client went away before any verdict was sent)
//! gives the slot back uncounted.
//!
//! ## Bounded memory
//! The key is the canonical client IP plus a SHA-256 of the canonical
//! username, so an entry has a fixed size whatever username is presented, and
//! both entry points refuse usernames over [`MAX_USERNAME_BYTES`] before they
//! get here. Only pairs with recorded failures or attempts in flight are kept.
//! Expired windows are swept on insert, amortized (one full sweep per
//! `max(len, 1024)` insertions); a map still full of live windows evicts its
//! oldest eighth at once, so no insert pays an O(n) scan on every call.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::Notify;

/// Longest username (in bytes) either password entry point accepts. Longer
/// ones are refused as plain invalid credentials before any lookup, throttle
/// bookkeeping or provider work, and are never counted as a failure.
pub const MAX_USERNAME_BYTES: usize = 256;

/// How many characters of a presented username are written to logs.
const LOG_USERNAME_CHARS: usize = 64;

/// The presented `username`, cut to a log-safe length (the caller picks it).
pub fn username_for_log(username: &str) -> Cow<'_, str> {
    match username.char_indices().nth(LOG_USERNAME_CHARS) {
        Some((cut, _)) => Cow::Owned(format!("{}…", &username[..cut])),
        None => Cow::Borrowed(username),
    }
}

/// How long an attempt waits for an in-flight slot of its pair before giving
/// up with [`AttemptRefused::Busy`].
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(10);

/// Upper bound on tracked pairs. A map this full of live windows evicts its
/// oldest [`EVICT_BATCH`] entries at once (pairs with attempts in flight are
/// kept).
const MAX_TRACKED: usize = 100_000;

/// Entries evicted together when the map is full of live windows.
const EVICT_BATCH: usize = MAX_TRACKED / 8;

/// Minimum number of insertions between two sweeps of expired windows.
const SWEEP_MIN_INSERTS: usize = 1024;

/// How long a network a username signed in from stays exempt from that
/// username's soft backoff.
pub const KNOWN_NETWORK_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Networks remembered per username (the most recent successes).
const KNOWN_NETWORKS_PER_USER: usize = 8;

/// How often a still-used network's success is written to the
/// [`KnownNetworkStore`] again.
const KNOWN_NETWORK_PERSIST_EVERY: Duration = Duration::from_secs(60 * 60);

/// How long the networks read from the [`KnownNetworkStore`] for a username
/// under backoff are used before they are read again.
pub const KNOWN_NETWORK_RELOAD: Duration = Duration::from_secs(5 * 60);

/// A network a username signed in from.
#[derive(Debug, Clone, Copy)]
struct KnownNet {
    net: IpAddr,
    /// The last success from it.
    seen: Instant,
    /// When that was last written to the store (`None`: not yet).
    persisted: Option<Instant>,
}

/// Per username hash: the networks it signed in from, newest last.
type KnownNetworks = HashMap<[u8; 32], Vec<KnownNet>>;

/// Where the networks a username signed in from are kept beyond this
/// instance's memory (see the [module docs](self)). Failures are the
/// store's to log; the throttle then works from memory alone.
#[async_trait::async_trait]
pub trait KnownNetworkStore: Send + Sync + std::fmt::Debug {
    /// Record a successful sign-in of `user` (a username hash) from `net`.
    async fn remember(&self, user: [u8; 32], net: IpAddr);
    /// The networks `user` signed in from within `within`, with how long ago.
    async fn recent(&self, user: [u8; 32], within: Duration) -> Vec<(IpAddr, Duration)>;
}

/// [`KnownNetworkStore`] over the `login_known_network` table.
#[derive(Debug, Clone)]
pub struct PgKnownNetworks {
    pool: sqlx::PgPool,
}

impl PgKnownNetworks {
    /// A store over `pool`.
    pub fn new(pool: sqlx::PgPool) -> Self {
        PgKnownNetworks { pool }
    }
}

#[async_trait::async_trait]
impl KnownNetworkStore for PgKnownNetworks {
    async fn remember(&self, user: [u8; 32], net: IpAddr) {
        let result = forge_db::login_network_dao::remember(
            &self.pool,
            &user,
            &net.to_string(),
            chrono::Utc::now(),
        )
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "could not record the network of a sign-in");
        }
    }

    async fn recent(&self, user: [u8; 32], within: Duration) -> Vec<(IpAddr, Duration)> {
        let now = chrono::Utc::now();
        let since = chrono::Duration::from_std(within)
            .ok()
            .and_then(|within| now.checked_sub_signed(within))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
        let rows = match forge_db::login_network_dao::recent(
            &self.pool,
            &user,
            since,
            KNOWN_NETWORKS_PER_USER as i64,
        )
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the networks a username signed in from");
                return Vec::new();
            }
        };
        rows.into_iter()
            .filter_map(|(net, at)| {
                let net = net.parse().ok()?;
                Some((net, (now - at).to_std().unwrap_or_default()))
            })
            .collect()
    }
}

/// The network a client address is accounted to: the address itself for
/// IPv4 (IPv4-mapped IPv6 included), its /64 for IPv6.
pub fn client_network(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(std::net::Ipv6Addr::from(prefix))
        }
        v4 => v4,
    }
}

/// Failures of one username across all networks (the soft backoff).
#[derive(Debug)]
struct UserEntry {
    failures: u32,
    window_start: Instant,
    /// Earliest start of the next attempt while backing off.
    next_allowed: Instant,
}

/// A tracked pair: the canonical client IP and a SHA-256 of the canonical
/// username. Fixed size, whatever the username.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    ip: IpAddr,
    user: [u8; 32],
}

#[derive(Debug)]
struct Entry {
    /// Failures recorded in the current window.
    failures: u32,
    /// Reserved attempts that have not reported a verdict yet.
    in_flight: u32,
    window_start: Instant,
    /// Wakes attempts waiting for one of this pair's in-flight slots; created
    /// on the first wait.
    waiters: Option<Arc<Notify>>,
}

#[derive(Debug, Default)]
struct State {
    entries: HashMap<Key, Entry>,
    /// New pairs inserted since the last sweep of expired windows.
    inserts_since_sweep: usize,
}

impl State {
    /// Called before inserting a new pair: sweep expired windows (amortized)
    /// and, if the map is still full, evict the oldest batch.
    fn make_room(&mut self, now: Instant, window: Duration) {
        self.inserts_since_sweep += 1;
        let len = self.entries.len();
        if len < MAX_TRACKED && self.inserts_since_sweep < len.max(SWEEP_MIN_INSERTS) {
            return;
        }
        self.inserts_since_sweep = 0;
        self.entries
            .retain(|_, e| e.in_flight > 0 || now.duration_since(e.window_start) < window);
        if self.entries.len() < MAX_TRACKED {
            return;
        }
        let mut starts: Vec<Instant> = self
            .entries
            .values()
            .filter(|e| e.in_flight == 0)
            .map(|e| e.window_start)
            .collect();
        if starts.is_empty() {
            return;
        }
        let nth = EVICT_BATCH.min(starts.len()) - 1;
        let cutoff = *starts.select_nth_unstable(nth).1;
        self.entries
            .retain(|_, e| e.in_flight > 0 || e.window_start > cutoff);
    }
}

/// Why [`LoginThrottle::begin`] refused an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptRefused {
    /// The pair used up its failures for the current window.
    Locked,
    /// Every remaining attempt of the pair stayed in flight for the whole
    /// wait. Not counted; callers answer as for an outage.
    Busy,
}

enum Reserve {
    Granted,
    Locked,
    Busy(Arc<Notify>),
}

enum Verdict {
    Failed,
    Succeeded,
    Released,
}

/// Fixed-window failure counter keyed by `(client network, username)`, plus a
/// per-username soft backoff (see the [module docs](self)).
#[derive(Debug)]
pub struct LoginThrottle {
    max_failures: u32,
    window: Duration,
    max_wait: Duration,
    state: Mutex<State>,
    /// Failures of a username (all networks) before its attempts are spaced.
    user_soft_threshold: u32,
    /// Spacing at the threshold; doubles per further failure.
    user_backoff_base: Duration,
    /// Largest spacing.
    user_backoff_max: Duration,
    users: Mutex<HashMap<[u8; 32], UserEntry>>,
    /// Networks each username recently signed in from; exempt from its soft
    /// backoff.
    known_networks: Mutex<KnownNetworks>,
    /// Shares those networks across instances and restarts.
    known_store: Option<Arc<dyn KnownNetworkStore>>,
    /// When each username's networks were last read from `known_store`.
    known_loaded: Mutex<HashMap<[u8; 32], Instant>>,
}

impl LoginThrottle {
    /// Build a throttle allowing `max_failures` failures per `window`. A
    /// `max_failures` of `0` disables throttling entirely.
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            max_wait: DEFAULT_MAX_WAIT,
            state: Mutex::new(State::default()),
            user_soft_threshold: max_failures.saturating_mul(3),
            user_backoff_base: Duration::from_secs(1),
            user_backoff_max: Duration::from_secs(30),
            users: Mutex::new(HashMap::new()),
            known_networks: Mutex::new(HashMap::new()),
            known_store: None,
            known_loaded: Mutex::new(HashMap::new()),
        }
    }

    /// Keep the networks usernames signed in from in `store` as well (see
    /// the [module docs](self)).
    pub fn with_known_network_store(mut self, store: Arc<dyn KnownNetworkStore>) -> Self {
        self.known_store = Some(store);
        self
    }

    /// Override the per-username soft backoff: after `threshold` failures of a
    /// username (all networks, same window) its attempts are spaced by `base`,
    /// doubling per further failure up to `max`. A `threshold` of `0` turns
    /// the backoff off.
    pub fn with_user_backoff(mut self, threshold: u32, base: Duration, max: Duration) -> Self {
        self.user_soft_threshold = threshold;
        self.user_backoff_base = base;
        self.user_backoff_max = max;
        self
    }

    /// How long the next attempt for `user` must wait (`Some(ZERO)` when it
    /// may start now), claiming that slot; `None` when the wait would exceed
    /// `max_wait` (nothing is claimed then).
    fn user_slot(&self, user: [u8; 32]) -> Option<Duration> {
        if self.user_soft_threshold == 0 {
            return Some(Duration::ZERO);
        }
        let now = Instant::now();
        let mut users = self.users.lock().expect("login throttle mutex poisoned");
        let Some(entry) = users.get_mut(&user) else {
            return Some(Duration::ZERO);
        };
        if now.duration_since(entry.window_start) >= self.window {
            users.remove(&user);
            return Some(Duration::ZERO);
        }
        if entry.failures < self.user_soft_threshold {
            return Some(Duration::ZERO);
        }
        let doublings = (entry.failures - self.user_soft_threshold).min(16);
        let backoff = self
            .user_backoff_base
            .saturating_mul(1u32 << doublings)
            .min(self.user_backoff_max);
        let slot = entry.next_allowed.max(now);
        let wait = slot.duration_since(now);
        if wait > self.max_wait {
            return None;
        }
        entry.next_allowed = slot + backoff;
        Some(wait)
    }

    /// Whether the username behind `key` signed in from its network within
    /// [`KNOWN_NETWORK_TTL`].
    fn is_known_network(&self, key: Key) -> bool {
        let now = Instant::now();
        self.known_networks
            .lock()
            .expect("login throttle mutex poisoned")
            .get(&key.user)
            .is_some_and(|nets| {
                nets.iter().any(|known| {
                    known.net == key.ip && now.duration_since(known.seen) < KNOWN_NETWORK_TTL
                })
            })
    }

    /// Remember that `user` signed in from `net` at `seen`. Returns whether
    /// the success is due to be written to the store.
    fn remember_network(&self, user: [u8; 32], net: IpAddr, seen: Instant, stored: bool) -> bool {
        let now = Instant::now();
        let mut known = self
            .known_networks
            .lock()
            .expect("login throttle mutex poisoned");
        if !known.contains_key(&user) && known.len() >= MAX_TRACKED {
            known.retain(|_, nets| {
                nets.retain(|known| now.duration_since(known.seen) < KNOWN_NETWORK_TTL);
                !nets.is_empty()
            });
            if known.len() >= MAX_TRACKED {
                // Full of live entries: stay bounded, remember no more.
                return false;
            }
        }
        let nets = known.entry(user).or_default();
        let previous = nets
            .iter()
            .position(|known| known.net == net)
            .map(|at| nets.remove(at));
        nets.retain(|known| now.duration_since(known.seen) < KNOWN_NETWORK_TTL);
        if previous.is_some_and(|known| known.seen > seen) {
            // A newer success is already known; keep it.
            nets.push(previous.expect("checked"));
            return false;
        }
        let persisted = if stored {
            Some(seen)
        } else {
            previous.and_then(|known| known.persisted)
        };
        let due = !stored
            && persisted.is_none_or(|at| now.duration_since(at) >= KNOWN_NETWORK_PERSIST_EVERY);
        if nets.len() >= KNOWN_NETWORKS_PER_USER {
            nets.remove(0);
        }
        nets.push(KnownNet {
            net,
            seen,
            persisted: if due { Some(now) } else { persisted },
        });
        nets.sort_by_key(|known| known.seen);
        due
    }

    /// Whether `user` is past its soft-backoff threshold in this window.
    fn user_backing_off(&self, user: [u8; 32]) -> bool {
        if self.user_soft_threshold == 0 {
            return false;
        }
        let now = Instant::now();
        self.users
            .lock()
            .expect("login throttle mutex poisoned")
            .get(&user)
            .is_some_and(|entry| {
                now.duration_since(entry.window_start) < self.window
                    && entry.failures >= self.user_soft_threshold
            })
    }

    /// Merge the networks the store knows for `user` into memory, unless they
    /// were read within [`KNOWN_NETWORK_RELOAD`].
    async fn load_known_networks(&self, user: [u8; 32]) {
        let Some(store) = &self.known_store else {
            return;
        };
        let now = Instant::now();
        {
            let mut loaded = self
                .known_loaded
                .lock()
                .expect("login throttle mutex poisoned");
            if loaded
                .get(&user)
                .is_some_and(|at| now.duration_since(*at) < KNOWN_NETWORK_RELOAD)
            {
                return;
            }
            if loaded.len() >= MAX_TRACKED {
                loaded.retain(|_, at| now.duration_since(*at) < KNOWN_NETWORK_RELOAD);
                if loaded.len() >= MAX_TRACKED {
                    return;
                }
            }
            loaded.insert(user, now);
        }
        for (net, age) in store.recent(user, KNOWN_NETWORK_TTL).await {
            if let Some(seen) = now.checked_sub(age) {
                self.remember_network(user, net, seen, true);
            }
        }
    }

    /// Record a verdict for the username behind `user` (soft backoff).
    fn record_user(&self, user: [u8; 32], verdict: &Verdict) {
        if self.user_soft_threshold == 0 {
            return;
        }
        let now = Instant::now();
        let mut users = self.users.lock().expect("login throttle mutex poisoned");
        match verdict {
            Verdict::Succeeded => {
                users.remove(&user);
            }
            Verdict::Released => {}
            Verdict::Failed => {
                if !users.contains_key(&user) && users.len() >= MAX_TRACKED {
                    let window = self.window;
                    users.retain(|_, e| now.duration_since(e.window_start) < window);
                    if users.len() >= MAX_TRACKED {
                        // Full of live entries: stay bounded, track no more.
                        return;
                    }
                }
                let entry = users.entry(user).or_insert(UserEntry {
                    failures: 0,
                    window_start: now,
                    next_allowed: now,
                });
                if now.duration_since(entry.window_start) >= self.window {
                    entry.failures = 0;
                    entry.window_start = now;
                }
                entry.failures = entry.failures.saturating_add(1);
            }
        }
    }

    /// A throttle that never locks (tests / wiring without config).
    pub fn disabled() -> Self {
        Self::new(0, Duration::ZERO)
    }

    /// Override how long an attempt waits for an in-flight slot of its pair
    /// (default [`DEFAULT_MAX_WAIT`]).
    pub fn with_max_wait(mut self, max_wait: Duration) -> Self {
        self.max_wait = max_wait;
        self
    }

    fn key(ip: IpAddr, username: &str) -> Key {
        // The canonical form every account lookup uses, so the spellings of
        // one name (case, spacing, Unicode composition) share one budget.
        let user = forge_db::username::canonical_username(username)
            .unwrap_or_else(|_| username.trim().to_lowercase());
        Key {
            ip: client_network(ip),
            user: Sha256::digest(user.as_bytes()).into(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("login throttle mutex poisoned")
    }

    /// Reserve one password attempt for the pair, waiting (bounded) while the
    /// pair's remaining budget is all in flight. Run the provider chain only on
    /// `Ok`, and report the verdict on the returned attempt.
    pub async fn begin(
        &self,
        ip: IpAddr,
        username: &str,
    ) -> Result<LoginAttempt<'_>, AttemptRefused> {
        if self.max_failures == 0 {
            return Ok(LoginAttempt {
                throttle: self,
                key: None,
            });
        }
        let key = Self::key(ip, username);
        // Per-username soft backoff first: wait for this username's next slot,
        // unless the attempt comes from a network the username signed in from
        // (here, or as recorded in the store) or its pair is locked anyway
        // (refused below without taking a slot from the owner).
        if !self.is_known_network(key) && !self.pair_locked(key) && self.user_backing_off(key.user)
        {
            self.load_known_networks(key.user).await;
        }
        if !self.is_known_network(key) && !self.pair_locked(key) {
            match self.user_slot(key.user) {
                None => return Err(AttemptRefused::Busy),
                Some(wait) if !wait.is_zero() => tokio::time::sleep(wait).await,
                Some(_) => {}
            }
        }
        let granted = || LoginAttempt {
            throttle: self,
            key: Some(key),
        };
        let deadline = Instant::now() + self.max_wait;
        loop {
            let waiters = match self.try_reserve(key) {
                Reserve::Granted => return Ok(granted()),
                Reserve::Locked => return Err(AttemptRefused::Locked),
                Reserve::Busy(waiters) => waiters,
            };
            let mut notified = std::pin::pin!(waiters.notified());
            notified.as_mut().enable();
            // Re-check once registered: a slot freed between the two lookups
            // would otherwise be a lost wakeup.
            match self.try_reserve(key) {
                Reserve::Granted => return Ok(granted()),
                Reserve::Locked => return Err(AttemptRefused::Locked),
                // The entry was dropped and re-created in between: register on
                // its new notifier instead.
                Reserve::Busy(current) if !Arc::ptr_eq(&current, &waiters) => continue,
                Reserve::Busy(_) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(AttemptRefused::Busy);
            }
        }
    }

    fn try_reserve(&self, key: Key) -> Reserve {
        let now = Instant::now();
        let mut state = self.lock();
        if !state.entries.contains_key(&key) {
            state.make_room(now, self.window);
        }
        let entry = state.entries.entry(key).or_insert_with(|| Entry {
            failures: 0,
            in_flight: 0,
            window_start: now,
            waiters: None,
        });
        if now.duration_since(entry.window_start) >= self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        if entry.failures >= self.max_failures {
            return Reserve::Locked;
        }
        if entry.failures.saturating_add(entry.in_flight) >= self.max_failures {
            return Reserve::Busy(entry.waiters.get_or_insert_with(Default::default).clone());
        }
        entry.in_flight += 1;
        Reserve::Granted
    }

    fn complete(&self, key: Key, verdict: Verdict) {
        self.record_user(key.user, &verdict);
        if matches!(verdict, Verdict::Succeeded)
            && self.remember_network(key.user, key.ip, Instant::now(), false)
        {
            if let (Some(store), Ok(runtime)) =
                (&self.known_store, tokio::runtime::Handle::try_current())
            {
                let store = store.clone();
                runtime.spawn(async move { store.remember(key.user, key.ip).await });
            }
        }
        let mut state = self.lock();
        let Some(entry) = state.entries.get_mut(&key) else {
            return;
        };
        entry.in_flight = entry.in_flight.saturating_sub(1);
        match verdict {
            Verdict::Failed => entry.failures = entry.failures.saturating_add(1),
            Verdict::Succeeded => entry.failures = 0,
            Verdict::Released => {}
        }
        if let Some(waiters) = &entry.waiters {
            waiters.notify_waiters();
        }
        if entry.failures == 0 && entry.in_flight == 0 {
            state.entries.remove(&key);
        }
    }

    /// Whether the pair is currently locked out (too many recent failures).
    pub fn is_locked(&self, ip: IpAddr, username: &str) -> bool {
        if self.max_failures == 0 {
            return false;
        }
        self.pair_locked(Self::key(ip, username))
    }

    fn pair_locked(&self, key: Key) -> bool {
        let now = Instant::now();
        self.lock().entries.get(&key).is_some_and(|e| {
            now.duration_since(e.window_start) < self.window && e.failures >= self.max_failures
        })
    }

    /// How many pairs are currently tracked (diagnostics and tests).
    pub fn tracked(&self) -> usize {
        self.lock().entries.len()
    }
}

impl Default for LoginThrottle {
    /// 10 failures per 5 minutes.
    fn default() -> Self {
        Self::new(10, Duration::from_secs(300))
    }
}

/// A fixed-window rate limit per client network (IPv6 by /64; see
/// [`client_network`]), for unauthenticated endpoints that do work or store
/// state per call (e.g. starting an OIDC login stores a flow row). Bounded
/// memory: expired windows are swept when the map fills, and a map still
/// full of live windows refuses networks it does not track yet.
#[derive(Debug)]
pub struct WindowLimiter {
    max: u32,
    window: Duration,
    state: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl WindowLimiter {
    /// Allow `max` calls per `window` per network; `0` disables the limit.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Count a call from `ip`; `false` when its network is over the limit.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.max == 0 {
            return true;
        }
        let now = Instant::now();
        let net = client_network(ip);
        let mut state = self.state.lock().expect("window limiter mutex poisoned");
        if !state.contains_key(&net) && state.len() >= MAX_TRACKED {
            let window = self.window;
            state.retain(|_, (start, _)| now.duration_since(*start) < window);
            if state.len() >= MAX_TRACKED {
                return false;
            }
        }
        let (start, count) = state.entry(net).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
            *start = now;
            *count = 0;
        }
        if *count >= self.max {
            return false;
        }
        *count += 1;
        true
    }
}

/// A reserved password attempt (see [`LoginThrottle::begin`]). Report its
/// verdict; one dropped without a verdict is released uncounted.
#[must_use = "report the attempt's verdict"]
#[derive(Debug)]
pub struct LoginAttempt<'a> {
    throttle: &'a LoginThrottle,
    /// `None` when throttling is disabled or the verdict was reported.
    key: Option<Key>,
}

impl LoginAttempt<'_> {
    /// The credential was refused: count one failure for the pair.
    pub fn failed(mut self) {
        self.finish(Verdict::Failed);
    }

    /// The credential was accepted: clear the pair's failures.
    pub fn succeeded(mut self) {
        self.finish(Verdict::Succeeded);
    }

    /// No verdict on the credential (an outage, not the caller's fault): give
    /// the slot back without counting a failure.
    pub fn released(mut self) {
        self.finish(Verdict::Released);
    }

    fn finish(&mut self, verdict: Verdict) {
        if let Some(key) = self.key.take() {
            self.throttle.complete(key, verdict);
        }
    }
}

impl Drop for LoginAttempt<'_> {
    fn drop(&mut self) {
        self.finish(Verdict::Released);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    async fn fail(t: &LoginThrottle, ip: IpAddr, username: &str) {
        t.begin(ip, username).await.expect("not refused").failed();
    }

    #[tokio::test]
    async fn locks_after_max_failures_per_ip_and_username() {
        let t = LoginThrottle::new(3, Duration::from_secs(60));
        let a = ip("203.0.113.1");
        for _ in 0..2 {
            fail(&t, a, "alice").await;
            assert!(!t.is_locked(a, "alice"));
        }
        fail(&t, a, "Alice").await;
        assert!(t.is_locked(a, "alice"), "username is case-insensitive");
        assert_eq!(
            t.begin(a, " alice ").await.unwrap_err(),
            AttemptRefused::Locked
        );
        // Other pairs are unaffected: another IP, another username.
        assert!(!t.is_locked(ip("203.0.113.2"), "alice"));
        assert!(!t.is_locked(a, "bob"));
    }

    #[tokio::test]
    async fn unicode_spellings_of_a_username_share_one_budget() {
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        let a = ip("203.0.113.1");
        // Precomposed ü, then U + combining diaeresis: one account, one budget.
        fail(&t, a, "J\u{00fc}rgen").await;
        fail(&t, a, "JU\u{0308}RGEN").await;
        assert!(t.is_locked(a, "jürgen"));
    }

    #[tokio::test]
    async fn ipv6_clients_are_keyed_by_their_64() {
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        fail(&t, ip("2001:db8:1:2::1"), "alice").await;
        fail(&t, ip("2001:db8:1:2:ffff::9"), "alice").await;
        assert!(
            t.is_locked(ip("2001:db8:1:2:dead:beef::7"), "alice"),
            "every address of the /64 shares the lockout"
        );
        assert!(
            !t.is_locked(ip("2001:db8:1:3::1"), "alice"),
            "another /64 does not"
        );
        assert_eq!(client_network(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
    }

    #[tokio::test]
    async fn a_username_guessed_from_many_networks_is_backed_off() {
        let t = LoginThrottle::new(5, Duration::from_secs(60)).with_user_backoff(
            3,
            Duration::from_millis(200),
            Duration::from_millis(400),
        );
        for n in 1..=3 {
            fail(&t, ip(&format!("203.0.113.{n}")), "alice").await;
        }
        assert!(
            !t.is_locked(ip("203.0.113.9"), "alice"),
            "no pair is locked"
        );
        // Each further attempt (from yet another network) waits for its slot.
        let started = Instant::now();
        fail(&t, ip("198.51.100.1"), "alice").await;
        fail(&t, ip("198.51.100.2"), "alice").await;
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
        // Other usernames are unaffected.
        let started = Instant::now();
        t.begin(ip("198.51.100.3"), "bob").await.unwrap().released();
        assert!(started.elapsed() < Duration::from_millis(100));
        // The owner still gets in, and a success clears the backoff.
        t.begin(ip("198.51.100.4"), "alice")
            .await
            .unwrap()
            .succeeded();
        let started = Instant::now();
        t.begin(ip("198.51.100.5"), "alice")
            .await
            .unwrap()
            .released();
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn the_backoff_cannot_keep_the_owner_out_of_a_known_network() {
        let t = LoginThrottle::new(5, Duration::from_secs(60))
            .with_user_backoff(2, Duration::from_millis(400), Duration::from_millis(400))
            .with_max_wait(Duration::from_millis(100));
        let office = ip("192.0.2.10");
        t.begin(office, "alice").await.unwrap().succeeded();
        // A guesser elsewhere pushes alice into the backoff and takes the
        // next slot, so another unknown network is turned away...
        fail(&t, ip("203.0.113.1"), "alice").await;
        fail(&t, ip("203.0.113.2"), "alice").await;
        t.begin(ip("203.0.113.3"), "alice")
            .await
            .unwrap()
            .released();
        assert_eq!(
            t.begin(ip("203.0.113.4"), "alice").await.unwrap_err(),
            AttemptRefused::Busy
        );
        // ...but the network alice signed in from is not held back.
        let started = Instant::now();
        t.begin(office, "alice").await.unwrap().released();
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    /// A [`KnownNetworkStore`] in memory, standing in for Postgres.
    #[derive(Debug, Default)]
    struct MemoryStore(Mutex<Vec<([u8; 32], IpAddr)>>);

    #[async_trait::async_trait]
    impl KnownNetworkStore for MemoryStore {
        async fn remember(&self, user: [u8; 32], net: IpAddr) {
            self.0.lock().unwrap().push((user, net));
        }
        async fn recent(&self, user: [u8; 32], _within: Duration) -> Vec<(IpAddr, Duration)> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(u, _)| *u == user)
                .map(|(_, net)| (*net, Duration::from_secs(60)))
                .collect()
        }
    }

    /// Review L4: the known-network exemption outlives the instance that saw
    /// the sign-in (a restart, or another instance behind the load balancer).
    #[tokio::test]
    async fn a_known_network_survives_a_restart_through_the_store() {
        let store = Arc::new(MemoryStore::default());
        let throttle = || {
            LoginThrottle::new(5, Duration::from_secs(60))
                .with_user_backoff(2, Duration::from_millis(400), Duration::from_millis(400))
                .with_max_wait(Duration::from_millis(100))
                .with_known_network_store(store.clone())
        };
        let office = ip("192.0.2.10");

        let before = throttle();
        before.begin(office, "alice").await.unwrap().succeeded();
        let deadline = Instant::now() + Duration::from_secs(5);
        while store.0.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the success was not recorded");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Further successes from the same network are not written again.
        before.begin(office, "alice").await.unwrap().succeeded();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(store.0.lock().unwrap().len(), 1);
        drop(before);

        let after = throttle();
        fail(&after, ip("203.0.113.1"), "alice").await;
        fail(&after, ip("203.0.113.2"), "alice").await;
        after
            .begin(ip("203.0.113.3"), "alice")
            .await
            .unwrap()
            .released();
        assert_eq!(
            after.begin(ip("203.0.113.4"), "alice").await.unwrap_err(),
            AttemptRefused::Busy
        );
        let started = Instant::now();
        after.begin(office, "alice").await.unwrap().released();
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "the owner's network was held back after the restart"
        );
    }

    #[tokio::test]
    async fn locked_attempts_do_not_take_the_usernames_slots() {
        let t = LoginThrottle::new(1, Duration::from_secs(60))
            .with_user_backoff(1, Duration::from_millis(400), Duration::from_millis(400))
            .with_max_wait(Duration::from_millis(100));
        let attacker = ip("203.0.113.1");
        fail(&t, attacker, "alice").await;
        for _ in 0..5 {
            assert_eq!(
                t.begin(attacker, "alice").await.unwrap_err(),
                AttemptRefused::Locked
            );
        }
        // The refused attempts claimed nothing: the next slot is still free.
        let started = Instant::now();
        t.begin(ip("198.51.100.1"), "alice")
            .await
            .unwrap()
            .released();
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn window_limiter_counts_per_network() {
        let l = WindowLimiter::new(2, Duration::from_secs(60));
        assert!(l.allow(ip("2001:db8::1")));
        assert!(l.allow(ip("2001:db8::2")));
        assert!(!l.allow(ip("2001:db8::3")), "same /64");
        assert!(l.allow(ip("2001:db8:0:1::1")), "another /64");
        assert!(WindowLimiter::new(0, Duration::ZERO).allow(ip("192.0.2.1")));
    }

    #[tokio::test]
    async fn success_clears_the_pair() {
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        let a = ip("203.0.113.1");
        fail(&t, a, "alice").await;
        t.begin(a, "alice").await.unwrap().succeeded();
        assert_eq!(t.tracked(), 0, "a cleared pair is not kept");
        fail(&t, a, "alice").await;
        assert!(!t.is_locked(a, "alice"));
    }

    #[tokio::test]
    async fn window_expiry_unlocks() {
        let t = LoginThrottle::new(1, Duration::from_millis(20));
        let a = ip("203.0.113.1");
        fail(&t, a, "alice").await;
        assert!(t.is_locked(a, "alice"));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!t.is_locked(a, "alice"));
        // A new failure starts a fresh window rather than stacking.
        fail(&t, a, "alice").await;
        assert!(t.is_locked(a, "alice"));
    }

    #[tokio::test]
    async fn zero_max_disables() {
        let t = LoginThrottle::disabled();
        let a = ip("203.0.113.1");
        for _ in 0..100 {
            fail(&t, a, "alice").await;
        }
        assert!(!t.is_locked(a, "alice"));
        assert_eq!(t.tracked(), 0);
    }

    #[test]
    fn key_is_fixed_size_whatever_the_username() {
        // B3: the map key never embeds the presented username.
        assert!(std::mem::size_of::<Key>() <= 64);
        let huge = "A".repeat(2 * 1024 * 1024);
        let a = ip("203.0.113.1");
        let k = LoginThrottle::key(a, &huge);
        // Pairing semantics survive the hashing: normalized usernames meet,
        // distinct ones (and other IPs) do not.
        assert_eq!(
            k,
            LoginThrottle::key(a, &format!("  {} ", huge.to_lowercase()))
        );
        assert_ne!(k, LoginThrottle::key(a, &format!("{huge}B")));
        assert_ne!(k, LoginThrottle::key(ip("203.0.113.2"), &huge));
    }

    #[tokio::test]
    async fn ipv4_mapped_peer_shares_the_ipv4_pair() {
        let t = LoginThrottle::new(1, Duration::from_secs(60));
        fail(&t, ip("::ffff:203.0.113.1"), "alice").await;
        assert!(t.is_locked(ip("203.0.113.1"), "alice"));
    }

    #[tokio::test]
    async fn expired_entries_are_pruned_on_insert() {
        let t = LoginThrottle::new(5, Duration::from_millis(500));
        let a = ip("203.0.113.1");
        for i in 0..5 {
            fail(&t, a, &format!("old-{i}")).await;
        }
        assert_eq!(t.tracked(), 5);
        tokio::time::sleep(Duration::from_millis(600)).await;
        // New pairs trigger the amortized sweep, which drops the lapsed ones.
        for i in 0..SWEEP_MIN_INSERTS {
            fail(&t, a, &format!("new-{i}")).await;
        }
        assert_eq!(t.tracked(), SWEEP_MIN_INSERTS, "expired windows swept");
    }

    #[tokio::test]
    async fn concurrent_attempts_cannot_exceed_the_budget() {
        // M4: attempts are reserved before any verdict, so a burst cannot all
        // pass the lockout check before the first failure is recorded.
        let t =
            LoginThrottle::new(3, Duration::from_secs(60)).with_max_wait(Duration::from_millis(50));
        let a = ip("203.0.113.1");
        let in_flight = [
            t.begin(a, "alice").await.unwrap(),
            t.begin(a, "alice").await.unwrap(),
            t.begin(a, "alice").await.unwrap(),
        ];
        assert_eq!(
            t.begin(a, "alice").await.unwrap_err(),
            AttemptRefused::Busy,
            "the whole budget is in flight"
        );
        for attempt in in_flight {
            attempt.failed();
        }
        assert_eq!(
            t.begin(a, "alice").await.unwrap_err(),
            AttemptRefused::Locked
        );
    }

    #[tokio::test]
    async fn a_waiting_attempt_proceeds_when_a_slot_frees() {
        let t = Arc::new(LoginThrottle::new(2, Duration::from_secs(60)));
        let a = ip("203.0.113.1");
        let first = t.begin(a, "alice").await.unwrap();
        let second = t.begin(a, "alice").await.unwrap();
        let waiter = {
            let t = t.clone();
            tokio::spawn(async move { t.begin(a, "alice").await.map(LoginAttempt::succeeded) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "waits while the budget is in flight");
        first.succeeded();
        assert_eq!(waiter.await.unwrap(), Ok(()));
        second.succeeded();
        assert_eq!(t.tracked(), 0);
    }

    #[tokio::test]
    async fn released_and_dropped_attempts_are_not_counted() {
        let t = LoginThrottle::new(1, Duration::from_secs(60));
        let a = ip("203.0.113.1");
        for _ in 0..5 {
            t.begin(a, "alice").await.unwrap().released();
            drop(t.begin(a, "alice").await.unwrap());
        }
        assert!(!t.is_locked(a, "alice"));
        assert_eq!(t.tracked(), 0);
    }

    #[test]
    fn username_for_log_truncates() {
        assert_eq!(username_for_log("alice"), "alice");
        let long = "é".repeat(1000);
        let logged = username_for_log(&long);
        assert_eq!(logged.chars().count(), LOG_USERNAME_CHARS + 1);
        assert!(logged.ends_with('…'));
    }
}
