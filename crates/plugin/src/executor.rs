//! The threads plugin code runs on.
//!
//! Guest code never runs on a tokio worker: the WASI bindings answer a
//! guest's stdout/stderr writes (a panic message, say) by blocking on a tokio
//! runtime, which panics inside an asynchronous context. Every call into a
//! plugin is therefore handed to a dedicated thread; an async caller awaits
//! the result, a synchronous one blocks until it is there.
//!
//! There are two pools, so that the calls a request makes synchronously — the
//! [`forge_core::Format`] rules, microseconds each, waited for on a tokio
//! worker — never queue behind long ones (rendering a large index, parsing a
//! package) and stall the server's workers while they wait.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};

use crate::PluginError;

type Job = Box<dyn FnOnce() + Send>;

/// Which pool a call runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pool {
    /// The format's rules (ids, versions, summaries): short calls a request
    /// waits for synchronously.
    Quick,
    /// Parsing packages and the client protocol: calls that may take as long
    /// as the plugin's time limit.
    Slow,
}

/// At most this many threads per pool (calls queue beyond it).
const MAX_THREADS: usize = 8;

struct Executor {
    jobs: Sender<Job>,
}

fn executor(pool: Pool) -> &'static Executor {
    static QUICK: OnceLock<Executor> = OnceLock::new();
    static SLOW: OnceLock<Executor> = OnceLock::new();
    let (cell, name) = match pool {
        Pool::Quick => (&QUICK, "quick"),
        Pool::Slow => (&SLOW, "slow"),
    };
    cell.get_or_init(|| {
        let (jobs, queue) = mpsc::channel::<Job>();
        let queue = Arc::new(Mutex::new(queue));
        let threads = std::thread::available_parallelism()
            .map_or(2, |n| n.get())
            .clamp(2, MAX_THREADS);
        for i in 0..threads {
            let queue = Arc::clone(&queue);
            std::thread::Builder::new()
                .name(format!("forge-plugin-{name}-{i}"))
                .spawn(move || worker(&queue))
                .expect("spawn a plugin thread");
        }
        Executor { jobs }
    })
}

fn worker(queue: &Mutex<Receiver<Job>>) {
    loop {
        // Hold the lock only to take a job, not while running it.
        let job = match queue.lock() {
            Ok(queue) => queue.recv(),
            Err(poisoned) => poisoned.into_inner().recv(),
        };
        let Ok(job) = job else {
            return;
        };
        // A panicking job (a host bug) must not take the thread with it; the
        // caller sees its result channel closed.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
    }
}

/// Run `f` on a thread of `pool` and block until it returns.
pub(crate) fn run_blocking<R, F>(pool: Pool, f: F) -> Result<R, PluginError>
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    executor(pool)
        .jobs
        .send(Box::new(move || {
            let _ = tx.send(f());
        }))
        .map_err(|_| PluginError::Trap("the plugin threads are gone".into()))?;
    rx.recv()
        .map_err(|_| PluginError::Trap("the plugin call panicked".into()))
}

/// Run `f` on a thread of `pool` and await its result.
pub(crate) async fn run<R, F>(pool: Pool, f: F) -> Result<R, PluginError>
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    executor(pool)
        .jobs
        .send(Box::new(move || {
            let _ = tx.send(f());
        }))
        .map_err(|_| PluginError::Trap("the plugin threads are gone".into()))?;
    rx.await
        .map_err(|_| PluginError::Trap("the plugin call panicked".into()))
}
