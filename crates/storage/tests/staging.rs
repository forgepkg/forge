//! The staging budget and directory of [`Cas::stage`] (review: temp space for
//! pushes and proxy downloads had no limit, and files a killed process left
//! were never removed). Staging touches neither S3 nor the database, so no
//! containers are needed: the store and pool below never connect.

use std::io::Cursor;
use std::time::{Duration, SystemTime};

use forge_storage::cas::{Cas, CasError, Staging};
use forge_storage::{BlobStore, ConditionalWrites, S3Config};

fn cas(staging: Staging) -> Cas {
    let store = BlobStore::new(S3Config {
        endpoint: "http://127.0.0.1:9".into(),
        region: "us-east-1".into(),
        bucket: "unused".into(),
        access_key: "unused".into(),
        secret_key: "unused".into(),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: ConditionalWrites::default(),
    });
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused@127.0.0.1:9/unused")
        .expect("lazy pool");
    Cas::new(store, pool).with_staging(staging)
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "forge-staging-test-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The staged files in `dir` and its subdirectories.
fn staged_files(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .map(|entry| {
            if entry.file_type().unwrap().is_dir() {
                staged_files(&entry.path())
            } else {
                usize::from(
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("forge-staging-"),
                )
            }
        })
        .sum()
}

/// Staged bytes count against the budget until the staged file is dropped;
/// a stage that would exceed it fails with `StagingFull` and leaves nothing.
#[tokio::test]
async fn the_budget_refuses_staging_beyond_it_and_is_released_on_drop() {
    let dir = scratch_dir("budget");
    let cas = cas(Staging::new(&dir, Some(100_000)).unwrap());
    let body = || Cursor::new(vec![7u8; 60_000]);

    let first = cas.stage(body(), 1_000_000).await.expect("fits");
    assert!(
        first.temp_path.starts_with(&dir),
        "staged in the staging dir"
    );
    match cas.stage(body(), 1_000_000).await {
        Err(CasError::StagingFull { limit }) => assert_eq!(limit, 100_000),
        other => panic!("expected StagingFull, got {other:?}"),
    }
    assert_eq!(staged_files(&dir), 1, "the refused stage left no file");

    drop(first);
    let again = cas.stage(body(), 1_000_000).await.expect("budget released");
    assert_eq!(again.size, 60_000);
    // The per-item limit is still reported as such.
    assert!(matches!(
        cas.stage(body(), 1_000).await,
        Err(CasError::TooLarge { limit: 1_000 })
    ));
    drop(again);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// No budget: any number of stages.
#[tokio::test]
async fn without_a_budget_staging_is_unbounded() {
    let dir = scratch_dir("unbounded");
    let cas = cas(Staging::new(&dir, None).unwrap());
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(
            cas.stage(Cursor::new(vec![1u8; 50_000]), 1_000_000)
                .await
                .unwrap(),
        );
    }
    drop(held);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Set for the child process of
/// `a_killed_processes_files_are_swept_at_once_live_ones_never`.
const CHILD_DIR: &str = "FORGE_TEST_STAGING_CHILD_DIR";

/// Run by `a_killed_processes_files_are_swept_at_once_live_ones_never` in
/// a child process (a no-op otherwise): stage a file and exit without any
/// cleanup, as a process that is killed mid-request does.
#[tokio::test]
#[ignore = "the child process of another test"]
async fn stage_and_die() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let cas = cas(Staging::new(dir, Some(100_000)).unwrap());
    let _staged = cas
        .stage(Cursor::new(vec![7u8; 60_000]), 1_000_000)
        .await
        .unwrap();
    std::process::exit(0);
}

/// Issue #26: files a killed process staged were removed only once idle for
/// an hour, and counted against no budget, so restarts on a volume sized just
/// above the budget ran it out of space. Each process stages in a locked
/// subdirectory of its own: the sweep removes a dead process's at once,
/// however recent, and never a live process's, however old.
#[tokio::test]
async fn a_killed_processes_files_are_swept_at_once_live_ones_never() {
    let dir = scratch_dir("killed");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["stage_and_die", "--exact", "--ignored", "--nocapture"])
        .env(CHILD_DIR, &dir)
        .output()
        .unwrap();
    assert!(child.status.success(), "child: {child:?}");
    assert_eq!(staged_files(&dir), 1, "the killed process left its file");

    // A live instance sharing the directory, and this process.
    let peer = Staging::new(&dir, None).unwrap();
    let peer_file = cas(peer.clone())
        .stage(Cursor::new(vec![1u8; 1_000]), 1_000_000)
        .await
        .unwrap();
    let staging = Staging::new(&dir, Some(100_000)).unwrap();
    let own_file = cas(staging.clone())
        .stage(Cursor::new(vec![2u8; 1_000]), 1_000_000)
        .await
        .unwrap();
    for file in [&peer_file.temp_path, &own_file.temp_path] {
        let long_ago = SystemTime::now() - Duration::from_secs(7200);
        let parent = std::fs::File::open(file.parent().unwrap()).unwrap();
        parent.set_modified(long_ago).unwrap();
        std::fs::File::options()
            .write(true)
            .open(file)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
    }

    assert_eq!(staging.sweep_stale(Duration::from_secs(3600)).unwrap(), 1);
    assert!(peer_file.temp_path.exists() && own_file.temp_path.exists());
    assert_eq!(staged_files(&dir), 2, "only the dead process's file went");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);

    // A staging's subdirectory goes with its last handle, staged files
    // included.
    drop((peer, staging, peer_file, own_file));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Loose staged files (from versions that staged in the directory itself)
/// and subdirectories whose creation was cut short are removed once idle
/// longer than the threshold, and nothing else.
#[test]
fn sweep_removes_only_idle_staged_files() {
    let dir = scratch_dir("sweep");
    let staging = Staging::new(&dir, None).unwrap();
    let file = |name: &str, idle: Duration| {
        let path = dir.join(name);
        let f = std::fs::File::create(&path).unwrap();
        f.set_modified(SystemTime::now() - idle).unwrap();
        path
    };
    let orphan = file("forge-staging-orphan", Duration::from_secs(7200));
    let live = file("forge-staging-live", Duration::from_secs(10));
    let foreign = file("someone-elses-file", Duration::from_secs(7200));
    let cut_short = dir.join(".forge-staging-proc-cut-short");
    std::fs::create_dir(&cut_short).unwrap();
    std::fs::File::open(&cut_short)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(7200))
        .unwrap();

    assert_eq!(staging.sweep_stale(Duration::from_secs(3600)).unwrap(), 1);
    assert!(!orphan.exists());
    assert!(!cut_short.exists());
    assert!(live.exists());
    assert!(foreign.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Issue #57: the sweep counted every failure to try a process
/// subdirectory's lock as "held", so where locks do not work (on NFS a
/// read-only file could not take one at all) a killed process's files were
/// never removed. A lock that cannot be tried falls back to the idle rule for
/// the files inside, and the directory stays. A `.lock` that is a directory
/// stands in for such a file system: it cannot be opened for writing.
#[test]
fn a_subdirectory_whose_lock_cannot_be_tried_keeps_only_its_live_files() {
    let dir = scratch_dir("unlockable");
    let staging = Staging::new(&dir, None).unwrap();
    let other = dir.join("forge-staging-proc-on-a-lockless-mount");
    std::fs::create_dir_all(other.join(".lock")).unwrap();
    let file = |name: &str, idle: Duration| {
        let path = other.join(name);
        let f = std::fs::File::create(&path).unwrap();
        f.set_modified(SystemTime::now() - idle).unwrap();
        path
    };
    let orphan = file("forge-staging-orphan", Duration::from_secs(7200));
    let live = file("forge-staging-live", Duration::from_secs(10));

    assert_eq!(staging.sweep_stale(Duration::from_secs(3600)).unwrap(), 1);
    assert!(!orphan.exists(), "the idle file went");
    assert!(live.exists(), "a possibly live file stays");
    assert!(other.join(".lock").exists(), "and so does its directory");
    drop(staging);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Issue #57: where locks only work within one host, a sweep on another
/// host can take a live process's lock and remove its subdirectory. The
/// process then staged into a missing directory until it restarted; now the
/// next stage creates (and locks) a new one.
#[tokio::test]
async fn a_subdirectory_swept_from_under_a_live_process_is_replaced() {
    let dir = scratch_dir("replaced");
    let staging = Staging::new(&dir, None).unwrap();
    let cas = cas(staging.clone());
    let first = cas
        .stage(Cursor::new(vec![1u8; 1_000]), 1_000_000)
        .await
        .unwrap();
    let swept = first.temp_path.parent().unwrap().to_path_buf();
    std::fs::remove_dir_all(&swept).unwrap();

    let second = cas
        .stage(Cursor::new(vec![2u8; 1_000]), 1_000_000)
        .await
        .expect("staged in a new subdirectory");
    let replacement = second.temp_path.parent().unwrap();
    assert_ne!(replacement, swept);
    assert!(replacement.starts_with(&dir));
    let lock = std::fs::File::options()
        .read(true)
        .write(true)
        .open(replacement.join(".lock"))
        .unwrap();
    assert!(
        matches!(lock.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "the new subdirectory is locked"
    );
    // Every clone stages there too.
    let third = cas
        .stage(Cursor::new(vec![3u8; 1_000]), 1_000_000)
        .await
        .unwrap();
    assert_eq!(third.temp_path.parent().unwrap(), replacement);

    drop((first, second, third, staging, cas));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #83: a process subdirectory without its lock file is what a process on
/// NFS leaves (unlinking its open lock renamed it, so the directory could
/// not be removed): it goes once idle, while a recent one stays.
#[test]
fn an_idle_subdirectory_without_a_lock_file_is_removed() {
    let dir = scratch_dir("lockless");
    let staging = Staging::new(&dir, None).unwrap();
    let leftover = |name: &str, idle: Duration| {
        let path = dir.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - idle)
            .unwrap();
        path
    };
    let old = leftover("forge-staging-proc-old-leftover", Duration::from_secs(7200));
    let recent = leftover(
        "forge-staging-proc-recent-leftover",
        Duration::from_secs(10),
    );

    staging.sweep_stale(Duration::from_secs(3600)).unwrap();
    assert!(!old.exists(), "an idle leftover went");
    assert!(recent.exists(), "a recent one stays until idle");
    drop(staging);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// #127: a staging directory another local user could tamper with is
/// refused: one writable by group or others (unless sticky, like `/tmp`), or
/// one that belongs to another user. Whoever can rename the process's
/// subdirectory could swap a package between its hashing and its upload.
#[cfg(unix)]
#[test]
fn a_staging_directory_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch_dir("open");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = Staging::new(&dir, None)
        .expect_err("world-writable")
        .to_string();
    assert!(err.contains("writable by group or others"), "{err}");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(Staging::new(&dir, None).is_err(), "group-writable");
    // Sticky, like /tmp: others cannot rename what is not theirs.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
    Staging::new(&dir, None).expect("sticky");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    Staging::new(&dir, None).expect("only the owner writes");

    // Another user's directory (needs root to give one away).
    if rustix::process::geteuid().is_root() {
        let theirs = scratch_dir("theirs");
        std::os::unix::fs::chown(&theirs, Some(4242), None).unwrap();
        let err = Staging::new(&theirs, None)
            .expect_err("not ours")
            .to_string();
        assert!(err.contains("uid 4242"), "{err}");
    }
}

/// #127: Forge creates a missing staging directory, and each process's
/// subdirectory, with mode 0700.
#[cfg(unix)]
#[tokio::test]
async fn staging_directories_are_created_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch_dir("private").join("nested").join("staging");
    let cas = cas(Staging::new(&dir, None).unwrap());
    let staged = cas.stage(Cursor::new(b"x".to_vec()), 1024).await.unwrap();
    let own = staged.temp_path.parent().unwrap();
    for created in [dir.as_path(), own] {
        let mode = std::fs::metadata(created).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", created.display());
    }
}

/// #127: a staged file is read back through the handle it was written and
/// hashed through, so replacing the file at its path in between (what the
/// owner of a shared staging directory could do) does not change what is
/// parsed or uploaded.
#[tokio::test]
async fn a_staged_file_is_read_through_its_own_handle() {
    let dir = scratch_dir("handle");
    let cas = cas(Staging::new(&dir, None).unwrap());
    let staged = cas
        .stage(Cursor::new(b"the hashed bytes".to_vec()), 1024)
        .await
        .unwrap();
    std::fs::remove_file(&staged.temp_path).unwrap();
    std::fs::write(&staged.temp_path, b"attacker bytes").unwrap();
    let read = std::fs::read(staged.read_path()).unwrap();
    if cfg!(target_os = "linux") {
        assert_eq!(read, b"the hashed bytes");
    }
}
