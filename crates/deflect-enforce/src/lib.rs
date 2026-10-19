//! Enforcement backends: turning a mitigation decision into a kernel-level drop.
//!
//! The detection plane produces [`deflect_core::Verdict`]s; this crate makes a
//! `Drop` real by programming the source into a drop set. An [`Enforcer`] adds
//! and removes bans by address and prefix length, so a host ban (`/32`, `/128`)
//! and a subnet ban (`/24`, `/64`) share one path.
//!
//! The nftables backend is split in two: [`nft`] builds the command scripts as
//! plain strings (pure and testable with no privileges), and [`NftEnforcer`]
//! runs them through an [`NftRunner`]. The real runner shells out to `nft -f -`,
//! batching so per-ban process spawns are amortised; tests inject a recording
//! runner instead. Bans carry an optional TTL that the kernel expires itself
//! via `flags timeout`, so there is no expiry loop to maintain.
//!
//! A netlink (rustables) fast path and an XDP driver-level drop set are planned
//! alongside this backend, behind the same [`Enforcer`] trait.
//!
//! ```
//! # use core::net::{IpAddr, Ipv4Addr};
//! # use core::time::Duration;
//! # use std::sync::{Arc, Mutex};
//! use deflect_enforce::{EnforceError, Enforcer, NftEnforcer, NftRunner};
//!
//! // A recording runner captures the scripts instead of shelling out to `nft`.
//! struct Recorder(Arc<Mutex<Vec<String>>>);
//! impl NftRunner for Recorder {
//!     fn run(&self, script: &str) -> Result<(), EnforceError> {
//!         self.0.lock().unwrap().push(script.to_string());
//!         Ok(())
//!     }
//! }
//!
//! # fn main() -> Result<(), EnforceError> {
//! let log = Arc::new(Mutex::new(Vec::new()));
//! let enforcer = NftEnforcer::with_runner("deflect", Recorder(log.clone()))?;
//!
//! // Ban a /24, letting the kernel expire it after 60 seconds.
//! enforcer.ban(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24, Some(Duration::from_secs(60)))?;
//!
//! let scripts = log.lock().unwrap();
//! assert!(scripts.iter().any(|s| s.contains("banned4 { 203.0.113.0/24 timeout 60s }")));
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod nft;

use core::net::IpAddr;
use core::time::Duration;
use std::collections::HashSet;
use std::sync::Mutex;

use deflect_core::SourceKey;

/// A failure while programming the data plane.
#[derive(Debug)]
pub enum EnforceError {
    /// The enforcement tool could not be launched.
    Spawn(std::io::Error),
    /// The tool ran but rejected the script.
    Rejected {
        /// Process exit code, absent if the tool was killed by a signal.
        code: Option<i32>,
        /// Captured standard error explaining the rejection.
        stderr: String,
    },
}

impl core::fmt::Display for EnforceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnforceError::Spawn(e) => write!(f, "failed to launch enforcement tool: {e}"),
            EnforceError::Rejected { code, stderr } => {
                write!(
                    f,
                    "enforcement tool rejected script (code {code:?}): {stderr}"
                )
            }
        }
    }
}

impl std::error::Error for EnforceError {}

/// Programs and withdraws source bans in the data plane.
pub trait Enforcer {
    /// Ban `addr` masked to `prefix_len` bits, expiring after `ttl` if given.
    ///
    /// # Errors
    /// Returns an [`EnforceError`] if the backend could not apply the ban.
    fn ban(&self, addr: IpAddr, prefix_len: u8, ttl: Option<Duration>) -> Result<(), EnforceError>;

    /// Remove a previously programmed ban.
    ///
    /// # Errors
    /// Returns an [`EnforceError`] if the backend could not remove the ban.
    fn unban(&self, addr: IpAddr, prefix_len: u8) -> Result<(), EnforceError>;

    /// Number of bans currently tracked by this enforcer's local mirror.
    fn banned_count(&self) -> usize;

    /// Ban a [`SourceKey`] at the given prefix length. The key's aggregation and
    /// `prefix_len` must agree for the kernel element to match the keyed space.
    ///
    /// # Errors
    /// Returns an [`EnforceError`] if the backend could not apply the ban.
    fn ban_source(
        &self,
        key: SourceKey,
        prefix_len: u8,
        ttl: Option<Duration>,
    ) -> Result<(), EnforceError> {
        self.ban(key.addr(), prefix_len, ttl)
    }
}

/// An enforcer that programs nothing but records intent locally: watch/dry-run
/// mode, and the backend tests exercise.
#[derive(Default)]
pub struct NullEnforcer {
    banned: Mutex<HashSet<(IpAddr, u8)>>,
}

impl NullEnforcer {
    /// Create an enforcer with no recorded bans.
    #[must_use]
    pub fn new() -> NullEnforcer {
        NullEnforcer::default()
    }

    /// Snapshot of the currently recorded bans.
    ///
    /// # Panics
    /// Panics only if the local mirror mutex was poisoned by a prior panic.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(IpAddr, u8)> {
        let g = self.banned.lock().expect("mirror poisoned");
        let mut v: Vec<_> = g.iter().copied().collect();
        v.sort();
        v
    }
}

impl Enforcer for NullEnforcer {
    fn ban(
        &self,
        addr: IpAddr,
        prefix_len: u8,
        _ttl: Option<Duration>,
    ) -> Result<(), EnforceError> {
        self.banned
            .lock()
            .expect("mirror poisoned")
            .insert((addr, prefix_len));
        Ok(())
    }

    fn unban(&self, addr: IpAddr, prefix_len: u8) -> Result<(), EnforceError> {
        self.banned
            .lock()
            .expect("mirror poisoned")
            .remove(&(addr, prefix_len));
        Ok(())
    }

    fn banned_count(&self) -> usize {
        self.banned.lock().expect("mirror poisoned").len()
    }
}

/// Executes an nftables script. The real implementation runs `nft -f -`.
pub trait NftRunner {
    /// Apply one nftables script atomically.
    ///
    /// # Errors
    /// Returns an [`EnforceError`] if the tool could not run or rejected input.
    fn run(&self, script: &str) -> Result<(), EnforceError>;
}

/// Runs scripts through the system `nft` binary via `nft -f -`.
pub struct ShellNftRunner {
    nft_path: std::path::PathBuf,
}

impl ShellNftRunner {
    /// Build a runner that invokes `nft` at `nft_path`.
    #[must_use]
    pub fn new(nft_path: impl Into<std::path::PathBuf>) -> ShellNftRunner {
        ShellNftRunner {
            nft_path: nft_path.into(),
        }
    }

    /// Use `nft` as found on `PATH`.
    #[must_use]
    pub fn system() -> ShellNftRunner {
        ShellNftRunner::new("nft")
    }
}

impl NftRunner for ShellNftRunner {
    fn run(&self, script: &str) -> Result<(), EnforceError> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut child = Command::new(&self.nft_path)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(EnforceError::Spawn)?;
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(script.as_bytes())
            .map_err(EnforceError::Spawn)?;
        let out = child.wait_with_output().map_err(EnforceError::Spawn)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(EnforceError::Rejected {
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            })
        }
    }
}

/// An [`Enforcer`] that programs bans into nftables through an [`NftRunner`].
pub struct NftEnforcer<R: NftRunner> {
    table: String,
    runner: R,
    mirror: Mutex<HashSet<(IpAddr, u8)>>,
}

impl NftEnforcer<ShellNftRunner> {
    /// Build an enforcer against the system `nft`, running setup immediately.
    ///
    /// # Errors
    /// Returns an [`EnforceError`] if the setup script could not be applied
    /// (typically missing privileges or no nftables support).
    pub fn system(table: impl Into<String>) -> Result<NftEnforcer<ShellNftRunner>, EnforceError> {
        NftEnforcer::with_runner(table, ShellNftRunner::system())
    }
}

impl<R: NftRunner> NftEnforcer<R> {
    /// Build an enforcer with a specific runner, applying the setup script.
    ///
    /// # Errors
    /// Returns an [`EnforceError`] if the setup script could not be applied.
    pub fn with_runner(
        table: impl Into<String>,
        runner: R,
    ) -> Result<NftEnforcer<R>, EnforceError> {
        let table = table.into();
        runner.run(&nft::setup_script(&table))?;
        Ok(NftEnforcer {
            table,
            runner,
            mirror: Mutex::new(HashSet::new()),
        })
    }

    /// Name of the nftables table this enforcer programs.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }
}

impl<R: NftRunner> Enforcer for NftEnforcer<R> {
    fn ban(&self, addr: IpAddr, prefix_len: u8, ttl: Option<Duration>) -> Result<(), EnforceError> {
        self.runner
            .run(&nft::ban_script(&self.table, addr, prefix_len, ttl))?;
        self.mirror
            .lock()
            .expect("mirror poisoned")
            .insert((addr, prefix_len));
        Ok(())
    }

    fn unban(&self, addr: IpAddr, prefix_len: u8) -> Result<(), EnforceError> {
        self.runner
            .run(&nft::unban_script(&self.table, addr, prefix_len))?;
        self.mirror
            .lock()
            .expect("mirror poisoned")
            .remove(&(addr, prefix_len));
        Ok(())
    }

    fn banned_count(&self) -> usize {
        self.mirror.lock().expect("mirror poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// A runner that records every script instead of touching the kernel. With
    /// `fail_from = Some(n)` it fails from the n-th call onward (0-based), so a
    /// test can let setup succeed and a later ban fail.
    #[derive(Default)]
    struct RecordingRunner {
        scripts: Mutex<Vec<String>>,
        calls: std::sync::atomic::AtomicUsize,
        fail_from: Option<usize>,
    }

    impl NftRunner for RecordingRunner {
        fn run(&self, script: &str) -> Result<(), EnforceError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_from.is_some_and(|f| n >= f) {
                return Err(EnforceError::Rejected {
                    code: Some(1),
                    stderr: "forced".into(),
                });
            }
            self.scripts.lock().unwrap().push(script.to_string());
            Ok(())
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn null_enforcer_tracks_bans() {
        let e = NullEnforcer::new();
        e.ban(v4(203, 0, 113, 0), 24, None).unwrap();
        e.ban(v4(198, 51, 100, 7), 32, Some(Duration::from_secs(30)))
            .unwrap();
        assert_eq!(e.banned_count(), 2);
        e.unban(v4(203, 0, 113, 0), 24).unwrap();
        assert_eq!(e.banned_count(), 1);
        assert_eq!(e.snapshot(), vec![(v4(198, 51, 100, 7), 32)]);
    }

    #[test]
    fn null_enforcer_ban_is_idempotent() {
        let e = NullEnforcer::new();
        e.ban(v4(1, 2, 3, 4), 32, None).unwrap();
        e.ban(v4(1, 2, 3, 4), 32, None).unwrap();
        assert_eq!(e.banned_count(), 1);
    }

    #[test]
    fn nft_enforcer_runs_setup_then_ban() {
        let e = NftEnforcer::with_runner("deflect", RecordingRunner::default()).unwrap();
        e.ban(v4(203, 0, 113, 0), 24, Some(Duration::from_secs(60)))
            .unwrap();
        e.unban(v4(203, 0, 113, 0), 24).unwrap();
        assert_eq!(e.banned_count(), 0);

        let scripts = e.runner.scripts.lock().unwrap();
        assert_eq!(scripts.len(), 3); // setup, ban, unban
        assert!(scripts[0].contains("add table inet deflect"));
        assert!(
            scripts[1].contains("add element inet deflect banned4 { 203.0.113.0/24 timeout 60s }")
        );
        assert!(scripts[2].contains("delete element inet deflect banned4"));
    }

    #[test]
    fn nft_enforcer_ban_source_uses_key_address() {
        let e = NftEnforcer::with_runner("deflect", RecordingRunner::default()).unwrap();
        let key = SourceKey::host(v4(198, 51, 100, 9));
        e.ban_source(key, 32, None).unwrap();
        let scripts = e.runner.scripts.lock().unwrap();
        assert!(scripts.last().unwrap().contains("198.51.100.9"));
    }

    #[test]
    fn setup_failure_is_propagated() {
        let runner = RecordingRunner {
            fail_from: Some(0),
            ..Default::default()
        };
        let r = NftEnforcer::with_runner("deflect", runner);
        assert!(matches!(r, Err(EnforceError::Rejected { .. })));
    }

    #[test]
    fn failed_ban_does_not_update_the_mirror() {
        // Setup (call 0) succeeds; the ban (call 1) fails. The mirror must not
        // record a ban that the kernel never accepted.
        let runner = RecordingRunner {
            fail_from: Some(1),
            ..Default::default()
        };
        let e = NftEnforcer::with_runner("deflect", runner).unwrap();
        let r = e.ban(v4(203, 0, 113, 0), 24, None);
        assert!(r.is_err());
        assert_eq!(e.banned_count(), 0);
    }

    #[test]
    fn error_messages_are_descriptive() {
        let spawn = EnforceError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "nft missing",
        ));
        assert!(spawn.to_string().contains("nft missing"));
        let rejected = EnforceError::Rejected {
            code: Some(1),
            stderr: "syntax error".into(),
        };
        let msg = rejected.to_string();
        assert!(msg.contains("rejected"), "{msg}");
        assert!(msg.contains("syntax error"), "{msg}");
    }

    #[test]
    fn table_name_is_reported() {
        let e = NftEnforcer::with_runner("deflect", RecordingRunner::default()).unwrap();
        assert_eq!(e.table(), "deflect");
    }

    #[test]
    fn nft_banned_count_tracks_live_bans() {
        let e = NftEnforcer::with_runner("deflect", RecordingRunner::default()).unwrap();
        e.ban(v4(203, 0, 113, 0), 24, None).unwrap();
        e.ban(v4(198, 51, 100, 7), 32, None).unwrap();
        assert_eq!(e.banned_count(), 2);
    }

    #[test]
    fn shell_runner_maps_exit_status_without_nft() {
        // `sh -f -` executes the piped script as a shell script: it reads stdin
        // fully (no broken-pipe race) and its exit status is the script's, so a
        // real ShellNftRunner can be exercised without nft or root.
        assert!(ShellNftRunner::new("sh").run("true\n").is_ok());
        match ShellNftRunner::new("sh").run("false\n") {
            Err(EnforceError::Rejected { code, .. }) => assert_eq!(code, Some(1)),
            other => panic!("expected Rejected, got {other:?}"),
        }
        match ShellNftRunner::new("/nonexistent/nft-binary").run("x\n") {
            Err(EnforceError::Spawn(_)) => {}
            other => panic!("expected Spawn, got {other:?}"),
        }
    }
}
