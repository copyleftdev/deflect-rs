//! Upstream remote-triggered blackhole (RTBH) announcement.
//!
//! When an attack is too large to absorb at the edge, the last resort is to ask
//! an upstream to discard the traffic in *their* network, before it reaches the
//! link at all. The operator advertises a blackhole route over BGP; the upstream
//! matches a well-known community (RFC 7999 `65535:666`) or a pre-routed discard
//! next hop and drops the traffic.
//!
//! This crate drives that over the [ExaBGP](https://github.com/Exa-Networks/exabgp)
//! text API, split the same way as [`deflect_enforce`](https://docs.rs/deflect-enforce):
//!
//! - [`exabgp`] builds the `announce`/`withdraw` command lines as pure strings.
//! - A [`BgpSession`] transmits them; [`WriterSession`] writes to ExaBGP's
//!   control input, and tests inject a recording session.
//! - [`RtbhController`] is the stateful front door: it authorizes every route
//!   through a [`Scope`], caps the number of live announcements, tracks them with
//!   deadlines, and [`sweep`](RtbhController::sweep)s expired blackholes away.
//!
//! **Blackholing is dangerous on purpose**, so the safety lives in the type that
//! issues it, not in the operator's discipline. A destination blackhole must
//! fall within owned address space (otherwise it is a hijack); nothing broader
//! than a floor or the default route is ever announced; every blackhole carries
//! `NO_EXPORT` so it cannot leak into the global table; and every blackhole has
//! a deadline so a forgotten one lifts itself.
#![forbid(unsafe_code)]
// Protocol and product names (ExaBGP, RTBH, NO_EXPORT) read better as prose than
// as code spans throughout the docs.
#![allow(clippy::doc_markdown)]

extern crate alloc;

pub mod cidr;
pub mod community;
pub mod exabgp;
pub mod route;
pub mod scope;

pub use cidr::Cidr;
pub use community::Community;
pub use route::{Blackhole, RtbhKind};
pub use scope::{Scope, ScopeError};

use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;

use deflect_core::Clock;

/// A failure announcing or withdrawing a blackhole.
#[derive(Debug)]
pub enum BgpError {
    /// The route was refused by the [`Scope`] and never transmitted.
    Scope(ScopeError),
    /// The live-announcement table is full; raising it risks tripping the
    /// upstream's max-prefix limit and tearing down the session.
    CapacityExceeded { max: usize },
    /// The session could not transmit the command.
    Transport(std::io::Error),
}

impl core::fmt::Display for BgpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BgpError::Scope(e) => write!(f, "{e}"),
            BgpError::CapacityExceeded { max } => {
                write!(f, "blackhole table full ({max} routes)")
            }
            BgpError::Transport(e) => write!(f, "failed to transmit BGP command: {e}"),
        }
    }
}

impl std::error::Error for BgpError {}

impl From<ScopeError> for BgpError {
    fn from(e: ScopeError) -> BgpError {
        BgpError::Scope(e)
    }
}

/// Transmits an ExaBGP command line to the BGP speaker.
pub trait BgpSession {
    /// Send one command (already newline-terminated).
    ///
    /// # Errors
    /// Returns [`BgpError::Transport`] if the command could not be written.
    fn send(&self, command: &str) -> Result<(), BgpError>;
}

/// A session that discards commands: dry-run / watch mode.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSession;

impl BgpSession for NullSession {
    fn send(&self, _command: &str) -> Result<(), BgpError> {
        Ok(())
    }
}

/// A session that writes each command to a sink — in production, the pipe
/// ExaBGP reads its control commands from (often the process's own stdout).
pub struct WriterSession<W: std::io::Write> {
    out: Mutex<W>,
}

impl<W: std::io::Write> WriterSession<W> {
    pub fn new(out: W) -> WriterSession<W> {
        WriterSession {
            out: Mutex::new(out),
        }
    }
}

impl WriterSession<std::io::Stdout> {
    /// Write commands to standard output, the usual ExaBGP control channel when
    /// this runs as an ExaBGP process.
    #[must_use]
    pub fn stdout() -> WriterSession<std::io::Stdout> {
        WriterSession::new(std::io::stdout())
    }
}

impl<W: std::io::Write> BgpSession for WriterSession<W> {
    fn send(&self, command: &str) -> Result<(), BgpError> {
        let mut out = self.out.lock().expect("session writer poisoned");
        out.write_all(command.as_bytes())
            .map_err(BgpError::Transport)?;
        out.flush().map_err(BgpError::Transport)
    }
}

struct Tracked {
    route: Blackhole,
    deadline: Option<u64>,
}

/// The stateful front door for RTBH: authorize, announce, track, and expire
/// blackhole routes over a [`BgpSession`].
pub struct RtbhController<S: BgpSession, C: Clock> {
    scope: Scope,
    session: S,
    clock: C,
    max_routes: usize,
    active: Mutex<HashMap<Cidr, Tracked>>,
}

impl<S: BgpSession, C: Clock> RtbhController<S, C> {
    #[must_use]
    pub fn new(scope: Scope, session: S, clock: C, max_routes: usize) -> RtbhController<S, C> {
        RtbhController {
            scope,
            session,
            clock,
            max_routes,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Announce a blackhole, expiring it after `ttl` if given.
    ///
    /// The route is authorized against the [`Scope`] first and the command is
    /// only transmitted — and tracked — once it passes and there is room.
    ///
    /// # Errors
    /// Returns [`BgpError::Scope`] if the route is refused, [`BgpError::CapacityExceeded`]
    /// if the table is full for a new prefix, or [`BgpError::Transport`] if the
    /// session could not send. A transport failure leaves the route untracked.
    ///
    /// # Panics
    /// Panics only if the internal table mutex was poisoned by a prior panic.
    pub fn announce(&self, route: Blackhole, ttl: Option<Duration>) -> Result<(), BgpError> {
        self.scope.authorize(route.kind, route.prefix)?;

        {
            let active = self.active.lock().expect("table poisoned");
            if !active.contains_key(&route.prefix) && active.len() >= self.max_routes {
                return Err(BgpError::CapacityExceeded {
                    max: self.max_routes,
                });
            }
        }

        self.session.send(&exabgp::announce_command(&route))?;

        let deadline = ttl.map(|d| {
            let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
            self.clock.now_nanos().saturating_add(nanos)
        });
        self.active
            .lock()
            .expect("table poisoned")
            .insert(route.prefix, Tracked { route, deadline });
        Ok(())
    }

    /// Announce a destination blackhole for `prefix` (must be owned).
    ///
    /// # Errors
    /// See [`announce`](Self::announce).
    pub fn blackhole_destination(
        &self,
        prefix: Cidr,
        ttl: Option<Duration>,
    ) -> Result<(), BgpError> {
        self.announce(Blackhole::destination(prefix), ttl)
    }

    /// Announce a source blackhole for `prefix` (attacker space).
    ///
    /// # Errors
    /// See [`announce`](Self::announce).
    pub fn blackhole_source(&self, prefix: Cidr, ttl: Option<Duration>) -> Result<(), BgpError> {
        self.announce(Blackhole::source(prefix), ttl)
    }

    /// Withdraw a tracked blackhole. Withdrawing an untracked prefix is a no-op.
    ///
    /// # Errors
    /// Returns [`BgpError::Transport`] if the withdrawal could not be sent; the
    /// route stays tracked in that case.
    ///
    /// # Panics
    /// Panics only if the internal table mutex was poisoned by a prior panic.
    pub fn withdraw(&self, prefix: Cidr) -> Result<(), BgpError> {
        let route = {
            let active = self.active.lock().expect("table poisoned");
            active.get(&prefix).map(|t| t.route.clone())
        };
        let Some(route) = route else { return Ok(()) };
        self.session.send(&exabgp::withdraw_command(&route))?;
        self.active.lock().expect("table poisoned").remove(&prefix);
        Ok(())
    }

    /// Withdraw every blackhole whose deadline has passed, returning how many
    /// were lifted. Stops at the first transport error, having withdrawn the
    /// routes up to it.
    ///
    /// # Errors
    /// Returns [`BgpError::Transport`] if withdrawing an expired route failed.
    ///
    /// # Panics
    /// Panics only if the internal table mutex was poisoned by a prior panic.
    pub fn sweep(&self) -> Result<usize, BgpError> {
        let now = self.clock.now_nanos();
        let expired: alloc::vec::Vec<Cidr> = {
            let active = self.active.lock().expect("table poisoned");
            active
                .iter()
                .filter(|(_, t)| t.deadline.is_some_and(|d| d <= now))
                .map(|(p, _)| *p)
                .collect()
        };
        let mut n = 0;
        for prefix in expired {
            self.withdraw(prefix)?;
            n += 1;
        }
        Ok(n)
    }

    /// Number of blackholes currently announced.
    ///
    /// # Panics
    /// Panics only if the internal table mutex was poisoned by a prior panic.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.lock().expect("table poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::net::IpAddr;
    use deflect_core::ManualClock;

    #[derive(Default)]
    struct RecordingSession {
        cmds: Mutex<alloc::vec::Vec<String>>,
        fail: bool,
    }

    impl BgpSession for RecordingSession {
        fn send(&self, command: &str) -> Result<(), BgpError> {
            if self.fail {
                return Err(BgpError::Transport(std::io::Error::other("forced")));
            }
            self.cmds.lock().unwrap().push(command.to_string());
            Ok(())
        }
    }

    use alloc::string::{String, ToString};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn scope() -> Scope {
        Scope::new(vec![Cidr::new(v4("203.0.113.0"), 24)])
    }

    fn controller(
        session: RecordingSession,
        clock: ManualClock,
    ) -> RtbhController<RecordingSession, ManualClock> {
        RtbhController::new(scope(), session, clock, 4)
    }

    #[test]
    fn owned_destination_announces_and_withdraws() {
        let c = controller(RecordingSession::default(), ManualClock::new(0));
        let p = Cidr::host(v4("203.0.113.9"));
        c.blackhole_destination(p, None).unwrap();
        assert_eq!(c.active_count(), 1);
        c.withdraw(p).unwrap();
        assert_eq!(c.active_count(), 0);

        let cmds = c.session.cmds.lock().unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0],
            "announce route 203.0.113.9/32 next-hop self community [65535:666 65535:65281]\n"
        );
        assert_eq!(cmds[1], "withdraw route 203.0.113.9/32 next-hop self\n");
    }

    #[test]
    fn unowned_destination_is_refused_and_sends_nothing() {
        let c = controller(RecordingSession::default(), ManualClock::new(0));
        let r = c.blackhole_destination(Cidr::host(v4("198.51.100.9")), None);
        assert!(matches!(r, Err(BgpError::Scope(ScopeError::Unowned(_)))));
        assert_eq!(c.active_count(), 0);
        assert!(c.session.cmds.lock().unwrap().is_empty());
    }

    #[test]
    fn capacity_is_bounded() {
        let scope = Scope::new(vec![Cidr::new(v4("203.0.113.0"), 24)]).with_floor(24, 48);
        let c = RtbhController::new(scope, RecordingSession::default(), ManualClock::new(0), 2);
        c.blackhole_destination(Cidr::host(v4("203.0.113.1")), None)
            .unwrap();
        c.blackhole_destination(Cidr::host(v4("203.0.113.2")), None)
            .unwrap();
        let r = c.blackhole_destination(Cidr::host(v4("203.0.113.3")), None);
        assert!(matches!(r, Err(BgpError::CapacityExceeded { max: 2 })));
        // Re-announcing an already-tracked prefix is a refresh, not a new slot.
        assert!(c
            .blackhole_destination(Cidr::host(v4("203.0.113.1")), None)
            .is_ok());
    }

    #[test]
    fn transport_failure_leaves_route_untracked() {
        let session = RecordingSession {
            fail: true,
            ..Default::default()
        };
        let c = controller(session, ManualClock::new(0));
        let r = c.blackhole_destination(Cidr::host(v4("203.0.113.9")), None);
        assert!(matches!(r, Err(BgpError::Transport(_))));
        assert_eq!(c.active_count(), 0);
    }

    #[test]
    fn sweep_lifts_only_expired_blackholes() {
        let clock = ManualClock::new(0);
        let c = controller(RecordingSession::default(), clock);
        c.blackhole_destination(Cidr::host(v4("203.0.113.9")), Some(Duration::from_secs(60)))
            .unwrap();
        c.blackhole_destination(Cidr::host(v4("203.0.113.10")), None)
            .unwrap();

        c.clock.advance_secs(59);
        assert_eq!(c.sweep().unwrap(), 0);
        assert_eq!(c.active_count(), 2);

        c.clock.advance_secs(2);
        assert_eq!(c.sweep().unwrap(), 1);
        assert_eq!(c.active_count(), 1); // the no-TTL blackhole stays

        let cmds = c.session.cmds.lock().unwrap();
        assert!(cmds
            .iter()
            .any(|s| s == "withdraw route 203.0.113.9/32 next-hop self\n"));
    }

    #[test]
    fn source_blackhole_needs_no_ownership() {
        let c = controller(RecordingSession::default(), ManualClock::new(0));
        c.blackhole_source(Cidr::host(v4("198.51.100.9")), None)
            .unwrap();
        assert_eq!(c.active_count(), 1);
    }

    #[test]
    fn error_messages_are_descriptive() {
        let scope = BgpError::Scope(ScopeError::DefaultRoute);
        assert!(scope.to_string().contains("default route"));
        let cap = BgpError::CapacityExceeded { max: 2 };
        assert!(cap.to_string().contains('2'));
        assert!(cap.to_string().contains("full"));
        let io = BgpError::Transport(std::io::Error::other("pipe closed"));
        assert!(io.to_string().contains("pipe closed"));
    }

    #[test]
    fn null_session_is_a_dry_run() {
        let c = RtbhController::new(scope(), NullSession, ManualClock::new(0), 4);
        c.blackhole_destination(Cidr::host(v4("203.0.113.9")), None)
            .unwrap();
        assert_eq!(c.active_count(), 1);
    }

    #[test]
    fn writer_session_emits_the_command() {
        let session = WriterSession::new(alloc::vec::Vec::<u8>::new());
        session
            .send("announce route 203.0.113.9/32 next-hop self\n")
            .unwrap();
        let out = session.out.lock().unwrap();
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "announce route 203.0.113.9/32 next-hop self\n"
        );
    }
}
