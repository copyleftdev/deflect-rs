//! Core contract shared by every `deflect-rs` mitigation primitive.
//!
//! The model is a pipeline: an [`Observation`] flows through [`Stage`]s, each
//! returning a [`Verdict`]; the pipeline keeps the most severe verdict. Types
//! here own no I/O and no allocation on the hot path, so the same primitives
//! run in a kernel-adjacent fast path, a userspace daemon, or a deterministic
//! simulation.
//!
//! ```
//! use core::net::{IpAddr, Ipv4Addr};
//! use deflect_core::{Aggregation, DropReason, Packet, SourceKey, Verdict, L4};
//!
//! // One stage flags a bad signature, another passes; the pipeline keeps the
//! // more severe verdict.
//! let pass = Verdict::Pass;
//! let drop = Verdict::Drop(DropReason::Signature);
//! assert_eq!(pass.worst(drop), drop);
//! assert!(drop.severity() > pass.severity());
//!
//! // Two hosts in one /24 collapse to a single source key.
//! let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
//! let packet = Packet::new(src, IpAddr::V4(Ipv4Addr::LOCALHOST), L4::Tcp);
//! let key = SourceKey::new(packet.src, Aggregation::SUBNET);
//! assert_eq!(key, SourceKey::V4([203, 0, 113, 0]));
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
mod observation;
mod source;
mod verdict;

#[cfg(feature = "std")]
pub use clock::MonotonicClock;
pub use clock::{Clock, ManualClock};
pub use observation::{Packet, TcpFlags, L4};
pub use source::{Aggregation, SourceKey};
pub use verdict::{ChallengeKind, DropReason, Verdict};

/// One observation presented to the pipeline.
///
/// Carries the parsed packet and a monotonic timestamp so stages never read a
/// clock themselves; the ingest path stamps each observation once.
#[derive(Debug, Clone, Copy)]
pub struct Observation<'a> {
    /// The parsed packet this observation carries.
    pub packet: Packet<'a>,
    /// Monotonic capture time in nanoseconds; the only time source the pipeline trusts.
    pub ts_nanos: u64,
}

impl<'a> Observation<'a> {
    /// Pairs a packet with its capture timestamp.
    #[must_use]
    pub fn new(packet: Packet<'a>, ts_nanos: u64) -> Observation<'a> {
        Observation { packet, ts_nanos }
    }

    /// Returns the source key for this observation's packet under `agg`.
    #[must_use]
    pub fn source_key(&self, agg: Aggregation) -> SourceKey {
        SourceKey::new(self.packet.src, agg)
    }
}

/// A single mitigation decision over one observation.
///
/// Stages are cheap, synchronous, and side-effecting only on their own state;
/// enforcement (programming nftables, announcing a route) is a separate concern
/// driven by the verdicts a stage returns.
pub trait Stage {
    /// Evaluates one observation and returns this stage's verdict for it.
    fn evaluate(&self, obs: &Observation<'_>) -> Verdict;

    /// Returns the display name of the stage, for metrics and event logs.
    fn name(&self) -> &'static str;
}
