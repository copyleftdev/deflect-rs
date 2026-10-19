//! Core contract shared by every `deflect-rs` mitigation primitive.
//!
//! The model is a pipeline: an [`Observation`] flows through [`Stage`]s, each
//! returning a [`Verdict`]; the pipeline keeps the most severe verdict. Types
//! here own no I/O and no allocation on the hot path, so the same primitives
//! run in a kernel-adjacent fast path, a userspace daemon, or a deterministic
//! simulation.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

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
    pub packet: Packet<'a>,
    pub ts_nanos: u64,
}

impl<'a> Observation<'a> {
    #[must_use]
    pub fn new(packet: Packet<'a>, ts_nanos: u64) -> Observation<'a> {
        Observation { packet, ts_nanos }
    }

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
    fn evaluate(&self, obs: &Observation<'_>) -> Verdict;

    /// Returns the display name of the stage, for metrics and event logs.
    fn name(&self) -> &'static str;
}
