#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! # deflect-kit
//!
//! Composable, **defensive** DDoS-mitigation primitives. This crate is a thin
//! umbrella over the `deflect-*` family: it adds no logic of its own, it just
//! re-exports each primitive behind a feature flag so a consumer takes one
//! dependency and compiles only what they ask for.
//!
//! ```toml
//! # Only the rate limiter and the attack detector, nothing else builds:
//! deflect-kit = { version = "0.1", features = ["ratelimit", "detect"] }
//! ```
//!
//! Every primitive speaks the same contract from [`deflect_core`]: a parsed
//! [`Observation`](crate::prelude::Observation) flows through
//! [`Stage`](crate::prelude::Stage)s, each returns a
//! [`Verdict`](crate::prelude::Verdict), and the pipeline keeps the most severe:
//!
//! ```text
//! Pass  <  Challenge  <  RateLimit  <  Drop
//! ```
//!
//! The contract itself is always available; the composable stages
//! ([`SourceGovernor`](deflect_ratelimit::SourceGovernor),
//! [`SignatureSet`](deflect_signature::SignatureSet),
//! [`ReflectionGuard`](deflect_reflect::ReflectionGuard),
//! [`Fingerprint`](deflect_fingerprint::Fingerprint)) each live behind their
//! crate's feature. Folding a sequence of verdicts to the worst one is the whole
//! pipeline:
//!
//! ```
//! use deflect_kit::prelude::*;
//!
//! let verdicts = [
//!     Verdict::Pass,
//!     Verdict::Challenge(ChallengeKind::SynCookie),
//!     Verdict::Drop(DropReason::Signature),
//! ];
//! let outcome = verdicts.into_iter().fold(Verdict::Pass, Verdict::worst);
//! assert!(matches!(outcome, Verdict::Drop(DropReason::Signature)));
//! ```
//!
//! See the `pipeline` example (built with `--features full`) for a real
//! multi-stage composition driving one observation through several primitives.

#[doc(inline)]
pub use deflect_core as contract;

#[cfg(feature = "bgp")]
#[doc(inline)]
pub use deflect_bgp as bgp;
#[cfg(feature = "detect")]
#[doc(inline)]
pub use deflect_detect as detect;
#[cfg(feature = "enforce")]
#[doc(inline)]
pub use deflect_enforce as enforce;
#[cfg(feature = "fingerprint")]
#[doc(inline)]
pub use deflect_fingerprint as fingerprint;
#[cfg(feature = "packet")]
#[doc(inline)]
pub use deflect_packet as packet;
#[cfg(feature = "ratelimit")]
#[doc(inline)]
pub use deflect_ratelimit as ratelimit;
#[cfg(feature = "reflect")]
#[doc(inline)]
pub use deflect_reflect as reflect;
#[cfg(feature = "signature")]
#[doc(inline)]
pub use deflect_signature as signature;
#[cfg(feature = "syncookie")]
#[doc(inline)]
pub use deflect_syncookie as syncookie;
#[cfg(feature = "telemetry")]
#[doc(inline)]
pub use deflect_telemetry as telemetry;

/// The common primitives, re-exported for `use deflect_kit::prelude::*;`.
///
/// The [`deflect_core`] contract is always present. Each primitive's types
/// appear only when its feature is enabled, so the prelude never pulls in a
/// crate the consumer did not ask for.
pub mod prelude {
    pub use deflect_core::{
        Aggregation, ChallengeKind, Clock, DropReason, Observation, Packet, SourceKey, Stage,
        TcpFlags, Verdict, L4,
    };

    #[cfg(feature = "bgp")]
    pub use deflect_bgp::{Blackhole, Cidr, RtbhController, Scope};
    #[cfg(feature = "detect")]
    pub use deflect_detect::{Phase, SlidingWindow, Trigger, Watermarks};
    #[cfg(feature = "enforce")]
    pub use deflect_enforce::{EnforceError, Enforcer, NullEnforcer};
    #[cfg(feature = "fingerprint")]
    pub use deflect_fingerprint::{Fingerprint, Fingerprinter};
    #[cfg(feature = "packet")]
    pub use deflect_packet::{parse_sampled_header, FiveTuple};
    #[cfg(feature = "ratelimit")]
    pub use deflect_ratelimit::{CostMode, GovernorConfig, SourceGovernor, Spend, TokenBucket};
    #[cfg(feature = "reflect")]
    pub use deflect_reflect::{ReflectConfig, ReflectStats, ReflectionGuard};
    #[cfg(feature = "signature")]
    pub use deflect_signature::{baseline, Action, Signature, SignatureSet};
    #[cfg(feature = "syncookie")]
    pub use deflect_syncookie::{CookieError, CookieKey, FourTuple, Recovered, SynCookie};
    #[cfg(feature = "telemetry")]
    pub use deflect_telemetry::{Decoder, FlowRecord};
}
