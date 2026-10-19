//! Rate-limiting primitives for deflect-rs.
//!
//! [`TokenBucket`] is an exact integer bucket usable in `no_std`. With `std`,
//! [`SourceGovernor`] layers a fixed-size table of buckets keyed by source so
//! per-source and per-subnet limiting runs in bounded memory.
//!
//! ```
//! use deflect_ratelimit::{Spend, TokenBucket};
//!
//! // Refill 1 token/sec, burst of 2, starting full at t=0.
//! let mut bucket = TokenBucket::new(1, 2, 0);
//! assert!(bucket.try_spend(1, 0).is_allowed());
//! assert!(bucket.try_spend(1, 0).is_allowed());
//!
//! // Burst exhausted at the same instant: the third spend is throttled.
//! match bucket.try_spend(1, 0) {
//!     Spend::Throttled { retry_after_nanos } => assert_eq!(retry_after_nanos, 1_000_000_000),
//!     Spend::Allowed => panic!("burst should be exhausted"),
//! }
//!
//! // One second later exactly one token has refilled, so a spend is allowed again.
//! assert!(bucket.try_spend(1, 1_000_000_000).is_allowed());
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bucket;

pub use bucket::{Spend, TokenBucket};

#[cfg(feature = "std")]
mod governor;
#[cfg(feature = "std")]
pub use governor::{CostMode, GovernorConfig, SourceGovernor};
