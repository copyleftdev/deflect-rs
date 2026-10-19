//! Rate-limiting primitives for deflect-rs.
//!
//! [`TokenBucket`] is an exact integer bucket usable in `no_std`. With `std`,
//! [`SourceGovernor`] layers a fixed-size table of buckets keyed by source so
//! per-source and per-subnet limiting runs in bounded memory.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

mod bucket;

pub use bucket::{Spend, TokenBucket};

#[cfg(feature = "std")]
mod governor;
#[cfg(feature = "std")]
pub use governor::{CostMode, GovernorConfig, SourceGovernor};
