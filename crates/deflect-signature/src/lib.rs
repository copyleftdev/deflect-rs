//! Signature matching for deflect-rs.
//!
//! A [`Signature`] is an AND of conditions over a packet — protocol, source and
//! destination port, TCP flags, wire length, and payload bytes — carrying an
//! [`Action`]. A [`SignatureSet`] evaluates them in priority order and returns
//! the first match's verdict, so a low-priority `Allow` is an allowlist and a
//! no-match passes.
//!
//! Payload search uses `memchr` for SIMD-accelerated scanning, because matching
//! payload bytes on every packet during a flood is a hot path. With the
//! optional `serde` feature, signatures and sets deserialize from data, so a
//! rule file can be loaded the way the original tool loads `methods.json`.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod builtin;
mod matcher;
mod set;
mod signature;

pub use builtin::{baseline, tcp_flag_anomalies};
pub use matcher::{FlagMatch, PayloadMatch, PortMatch};
pub use set::SignatureSet;
pub use signature::{Action, Signature};
