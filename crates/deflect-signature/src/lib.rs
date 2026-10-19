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
//!
//! ```
//! use deflect_signature::{Action, PortMatch, Signature, SignatureSet};
//! use deflect_core::{DropReason, Packet, Verdict, L4};
//! # use std::net::{IpAddr, Ipv4Addr};
//!
//! // Drop UDP packets whose source port is 53: DNS responses used for reflection.
//! let dns_reflection = Signature::new(1, "udp-dns-reflection")
//!     .proto(L4::Udp)
//!     .src_port(PortMatch::Exact(53))
//!     .action(Action::Drop(DropReason::Reflection));
//!
//! let set = SignatureSet::new(vec![dns_reflection]);
//!
//! # let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
//! let spoofed = Packet::new(ip, ip, L4::Udp).with_ports(53, 40000);
//! assert_eq!(set.classify(&spoofed), Verdict::Drop(DropReason::Reflection));
//!
//! // A packet matching no signature passes.
//! # let ip2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
//! let benign = Packet::new(ip2, ip2, L4::Udp).with_ports(40000, 443);
//! assert_eq!(set.classify(&benign), Verdict::Pass);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod builtin;
mod matcher;
mod set;
mod signature;

pub use builtin::{baseline, tcp_flag_anomalies};
pub use matcher::{FlagMatch, PayloadMatch, PortMatch};
pub use set::SignatureSet;
pub use signature::{Action, Signature};
