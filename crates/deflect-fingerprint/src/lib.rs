//! Adaptive attack-fingerprint learning.
//!
//! When traffic is under attack but matches no known signature, this primitive
//! learns what the flood has in common. Flood traffic is homogeneous — a botnet
//! emits near-identical packets — while legitimate traffic is diverse, so the
//! attack is captured by whichever feature *values* dominate a sample. Each
//! feature dimension (protocol, destination port, wire length, TCP flags,
//! payload prefix) is tracked with a bounded [`TopValues`] heavy-hitter
//! summary; [`Fingerprinter::synthesize`] emits a [`Fingerprint`] from the
//! dimensions whose leading value clears a dominance threshold.
//!
//! The summaries never overstate a value's share, so a synthesized fingerprint
//! reflects traffic that really dominated the sample. Feeding only
//! *unrecognised* packets (those a [`deflect_signature`] set passed) and only
//! while a [`deflect_detect`] trigger reports an attack is the caller's job;
//! this crate counts what it is given and reports what dominates.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(not(feature = "std"))]
compile_error!("deflect-fingerprint currently requires the `std` feature");

mod counter;
mod fingerprint;

use std::sync::Mutex;

use deflect_core::{Packet, TcpFlags, L4};

pub use counter::TopValues;
pub use fingerprint::{Fingerprint, Prefix, PREFIX_LEN};

/// Default per-dimension counter capacity.
pub const DEFAULT_CAPACITY: usize = 64;

struct Counters {
    l4: TopValues<u8>,
    dst_port: TopValues<u16>,
    wire_len: TopValues<u32>,
    flags: TopValues<u8>,
    prefix: TopValues<Prefix>,
}

impl Counters {
    fn new(capacity: usize) -> Counters {
        Counters {
            l4: TopValues::new(capacity),
            dst_port: TopValues::new(capacity),
            wire_len: TopValues::new(capacity),
            flags: TopValues::new(capacity),
            prefix: TopValues::new(capacity),
        }
    }
}

/// Learns an attack [`Fingerprint`] from a stream of sampled packets.
pub struct Fingerprinter {
    capacity: usize,
    inner: Mutex<Counters>,
}

impl Fingerprinter {
    #[must_use]
    pub fn new(capacity: usize) -> Fingerprinter {
        Fingerprinter {
            capacity: capacity.max(1),
            inner: Mutex::new(Counters::new(capacity.max(1))),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Fingerprinter {
        Fingerprinter::new(DEFAULT_CAPACITY)
    }

    /// Fold one sampled packet into the feature summaries.
    ///
    /// # Panics
    /// Panics only if the internal mutex was poisoned by a prior panic.
    pub fn observe(&self, packet: &Packet<'_>) {
        let mut c = self.inner.lock().expect("counters mutex poisoned");
        c.l4.observe(packet.l4.ip_proto());
        c.dst_port.observe(packet.dst_port);
        c.wire_len.observe(packet.wire_len);
        c.flags.observe(packet.tcp_flags.bits());
        c.prefix.observe(Prefix::from_payload(packet.payload));
    }

    /// Number of packets observed so far.
    ///
    /// # Panics
    /// Panics only if the internal mutex was poisoned by a prior panic.
    #[must_use]
    pub fn sampled(&self) -> u64 {
        self.inner
            .lock()
            .expect("counters mutex poisoned")
            .l4
            .total()
    }

    /// Discard all learned state.
    ///
    /// # Panics
    /// Panics only if the internal mutex was poisoned by a prior panic.
    pub fn reset(&self) {
        let mut c = self.inner.lock().expect("counters mutex poisoned");
        c.l4.clear();
        c.dst_port.clear();
        c.wire_len.clear();
        c.flags.clear();
        c.prefix.clear();
    }

    /// Synthesize a fingerprint from the dimensions whose leading value covers
    /// at least `dominance_pct` of the sample.
    ///
    /// Returns `None` unless at least one *specific* dimension — destination
    /// port, wire length, or a non-empty payload prefix — dominates, so the
    /// result can never be a fingerprint as broad as "all UDP". Protocol and
    /// flags are added only as refining constraints when they too dominate.
    ///
    /// # Panics
    /// Panics only if the internal mutex was poisoned by a prior panic.
    #[must_use]
    pub fn synthesize(&self, dominance_pct: u8) -> Option<Fingerprint> {
        let c = self.inner.lock().expect("counters mutex poisoned");
        if c.l4.total() == 0 {
            return None;
        }

        let mut shares: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut take = |share: u8| -> bool {
            if share >= dominance_pct {
                shares.push(share);
                true
            } else {
                false
            }
        };

        let dst_port = c
            .dst_port
            .leader()
            .filter(|_| take(c.dst_port.leader_share_pct()))
            .map(|(v, _)| v);
        let wire_len = c
            .wire_len
            .leader()
            .filter(|_| take(c.wire_len.leader_share_pct()))
            .map(|(v, _)| v);
        let prefix = c
            .prefix
            .leader()
            .filter(|(p, _)| p.len > 0)
            .filter(|_| take(c.prefix.leader_share_pct()))
            .map(|(p, _)| p);

        // Require at least one specific dimension, or the fingerprint is useless.
        if dst_port.is_none() && wire_len.is_none() && prefix.is_none() {
            return None;
        }

        let l4 =
            c.l4.leader()
                .filter(|_| take(c.l4.leader_share_pct()))
                .map(|(v, _)| L4::from_ip_proto(v));
        let flags = c
            .flags
            .leader()
            .filter(|(bits, _)| *bits != 0)
            .filter(|_| take(c.flags.leader_share_pct()))
            .map(|(bits, _)| TcpFlags(bits));

        let coverage_pct = shares.into_iter().min().unwrap_or(0);
        Some(Fingerprint {
            l4,
            dst_port,
            wire_len,
            flags,
            prefix,
            coverage_pct,
        })
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr};
    use deflect_core::DropReason;
    use deflect_core::{Stage, Verdict};

    fn udp_flood_packet(payload: &[u8]) -> Packet<'_> {
        let src = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        Packet::new(src, dst, L4::Udp)
            .with_ports(12345, 80)
            .with_wire_len(1400)
            .with_payload(payload)
    }

    #[test]
    fn learns_homogeneous_udp_flood() {
        let fp = Fingerprinter::with_defaults();
        let attack_payload = b"\xde\xad\xbe\xef\x00\x01gg";
        // 95 near-identical flood packets.
        for _ in 0..95 {
            fp.observe(&udp_flood_packet(attack_payload));
        }
        // 5 diverse legitimate packets.
        for i in 0..5u8 {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
            let payload = [i];
            let p = Packet::new(src, dst, L4::Tcp)
                .with_ports(40000 + u16::from(i), 443)
                .with_wire_len(60 + u32::from(i))
                .with_payload(&payload);
            fp.observe(&p);
        }
        assert_eq!(fp.sampled(), 100);

        let f = fp.synthesize(80).expect("should synthesize");
        assert_eq!(f.l4, Some(L4::Udp));
        assert_eq!(f.dst_port, Some(80));
        assert_eq!(f.wire_len, Some(1400));
        assert_eq!(f.prefix.unwrap().as_slice(), attack_payload);
        assert!(f.coverage_pct >= 80);
    }

    #[test]
    fn synthesized_fingerprint_matches_the_flood_not_the_legit() {
        let fp = Fingerprinter::with_defaults();
        let payload = b"\xde\xad\xbe\xef";
        for _ in 0..90 {
            fp.observe(&udp_flood_packet(payload));
        }
        let f = fp.synthesize(80).unwrap();

        let flood = udp_flood_packet(payload);
        assert!(f.matches(&flood));
        assert_eq!(
            Stage::evaluate(&f, &deflect_core::Observation::new(flood, 0)),
            Verdict::Drop(DropReason::Fingerprint)
        );

        // Legit TCP:443 traffic of a different shape must not match.
        let legit = Packet::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            L4::Tcp,
        )
        .with_ports(50000, 443)
        .with_wire_len(500)
        .with_payload(b"GET / HTTP/1.1");
        assert!(!f.matches(&legit));
    }

    #[test]
    fn diffuse_traffic_yields_no_fingerprint() {
        let fp = Fingerprinter::with_defaults();
        for i in 0..200u32 {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
            let bytes = i.to_be_bytes();
            let p = Packet::new(src, dst, L4::Udp)
                .with_ports(10000, u16::try_from(i % 1000).unwrap())
                .with_wire_len(100 + i)
                .with_payload(&bytes);
            fp.observe(&p);
        }
        assert!(fp.synthesize(80).is_none());
    }

    #[test]
    fn empty_sampler_synthesizes_nothing() {
        let fp = Fingerprinter::with_defaults();
        assert!(fp.synthesize(80).is_none());
    }

    #[test]
    fn reset_clears_learning() {
        let fp = Fingerprinter::with_defaults();
        for _ in 0..90 {
            fp.observe(&udp_flood_packet(b"abc"));
        }
        fp.reset();
        assert_eq!(fp.sampled(), 0);
        assert!(fp.synthesize(80).is_none());
    }

    #[test]
    fn capacity_reports_configured_value() {
        assert_eq!(Fingerprinter::new(32).capacity(), 32);
        assert_eq!(Fingerprinter::with_defaults().capacity(), DEFAULT_CAPACITY);
    }

    #[test]
    fn a_single_dominant_specific_dimension_is_enough() {
        // Only dst_port is constant; wire length and payload are all different,
        // so only one specific dimension dominates. That must still synthesize
        // (the specific-dimension guard is an AND of "all none", not an OR).
        let fp = Fingerprinter::with_defaults();
        for i in 0..100u32 {
            let payload = i.to_be_bytes();
            let p = Packet::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                L4::Udp,
            )
            .with_ports(10000, 80) // dst_port constant
            .with_wire_len(100 + i) // all different
            .with_payload(&payload); // all different
            fp.observe(&p);
        }
        let f = fp.synthesize(80).expect("dst_port alone dominates");
        assert_eq!(f.dst_port, Some(80));
        assert_eq!(f.wire_len, None);
        assert_eq!(f.prefix, None);
    }

    #[test]
    fn empty_payload_is_not_captured_as_a_prefix() {
        // A flood with empty payloads dominates on an all-zero-length prefix, but
        // an empty prefix must never be captured (the `len > 0` guard).
        let fp = Fingerprinter::with_defaults();
        let src = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        for _ in 0..90 {
            let p = Packet::new(src, dst, L4::Udp)
                .with_ports(12345, 80)
                .with_wire_len(1400);
            fp.observe(&p);
        }
        let f = fp.synthesize(80).expect("dst_port/wire_len dominate");
        assert_eq!(f.dst_port, Some(80));
        assert_eq!(f.wire_len, Some(1400));
        assert_eq!(f.prefix, None, "empty payload must not become a prefix");
    }

    #[test]
    fn dominant_nonzero_flags_are_captured() {
        // A TCP SYN flood: non-zero flags dominate and must be captured as a
        // refining constraint (the `bits != 0` guard keeps real flags).
        let fp = Fingerprinter::with_defaults();
        let src = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        for _ in 0..90 {
            let p = Packet::new(src, dst, L4::Tcp)
                .with_ports(12345, 80)
                .with_wire_len(40)
                .with_flags(TcpFlags::SYN);
            fp.observe(&p);
        }
        let f = fp.synthesize(80).expect("flood dominates");
        assert_eq!(f.flags, Some(TcpFlags::SYN));
    }

    #[test]
    fn requires_a_specific_dimension() {
        // Protocol dominates (all UDP) but ports/lengths/payloads are diffuse:
        // no fingerprint, because "all UDP" is too broad to act on.
        let fp = Fingerprinter::with_defaults();
        for i in 0..200u32 {
            let payload = i.to_be_bytes();
            let p = Packet::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                L4::Udp,
            )
            .with_ports(10000, u16::try_from(i % 2000).unwrap())
            .with_wire_len(64 + i)
            .with_payload(&payload);
            fp.observe(&p);
        }
        assert!(fp.synthesize(80).is_none());
    }
}
