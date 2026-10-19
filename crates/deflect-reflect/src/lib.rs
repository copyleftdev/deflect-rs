//! Reflection and amplification defense.
//!
//! In a reflection attack the adversary spoofs the victim's address and sends
//! small queries to amplifier services (DNS, NTP, memcached, …); those servers
//! send large replies to the victim. The replies look like ordinary traffic
//! from a legitimate server's source port, which is why a blind "drop UDP from
//! port 53" rule also kills real DNS.
//!
//! The distinguishing fact is solicitation: a reply is an attack only if *we
//! never sent the request*. This guard records outbound requests to amplifier
//! ports and, on an inbound reply from such a port, drops it when no recent
//! matching request exists. Both the amplifier-port set and the request table
//! are fixed-size, so an attacker cannot grow state.
//!
//! ## Deployment
//! The guard must see egress to correlate: feed outbound packets to
//! [`ReflectionGuard::note_outbound`] and inbound packets to
//! [`ReflectionGuard::classify`] (the [`Stage`] impl classifies inbound). For
//! an inbound-only vantage point with no egress visibility, use
//! [`ReflectionGuard::size_only`], which cannot tell solicited from unsolicited
//! and instead drops amplifier-port replies at or above a size threshold.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
compile_error!("deflect-reflect currently requires the `std` feature");

mod ports;

use core::net::IpAddr;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use deflect_core::{DropReason, Observation, Packet, Stage, Verdict, L4};

pub use ports::AmplifierPorts;

/// Configuration for a [`ReflectionGuard`].
pub struct ReflectConfig {
    pub ports: AmplifierPorts,
    /// How long an outbound request keeps an inbound reply "solicited".
    pub solicit_ttl_nanos: u64,
    /// Inbound amplifier replies at or above this wire length are eligible to
    /// drop; smaller unsolicited replies pass. `0` makes every unsolicited
    /// amplifier reply eligible (correlated mode).
    pub min_reply_len: u32,
    /// Request-table size; rounded up to a power of two, minimum one.
    pub slots: usize,
}

impl Default for ReflectConfig {
    fn default() -> Self {
        ReflectConfig {
            ports: AmplifierPorts::with_defaults(),
            solicit_ttl_nanos: 10 * 1_000_000_000,
            min_reply_len: 0,
            slots: 1 << 16,
        }
    }
}

#[derive(Clone, Copy)]
struct Expect {
    fp: u64,
    ts_nanos: u64,
    req_len: u32,
}

/// Running counters, read via [`ReflectionGuard::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReflectStats {
    pub solicited_passed: u64,
    pub unsolicited_dropped: u64,
    pub bytes_dropped: u64,
    /// Largest solicited reply-to-request ratio seen, in percent (e.g. 4200 =
    /// 42x). Zero until a solicited reply with a known request size arrives.
    pub peak_amplification_pct: u64,
}

/// Stateful guard that drops unsolicited replies from amplifier ports.
pub struct ReflectionGuard {
    ports: AmplifierPorts,
    ttl: u64,
    min_reply_len: u32,
    mask: u64,
    table: Box<[Mutex<Expect>]>,
    solicited: AtomicU64,
    dropped: AtomicU64,
    bytes_dropped: AtomicU64,
    peak_amp_pct: AtomicU64,
}

impl ReflectionGuard {
    #[must_use]
    pub fn new(config: ReflectConfig) -> ReflectionGuard {
        let n = config.slots.max(1).next_power_of_two();
        let table: Vec<Mutex<Expect>> = (0..n)
            .map(|_| {
                Mutex::new(Expect {
                    fp: 0,
                    ts_nanos: 0,
                    req_len: 0,
                })
            })
            .collect();
        ReflectionGuard {
            ports: config.ports,
            ttl: config.solicit_ttl_nanos,
            min_reply_len: config.min_reply_len,
            mask: (n - 1) as u64,
            table: table.into_boxed_slice(),
            solicited: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            bytes_dropped: AtomicU64::new(0),
            peak_amp_pct: AtomicU64::new(0),
        }
    }

    /// Inbound-only guard with no egress visibility: every amplifier-port reply
    /// is treated as unsolicited, so one at or above `min_reply_len` is dropped.
    /// Set `min_reply_len` high enough to clear ordinary small replies.
    #[must_use]
    pub fn size_only(ports: AmplifierPorts, min_reply_len: u32, slots: usize) -> ReflectionGuard {
        ReflectionGuard::new(ReflectConfig {
            ports,
            solicit_ttl_nanos: 0,
            min_reply_len,
            slots,
        })
    }

    fn slot(&self, fp: u64) -> usize {
        usize::try_from(fp & self.mask).expect("masked slot fits usize")
    }

    /// Record an outbound packet. If it targets an amplifier port, a matching
    /// inbound reply within the TTL is treated as solicited.
    ///
    /// # Panics
    /// Panics only if a slot mutex was poisoned by a prior panic while held.
    pub fn note_outbound(&self, packet: &Packet<'_>, now_nanos: u64) {
        if packet.l4 != L4::Udp || !self.ports.contains(packet.dst_port) {
            return;
        }
        let fp = fingerprint(packet.dst, packet.dst_port);
        let mut e = self.table[self.slot(fp)]
            .lock()
            .expect("expect mutex poisoned");
        *e = Expect {
            fp,
            ts_nanos: now_nanos,
            req_len: packet.wire_len,
        };
    }

    /// Classify an inbound packet.
    #[must_use]
    pub fn classify(&self, packet: &Packet<'_>, now_nanos: u64) -> Verdict {
        if packet.l4 != L4::Udp || !self.ports.contains(packet.src_port) {
            return Verdict::Pass;
        }
        let fp = fingerprint(packet.src, packet.src_port);
        if self.consume_expectation(fp, packet.wire_len, now_nanos) {
            self.solicited.fetch_add(1, Ordering::Relaxed);
            return Verdict::Pass;
        }
        if packet.wire_len < self.min_reply_len {
            return Verdict::Pass;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.bytes_dropped
            .fetch_add(u64::from(packet.wire_len), Ordering::Relaxed);
        Verdict::Drop(DropReason::Reflection)
    }

    /// Returns true if a live request matched `fp`; consumes it so a single
    /// request authorises a single reply.
    fn consume_expectation(&self, fp: u64, reply_len: u32, now_nanos: u64) -> bool {
        let mut e = self.table[self.slot(fp)]
            .lock()
            .expect("expect mutex poisoned");
        if e.fp != fp || e.fp == 0 {
            return false;
        }
        let fresh = now_nanos.saturating_sub(e.ts_nanos) <= self.ttl;
        if !fresh {
            return false;
        }
        if e.req_len > 0 {
            let pct = u64::from(reply_len) * 100 / u64::from(e.req_len);
            self.peak_amp_pct.fetch_max(pct, Ordering::Relaxed);
        }
        e.fp = 0;
        true
    }

    #[must_use]
    pub fn stats(&self) -> ReflectStats {
        ReflectStats {
            solicited_passed: self.solicited.load(Ordering::Relaxed),
            unsolicited_dropped: self.dropped.load(Ordering::Relaxed),
            bytes_dropped: self.bytes_dropped.load(Ordering::Relaxed),
            peak_amplification_pct: self.peak_amp_pct.load(Ordering::Relaxed),
        }
    }
}

impl Stage for ReflectionGuard {
    fn evaluate(&self, obs: &Observation<'_>) -> Verdict {
        self.classify(&obs.packet, obs.ts_nanos)
    }

    fn name(&self) -> &'static str {
        "reflection_guard"
    }
}

fn fingerprint(addr: IpAddr, port: u16) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x1000_0000_01b3;
    let mut h = OFFSET;
    let mut mix = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    };
    match addr {
        IpAddr::V4(v4) => {
            mix(4);
            for b in v4.octets() {
                mix(b);
            }
        }
        IpAddr::V6(v6) => {
            mix(6);
            for b in v6.octets() {
                mix(b);
            }
        }
    }
    mix((port >> 8) as u8);
    mix((port & 0xff) as u8);
    // A fingerprint of 0 is reserved to mean "empty slot"; map it away.
    if h == 0 {
        1
    } else {
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    fn amp_reply<'a>(src_port: u16, len: u32) -> Packet<'a> {
        let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let me = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        Packet::new(server, me, L4::Udp)
            .with_ports(src_port, 40000)
            .with_wire_len(len)
    }

    fn my_query<'a>(dst_port: u16, len: u32) -> Packet<'a> {
        let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let me = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        Packet::new(me, server, L4::Udp)
            .with_ports(40000, dst_port)
            .with_wire_len(len)
    }

    fn guard() -> ReflectionGuard {
        ReflectionGuard::new(ReflectConfig {
            slots: 1 << 12,
            ..Default::default()
        })
    }

    #[test]
    fn unsolicited_dns_reply_is_dropped() {
        let g = guard();
        assert_eq!(
            g.classify(&amp_reply(53, 4096), 1_000),
            Verdict::Drop(DropReason::Reflection)
        );
        assert_eq!(g.stats().unsolicited_dropped, 1);
    }

    #[test]
    fn solicited_dns_reply_passes() {
        let g = guard();
        g.note_outbound(&my_query(53, 60), 1_000);
        assert_eq!(g.classify(&amp_reply(53, 4096), 1_500), Verdict::Pass);
        let s = g.stats();
        assert_eq!(s.solicited_passed, 1);
        assert_eq!(s.unsolicited_dropped, 0);
        // 4096 / 60 ~= 68x.
        assert_eq!(s.peak_amplification_pct, 4096 * 100 / 60);
    }

    #[test]
    fn one_request_authorises_one_reply() {
        let g = guard();
        g.note_outbound(&my_query(53, 60), 1_000);
        assert_eq!(g.classify(&amp_reply(53, 4096), 1_500), Verdict::Pass);
        // A second reply for the same single request is now unsolicited.
        assert_eq!(
            g.classify(&amp_reply(53, 4096), 1_600),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn expired_request_no_longer_solicits() {
        let g = guard();
        g.note_outbound(&my_query(123, 48), 0);
        // 20s later, past the 10s TTL.
        assert_eq!(
            g.classify(&amp_reply(123, 4000), 20_000_000_000),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn non_amplifier_port_passes() {
        let g = guard();
        assert_eq!(g.classify(&amp_reply(443, 4096), 1_000), Verdict::Pass);
    }

    #[test]
    fn non_udp_passes() {
        let g = guard();
        let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let me = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let tcp = Packet::new(server, me, L4::Tcp)
            .with_ports(53, 40000)
            .with_wire_len(4096);
        assert_eq!(g.classify(&tcp, 1_000), Verdict::Pass);
    }

    #[test]
    fn size_only_mode_uses_threshold() {
        let g = ReflectionGuard::size_only(AmplifierPorts::with_defaults(), 512, 1 << 12);
        // Small amplifier-port reply passes under the threshold.
        assert_eq!(g.classify(&amp_reply(53, 100), 1_000), Verdict::Pass);
        // Large one is dropped.
        assert_eq!(
            g.classify(&amp_reply(53, 4096), 1_000),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn different_server_reply_is_unsolicited() {
        let g = guard();
        g.note_outbound(&my_query(53, 60), 1_000);
        // Reply from a different server IP on port 53 we never queried.
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
        let me = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let reply = Packet::new(other, me, L4::Udp)
            .with_ports(53, 40000)
            .with_wire_len(4096);
        assert_eq!(
            g.classify(&reply, 1_500),
            Verdict::Drop(DropReason::Reflection)
        );
    }
}
