//! Property tests for the reflection guard: solicitation is what distinguishes a
//! reply, so a request always authorises its reply, an unrequested amplifier
//! reply is always dropped, and non-amplifier traffic always passes — and
//! classification never panics on arbitrary input.

use core::net::{IpAddr, Ipv4Addr};

use deflect_core::{DropReason, Packet, Verdict, L4};
use deflect_reflect::{AmplifierPorts, ReflectConfig, ReflectionGuard};
use proptest::prelude::*;

const AMP_PORTS: &[u16] = &[53, 123, 1900, 11211, 389, 161];

fn me() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
}

fn guard() -> ReflectionGuard {
    ReflectionGuard::new(ReflectConfig {
        slots: 1 << 12,
        ..Default::default()
    })
}

proptest! {
    #[test]
    fn a_request_authorises_its_reply(
        srv in any::<[u8; 4]>(), pi in 0usize..AMP_PORTS.len(),
        qlen in 1u32..1_500, rlen in 1u32..65_000,
    ) {
        let port = AMP_PORTS[pi];
        let server = IpAddr::V4(Ipv4Addr::from(srv));
        let g = guard();
        let query = Packet::new(me(), server, L4::Udp).with_ports(40000, port).with_wire_len(qlen);
        let reply = Packet::new(server, me(), L4::Udp).with_ports(port, 40000).with_wire_len(rlen);
        g.note_outbound(&query, 1_000);
        prop_assert_eq!(g.classify(&reply, 1_500), Verdict::Pass);
    }

    #[test]
    fn an_unrequested_amplifier_reply_is_always_dropped(
        srv in any::<[u8; 4]>(), pi in 0usize..AMP_PORTS.len(), rlen in 1u32..65_000,
    ) {
        let port = AMP_PORTS[pi];
        let server = IpAddr::V4(Ipv4Addr::from(srv));
        let g = guard(); // correlated mode, min_reply_len 0
        let reply = Packet::new(server, me(), L4::Udp).with_ports(port, 40000).with_wire_len(rlen);
        prop_assert_eq!(g.classify(&reply, 1_000), Verdict::Drop(DropReason::Reflection));
    }

    #[test]
    fn non_amplifier_replies_always_pass(
        srv in any::<[u8; 4]>(), port in any::<u16>(), rlen in 1u32..65_000,
    ) {
        prop_assume!(!AmplifierPorts::with_defaults().contains(port));
        let server = IpAddr::V4(Ipv4Addr::from(srv));
        let g = guard();
        let reply = Packet::new(server, me(), L4::Udp).with_ports(port, 40000).with_wire_len(rlen);
        prop_assert_eq!(g.classify(&reply, 1_000), Verdict::Pass);
    }

    #[test]
    fn classification_never_panics(
        sa in any::<[u8; 4]>(), sp in any::<u16>(), dp in any::<u16>(),
        len in any::<u32>(), now in any::<u64>(), udp in any::<bool>(),
    ) {
        let server = IpAddr::V4(Ipv4Addr::from(sa));
        let l4 = if udp { L4::Udp } else { L4::Tcp };
        let g = guard();
        let p = Packet::new(server, me(), l4).with_ports(sp, dp).with_wire_len(len);
        g.note_outbound(&p, now);
        let _ = g.classify(&p, now);
    }
}
