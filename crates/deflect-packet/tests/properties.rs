//! Property tests for the packet-header parser. Sampled headers are
//! attacker-controlled and routinely truncated, so the dominant guarantee is
//! that parsing *any* byte string under *any* link type returns rather than
//! panicking. Well-formed IPv4/IPv6 TCP and UDP packets also round-trip their
//! 5-tuple exactly.
#![allow(clippy::cast_possible_truncation)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use deflect_core::TcpFlags;
use deflect_packet::{link_type, parse_ethernet, parse_ipv4, parse_ipv6, parse_sampled_header};
use proptest::prelude::*;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn tcp_segment(src: u16, dst: u16, flags: u8) -> Vec<u8> {
    let mut s = vec![0u8; 14];
    s[0..2].copy_from_slice(&src.to_be_bytes());
    s[2..4].copy_from_slice(&dst.to_be_bytes());
    s[13] = flags;
    s
}

fn udp_datagram(src: u16, dst: u16) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend(src.to_be_bytes());
    u.extend(dst.to_be_bytes());
    u.extend([0u8; 4]); // length + checksum
    u
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0x45);
    p.push(0);
    p.extend((20u16 + l4.len() as u16).to_be_bytes());
    p.extend(0u16.to_be_bytes());
    p.extend(0u16.to_be_bytes()); // offset 0 -> leading fragment
    p.push(64);
    p.push(protocol);
    p.extend(0u16.to_be_bytes());
    p.extend(src.octets());
    p.extend(dst.octets());
    p.extend_from_slice(l4);
    p
}

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(0x6000_0000u32.to_be_bytes());
    p.extend((l4.len() as u16).to_be_bytes());
    p.push(protocol);
    p.push(64);
    p.extend(src.octets());
    p.extend(dst.octets());
    p.extend_from_slice(l4);
    p
}

proptest! {
    #[test]
    fn parsing_arbitrary_bytes_never_panics(
        link in prop_oneof![Just(link_type::ETHERNET), Just(link_type::IPV4), Just(link_type::IPV6), any::<u32>()],
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = parse_sampled_header(link, &bytes);
        let _ = parse_ethernet(&bytes);
        let _ = parse_ipv4(&bytes);
        let _ = parse_ipv6(&bytes);
    }

    #[test]
    fn truncating_a_valid_packet_never_panics(
        a in any::<[u8; 4]>(),
        sp in any::<u16>(),
        dp in any::<u16>(),
        cut in 0usize..64,
    ) {
        let pkt = ipv4(Ipv4Addr::from(a), Ipv4Addr::from(a), PROTO_TCP, &tcp_segment(sp, dp, 0x02));
        let end = cut.min(pkt.len());
        let _ = parse_ipv4(&pkt[..end]);
    }

    #[test]
    fn ipv4_tcp_tuple_round_trips(
        s in any::<[u8; 4]>(),
        d in any::<[u8; 4]>(),
        sp in any::<u16>(),
        dp in any::<u16>(),
        flags in any::<u8>(),
    ) {
        let src = Ipv4Addr::from(s);
        let dst = Ipv4Addr::from(d);
        let pkt = ipv4(src, dst, PROTO_TCP, &tcp_segment(sp, dp, flags));
        let t = parse_ipv4(&pkt).unwrap();
        prop_assert_eq!(t.src, IpAddr::V4(src));
        prop_assert_eq!(t.dst, IpAddr::V4(dst));
        prop_assert_eq!(t.protocol, PROTO_TCP);
        prop_assert_eq!(t.src_port, sp);
        prop_assert_eq!(t.dst_port, dp);
        prop_assert_eq!(t.tcp_flags, TcpFlags(flags));
    }

    #[test]
    fn ipv6_udp_tuple_round_trips(
        s in any::<[u8; 16]>(),
        d in any::<[u8; 16]>(),
        sp in any::<u16>(),
        dp in any::<u16>(),
    ) {
        let src = Ipv6Addr::from(s);
        let dst = Ipv6Addr::from(d);
        let pkt = ipv6(src, dst, PROTO_UDP, &udp_datagram(sp, dp));
        let t = parse_ipv6(&pkt).unwrap();
        prop_assert_eq!(t.src, IpAddr::V6(src));
        prop_assert_eq!(t.dst, IpAddr::V6(dst));
        prop_assert_eq!(t.src_port, sp);
        prop_assert_eq!(t.dst_port, dp);
        prop_assert_eq!(t.tcp_flags, TcpFlags(0)); // UDP carries no control bits
    }
}
