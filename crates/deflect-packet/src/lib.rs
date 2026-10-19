//! Bounds-checked parsing of a sampled packet header into its 5-tuple.
//!
//! sFlow and packet-capture pipelines hand a mitigation stack the first bytes of
//! a real frame rather than a pre-aggregated flow record. This crate turns those
//! bytes into a [`FiveTuple`] — source and destination address, protocol, ports,
//! and TCP flags — by walking Ethernet (with VLAN tags), IPv4, and IPv6 (with its
//! extension-header chain) down to the TCP or UDP header.
//!
//! The input is attacker-controlled and often *deliberately truncated* (a sampler
//! keeps only the first N bytes of each packet), so every read is checked: a parse
//! returns `None` where it cannot continue and never panics, and a header cut off
//! after the IP addresses still yields the addresses and protocol with ports left
//! at zero.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
// Test fixtures build packets with length casts; that pedantic lint adds nothing
// to fixture code.
#![cfg_attr(test, allow(clippy::cast_possible_truncation))]

use core::net::IpAddr;

use deflect_core::{TcpFlags, L4};

mod cursor;
use cursor::Cursor;

/// The connection-identifying tuple recovered from a packet header.
///
/// `src_port`, `dst_port`, and `tcp_flags` are zero when the protocol carries no
/// ports (e.g. ICMP), when the packet is a non-leading IP fragment, or when the
/// sampled header was truncated before the layer-4 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveTuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: TcpFlags,
}

impl FiveTuple {
    /// The layer-4 protocol, classified the same way as the rest of deflect-rs.
    #[must_use]
    pub fn l4(&self) -> L4 {
        L4::from_ip_proto(self.protocol)
    }
}

/// sFlow `header_protocol` values for the sampled-header formats this crate
/// parses; other values (token ring, PPP, MPLS, …) are not decoded.
pub mod link_type {
    /// IEEE 802.3 / Ethernet II framing.
    pub const ETHERNET: u32 = 1;
    /// A bare IPv4 packet (no link-layer header).
    pub const IPV4: u32 = 11;
    /// A bare IPv6 packet (no link-layer header).
    pub const IPV6: u32 = 12;
}

/// Parse a sampled header whose link type is given by an sFlow `header_protocol`
/// value (see [`link_type`]), returning the 5-tuple if it can be recovered.
#[must_use]
pub fn parse_sampled_header(header_protocol: u32, header: &[u8]) -> Option<FiveTuple> {
    match header_protocol {
        link_type::ETHERNET => parse_ethernet(header),
        link_type::IPV4 => parse_ipv4(header),
        link_type::IPV6 => parse_ipv6(header),
        _ => None,
    }
}

/// Parse an Ethernet II frame (stripping up to two 802.1Q/802.1ad VLAN tags) and
/// dispatch on its `EtherType` to the IP parser.
#[must_use]
pub fn parse_ethernet(header: &[u8]) -> Option<FiveTuple> {
    parse_ethernet_inner(&mut Cursor::new(header))
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const MAX_VLAN_TAGS: u8 = 2;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTIONS: u8 = 60;
const EXT_MOBILITY: u8 = 135;
const EXT_AUTH: u8 = 51;
const MAX_EXT_HEADERS: u8 = 8;

fn parse_ethernet_inner(c: &mut Cursor<'_>) -> Option<FiveTuple> {
    c.skip(12)?; // destination and source MAC addresses
    let mut ethertype = c.u16()?;
    let mut tags = 0u8;
    while ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        c.skip(2)?; // VLAN tag control information
        ethertype = c.u16()?;
        tags += 1;
        if tags > MAX_VLAN_TAGS {
            return None;
        }
    }
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4_inner(c),
        ETHERTYPE_IPV6 => parse_ipv6_inner(c),
        _ => None,
    }
}

/// Parse an IPv4 packet starting at its header.
#[must_use]
pub fn parse_ipv4(header: &[u8]) -> Option<FiveTuple> {
    parse_ipv4_inner(&mut Cursor::new(header))
}

fn parse_ipv4_inner(c: &mut Cursor<'_>) -> Option<FiveTuple> {
    let version_ihl = c.u8()?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(version_ihl & 0x0f);
    if ihl < 5 {
        return None; // the base header is five 32-bit words
    }
    c.skip(1)?; // DSCP and ECN
    c.skip(2)?; // total length
    c.skip(2)?; // identification
    let flags_fragment = c.u16()?;
    c.skip(1)?; // time to live
    let protocol = c.u8()?;
    c.skip(2)?; // header checksum
    let src = c.ipv4()?;
    let dst = c.ipv4()?;
    c.skip((ihl - 5) * 4)?; // options
    let fragment_offset = flags_fragment & 0x1fff;
    let leading_fragment = fragment_offset == 0;
    let (src_port, dst_port, tcp_flags) = if leading_fragment {
        layer4(c, protocol)
    } else {
        (0, 0, 0)
    };
    Some(FiveTuple {
        src,
        dst,
        protocol,
        src_port,
        dst_port,
        tcp_flags: TcpFlags(tcp_flags),
    })
}

/// Parse an IPv6 packet starting at its header, following the extension-header
/// chain to the upper-layer protocol.
#[must_use]
pub fn parse_ipv6(header: &[u8]) -> Option<FiveTuple> {
    parse_ipv6_inner(&mut Cursor::new(header))
}

fn parse_ipv6_inner(c: &mut Cursor<'_>) -> Option<FiveTuple> {
    let version_class_label = c.u32()?;
    if version_class_label >> 28 != 6 {
        return None;
    }
    c.skip(2)?; // payload length
    let mut next_header = c.u8()?;
    c.skip(1)?; // hop limit
    let src = c.ipv6()?;
    let dst = c.ipv6()?;

    let mut past_leading_fragment = false;
    let mut depth = 0u8;
    loop {
        match next_header {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTIONS | EXT_MOBILITY => {
                let nh = c.u8()?;
                let ext_len = usize::from(c.u8()?);
                c.skip((ext_len + 1) * 8 - 2)?; // length is in 8-octet units, minus the two read
                next_header = nh;
            }
            EXT_FRAGMENT => {
                let nh = c.u8()?;
                c.skip(1)?; // reserved
                let fragment = c.u16()?;
                c.skip(4)?; // identification
                if fragment >> 3 != 0 {
                    past_leading_fragment = true;
                }
                next_header = nh;
            }
            EXT_AUTH => {
                let nh = c.u8()?;
                let payload_len = usize::from(c.u8()?);
                c.skip((payload_len + 2) * 4 - 2)?; // length is in 4-octet units, plus two, minus the two read
                next_header = nh;
            }
            _ => break,
        }
        depth += 1;
        if depth > MAX_EXT_HEADERS {
            return None;
        }
    }

    let protocol = next_header;
    let (src_port, dst_port, tcp_flags) = if past_leading_fragment {
        (0, 0, 0)
    } else {
        layer4(c, protocol)
    };
    Some(FiveTuple {
        src,
        dst,
        protocol,
        src_port,
        dst_port,
        tcp_flags: TcpFlags(tcp_flags),
    })
}

/// Read the layer-4 ports and (for TCP) control bits best-effort: a header
/// truncated after the ports still yields what was present, with zeros for the
/// rest, because a sampler may have kept only the first bytes of the segment.
fn layer4(c: &mut Cursor<'_>, protocol: u8) -> (u16, u16, u8) {
    match protocol {
        PROTO_TCP => {
            let src_port = c.u16().unwrap_or(0);
            let dst_port = c.u16().unwrap_or(0);
            let flags = tcp_control_bits(c).unwrap_or(0);
            (src_port, dst_port, flags)
        }
        PROTO_UDP => {
            let src_port = c.u16().unwrap_or(0);
            let dst_port = c.u16().unwrap_or(0);
            (src_port, dst_port, 0)
        }
        _ => (0, 0, 0),
    }
}

fn tcp_control_bits(c: &mut Cursor<'_>) -> Option<u8> {
    c.skip(8)?; // sequence and acknowledgement numbers
    let data_offset_and_flags = c.take(2)?;
    Some(data_offset_and_flags[1]) // low byte holds FIN..CWR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_segment(src_port: u16, dst_port: u16, flags: u8) -> [u8; 14] {
        let mut s = [0u8; 14];
        s[0..2].copy_from_slice(&src_port.to_be_bytes());
        s[2..4].copy_from_slice(&dst_port.to_be_bytes());
        // seq (4) + ack (4) stay zero; byte 12 = data offset, byte 13 = flags.
        s[13] = flags;
        s
    }

    fn ipv4_packet(protocol: u8, l4: &[u8]) -> Vec<u8> {
        ipv4_packet_frag(protocol, 0, l4)
    }

    fn ipv4_packet_frag(protocol: u8, fragment_field: u16, l4: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(0x45); // version 4, IHL 5
        p.push(0); // DSCP/ECN
        p.extend((20u16 + l4.len() as u16).to_be_bytes());
        p.extend(0u16.to_be_bytes()); // identification
        p.extend(fragment_field.to_be_bytes());
        p.push(64); // TTL
        p.push(protocol);
        p.extend(0u16.to_be_bytes()); // checksum
        p.extend([203, 0, 113, 10]);
        p.extend([198, 51, 100, 20]);
        p.extend_from_slice(l4);
        p
    }

    fn ipv6_packet(next_header: u8, body: &[u8]) -> Vec<u8> {
        let src: core::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: core::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut p = Vec::new();
        p.extend(0x6000_0000u32.to_be_bytes()); // version 6
        p.extend((body.len() as u16).to_be_bytes());
        p.push(next_header);
        p.push(64); // hop limit
        p.extend(src.octets());
        p.extend(dst.octets());
        p.extend_from_slice(body);
        p
    }

    fn ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12]; // MAC addresses
        f.extend(ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn ipv4_tcp_full_tuple() {
        let pkt = ipv4_packet(PROTO_TCP, &tcp_segment(12345, 80, 0x12));
        let t = parse_ipv4(&pkt).unwrap();
        assert_eq!(t.src, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(t.dst, "198.51.100.20".parse::<IpAddr>().unwrap());
        assert_eq!(t.protocol, PROTO_TCP);
        assert_eq!(t.l4(), L4::Tcp);
        assert_eq!(t.src_port, 12345);
        assert_eq!(t.dst_port, 80);
        assert_eq!(t.tcp_flags, TcpFlags(0x12));
    }

    #[test]
    fn ipv4_udp_has_ports_but_no_flags() {
        let mut udp = Vec::new();
        udp.extend(53u16.to_be_bytes());
        udp.extend(40000u16.to_be_bytes());
        udp.extend(0u16.to_be_bytes()); // length
        udp.extend(0u16.to_be_bytes()); // checksum
        let t = parse_ipv4(&ipv4_packet(PROTO_UDP, &udp)).unwrap();
        assert_eq!(t.l4(), L4::Udp);
        assert_eq!(t.src_port, 53);
        assert_eq!(t.dst_port, 40000);
        assert_eq!(t.tcp_flags, TcpFlags(0));
    }

    #[test]
    fn ipv4_icmp_has_no_ports() {
        let t = parse_ipv4(&ipv4_packet(1, &[8, 0, 0, 0])).unwrap();
        assert_eq!(t.l4(), L4::Icmp);
        assert_eq!(t.src_port, 0);
        assert_eq!(t.dst_port, 0);
    }

    #[test]
    fn ipv4_options_are_skipped_before_layer4() {
        // IHL 6 (one 32-bit option word) must be stepped over to reach the ports.
        let mut pkt = ipv4_packet(PROTO_TCP, &tcp_segment(1111, 2222, 0x02));
        pkt[0] = 0x46; // IHL 6
                       // Insert a 4-byte option after the 20-byte base header.
        pkt.splice(20..20, [0x01, 0x01, 0x01, 0x00]);
        // total length field now understates, but the parser uses IHL, not it.
        let t = parse_ipv4(&pkt).unwrap();
        assert_eq!(t.src_port, 1111);
        assert_eq!(t.dst_port, 2222);
        assert_eq!(t.tcp_flags, TcpFlags::SYN);
    }

    #[test]
    fn ipv4_non_leading_fragment_has_no_ports() {
        // Fragment offset 185 (bytes 1480) -> not the first fragment.
        let pkt = ipv4_packet_frag(PROTO_TCP, 185, &tcp_segment(1111, 2222, 0x10));
        let t = parse_ipv4(&pkt).unwrap();
        assert_eq!(t.protocol, PROTO_TCP);
        assert_eq!(t.src_port, 0);
        assert_eq!(t.dst_port, 0);
        assert_eq!(t.tcp_flags, TcpFlags(0));
    }

    #[test]
    fn ipv4_leading_fragment_more_flag_set_still_reads_ports() {
        // Offset 0 with the MORE_FRAGMENTS flag (0x2000) is the first fragment.
        let pkt = ipv4_packet_frag(PROTO_TCP, 0x2000, &tcp_segment(1111, 2222, 0x18));
        let t = parse_ipv4(&pkt).unwrap();
        assert_eq!(t.src_port, 1111);
        assert_eq!(t.dst_port, 2222);
    }

    #[test]
    fn ipv4_truncated_after_addresses_keeps_addresses_zero_ports() {
        let pkt = ipv4_packet(PROTO_TCP, &[]);
        let t = parse_ipv4(&pkt).unwrap();
        assert_eq!(t.src, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(t.protocol, PROTO_TCP);
        assert_eq!(t.src_port, 0);
        assert_eq!(t.dst_port, 0);
    }

    #[test]
    fn ipv4_truncated_after_src_port_keeps_src_zero_dst() {
        // Only two bytes of the TCP header: src port present, dst port absent.
        let pkt = ipv4_packet(PROTO_TCP, &9999u16.to_be_bytes());
        let t = parse_ipv4(&pkt).unwrap();
        assert_eq!(t.src_port, 9999);
        assert_eq!(t.dst_port, 0);
        assert_eq!(t.tcp_flags, TcpFlags(0));
    }

    #[test]
    fn wrong_version_nibble_is_rejected() {
        let mut pkt = ipv4_packet(PROTO_TCP, &tcp_segment(1, 2, 0));
        pkt[0] = 0x65; // version 6 in an IPv4 position
        assert_eq!(parse_ipv4(&pkt), None);
    }

    #[test]
    fn ihl_below_five_is_rejected() {
        let mut pkt = ipv4_packet(PROTO_TCP, &tcp_segment(1, 2, 0));
        pkt[0] = 0x44; // IHL 4 is impossible
        assert_eq!(parse_ipv4(&pkt), None);
    }

    #[test]
    fn ipv6_tcp_full_tuple() {
        let pkt = ipv6_packet(PROTO_TCP, &tcp_segment(5000, 443, 0x10));
        let t = parse_ipv6(&pkt).unwrap();
        assert_eq!(t.src, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(t.dst, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert_eq!(t.l4(), L4::Tcp);
        assert_eq!(t.src_port, 5000);
        assert_eq!(t.dst_port, 443);
        assert_eq!(t.tcp_flags, TcpFlags::ACK);
    }

    #[test]
    fn ipv6_hop_by_hop_extension_is_walked() {
        // One hop-by-hop header (8 bytes): next=UDP, ext_len=0.
        let mut body = Vec::new();
        body.push(PROTO_UDP);
        body.push(0); // ext len: (0+1)*8 = 8 bytes total
        body.extend([0u8; 6]); // options padding
        let mut udp = Vec::new();
        udp.extend(53u16.to_be_bytes());
        udp.extend(123u16.to_be_bytes());
        udp.extend([0u8; 4]);
        body.extend_from_slice(&udp);
        let t = parse_ipv6(&ipv6_packet(EXT_HOP_BY_HOP, &body)).unwrap();
        assert_eq!(t.protocol, PROTO_UDP);
        assert_eq!(t.src_port, 53);
        assert_eq!(t.dst_port, 123);
    }

    #[test]
    fn ipv6_non_leading_fragment_has_no_ports() {
        // Fragment header with a non-zero offset (0x0100 -> offset 32).
        let mut body = Vec::new();
        body.push(PROTO_TCP);
        body.push(0); // reserved
        body.extend(0x0100u16.to_be_bytes()); // offset != 0
        body.extend(0u32.to_be_bytes()); // identification
        body.extend_from_slice(&tcp_segment(1, 2, 0x02));
        let t = parse_ipv6(&ipv6_packet(EXT_FRAGMENT, &body)).unwrap();
        assert_eq!(t.protocol, PROTO_TCP);
        assert_eq!(t.src_port, 0);
        assert_eq!(t.dst_port, 0);
    }

    #[test]
    fn ipv6_leading_fragment_reads_ports() {
        let mut body = Vec::new();
        body.push(PROTO_TCP);
        body.push(0);
        body.extend(0x0001u16.to_be_bytes()); // offset 0, MORE flag set
        body.extend(0u32.to_be_bytes());
        body.extend_from_slice(&tcp_segment(7, 8, 0x02));
        let t = parse_ipv6(&ipv6_packet(EXT_FRAGMENT, &body)).unwrap();
        assert_eq!(t.src_port, 7);
        assert_eq!(t.dst_port, 8);
    }

    #[test]
    fn ipv6_authentication_header_is_walked() {
        // AH: next=TCP, payload_len=1 -> (1+2)*4 = 12 bytes total.
        let mut body = Vec::new();
        body.push(PROTO_TCP);
        body.push(1);
        body.extend([0u8; 10]); // reserved + SPI + sequence + ICV (10 more bytes)
        body.extend_from_slice(&tcp_segment(21, 22, 0x02));
        let t = parse_ipv6(&ipv6_packet(EXT_AUTH, &body)).unwrap();
        assert_eq!(t.protocol, PROTO_TCP);
        assert_eq!(t.src_port, 21);
        assert_eq!(t.dst_port, 22);
    }

    #[test]
    fn ipv6_extension_header_loop_is_bounded() {
        // A routing header that points to itself would loop forever without the
        // depth cap; nine of them exceeds MAX_EXT_HEADERS and yields None.
        let mut body = Vec::new();
        for _ in 0..9 {
            body.push(EXT_ROUTING);
            body.push(0);
            body.extend([0u8; 6]);
        }
        body.push(PROTO_TCP);
        body.push(0);
        body.extend([0u8; 6]);
        body.extend_from_slice(&tcp_segment(1, 2, 0x02));
        assert_eq!(parse_ipv6(&ipv6_packet(EXT_ROUTING, &body)), None);
    }

    #[test]
    fn ipv6_exactly_max_extension_headers_still_parses() {
        // MAX_EXT_HEADERS (8) extension headers is the limit that must still be
        // walked through to the layer-4 header; the ninth is what trips the cap.
        // This pins the boundary at `>` rather than `>=` or `==`.
        assert_eq!(MAX_EXT_HEADERS, 8);
        let mut body = Vec::new();
        for _ in 0..7 {
            body.push(EXT_ROUTING);
            body.push(0);
            body.extend([0u8; 6]);
        }
        // The eighth extension header points to TCP.
        body.push(PROTO_TCP);
        body.push(0);
        body.extend([0u8; 6]);
        body.extend_from_slice(&tcp_segment(4321, 1234, 0x02));
        let t = parse_ipv6(&ipv6_packet(EXT_ROUTING, &body)).unwrap();
        assert_eq!(t.protocol, PROTO_TCP);
        assert_eq!(t.src_port, 4321);
        assert_eq!(t.dst_port, 1234);
    }

    #[test]
    fn ipv6_wrong_version_rejected() {
        let mut pkt = ipv6_packet(PROTO_TCP, &tcp_segment(1, 2, 0));
        pkt[0] = 0x40; // version 4 in an IPv6 position
        assert_eq!(parse_ipv6(&pkt), None);
    }

    #[test]
    fn ethernet_dispatches_to_ipv4() {
        let inner = ipv4_packet(PROTO_TCP, &tcp_segment(1000, 2000, 0x02));
        let frame = ethernet_frame(ETHERTYPE_IPV4, &inner);
        let t = parse_ethernet(&frame).unwrap();
        assert_eq!(t.src_port, 1000);
        assert_eq!(t.dst_port, 2000);
        // The dispatch helper agrees with the standalone entry point.
        assert_eq!(parse_sampled_header(link_type::ETHERNET, &frame), Some(t));
    }

    #[test]
    fn ethernet_dispatches_to_ipv6() {
        let inner = ipv6_packet(PROTO_TCP, &tcp_segment(3000, 4000, 0x10));
        let frame = ethernet_frame(ETHERTYPE_IPV6, &inner);
        let t = parse_ethernet(&frame).unwrap();
        assert_eq!(t.l4(), L4::Tcp);
        assert_eq!(t.dst_port, 4000);
    }

    #[test]
    fn ethernet_single_vlan_tag_is_stripped() {
        let inner = ipv4_packet(PROTO_UDP, &{
            let mut u = Vec::new();
            u.extend(53u16.to_be_bytes());
            u.extend(5353u16.to_be_bytes());
            u.extend([0u8; 4]);
            u
        });
        let mut frame = vec![0u8; 12];
        frame.extend(ETHERTYPE_VLAN.to_be_bytes());
        frame.extend(0x0064u16.to_be_bytes()); // VLAN id 100
        frame.extend(ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&inner);
        let t = parse_ethernet(&frame).unwrap();
        assert_eq!(t.src_port, 53);
        assert_eq!(t.dst_port, 5353);
    }

    #[test]
    fn ethernet_qinq_double_tag_is_stripped() {
        let inner = ipv4_packet(PROTO_TCP, &tcp_segment(10, 20, 0x02));
        let mut frame = vec![0u8; 12];
        frame.extend(ETHERTYPE_QINQ.to_be_bytes());
        frame.extend(0x0064u16.to_be_bytes());
        frame.extend(ETHERTYPE_VLAN.to_be_bytes());
        frame.extend(0x00c8u16.to_be_bytes());
        frame.extend(ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&inner);
        let t = parse_ethernet(&frame).unwrap();
        assert_eq!(t.src_port, 10);
        assert_eq!(t.dst_port, 20);
    }

    #[test]
    fn ethernet_more_than_two_vlan_tags_is_rejected() {
        let mut frame = vec![0u8; 12];
        for _ in 0..3 {
            frame.extend(ETHERTYPE_VLAN.to_be_bytes());
            frame.extend(0x0064u16.to_be_bytes());
        }
        frame.extend(ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ipv4_packet(PROTO_TCP, &tcp_segment(1, 2, 0)));
        assert_eq!(parse_ethernet(&frame), None);
    }

    #[test]
    fn unknown_ethertype_is_not_decoded() {
        let frame = ethernet_frame(0x0806, &[0u8; 28]); // ARP
        assert_eq!(parse_ethernet(&frame), None);
    }

    #[test]
    fn unknown_link_type_is_not_decoded() {
        let pkt = ipv4_packet(PROTO_TCP, &tcp_segment(1, 2, 0));
        assert_eq!(parse_sampled_header(7, &pkt), None); // 7 = PPP, unsupported
    }

    #[test]
    fn bare_ipv4_and_ipv6_link_types_dispatch() {
        let v4 = ipv4_packet(PROTO_TCP, &tcp_segment(1, 2, 0x02));
        assert!(parse_sampled_header(link_type::IPV4, &v4).is_some());
        let v6 = ipv6_packet(PROTO_TCP, &tcp_segment(1, 2, 0x02));
        assert!(parse_sampled_header(link_type::IPV6, &v6).is_some());
    }

    #[test]
    fn empty_header_never_panics() {
        for lt in [link_type::ETHERNET, link_type::IPV4, link_type::IPV6, 99] {
            assert_eq!(parse_sampled_header(lt, &[]), None);
        }
    }
}
