use core::net::{IpAddr, Ipv4Addr};

use deflect_core::{TcpFlags, L4};

/// A flow as reported by a NetFlow/IPFIX exporter: a 5-tuple plus the packet
/// and byte counts the exporter attributes to it. Unlike a [`deflect_core::Packet`]
/// this is an aggregate over many packets, so it drives rate monitoring rather
/// than per-packet matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRecord {
    /// Source IP address of the flow.
    pub src: IpAddr,
    /// Destination IP address of the flow.
    pub dst: IpAddr,
    /// IANA IP protocol number (e.g. 6 TCP, 17 UDP).
    pub protocol: u8,
    /// Source transport port (0 when the protocol has none or it was not captured).
    pub src_port: u16,
    /// Destination transport port (0 when the protocol has none or it was not captured).
    pub dst_port: u16,
    /// Union of TCP control bits seen across the flow's packets.
    pub tcp_flags: TcpFlags,
    /// Packet count the exporter attributes to the flow.
    pub packets: u64,
    /// Byte count the exporter attributes to the flow.
    pub bytes: u64,
}

impl FlowRecord {
    /// The layer-4 protocol, derived from [`protocol`](Self::protocol).
    #[must_use]
    pub fn l4(&self) -> L4 {
        L4::from_ip_proto(self.protocol)
    }
}

/// IANA IPFIX information element IDs (shared with NetFlow v9 field types) that
/// this decoder understands. Unlisted fields are skipped by length.
pub mod field {
    /// Bytes in the flow (IE 1); maps to [`FlowRecord::bytes`](super::FlowRecord::bytes).
    pub const OCTET_DELTA_COUNT: u16 = 1;
    /// Packets in the flow (IE 2); maps to [`FlowRecord::packets`](super::FlowRecord::packets).
    pub const PACKET_DELTA_COUNT: u16 = 2;
    /// IP protocol number (IE 4).
    pub const PROTOCOL: u16 = 4;
    /// TCP control bits (IE 6).
    pub const TCP_CONTROL_BITS: u16 = 6;
    /// Source transport port (IE 7).
    pub const SRC_PORT: u16 = 7;
    /// Source IPv4 address (IE 8); honoured only at a 4-byte length.
    pub const SRC_IPV4: u16 = 8;
    /// Destination transport port (IE 11).
    pub const DST_PORT: u16 = 11;
    /// Destination IPv4 address (IE 12); honoured only at a 4-byte length.
    pub const DST_IPV4: u16 = 12;
    /// Source IPv6 address (IE 27); honoured only at a 16-byte length.
    pub const SRC_IPV6: u16 = 27;
    /// Destination IPv6 address (IE 28); honoured only at a 16-byte length.
    pub const DST_IPV6: u16 = 28;
}

/// Accumulates decoded fields into a [`FlowRecord`]; whatever the template does
/// not supply stays at its zero default.
#[derive(Debug, Clone)]
pub(crate) struct FlowBuilder {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    packets: u64,
    bytes: u64,
}

impl Default for FlowBuilder {
    fn default() -> Self {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        FlowBuilder {
            src: any,
            dst: any,
            protocol: 0,
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            packets: 0,
            bytes: 0,
        }
    }
}

impl FlowBuilder {
    pub(crate) fn set_src(&mut self, a: IpAddr) {
        self.src = a;
    }
    pub(crate) fn set_dst(&mut self, a: IpAddr) {
        self.dst = a;
    }
    pub(crate) fn set_protocol(&mut self, p: u8) {
        self.protocol = p;
    }
    pub(crate) fn set_src_port(&mut self, p: u16) {
        self.src_port = p;
    }
    pub(crate) fn set_dst_port(&mut self, p: u16) {
        self.dst_port = p;
    }
    pub(crate) fn set_tcp_flags(&mut self, f: u8) {
        self.tcp_flags = f;
    }
    pub(crate) fn set_packets(&mut self, n: u64) {
        self.packets = n;
    }
    pub(crate) fn set_bytes(&mut self, n: u64) {
        self.bytes = n;
    }

    pub(crate) fn build(self) -> FlowRecord {
        FlowRecord {
            src: self.src,
            dst: self.dst,
            protocol: self.protocol,
            src_port: self.src_port,
            dst_port: self.dst_port,
            tcp_flags: TcpFlags(self.tcp_flags),
            packets: self.packets,
            bytes: self.bytes,
        }
    }
}
