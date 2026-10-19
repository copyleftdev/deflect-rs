use core::net::IpAddr;

/// Layer-4 protocol of an observation, carrying the IANA protocol number for
/// anything not called out explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum L4 {
    /// TCP (IP protocol 6).
    Tcp,
    /// UDP (IP protocol 17).
    Udp,
    /// ICMP (IP protocol 1).
    Icmp,
    /// `ICMPv6` (IP protocol 58).
    IcmpV6,
    /// Any other protocol, carrying its IANA protocol number.
    Other(u8),
}

impl L4 {
    /// Classifies an IANA IP protocol number, mapping unknowns to `Other`.
    #[must_use]
    pub const fn from_ip_proto(proto: u8) -> L4 {
        match proto {
            1 => L4::Icmp,
            6 => L4::Tcp,
            17 => L4::Udp,
            58 => L4::IcmpV6,
            other => L4::Other(other),
        }
    }

    /// Returns the IANA IP protocol number; inverse of [`L4::from_ip_proto`].
    #[must_use]
    pub const fn ip_proto(self) -> u8 {
        match self {
            L4::Icmp => 1,
            L4::Tcp => 6,
            L4::Udp => 17,
            L4::IcmpV6 => 58,
            L4::Other(p) => p,
        }
    }
}

/// TCP control bits, packed into one byte in the usual wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TcpFlags(
    /// The raw flag byte in wire bit order.
    pub u8,
);

impl TcpFlags {
    /// FIN: no more data from the sender.
    pub const FIN: TcpFlags = TcpFlags(0x01);
    /// SYN: synchronize sequence numbers.
    pub const SYN: TcpFlags = TcpFlags(0x02);
    /// RST: reset the connection.
    pub const RST: TcpFlags = TcpFlags(0x04);
    /// PSH: push buffered data to the application.
    pub const PSH: TcpFlags = TcpFlags(0x08);
    /// ACK: the acknowledgment field is significant.
    pub const ACK: TcpFlags = TcpFlags(0x10);
    /// URG: the urgent pointer field is significant.
    pub const URG: TcpFlags = TcpFlags(0x20);
    /// ECE: ECN-Echo.
    pub const ECE: TcpFlags = TcpFlags(0x40);
    /// CWR: Congestion Window Reduced.
    pub const CWR: TcpFlags = TcpFlags(0x80);

    /// Returns a flag set with no bits set.
    #[must_use]
    pub const fn empty() -> TcpFlags {
        TcpFlags(0)
    }

    /// Returns the raw flag byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True if every bit set in `mask` is also set in `self`.
    #[must_use]
    pub const fn contains(self, mask: TcpFlags) -> bool {
        self.0 & mask.0 == mask.0
    }

    /// True if any bit set in `mask` is also set in `self`.
    #[must_use]
    pub const fn intersects(self, mask: TcpFlags) -> bool {
        self.0 & mask.0 != 0
    }

    /// True when no flag bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for TcpFlags {
    type Output = TcpFlags;
    fn bitor(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | rhs.0)
    }
}

/// Metadata extracted from one packet, borrowing its payload rather than
/// owning it so a stage can inspect bytes without a copy.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Layer-4 protocol.
    pub l4: L4,
    /// Source transport port, or 0 when the protocol has none.
    pub src_port: u16,
    /// Destination transport port, or 0 when the protocol has none.
    pub dst_port: u16,
    /// TCP control bits; empty for non-TCP packets.
    pub tcp_flags: TcpFlags,
    /// Total wire length of the packet in bytes (L3 onward).
    pub wire_len: u32,
    /// Borrowed transport payload bytes.
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Builds a packet with the given addresses and protocol; ports, flags,
    /// wire length, and payload start empty and are set with the `with_*` methods.
    #[must_use]
    pub fn new(src: IpAddr, dst: IpAddr, l4: L4) -> Packet<'a> {
        Packet {
            src,
            dst,
            l4,
            src_port: 0,
            dst_port: 0,
            tcp_flags: TcpFlags::empty(),
            wire_len: 0,
            payload: &[],
        }
    }

    /// Sets the source and destination ports.
    #[must_use]
    pub fn with_ports(mut self, src_port: u16, dst_port: u16) -> Self {
        self.src_port = src_port;
        self.dst_port = dst_port;
        self
    }

    /// Sets the TCP control bits.
    #[must_use]
    pub fn with_flags(mut self, flags: TcpFlags) -> Self {
        self.tcp_flags = flags;
        self
    }

    /// Sets the total wire length in bytes.
    #[must_use]
    pub fn with_wire_len(mut self, len: u32) -> Self {
        self.wire_len = len;
        self
    }

    /// Borrows `payload` as the packet's transport payload.
    #[must_use]
    pub fn with_payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = payload;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_proto_roundtrips_known_protocols() {
        for proto in [1u8, 6, 17, 58, 0, 47, 132, 255] {
            assert_eq!(L4::from_ip_proto(proto).ip_proto(), proto);
        }
        assert_eq!(L4::Tcp.ip_proto(), 6);
        assert_eq!(L4::Udp.ip_proto(), 17);
        assert_eq!(L4::Icmp.ip_proto(), 1);
        assert_eq!(L4::IcmpV6.ip_proto(), 58);
    }

    #[test]
    fn bits_returns_the_raw_byte() {
        assert_eq!(TcpFlags(0x12).bits(), 0x12);
        assert_eq!(TcpFlags::SYN.bits(), 0x02);
    }

    #[test]
    fn contains_requires_every_masked_bit() {
        let synack = TcpFlags::SYN | TcpFlags::ACK;
        assert!(synack.contains(TcpFlags::SYN));
        assert!(synack.contains(TcpFlags::ACK));
        assert!(synack.contains(synack));
        assert!(!TcpFlags::SYN.contains(TcpFlags::ACK));
        assert!(!TcpFlags::SYN.contains(synack));
    }

    #[test]
    fn intersects_requires_any_masked_bit() {
        let synack = TcpFlags::SYN | TcpFlags::ACK;
        assert!(TcpFlags::SYN.intersects(TcpFlags::SYN));
        assert!(synack.intersects(TcpFlags::ACK));
        assert!(!TcpFlags::SYN.intersects(TcpFlags::ACK));
        assert!(!TcpFlags::SYN.intersects(TcpFlags::empty()));
    }

    #[test]
    fn is_empty_only_when_no_bits_set() {
        assert!(TcpFlags::empty().is_empty());
        assert!(!TcpFlags::SYN.is_empty());
    }

    #[test]
    fn bitor_unions_bits() {
        // Overlapping bits so OR is distinguishable from XOR and AND.
        assert_eq!((TcpFlags(0x12) | TcpFlags(0x10)).bits(), 0x12);
        assert_eq!((TcpFlags::SYN | TcpFlags::ACK).bits(), 0x12);
    }
}
