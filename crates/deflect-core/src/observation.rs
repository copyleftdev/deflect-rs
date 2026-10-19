use core::net::IpAddr;

/// Layer-4 protocol of an observation, carrying the IANA protocol number for
/// anything not called out explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4 {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

impl L4 {
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
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    #[must_use]
    pub const fn empty() -> TcpFlags {
        TcpFlags(0)
    }

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
    pub src: IpAddr,
    pub dst: IpAddr,
    pub l4: L4,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: TcpFlags,
    /// Total wire length of the packet in bytes (L3 onward).
    pub wire_len: u32,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
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

    #[must_use]
    pub fn with_ports(mut self, src_port: u16, dst_port: u16) -> Self {
        self.src_port = src_port;
        self.dst_port = dst_port;
        self
    }

    #[must_use]
    pub fn with_flags(mut self, flags: TcpFlags) -> Self {
        self.tcp_flags = flags;
        self
    }

    #[must_use]
    pub fn with_wire_len(mut self, len: u32) -> Self {
        self.wire_len = len;
        self
    }

    #[must_use]
    pub fn with_payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = payload;
        self
    }
}
