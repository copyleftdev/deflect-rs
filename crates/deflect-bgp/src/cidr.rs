use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network prefix: a masked base address plus a prefix length. Construction
/// masks the address to the length, so two addresses in the same prefix yield
/// equal `Cidr`s and containment is an exact equality check after re-masking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl Cidr {
    /// Build a prefix, masking `addr` to `len` bits. `len` is clamped to the
    /// address family's width (32 for IPv4, 128 for IPv6).
    #[must_use]
    pub fn new(addr: IpAddr, len: u8) -> Cidr {
        match addr {
            IpAddr::V4(a) => {
                let len = len.min(32);
                Cidr {
                    net: IpAddr::V4(Ipv4Addr::from(mask_v4(u32::from(a), len))),
                    len,
                }
            }
            IpAddr::V6(a) => {
                let len = len.min(128);
                Cidr {
                    net: IpAddr::V6(Ipv6Addr::from(mask_v6(u128::from(a), len))),
                    len,
                }
            }
        }
    }

    /// A single-host prefix (`/32` or `/128`).
    #[must_use]
    pub fn host(addr: IpAddr) -> Cidr {
        let len = if addr.is_ipv4() { 32 } else { 128 };
        Cidr::new(addr, len)
    }

    #[must_use]
    pub fn net(&self) -> IpAddr {
        self.net
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// The prefix length of a full host address in this prefix's family.
    #[must_use]
    pub fn max_len(&self) -> u8 {
        if self.net.is_ipv4() {
            32
        } else {
            128
        }
    }

    #[must_use]
    pub fn is_host(&self) -> bool {
        self.len == self.max_len()
    }

    /// The default route (`0.0.0.0/0` or `::/0`) — the whole address space.
    #[must_use]
    pub fn is_default_route(&self) -> bool {
        self.len == 0
    }

    /// Whether this prefix contains `other`: same family, this prefix is no
    /// more specific, and `other`'s base re-masked to this length matches.
    #[must_use]
    pub fn contains(&self, other: &Cidr) -> bool {
        match (self.net, other.net) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                self.len <= other.len && Cidr::new(other.net, self.len).net == self.net
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

fn mask_v4(bits: u32, len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - u32::from(len)))
    }
}

fn mask_v6(bits: u128, len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - u32::from(len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn cidr(s: &str, len: u8) -> Cidr {
        Cidr::new(v4(s), len)
    }

    #[test]
    fn construction_masks_host_bits() {
        let c = cidr("203.0.113.200", 24);
        assert_eq!(c.net(), v4("203.0.113.0"));
        assert_eq!(c.to_string(), "203.0.113.0/24");
    }

    #[test]
    fn host_is_full_length() {
        let c = Cidr::host(v4("198.51.100.7"));
        assert_eq!(c.prefix_len(), 32);
        assert!(c.is_host());
        assert_eq!(c.to_string(), "198.51.100.7/32");
    }

    #[test]
    fn contains_more_specific() {
        let block = cidr("203.0.113.0", 24);
        assert!(block.contains(&Cidr::host(v4("203.0.113.9"))));
        assert!(block.contains(&cidr("203.0.113.128", 25)));
        assert!(block.contains(&block));
    }

    #[test]
    fn does_not_contain_outside_or_broader() {
        let block = cidr("203.0.113.0", 24);
        assert!(!block.contains(&Cidr::host(v4("203.0.114.9"))));
        assert!(!block.contains(&cidr("203.0.0.0", 16)));
    }

    #[test]
    fn different_families_never_contain() {
        let v4block = cidr("203.0.113.0", 24);
        let v6host = Cidr::host("2001:db8::1".parse().unwrap());
        assert!(!v4block.contains(&v6host));
        assert!(!v6host.contains(&v4block));
    }

    #[test]
    fn default_route_detected_and_contains_everything() {
        let any = cidr("0.0.0.0", 0);
        assert!(any.is_default_route());
        assert!(any.contains(&Cidr::host(v4("8.8.8.8"))));
    }

    #[test]
    fn v6_masks_and_contains() {
        let block = Cidr::new("2001:db8:abcd::".parse().unwrap(), 48);
        let host: Cidr = Cidr::host("2001:db8:abcd:1234::1".parse().unwrap());
        assert!(block.contains(&host));
        assert_eq!(block.to_string(), "2001:db8:abcd::/48");
    }

    #[test]
    fn length_clamped_to_family_width() {
        let c = Cidr::new(v4("1.2.3.4"), 200);
        assert_eq!(c.prefix_len(), 32);
    }
}
