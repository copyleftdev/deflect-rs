use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Prefix lengths used to aggregate sources before keying state on them.
///
/// Defaults aggregate IPv4 to `/24` and IPv6 to `/64`: the smallest blocks a
/// network operator is typically allocated, so an attacker rotating addresses
/// within one allocation still collapses to a single key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aggregation {
    /// Prefix length kept for IPv4 addresses.
    pub v4_bits: u8,
    /// Prefix length kept for IPv6 addresses.
    pub v6_bits: u8,
}

impl Aggregation {
    /// No aggregation: every host is its own key (`/32` and `/128`).
    pub const HOST: Aggregation = Aggregation {
        v4_bits: 32,
        v6_bits: 128,
    };
    /// Default subnet aggregation (`/24` and `/64`).
    pub const SUBNET: Aggregation = Aggregation {
        v4_bits: 24,
        v6_bits: 64,
    };

    /// Builds an aggregation, clamping each prefix length to its address width.
    #[must_use]
    pub const fn new(v4_bits: u8, v6_bits: u8) -> Aggregation {
        Aggregation {
            v4_bits: if v4_bits > 32 { 32 } else { v4_bits },
            v6_bits: if v6_bits > 128 { 128 } else { v6_bits },
        }
    }
}

impl Default for Aggregation {
    fn default() -> Self {
        Aggregation::SUBNET
    }
}

/// A canonical, hashable key identifying the source of traffic.
///
/// Addresses are masked to the configured [`Aggregation`] at construction, so
/// two hosts in the same keyed prefix produce an equal `SourceKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// A masked IPv4 address.
    V4([u8; 4]),
    /// A masked IPv6 address.
    V6([u8; 16]),
}

impl SourceKey {
    /// Builds a key by masking `addr` to `agg`'s prefix length.
    #[must_use]
    pub fn new(addr: IpAddr, agg: Aggregation) -> SourceKey {
        match addr {
            IpAddr::V4(v4) => SourceKey::V4(mask_v4(v4.octets(), agg.v4_bits)),
            IpAddr::V6(v6) => SourceKey::V6(mask_v6(v6.octets(), agg.v6_bits)),
        }
    }

    /// Builds an unaggregated per-host key for `addr`.
    #[must_use]
    pub fn host(addr: IpAddr) -> SourceKey {
        SourceKey::new(addr, Aggregation::HOST)
    }

    /// True when the key holds an IPv4 address.
    #[must_use]
    pub fn is_v4(&self) -> bool {
        matches!(self, SourceKey::V4(_))
    }

    /// Returns the masked address this key represents.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        match self {
            SourceKey::V4(o) => IpAddr::V4(Ipv4Addr::from(*o)),
            SourceKey::V6(o) => IpAddr::V6(Ipv6Addr::from(*o)),
        }
    }
}

fn mask_octets<const N: usize>(mut octets: [u8; N], bits: u8) -> [u8; N] {
    let bits = (bits as usize).min(N * 8);
    let full = bits / 8;
    let rem = bits % 8;
    if rem != 0 {
        // Keep the high `rem` bits of the boundary octet, clear the rest.
        octets[full] &= 0xFFu8 << (8 - rem);
    }
    for b in octets.iter_mut().skip(full + usize::from(rem != 0)) {
        *b = 0;
    }
    octets
}

fn mask_v4(octets: [u8; 4], bits: u8) -> [u8; 4] {
    mask_octets(octets, bits)
}

fn mask_v6(octets: [u8; 16], bits: u8) -> [u8; 16] {
    mask_octets(octets, bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn subnet_collapses_same_v4_prefix() {
        let a = SourceKey::new(v4("203.0.113.5"), Aggregation::SUBNET);
        let b = SourceKey::new(v4("203.0.113.200"), Aggregation::SUBNET);
        assert_eq!(a, b);
        assert_eq!(a, SourceKey::V4([203, 0, 113, 0]));
    }

    #[test]
    fn subnet_separates_different_v4_prefix() {
        let a = SourceKey::new(v4("203.0.113.5"), Aggregation::SUBNET);
        let b = SourceKey::new(v4("203.0.114.5"), Aggregation::SUBNET);
        assert_ne!(a, b);
    }

    #[test]
    fn host_keeps_full_v4() {
        let a = SourceKey::host(v4("203.0.113.5"));
        assert_eq!(a, SourceKey::V4([203, 0, 113, 5]));
    }

    #[test]
    fn non_octet_boundary_masks_partial_byte() {
        // /20 keeps 4 high bits of the third octet.
        let k = SourceKey::new(v4("10.17.255.255"), Aggregation::new(20, 64));
        assert_eq!(k, SourceKey::V4([10, 17, 240, 0]));
    }

    #[test]
    fn v6_aggregates_to_64() {
        let a: IpAddr = "2001:db8::dead:beef".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            SourceKey::new(a, Aggregation::SUBNET),
            SourceKey::new(b, Aggregation::SUBNET)
        );
    }

    #[test]
    fn bits_beyond_width_are_clamped() {
        let k = SourceKey::new(v4("1.2.3.4"), Aggregation::new(200, 200));
        assert_eq!(k, SourceKey::V4([1, 2, 3, 4]));
    }

    #[test]
    fn is_v4_distinguishes_family() {
        assert!(SourceKey::host(v4("203.0.113.5")).is_v4());
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!SourceKey::host(v6).is_v4());
    }

    #[test]
    fn mask_v6_keeps_prefix_and_zeroes_host() {
        // A concrete masked value, so the mask is checked rather than only that
        // two addresses in one prefix compare equal.
        let a: IpAddr = "2001:db8::dead:beef".parse().unwrap();
        let k = SourceKey::new(a, Aggregation::SUBNET);
        assert_eq!(
            k,
            SourceKey::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn addr_roundtrips_the_masked_key() {
        let k = SourceKey::new(v4("203.0.113.200"), Aggregation::SUBNET);
        assert_eq!(k.addr(), v4("203.0.113.0"));
    }
}
