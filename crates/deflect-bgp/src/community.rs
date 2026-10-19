use core::fmt;

/// A BGP standard community, the 16-bit ASN and 16-bit value pair that upstreams
/// match to decide how to treat a route. Rendered on the wire as `asn:value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Community {
    pub asn: u16,
    pub value: u16,
}

impl Community {
    #[must_use]
    pub const fn new(asn: u16, value: u16) -> Community {
        Community { asn, value }
    }

    /// The well-known BLACKHOLE community, `65535:666` (RFC 7999). A route
    /// tagged with it asks the receiving network to discard traffic to the
    /// advertised prefix.
    pub const BLACKHOLE: Community = Community::new(65535, 666);

    /// `NO_EXPORT` (`65535:65281`, RFC 1997). Keeps the route inside the
    /// receiving AS. RFC 7999 requires a blackhole to carry this (or
    /// `NO_ADVERTISE`) so the discard cannot leak into the wider routing table.
    pub const NO_EXPORT: Community = Community::new(65535, 65281);

    /// `NO_ADVERTISE` (`65535:65282`, RFC 1997). The route is not passed to any
    /// peer at all — the strictest containment for a blackhole.
    pub const NO_ADVERTISE: Community = Community::new(65535, 65282);
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.asn, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn well_known_values() {
        assert_eq!(Community::BLACKHOLE, Community::new(65535, 666));
        assert_eq!(Community::NO_EXPORT, Community::new(65535, 65281));
        assert_eq!(Community::NO_ADVERTISE, Community::new(65535, 65282));
    }

    #[test]
    fn renders_as_asn_value() {
        assert_eq!(Community::BLACKHOLE.to_string(), "65535:666");
        assert_eq!(Community::new(64500, 100).to_string(), "64500:100");
    }
}
