use alloc::vec;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::cidr::Cidr;
use crate::community::Community;

/// Which direction of traffic an RTBH route discards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtbhKind {
    /// Destination-based RTBH: the prefix is a victim under attack, and the
    /// upstream drops *all* traffic toward it. This sacrifices the victim to
    /// protect the rest of the network, so the prefix must be one the operator
    /// owns — see [`crate::Scope`].
    Destination,
    /// Source-based RTBH: the prefix is an attack source, and the upstream (with
    /// loose uRPF) drops traffic *from* it. More surgical, but it depends on the
    /// upstream having source-address validation enabled.
    Source,
}

/// A blackhole route to advertise: the prefix, its direction, an optional
/// discard next hop (legacy next-hop-based RTBH), and the communities that tell
/// the upstream to blackhole it.
///
/// Built with [`Blackhole::destination`] / [`Blackhole::source`], which default
/// to community-based signalling carrying [`Community::BLACKHOLE`] and
/// [`Community::NO_EXPORT`] — the containment RFC 7999 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blackhole {
    pub prefix: Cidr,
    pub kind: RtbhKind,
    pub next_hop: Option<IpAddr>,
    pub communities: Vec<Community>,
}

impl Blackhole {
    #[must_use]
    pub fn destination(prefix: Cidr) -> Blackhole {
        Blackhole {
            prefix,
            kind: RtbhKind::Destination,
            next_hop: None,
            communities: vec![Community::BLACKHOLE, Community::NO_EXPORT],
        }
    }

    #[must_use]
    pub fn source(prefix: Cidr) -> Blackhole {
        Blackhole {
            prefix,
            kind: RtbhKind::Source,
            next_hop: None,
            communities: vec![Community::BLACKHOLE, Community::NO_EXPORT],
        }
    }

    /// Use legacy next-hop-based RTBH: advertise the route with a next hop the
    /// upstream has pre-routed to its discard interface, instead of (or in
    /// addition to) the blackhole community.
    #[must_use]
    pub fn with_next_hop(mut self, next_hop: IpAddr) -> Blackhole {
        self.next_hop = Some(next_hop);
        self
    }

    /// Replace the community set wholesale.
    #[must_use]
    pub fn with_communities(mut self, communities: Vec<Community>) -> Blackhole {
        self.communities = communities;
        self
    }

    /// Append one community (e.g. a provider-specific blackhole tag).
    #[must_use]
    pub fn add_community(mut self, community: Community) -> Blackhole {
        self.communities.push(community);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn host() -> Cidr {
        Cidr::host("203.0.113.9".parse().unwrap())
    }

    #[test]
    fn destination_defaults_to_contained_community_signalling() {
        let b = Blackhole::destination(host());
        assert_eq!(b.kind, RtbhKind::Destination);
        assert_eq!(b.next_hop, None);
        assert_eq!(
            b.communities,
            vec![Community::BLACKHOLE, Community::NO_EXPORT]
        );
    }

    #[test]
    fn source_sets_kind_source() {
        assert_eq!(Blackhole::source(host()).kind, RtbhKind::Source);
    }

    #[test]
    fn builders_compose() {
        let nh: IpAddr = "192.0.2.1".parse().unwrap();
        let b = Blackhole::destination(host())
            .with_next_hop(nh)
            .add_community(Community::new(64500, 666));
        assert_eq!(b.next_hop, Some(nh));
        assert_eq!(b.communities.len(), 3);
        assert_eq!(b.communities[2], Community::new(64500, 666));
    }
}
