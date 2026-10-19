//! Property tests for the blackhole authorization boundary. These assert the
//! safety laws across the whole input space: masking only clears host bits,
//! containment is a partial order, and `Scope` never authorizes a destination
//! blackhole outside owned space or broader than the floor.

use core::net::{IpAddr, Ipv4Addr};

use deflect_bgp::{Cidr, RtbhKind, Scope};
use proptest::prelude::*;

fn v4(o: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(o))
}

proptest! {
    #[test]
    fn construction_is_idempotent(o in any::<[u8; 4]>(), len in 0u8..=32) {
        let once = Cidr::new(v4(o), len);
        let twice = Cidr::new(once.net(), len);
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn masking_only_clears_bits(o in any::<[u8; 4]>(), len in 0u8..=32) {
        let net = Cidr::new(v4(o), len).net();
        let IpAddr::V4(masked) = net else {
            unreachable!("v4 input yields a v4 network")
        };
        let m = masked.octets();
        for i in 0..4 {
            prop_assert_eq!(m[i] & !o[i], 0);
        }
    }

    #[test]
    fn contains_is_reflexive(o in any::<[u8; 4]>(), len in 0u8..=32) {
        let c = Cidr::new(v4(o), len);
        prop_assert!(c.contains(&c));
    }

    #[test]
    fn a_prefix_contains_its_hosts(o in any::<[u8; 4]>(), len in 0u8..=32) {
        let block = Cidr::new(v4(o), len);
        let host = Cidr::host(v4(o));
        // The block was built from this address, so it must contain that host.
        prop_assert!(block.contains(&host));
        // And a container is never more specific than what it contains.
        prop_assert!(block.prefix_len() <= host.prefix_len());
    }

    #[test]
    fn destination_authorization_matches_ownership(
        owned_o in any::<[u8; 4]>(),
        target_o in any::<[u8; 4]>(),
    ) {
        // Owned space is a /16; floor is the default /24 so a /32 target is fine.
        let owned = Cidr::new(v4(owned_o), 16);
        let scope = Scope::new(vec![owned]);
        let target = Cidr::host(v4(target_o));
        let authorized = scope
            .authorize(RtbhKind::Destination, target)
            .is_ok();
        // Authorized iff the target is genuinely inside owned space.
        prop_assert_eq!(authorized, owned.contains(&target));
    }

    #[test]
    fn nothing_broader_than_the_floor_is_authorized(
        o in any::<[u8; 4]>(),
        len in 0u8..24,
    ) {
        // Any owned prefix, but a target broader than the /24 floor.
        let scope = Scope::new(vec![Cidr::new(v4(o), 8)]);
        let target = Cidr::new(v4(o), len);
        prop_assert!(scope.authorize(RtbhKind::Destination, target).is_err());
        prop_assert!(scope.authorize(RtbhKind::Source, target).is_err());
    }
}
