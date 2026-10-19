//! Property tests for the core contract. These assert the laws the data plane
//! relies on — verdict severity is a lattice, masking only ever clears bits,
//! protocol numbers round-trip — across the whole input space, not just the
//! examples the unit tests pin down.

use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;

use deflect_core::{Aggregation, ChallengeKind, DropReason, SourceKey, TcpFlags, Verdict, L4};
use proptest::prelude::*;

fn verdict_of_severity(s: u8) -> Verdict {
    match s {
        0 => Verdict::Pass,
        1 => Verdict::Challenge(ChallengeKind::SynCookie),
        2 => Verdict::RateLimit {
            retry_after: Duration::ZERO,
        },
        _ => Verdict::Drop(DropReason::Banned),
    }
}

proptest! {
    #[test]
    fn worst_keeps_the_higher_severity(a in 0u8..=3, b in 0u8..=3) {
        let w = verdict_of_severity(a).worst(verdict_of_severity(b));
        prop_assert_eq!(w.severity(), a.max(b));
    }

    #[test]
    fn worst_is_idempotent(a in 0u8..=3) {
        let v = verdict_of_severity(a);
        prop_assert_eq!(v.worst(v), v);
    }

    #[test]
    fn pass_is_the_identity_of_worst(a in 0u8..=3) {
        let v = verdict_of_severity(a);
        prop_assert_eq!(Verdict::Pass.worst(v), v);
        prop_assert_eq!(v.worst(Verdict::Pass).severity(), v.severity());
    }

    #[test]
    fn worst_is_associative_in_severity(a in 0u8..=3, b in 0u8..=3, c in 0u8..=3) {
        let (va, vb, vc) = (
            verdict_of_severity(a),
            verdict_of_severity(b),
            verdict_of_severity(c),
        );
        prop_assert_eq!(va.worst(vb).worst(vc).severity(), va.worst(vb.worst(vc)).severity());
    }

    #[test]
    fn l4_protocol_number_roundtrips(p in any::<u8>()) {
        prop_assert_eq!(L4::from_ip_proto(p).ip_proto(), p);
    }

    #[test]
    fn tcp_flag_predicates_match_their_definitions(a in any::<u8>(), b in any::<u8>()) {
        let (fa, fb) = (TcpFlags(a), TcpFlags(b));
        prop_assert_eq!(fa.contains(fb), (a & b) == b);
        prop_assert_eq!(fa.intersects(fb), (a & b) != 0);
        prop_assert_eq!(fa.is_empty(), a == 0);
        prop_assert_eq!(fa.bits(), a);
    }

    #[test]
    fn tcp_union_contains_both_operands(a in any::<u8>(), b in any::<u8>()) {
        let u = TcpFlags(a) | TcpFlags(b);
        prop_assert!(u.contains(TcpFlags(a)));
        prop_assert!(u.contains(TcpFlags(b)));
        prop_assert_eq!(u.bits(), a | b);
    }

    #[test]
    fn masking_only_clears_bits(o in any::<[u8; 4]>(), bits in 0u8..=32) {
        let agg = Aggregation::new(bits, 64);
        let key = SourceKey::new(IpAddr::V4(Ipv4Addr::from(o)), agg);
        let SourceKey::V4(masked) = key else {
            unreachable!("v4 input yields a v4 key")
        };
        for i in 0..4 {
            // A masked octet can only turn bits off, never on.
            prop_assert_eq!(masked[i] & !o[i], 0);
        }
    }

    #[test]
    fn masking_is_idempotent(o in any::<[u8; 4]>(), bits in 0u8..=32) {
        let agg = Aggregation::new(bits, 64);
        let addr = IpAddr::V4(Ipv4Addr::from(o));
        let once = SourceKey::new(addr, agg);
        let twice = SourceKey::new(once.addr(), agg);
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn full_prefix_is_the_identity(o in any::<[u8; 4]>()) {
        let key = SourceKey::new(IpAddr::V4(Ipv4Addr::from(o)), Aggregation::HOST);
        prop_assert_eq!(key, SourceKey::V4(o));
    }
}
