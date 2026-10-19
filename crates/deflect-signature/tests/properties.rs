//! Property tests for the matching engine: each matcher agrees with its own
//! definition across the input space, and a set's verdict is exactly the
//! first-matching signature's action (else Pass).

use core::net::{IpAddr, Ipv4Addr};

use deflect_core::{DropReason, Packet, TcpFlags, L4};
use deflect_signature::{Action, FlagMatch, PayloadMatch, PortMatch, Signature, SignatureSet};
use proptest::prelude::*;

proptest! {
    #[test]
    fn flag_match_agrees_with_definition(req in any::<u8>(), forbid in any::<u8>(), flags in any::<u8>()) {
        let m = FlagMatch { required: req, forbidden: forbid };
        let expected = (flags & req) == req && (flags & forbid) == 0;
        prop_assert_eq!(m.matches(TcpFlags(flags)), expected);
    }

    #[test]
    fn port_range_is_normalised_and_inclusive(a in any::<u16>(), b in any::<u16>(), p in any::<u16>()) {
        let m = PortMatch::range(a, b);
        let (lo, hi) = (a.min(b), a.max(b));
        prop_assert_eq!(m.matches(p), p >= lo && p <= hi);
    }

    #[test]
    fn payload_length_bounds_agree(len in 0usize..2_048, n in any::<u32>()) {
        let payload = vec![0u8; len];
        prop_assert_eq!(
            PayloadMatch::MinLen(n).matches(&payload),
            u64::try_from(len).unwrap() >= u64::from(n)
        );
        prop_assert_eq!(
            PayloadMatch::MaxLen(n).matches(&payload),
            u64::try_from(len).unwrap() <= u64::from(n)
        );
    }

    #[test]
    fn classify_is_the_first_match_in_priority_order(
        ports in prop::collection::vec((any::<u16>(), 0i32..1_000, any::<bool>()), 0..8),
        probe in any::<u16>(),
    ) {
        // Build signatures that each match one exact dst port; classify must
        // agree with a hand-rolled lowest-priority-first scan.
        let sigs: Vec<Signature> = ports.iter().enumerate().map(|(i, &(port, prio, allow))| {
            let s = Signature::new(u32::try_from(i).unwrap(), "p")
                .proto(L4::Udp)
                .dst_port(PortMatch::Exact(port))
                .priority(prio);
            if allow { s.allow() } else { s.action(Action::Drop(DropReason::Signature)) }
        }).collect();
        let set = SignatureSet::new(sigs.clone());

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let pkt = Packet::new(ip, ip, L4::Udp).with_ports(1, probe);

        // Expected: the matching signature with the smallest priority wins.
        let expected = sigs
            .iter()
            .filter(|s| s.dst_port == PortMatch::Exact(probe))
            .min_by_key(|s| s.priority)
            .map_or(deflect_core::Verdict::Pass, |s| s.action.verdict());
        prop_assert_eq!(set.classify(&pkt), expected);
    }
}
