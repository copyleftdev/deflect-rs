use alloc::vec::Vec;

use deflect_core::{Observation, Packet, Stage, Verdict};

use crate::signature::Signature;

/// An ordered collection of [`Signature`]s evaluated against each packet.
///
/// Signatures are sorted by `priority` (ascending) at construction; the first
/// that matches decides the verdict, so an `Allow` placed at a low priority
/// acts as an allowlist that short-circuits later drops. A no-match is `Pass`.
#[derive(Debug, Clone, Default)]
pub struct SignatureSet {
    signatures: Vec<Signature>,
}

impl SignatureSet {
    #[must_use]
    pub fn new(mut signatures: Vec<Signature>) -> SignatureSet {
        signatures.sort_by_key(|s| s.priority);
        SignatureSet { signatures }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn push(&mut self, sig: Signature) {
        let at = self
            .signatures
            .partition_point(|s| s.priority <= sig.priority);
        self.signatures.insert(at, sig);
    }

    /// The first signature that matches `packet`, in priority order.
    #[must_use]
    pub fn first_match(&self, packet: &Packet<'_>) -> Option<&Signature> {
        self.signatures.iter().find(|s| s.matches(packet))
    }

    /// The verdict for `packet`: the first matching signature's action, else
    /// [`Verdict::Pass`].
    #[must_use]
    pub fn classify(&self, packet: &Packet<'_>) -> Verdict {
        self.first_match(packet)
            .map_or(Verdict::Pass, |s| s.action.verdict())
    }

    /// Iterate the signatures in evaluation (priority) order.
    pub fn iter(&self) -> impl Iterator<Item = &Signature> {
        self.signatures.iter()
    }
}

impl Stage for SignatureSet {
    fn evaluate(&self, obs: &Observation<'_>) -> Verdict {
        self.classify(&obs.packet)
    }

    fn name(&self) -> &'static str {
        "signature_set"
    }
}

impl FromIterator<Signature> for SignatureSet {
    fn from_iter<I: IntoIterator<Item = Signature>>(iter: I) -> Self {
        SignatureSet::new(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr};
    use deflect_core::{DropReason, TcpFlags, L4};

    use crate::matcher::{FlagMatch, PortMatch};
    use crate::signature::Action;

    fn pkt<'a>(l4: L4, src_port: u16, dst_port: u16) -> Packet<'a> {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        Packet::new(ip, ip, l4)
            .with_ports(src_port, dst_port)
            .with_wire_len(512)
    }

    fn drop_udp_dns() -> Signature {
        Signature::new(1, "udp-dns-src")
            .proto(L4::Udp)
            .src_port(PortMatch::Exact(53))
            .action(Action::Drop(DropReason::Reflection))
    }

    #[test]
    fn matches_and_drops() {
        let set = SignatureSet::new(vec![drop_udp_dns()]);
        assert_eq!(
            set.classify(&pkt(L4::Udp, 53, 40000)),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn no_match_passes() {
        let set = SignatureSet::new(vec![drop_udp_dns()]);
        assert_eq!(set.classify(&pkt(L4::Udp, 80, 40000)), Verdict::Pass);
        assert_eq!(set.classify(&pkt(L4::Tcp, 53, 40000)), Verdict::Pass);
    }

    #[test]
    fn allowlist_short_circuits_a_later_drop() {
        let allow = Signature::new(2, "trusted-resolver")
            .proto(L4::Udp)
            .src_port(PortMatch::Exact(53))
            .dst_port(PortMatch::Exact(40000))
            .priority(-10)
            .allow();
        let set = SignatureSet::new(vec![drop_udp_dns(), allow]);
        // The allow has lower priority value, so it is evaluated first.
        assert_eq!(set.classify(&pkt(L4::Udp, 53, 40000)), Verdict::Pass);
        // A different dst port misses the allow and hits the drop.
        assert_eq!(
            set.classify(&pkt(L4::Udp, 53, 40001)),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn priority_orders_evaluation() {
        let hi = Signature::new(10, "hi").priority(5).action(Action::Allow);
        let lo = Signature::new(11, "lo")
            .priority(1)
            .action(Action::Drop(DropReason::Signature));
        let set = SignatureSet::new(vec![hi, lo]);
        // Both match everything; priority 1 (drop) wins over priority 5 (allow).
        assert_eq!(
            set.classify(&pkt(L4::Udp, 1, 2)),
            Verdict::Drop(DropReason::Signature)
        );
    }

    #[test]
    fn push_keeps_priority_order() {
        let mut set = SignatureSet::new(vec![Signature::new(1, "a")
            .priority(10)
            .action(Action::Allow)]);
        set.push(
            Signature::new(2, "b")
                .priority(1)
                .action(Action::Drop(DropReason::Signature)),
        );
        assert_eq!(set.iter().next().unwrap().id, 2);
    }

    #[test]
    fn len_and_is_empty_track_contents() {
        let empty = SignatureSet::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let set = SignatureSet::new(vec![drop_udp_dns()]);
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn stage_evaluate_returns_the_match_verdict() {
        let set = SignatureSet::new(vec![drop_udp_dns()]);
        let p = pkt(L4::Udp, 53, 40000);
        assert_eq!(
            Stage::evaluate(&set, &Observation::new(p, 0)),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn stage_name_is_stable() {
        assert_eq!(Stage::name(&SignatureSet::default()), "signature_set");
    }

    #[test]
    fn from_iter_collects_into_a_working_set() {
        let set: SignatureSet = [drop_udp_dns()].into_iter().collect();
        assert_eq!(set.len(), 1);
        assert_eq!(
            set.classify(&pkt(L4::Udp, 53, 40000)),
            Verdict::Drop(DropReason::Reflection)
        );
    }

    #[test]
    fn tcp_flag_signature_ignores_non_tcp() {
        let xmas = Signature::new(3, "xmas")
            .proto(L4::Tcp)
            .flags(FlagMatch::require(
                TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            ))
            .action(Action::Drop(DropReason::Signature));
        let set = SignatureSet::new(vec![xmas]);
        let mut tcp = pkt(L4::Tcp, 1, 2);
        tcp.tcp_flags = TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;
        assert_eq!(set.classify(&tcp), Verdict::Drop(DropReason::Signature));
        // Same flags-shaped packet but UDP must not match.
        assert_eq!(set.classify(&pkt(L4::Udp, 1, 2)), Verdict::Pass);
    }
}
