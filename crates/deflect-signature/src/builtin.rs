use alloc::vec;
use alloc::vec::Vec;

use deflect_core::{DropReason, TcpFlags, L4};

use crate::matcher::FlagMatch;
use crate::set::SignatureSet;
use crate::signature::{Action, Signature};

const ALL_FLAGS: TcpFlags = TcpFlags(0xFF);

/// Illegal or scan-only TCP flag combinations. These never occur in a valid
/// handshake, so dropping them is safe regardless of load — unlike port- or
/// size-based heuristics, which can catch legitimate traffic and belong in the
/// stateful reflection and rate-limiting primitives instead.
#[must_use]
pub fn tcp_flag_anomalies() -> Vec<Signature> {
    let drop = Action::Drop(DropReason::Signature);
    vec![
        // NULL scan: no control bits set at all.
        Signature::new(1001, "tcp-null-scan")
            .proto(L4::Tcp)
            .flags(FlagMatch::any().forbid(ALL_FLAGS))
            .priority(10)
            .action(drop),
        // XMAS scan: FIN + PSH + URG lit up together.
        Signature::new(1002, "tcp-xmas-scan")
            .proto(L4::Tcp)
            .flags(FlagMatch::require(
                TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            ))
            .priority(10)
            .action(drop),
        // SYN+FIN: opening and closing in one segment.
        Signature::new(1003, "tcp-syn-fin")
            .proto(L4::Tcp)
            .flags(FlagMatch::require(TcpFlags::SYN | TcpFlags::FIN))
            .priority(10)
            .action(drop),
        // SYN+RST: contradictory control bits.
        Signature::new(1004, "tcp-syn-rst")
            .proto(L4::Tcp)
            .flags(FlagMatch::require(TcpFlags::SYN | TcpFlags::RST))
            .priority(10)
            .action(drop),
        // FIN scan: a bare FIN with no ACK, never valid mid-connection.
        Signature::new(1005, "tcp-fin-scan")
            .proto(L4::Tcp)
            .flags(FlagMatch::require(TcpFlags::FIN).forbid(TcpFlags::ACK))
            .priority(20)
            .action(drop),
    ]
}

/// A conservative baseline set safe to run unconditionally: only the
/// unambiguous TCP flag anomalies. Extend it with site-specific signatures.
#[must_use]
pub fn baseline() -> SignatureSet {
    SignatureSet::new(tcp_flag_anomalies())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr};
    use deflect_core::{Packet, Verdict};

    fn tcp<'a>(flags: TcpFlags) -> Packet<'a> {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        Packet::new(ip, ip, L4::Tcp)
            .with_ports(44000, 80)
            .with_flags(flags)
            .with_wire_len(40)
    }

    #[test]
    fn baseline_drops_null_scan() {
        let set = baseline();
        assert_eq!(
            set.classify(&tcp(TcpFlags::empty())),
            Verdict::Drop(DropReason::Signature)
        );
    }

    #[test]
    fn baseline_drops_xmas_and_syn_fin() {
        let set = baseline();
        assert!(set
            .classify(&tcp(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG))
            .blocks());
        assert!(set.classify(&tcp(TcpFlags::SYN | TcpFlags::FIN)).blocks());
    }

    #[test]
    fn baseline_passes_normal_syn() {
        let set = baseline();
        assert_eq!(set.classify(&tcp(TcpFlags::SYN)), Verdict::Pass);
    }

    #[test]
    fn baseline_passes_established_ack() {
        let set = baseline();
        assert_eq!(
            set.classify(&tcp(TcpFlags::ACK | TcpFlags::PSH)),
            Verdict::Pass
        );
    }
}
