use deflect_core::{DropReason, Observation, Packet, Stage, TcpFlags, Verdict, L4};

/// Number of leading payload bytes captured as a prefix feature.
pub const PREFIX_LEN: usize = 8;

/// A captured payload prefix: up to [`PREFIX_LEN`] leading bytes plus how many
/// are real, so a shorter payload is not confused with one zero-padded to the
/// same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    /// The leading payload bytes, zero-padded past [`Prefix::len`].
    pub bytes: [u8; PREFIX_LEN],
    /// How many of `bytes` are real payload; padding beyond it is not matched.
    pub len: u8,
}

impl Prefix {
    /// Capture the first [`PREFIX_LEN`] bytes of `payload` (fewer if shorter).
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Prefix {
        let n = payload.len().min(PREFIX_LEN);
        let mut bytes = [0u8; PREFIX_LEN];
        bytes[..n].copy_from_slice(&payload[..n]);
        // n <= PREFIX_LEN (8), so try_from always succeeds; the fallback is dead.
        Prefix {
            bytes,
            len: u8::try_from(n).unwrap_or(8),
        }
    }

    /// The real captured bytes, excluding any zero padding.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Whether `payload` begins with this prefix's captured bytes.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        payload.starts_with(self.as_slice())
    }
}

/// A synthesized attack fingerprint: the conjunction of the feature values that
/// dominated a sample of unrecognised traffic. Every set field must hold for a
/// packet to match; unset fields are unconstrained. Implements
/// [`deflect_core::Stage`], dropping any packet it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    /// Dominant transport protocol, when it too dominated; a refining constraint.
    pub l4: Option<L4>,
    /// Dominant destination port; a specific dimension that can justify a rule.
    pub dst_port: Option<u16>,
    /// Dominant wire length; a specific dimension that can justify a rule.
    pub wire_len: Option<u32>,
    /// Dominant non-zero TCP flags, when present; a refining constraint.
    pub flags: Option<TcpFlags>,
    /// Dominant non-empty payload prefix; a specific dimension that can justify a rule.
    pub prefix: Option<Prefix>,
    /// Lower-bound share (percent) of the sample this fingerprint covers,
    /// taken as the least-dominant of its constituent features.
    pub coverage_pct: u8,
}

impl Fingerprint {
    /// Count of constrained feature dimensions.
    #[must_use]
    pub fn specificity(&self) -> u8 {
        u8::from(self.l4.is_some())
            + u8::from(self.dst_port.is_some())
            + u8::from(self.wire_len.is_some())
            + u8::from(self.flags.is_some())
            + u8::from(self.prefix.is_some())
    }

    /// Whether `packet` satisfies every constrained dimension; unset fields
    /// impose no constraint.
    #[must_use]
    pub fn matches(&self, packet: &Packet<'_>) -> bool {
        if let Some(l4) = self.l4 {
            if l4 != packet.l4 {
                return false;
            }
        }
        if let Some(port) = self.dst_port {
            if port != packet.dst_port {
                return false;
            }
        }
        if let Some(len) = self.wire_len {
            if len != packet.wire_len {
                return false;
            }
        }
        if let Some(flags) = self.flags {
            if flags != packet.tcp_flags {
                return false;
            }
        }
        if let Some(prefix) = self.prefix {
            if !prefix.matches(packet.payload) {
                return false;
            }
        }
        true
    }
}

impl Stage for Fingerprint {
    fn evaluate(&self, obs: &Observation<'_>) -> Verdict {
        if self.matches(&obs.packet) {
            Verdict::Drop(DropReason::Fingerprint)
        } else {
            Verdict::Pass
        }
    }

    fn name(&self) -> &'static str {
        "fingerprint"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr};
    use deflect_core::Observation;

    fn pkt(l4: L4, dst_port: u16, wire_len: u32, flags: TcpFlags, payload: &[u8]) -> Packet<'_> {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        Packet::new(ip, ip, l4)
            .with_ports(1234, dst_port)
            .with_wire_len(wire_len)
            .with_flags(flags)
            .with_payload(payload)
    }

    #[test]
    fn specificity_counts_constrained_dimensions() {
        let none = Fingerprint {
            l4: None,
            dst_port: None,
            wire_len: None,
            flags: None,
            prefix: None,
            coverage_pct: 0,
        };
        assert_eq!(none.specificity(), 0);

        let all = Fingerprint {
            l4: Some(L4::Udp),
            dst_port: Some(53),
            wire_len: Some(100),
            flags: Some(TcpFlags::SYN),
            prefix: Some(Prefix::from_payload(b"ab")),
            coverage_pct: 90,
        };
        assert_eq!(all.specificity(), 5);
    }

    #[test]
    fn prefix_matches_only_its_own_bytes() {
        let p = Prefix::from_payload(b"abc");
        assert!(p.matches(b"abcdef"));
        assert!(!p.matches(b"xyz"));
        assert_eq!(p.as_slice(), b"abc");
    }

    #[test]
    fn flags_dimension_gates_matching() {
        let f = Fingerprint {
            l4: Some(L4::Tcp),
            dst_port: None,
            wire_len: None,
            flags: Some(TcpFlags::SYN),
            prefix: None,
            coverage_pct: 90,
        };
        assert!(f.matches(&pkt(L4::Tcp, 80, 40, TcpFlags::SYN, b"")));
        // Same packet but different flags must not match.
        assert!(!f.matches(&pkt(L4::Tcp, 80, 40, TcpFlags::ACK, b"")));
    }

    #[test]
    fn stage_name_is_stable() {
        let f = Fingerprint {
            l4: Some(L4::Udp),
            dst_port: Some(53),
            wire_len: None,
            flags: None,
            prefix: None,
            coverage_pct: 90,
        };
        assert_eq!(Stage::name(&f), "fingerprint");
        // And a non-match passes rather than drops.
        assert_eq!(
            Stage::evaluate(
                &f,
                &Observation::new(pkt(L4::Tcp, 53, 40, TcpFlags::empty(), b""), 0)
            ),
            Verdict::Pass
        );
    }
}
