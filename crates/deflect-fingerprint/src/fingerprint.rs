use deflect_core::{DropReason, Observation, Packet, Stage, TcpFlags, Verdict, L4};

/// Number of leading payload bytes captured as a prefix feature.
pub const PREFIX_LEN: usize = 8;

/// A captured payload prefix: up to [`PREFIX_LEN`] leading bytes plus how many
/// are real, so a shorter payload is not confused with one zero-padded to the
/// same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub bytes: [u8; PREFIX_LEN],
    pub len: u8,
}

impl Prefix {
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

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        payload.starts_with(self.as_slice())
    }
}

/// A synthesized attack fingerprint: the conjunction of the feature values that
/// dominated a sample of unrecognised traffic. Every set field must hold for a
/// packet to match; unset fields are unconstrained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub l4: Option<L4>,
    pub dst_port: Option<u16>,
    pub wire_len: Option<u32>,
    pub flags: Option<TcpFlags>,
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
