use alloc::vec::Vec;

use deflect_core::TcpFlags;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// How a signature constrains a port field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PortMatch {
    /// Matches any port.
    #[default]
    Any,
    /// Matches exactly this port.
    Exact(u16),
    /// Inclusive range `[lo, hi]`; constructed normalised so `lo <= hi`.
    Range(u16, u16),
    /// Matches any port in the list.
    OneOf(Vec<u16>),
}

impl PortMatch {
    /// A [`PortMatch::Range`] with the bounds normalised so the smaller is `lo`.
    #[must_use]
    pub fn range(a: u16, b: u16) -> PortMatch {
        PortMatch::Range(a.min(b), a.max(b))
    }

    /// True if `port` satisfies this constraint.
    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatch::Any => true,
            PortMatch::Exact(p) => *p == port,
            PortMatch::Range(lo, hi) => (*lo..=*hi).contains(&port),
            PortMatch::OneOf(ports) => ports.contains(&port),
        }
    }
}

/// How a signature constrains TCP control bits: every bit in `required` must be
/// set and every bit in `forbidden` must be clear. An empty match accepts any
/// flags, so a non-TCP signature leaves this at its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FlagMatch {
    /// Bitmask of control bits that must all be set.
    pub required: u8,
    /// Bitmask of control bits that must all be clear.
    pub forbidden: u8,
}

impl FlagMatch {
    /// A match that accepts any flags (no bits required or forbidden).
    #[must_use]
    pub const fn any() -> FlagMatch {
        FlagMatch {
            required: 0,
            forbidden: 0,
        }
    }

    /// A match requiring every bit in `flags` to be set.
    #[must_use]
    pub const fn require(flags: TcpFlags) -> FlagMatch {
        FlagMatch {
            required: flags.bits(),
            forbidden: 0,
        }
    }

    /// Adds `flags` to the forbidden set and returns `self`.
    #[must_use]
    pub const fn forbid(mut self, flags: TcpFlags) -> FlagMatch {
        self.forbidden |= flags.bits();
        self
    }

    /// Adds `flags` to the required set and returns `self`.
    #[must_use]
    pub const fn and_require(mut self, flags: TcpFlags) -> FlagMatch {
        self.required |= flags.bits();
        self
    }

    /// True if every required bit is set in `flags` and no forbidden bit is.
    #[must_use]
    pub fn matches(&self, flags: TcpFlags) -> bool {
        let bits = flags.bits();
        (bits & self.required) == self.required && (bits & self.forbidden) == 0
    }
}

/// How a signature constrains the packet payload. Length bounds are in bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PayloadMatch {
    /// Matches any payload, including empty.
    #[default]
    Any,
    /// Payload length is at least `n`.
    MinLen(u32),
    /// Payload length is at most `n`.
    MaxLen(u32),
    /// The payload begins, at `offset`, with exactly `bytes`.
    PrefixAt {
        /// Byte offset into the payload at which to compare.
        offset: u32,
        /// Exact bytes expected starting at `offset`.
        bytes: Vec<u8>,
    },
    /// `bytes` occurs anywhere in the payload.
    Contains(Vec<u8>),
}

impl PayloadMatch {
    /// True if `payload` satisfies this constraint; an out-of-range offset or
    /// empty `Contains` needle never panics.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        match self {
            PayloadMatch::Any => true,
            PayloadMatch::MinLen(n) => payload.len() as u64 >= u64::from(*n),
            PayloadMatch::MaxLen(n) => payload.len() as u64 <= u64::from(*n),
            PayloadMatch::PrefixAt { offset, bytes } => {
                let off = *offset as usize;
                payload
                    .get(off..)
                    .is_some_and(|tail| tail.starts_with(bytes))
            }
            PayloadMatch::Contains(bytes) => {
                if bytes.is_empty() {
                    return true;
                }
                memchr::memmem::find(payload, bytes).is_some()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn port_match_variants() {
        assert!(PortMatch::Any.matches(1234));
        assert!(PortMatch::Exact(53).matches(53));
        assert!(!PortMatch::Exact(53).matches(54));
        assert!(PortMatch::range(100, 200).matches(150));
        assert!(!PortMatch::range(100, 200).matches(99));
        assert!(PortMatch::range(200, 100).matches(150)); // normalised
        assert!(PortMatch::OneOf(vec![53, 123, 1900]).matches(123));
        assert!(!PortMatch::OneOf(vec![53, 123]).matches(80));
    }

    #[test]
    fn flag_match_requires_and_forbids() {
        let syn_not_ack = FlagMatch::require(TcpFlags::SYN).forbid(TcpFlags::ACK);
        assert!(syn_not_ack.matches(TcpFlags::SYN));
        assert!(!syn_not_ack.matches(TcpFlags::SYN | TcpFlags::ACK));
        assert!(!syn_not_ack.matches(TcpFlags::empty()));
    }

    #[test]
    fn flag_match_any_accepts_everything() {
        assert!(FlagMatch::any().matches(TcpFlags::empty()));
        assert!(FlagMatch::any().matches(TcpFlags::SYN | TcpFlags::ACK | TcpFlags::FIN));
    }

    #[test]
    fn and_require_accumulates_required_bits() {
        let both = FlagMatch::require(TcpFlags::SYN).and_require(TcpFlags::ACK);
        assert!(both.matches(TcpFlags::SYN | TcpFlags::ACK));
        // Each required bit is necessary; neither alone suffices.
        assert!(!both.matches(TcpFlags::SYN));
        assert!(!both.matches(TcpFlags::ACK));
    }

    #[test]
    fn payload_len_bounds() {
        assert!(PayloadMatch::MinLen(4).matches(&[0, 1, 2, 3]));
        assert!(!PayloadMatch::MinLen(5).matches(&[0, 1, 2, 3]));
        assert!(PayloadMatch::MaxLen(4).matches(&[0, 1, 2, 3]));
        assert!(!PayloadMatch::MaxLen(3).matches(&[0, 1, 2, 3]));
    }

    #[test]
    fn payload_prefix_at_offset() {
        let m = PayloadMatch::PrefixAt {
            offset: 2,
            bytes: vec![0xAA, 0xBB],
        };
        assert!(m.matches(&[0, 1, 0xAA, 0xBB, 2]));
        assert!(!m.matches(&[0, 1, 0xAA, 0xCC]));
        // Offset beyond the payload never matches and never panics.
        assert!(!m.matches(&[0]));
    }

    #[test]
    fn payload_contains() {
        let m = PayloadMatch::Contains(vec![0x13, 0x37]);
        assert!(m.matches(&[0, 0, 0x13, 0x37, 0]));
        assert!(!m.matches(&[0x13, 0x00, 0x37]));
        assert!(PayloadMatch::Contains(vec![]).matches(&[]));
    }
}
