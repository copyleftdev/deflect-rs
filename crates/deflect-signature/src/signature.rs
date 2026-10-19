use alloc::borrow::Cow;

use deflect_core::{DropReason, Packet, Verdict, L4};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::matcher::{FlagMatch, PayloadMatch, PortMatch};

/// What to do with a packet a signature matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Action {
    /// Allowlist: stop evaluation and pass the packet.
    Allow,
    /// Drop the packet, attributing it to `reason`.
    Drop(DropReason),
}

impl Action {
    /// The [`Verdict`] this action yields: `Allow` passes, `Drop(reason)` drops
    /// carrying the same reason.
    #[must_use]
    pub fn verdict(self) -> Verdict {
        match self {
            Action::Allow => Verdict::Pass,
            Action::Drop(reason) => Verdict::Drop(reason),
        }
    }
}

/// One matchable rule. Every set condition must hold (logical AND) for the
/// signature to match; unset conditions are left at their permissive default.
///
/// Signatures carry a `priority` used only to order a set; lower sorts first
/// and therefore wins when several match.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// Caller-assigned identifier, surfaced for reporting; not used in matching.
    pub id: u32,
    /// Human-readable label for the rule; not used in matching.
    pub name: Cow<'static, str>,
    /// Evaluation order within a set; lower sorts first and wins on a tie.
    pub priority: i32,
    /// Required L4 protocol, or `None` to match any protocol.
    #[cfg_attr(feature = "serde", serde(default))]
    pub l4: Option<L4>,
    /// Constraint on the packet's source port.
    #[cfg_attr(feature = "serde", serde(default))]
    pub src_port: PortMatch,
    /// Constraint on the packet's destination port.
    #[cfg_attr(feature = "serde", serde(default))]
    pub dst_port: PortMatch,
    /// Constraint on TCP control bits; applies only to TCP packets.
    #[cfg_attr(feature = "serde", serde(default = "FlagMatch::any"))]
    pub flags: FlagMatch,
    /// Minimum on-wire length in bytes (inclusive); defaults to 0.
    #[cfg_attr(feature = "serde", serde(default))]
    pub min_wire_len: u32,
    /// Maximum on-wire length in bytes (inclusive); defaults to `u32::MAX`.
    #[cfg_attr(feature = "serde", serde(default = "max_wire_default"))]
    pub max_wire_len: u32,
    /// Constraint on the packet payload bytes.
    #[cfg_attr(feature = "serde", serde(default))]
    pub payload: PayloadMatch,
    /// Verdict to apply when every condition holds.
    pub action: Action,
}

#[cfg(feature = "serde")]
fn max_wire_default() -> u32 {
    u32::MAX
}

impl Signature {
    /// A permissive signature that matches every packet and drops it; refine it
    /// with the builder methods, then set a real [`Action`].
    #[must_use]
    pub fn new(id: u32, name: impl Into<Cow<'static, str>>) -> Signature {
        Signature {
            id,
            name: name.into(),
            priority: 0,
            l4: None,
            src_port: PortMatch::Any,
            dst_port: PortMatch::Any,
            flags: FlagMatch::any(),
            min_wire_len: 0,
            max_wire_len: u32::MAX,
            payload: PayloadMatch::Any,
            action: Action::Drop(DropReason::Signature),
        }
    }

    /// Sets the evaluation priority and returns `self`.
    #[must_use]
    pub fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    /// Pins the required L4 protocol and returns `self`.
    #[must_use]
    pub fn proto(mut self, l4: L4) -> Self {
        self.l4 = Some(l4);
        self
    }

    /// Sets the source-port constraint and returns `self`.
    #[must_use]
    pub fn src_port(mut self, m: PortMatch) -> Self {
        self.src_port = m;
        self
    }

    /// Sets the destination-port constraint and returns `self`.
    #[must_use]
    pub fn dst_port(mut self, m: PortMatch) -> Self {
        self.dst_port = m;
        self
    }

    /// Sets the TCP flag constraint and returns `self`.
    #[must_use]
    pub fn flags(mut self, m: FlagMatch) -> Self {
        self.flags = m;
        self
    }

    /// Sets the inclusive wire-length bounds and returns `self`; the arguments
    /// are normalised so the smaller becomes the minimum.
    #[must_use]
    pub fn wire_len(mut self, min: u32, max: u32) -> Self {
        self.min_wire_len = min.min(max);
        self.max_wire_len = min.max(max);
        self
    }

    /// Sets the payload constraint and returns `self`.
    #[must_use]
    pub fn payload(mut self, m: PayloadMatch) -> Self {
        self.payload = m;
        self
    }

    /// Sets the action to apply on a match and returns `self`.
    #[must_use]
    pub fn action(mut self, a: Action) -> Self {
        self.action = a;
        self
    }

    /// Sets the action to [`Action::Allow`], making this an allowlist rule, and
    /// returns `self`.
    #[must_use]
    pub fn allow(mut self) -> Self {
        self.action = Action::Allow;
        self
    }

    /// True if `packet` satisfies every condition of this signature.
    #[must_use]
    pub fn matches(&self, packet: &Packet<'_>) -> bool {
        if let Some(l4) = self.l4 {
            if l4 != packet.l4 {
                return false;
            }
        }
        if packet.wire_len < self.min_wire_len || packet.wire_len > self.max_wire_len {
            return false;
        }
        if !self.src_port.matches(packet.src_port) || !self.dst_port.matches(packet.dst_port) {
            return false;
        }
        // Flag constraints are meaningful only for TCP; a flag-bearing signature
        // should also pin `l4 = Tcp`, but guard here so a stray constraint on a
        // non-TCP packet cannot match on its always-zero flags.
        if self.flags != FlagMatch::any() {
            if packet.l4 != L4::Tcp {
                return false;
            }
            if !self.flags.matches(packet.tcp_flags) {
                return false;
            }
        }
        self.payload.matches(packet.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr};

    fn pkt_len<'a>(wire_len: u32) -> Packet<'a> {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        Packet::new(ip, ip, L4::Udp).with_wire_len(wire_len)
    }

    fn len_sig() -> Signature {
        Signature::new(1, "len")
            .proto(L4::Udp)
            .wire_len(100, 200)
            .action(Action::Drop(DropReason::Signature))
    }

    #[test]
    fn wire_len_bounds_are_inclusive() {
        let s = len_sig();
        assert!(s.matches(&pkt_len(100)), "lower bound is inclusive");
        assert!(s.matches(&pkt_len(200)), "upper bound is inclusive");
        assert!(s.matches(&pkt_len(150)));
        assert!(!s.matches(&pkt_len(99)), "below min must not match");
        assert!(!s.matches(&pkt_len(201)), "above max must not match");
    }

    #[test]
    fn action_verdict_maps_both_arms() {
        assert_eq!(Action::Allow.verdict(), Verdict::Pass);
        assert_eq!(
            Action::Drop(DropReason::Signature).verdict(),
            Verdict::Drop(DropReason::Signature)
        );
    }
}
