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
    pub id: u32,
    pub name: Cow<'static, str>,
    pub priority: i32,
    #[cfg_attr(feature = "serde", serde(default))]
    pub l4: Option<L4>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub src_port: PortMatch,
    #[cfg_attr(feature = "serde", serde(default))]
    pub dst_port: PortMatch,
    #[cfg_attr(feature = "serde", serde(default = "FlagMatch::any"))]
    pub flags: FlagMatch,
    #[cfg_attr(feature = "serde", serde(default))]
    pub min_wire_len: u32,
    #[cfg_attr(feature = "serde", serde(default = "max_wire_default"))]
    pub max_wire_len: u32,
    #[cfg_attr(feature = "serde", serde(default))]
    pub payload: PayloadMatch,
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

    #[must_use]
    pub fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    #[must_use]
    pub fn proto(mut self, l4: L4) -> Self {
        self.l4 = Some(l4);
        self
    }

    #[must_use]
    pub fn src_port(mut self, m: PortMatch) -> Self {
        self.src_port = m;
        self
    }

    #[must_use]
    pub fn dst_port(mut self, m: PortMatch) -> Self {
        self.dst_port = m;
        self
    }

    #[must_use]
    pub fn flags(mut self, m: FlagMatch) -> Self {
        self.flags = m;
        self
    }

    #[must_use]
    pub fn wire_len(mut self, min: u32, max: u32) -> Self {
        self.min_wire_len = min.min(max);
        self.max_wire_len = min.max(max);
        self
    }

    #[must_use]
    pub fn payload(mut self, m: PayloadMatch) -> Self {
        self.payload = m;
        self
    }

    #[must_use]
    pub fn action(mut self, a: Action) -> Self {
        self.action = a;
        self
    }

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
