use alloc::vec::Vec;
use core::fmt;

use crate::cidr::Cidr;
use crate::route::RtbhKind;

/// Why a blackhole was refused before it could ever be announced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// A destination blackhole for a prefix the operator has not declared it
    /// owns. Announcing it would be a route hijack, not a mitigation.
    Unowned(Cidr),
    /// The prefix is broader (numerically shorter) than the configured floor,
    /// so it would blackhole far more than the target.
    TooBroad {
        /// The refused prefix.
        prefix: Cidr,
        /// The broadest prefix length allowed for its family.
        floor: u8,
    },
    /// The default route (`/0`) — never blackhole-able; it is a total outage.
    DefaultRoute,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeError::Unowned(c) => {
                write!(
                    f,
                    "refusing to blackhole {c}: not within owned address space"
                )
            }
            ScopeError::TooBroad { prefix, floor } => write!(
                f,
                "refusing to blackhole {prefix}: broader than the /{floor} floor"
            ),
            ScopeError::DefaultRoute => write!(f, "refusing to blackhole the default route"),
        }
    }
}

/// The authorization boundary for blackhole announcements.
///
/// Blackholing is an act of self-harm by design: a destination blackhole asks
/// the upstream to drop *all* traffic to a prefix. Two mistakes turn it into an
/// outage or an attack of your own — advertising a prefix that is not yours (a
/// hijack), and advertising one so broad it discards far more than intended.
/// `Scope` refuses both before any command reaches the wire:
///
/// - **Ownership.** A destination blackhole must fall inside a declared owned
///   prefix. (Source blackholes name attacker space, which is not yours, so
///   ownership is not required for them.)
/// - **A blast-radius floor.** No blackhole may be broader than the per-family
///   floor, and the default route is always refused.
#[derive(Debug, Clone)]
pub struct Scope {
    owned: Vec<Cidr>,
    floor_v4: u8,
    floor_v6: u8,
}

impl Scope {
    /// A scope owning `owned`, with conservative floors (`/24`, `/48`): a
    /// blackhole may be as specific as a host but no broader than those.
    #[must_use]
    pub fn new(owned: Vec<Cidr>) -> Scope {
        Scope {
            owned,
            floor_v4: 24,
            floor_v6: 48,
        }
    }

    /// Set the broadest prefix a blackhole may use per family. A larger number
    /// is stricter (a smaller blast radius).
    #[must_use]
    pub fn with_floor(mut self, floor_v4: u8, floor_v6: u8) -> Scope {
        self.floor_v4 = floor_v4.min(32);
        self.floor_v6 = floor_v6.min(128);
        self
    }

    /// The declared owned prefixes a destination blackhole must fall within.
    #[must_use]
    pub fn owned(&self) -> &[Cidr] {
        &self.owned
    }

    fn floor_for(&self, prefix: &Cidr) -> u8 {
        if prefix.net().is_ipv4() {
            self.floor_v4
        } else {
            self.floor_v6
        }
    }

    /// Whether some owned prefix contains `prefix`.
    #[must_use]
    pub fn owns(&self, prefix: &Cidr) -> bool {
        self.owned.iter().any(|o| o.contains(prefix))
    }

    /// Decide whether a blackhole of `kind` for `prefix` may be announced.
    ///
    /// # Errors
    /// Returns a [`ScopeError`] if the prefix is the default route, broader than
    /// the floor, or (for a destination blackhole) not within owned space.
    pub fn authorize(&self, kind: RtbhKind, prefix: Cidr) -> Result<(), ScopeError> {
        if prefix.is_default_route() {
            return Err(ScopeError::DefaultRoute);
        }
        let floor = self.floor_for(&prefix);
        if prefix.prefix_len() < floor {
            return Err(ScopeError::TooBroad { prefix, floor });
        }
        if kind == RtbhKind::Destination && !self.owns(&prefix) {
            return Err(ScopeError::Unowned(prefix));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::net::IpAddr;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn scope() -> Scope {
        Scope::new(vec![Cidr::new(v4("203.0.113.0"), 24)])
    }

    #[test]
    fn owned_host_destination_is_authorized() {
        let s = scope();
        assert!(s
            .authorize(RtbhKind::Destination, Cidr::host(v4("203.0.113.9")))
            .is_ok());
    }

    #[test]
    fn unowned_destination_is_refused() {
        let s = scope();
        let p = Cidr::host(v4("198.51.100.9"));
        assert_eq!(
            s.authorize(RtbhKind::Destination, p),
            Err(ScopeError::Unowned(p))
        );
    }

    #[test]
    fn unowned_source_is_allowed_within_floor() {
        // Source RTBH names attacker space, which is not ours to own.
        let s = scope();
        assert!(s
            .authorize(RtbhKind::Source, Cidr::host(v4("198.51.100.9")))
            .is_ok());
    }

    #[test]
    fn too_broad_is_refused_even_if_owned() {
        let s = Scope::new(vec![Cidr::new(v4("203.0.0.0"), 16)]);
        let p = Cidr::new(v4("203.0.0.0"), 16);
        assert_eq!(
            s.authorize(RtbhKind::Destination, p),
            Err(ScopeError::TooBroad {
                prefix: p,
                floor: 24
            })
        );
    }

    #[test]
    fn default_route_always_refused() {
        let s = scope();
        assert_eq!(
            s.authorize(RtbhKind::Source, Cidr::new(v4("0.0.0.0"), 0)),
            Err(ScopeError::DefaultRoute)
        );
    }

    #[test]
    fn loosened_floor_permits_subnet() {
        let s = Scope::new(vec![Cidr::new(v4("203.0.0.0"), 16)]).with_floor(16, 32);
        assert!(s
            .authorize(RtbhKind::Destination, Cidr::new(v4("203.0.0.0"), 16))
            .is_ok());
    }

    #[test]
    fn owned_returns_the_configured_prefixes() {
        let owned = vec![
            Cidr::new(v4("203.0.113.0"), 24),
            Cidr::new(v4("198.18.0.0"), 15),
        ];
        let s = Scope::new(owned.clone());
        assert_eq!(s.owned(), owned.as_slice());
    }

    #[test]
    fn scope_error_messages_name_the_cause() {
        let p = Cidr::host(v4("198.51.100.9"));
        assert!(ScopeError::Unowned(p)
            .to_string()
            .contains("owned address space"));
        assert!(ScopeError::TooBroad {
            prefix: p,
            floor: 24
        }
        .to_string()
        .contains("broader than"));
        assert!(ScopeError::DefaultRoute
            .to_string()
            .contains("default route"));
    }
}
