use core::time::Duration;

/// Why a stage decided to drop traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DropReason {
    /// The source exceeded its allowed packet or byte rate.
    RateExceeded,
    /// The packet matched a known-bad byte signature.
    Signature,
    /// The packet is part of a reflection or amplification pattern.
    Reflection,
    /// The source's protocol fingerprint marks it as hostile.
    Fingerprint,
    /// A SYN-cookie or challenge token failed validation.
    InvalidCookie,
    /// The source is on an active ban list.
    Banned,
    /// The packet could not be parsed as well-formed.
    MalformedPacket,
}

/// A challenge a source must satisfy before it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ChallengeKind {
    /// Prove liveness by completing a TCP handshake against a SYN cookie.
    SynCookie,
}

/// The decision a mitigation stage returns for one observation.
///
/// Verdicts form a total order of severity so a pipeline can keep the most
/// severe decision across its stages: `Pass < Challenge < RateLimit < Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Verdict {
    /// Allow the observation through untouched; the least severe verdict.
    #[default]
    Pass,
    /// Admit the source only once it satisfies the given challenge.
    Challenge(ChallengeKind),
    /// Throttle the source, telling it to retry no sooner than `retry_after`.
    RateLimit {
        /// Minimum delay the source must wait before retrying.
        retry_after: Duration,
    },
    /// Drop the observation for the given reason; the most severe verdict.
    Drop(DropReason),
}

impl Verdict {
    /// Returns the severity rank: `Pass` 0, `Challenge` 1, `RateLimit` 2, `Drop` 3.
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::Challenge(_) => 1,
            Verdict::RateLimit { .. } => 2,
            Verdict::Drop(_) => 3,
        }
    }

    /// True only for `Pass`.
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    /// True when the verdict denies service: `Drop` or `RateLimit`, not `Challenge`.
    #[must_use]
    pub const fn blocks(&self) -> bool {
        matches!(self, Verdict::Drop(_) | Verdict::RateLimit { .. })
    }

    /// Combine two verdicts, keeping the more severe. On equal severity the
    /// left verdict wins, so a pipeline's earlier stages set the reason.
    #[must_use]
    pub fn worst(self, other: Verdict) -> Verdict {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_is_ordered() {
        assert!(Verdict::Pass.severity() < Verdict::Challenge(ChallengeKind::SynCookie).severity());
        assert!(
            Verdict::Challenge(ChallengeKind::SynCookie).severity()
                < Verdict::RateLimit {
                    retry_after: Duration::ZERO
                }
                .severity()
        );
        assert!(
            Verdict::RateLimit {
                retry_after: Duration::ZERO
            }
            .severity()
                < Verdict::Drop(DropReason::Banned).severity()
        );
    }

    #[test]
    fn worst_keeps_more_severe() {
        let drop = Verdict::Drop(DropReason::Signature);
        assert_eq!(Verdict::Pass.worst(drop), drop);
        assert_eq!(drop.worst(Verdict::Pass), drop);
    }

    #[test]
    fn worst_left_wins_on_tie() {
        let a = Verdict::Drop(DropReason::Signature);
        let b = Verdict::Drop(DropReason::Banned);
        assert_eq!(a.worst(b), a);
    }

    #[test]
    fn is_pass_only_for_pass() {
        assert!(Verdict::Pass.is_pass());
        assert!(!Verdict::Challenge(ChallengeKind::SynCookie).is_pass());
        assert!(!Verdict::Drop(DropReason::Banned).is_pass());
    }

    #[test]
    fn blocks_for_ratelimit_and_drop_only() {
        assert!(Verdict::Drop(DropReason::Signature).blocks());
        assert!(Verdict::RateLimit {
            retry_after: Duration::ZERO
        }
        .blocks());
        assert!(!Verdict::Pass.blocks());
        assert!(!Verdict::Challenge(ChallengeKind::SynCookie).blocks());
    }

    #[test]
    fn worst_is_symmetric_in_severity() {
        // Whichever order, the kept verdict has the higher severity.
        let hi = Verdict::RateLimit {
            retry_after: Duration::ZERO,
        };
        let lo = Verdict::Challenge(ChallengeKind::SynCookie);
        assert_eq!(lo.worst(hi), hi);
        assert_eq!(hi.worst(lo), hi);
    }
}
