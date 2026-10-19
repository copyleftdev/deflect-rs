const NANOS_PER_SEC: u128 = 1_000_000_000;

/// A token bucket with exact integer arithmetic and no floating point.
///
/// Internally tokens are held in fixed-point units where one token is
/// `NANOS_PER_SEC` units. A refill rate of `r` tokens per second then adds
/// exactly `r` units per nanosecond, so the integration `added = rate *
/// elapsed_nanos` is lossless and carries no rounding drift across calls.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_per_sec: u64,
    capacity_units: u128,
    tokens_units: u128,
    last_nanos: u64,
}

/// Outcome of attempting to spend from a [`TokenBucket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spend {
    /// The cost was available and has been deducted.
    Allowed,
    /// The cost was not available; the bucket is unchanged. `retry_after_nanos`
    /// is the earliest time from `now` at which the same cost would succeed if
    /// no other spend intervenes.
    Throttled {
        /// Nanoseconds from `now` until the refused cost would next succeed;
        /// [`u64::MAX`] when the bucket never refills (`rate_per_sec` of zero).
        retry_after_nanos: u64,
    },
}

impl Spend {
    /// Whether this is [`Spend::Allowed`].
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Spend::Allowed)
    }
}

impl TokenBucket {
    /// Create a bucket that refills at `rate_per_sec` tokens per second and
    /// holds at most `burst` tokens, starting full at time `now_nanos`.
    ///
    /// A `rate_per_sec` of zero makes a fixed quota of `burst` that never
    /// refills.
    #[must_use]
    pub fn new(rate_per_sec: u64, burst: u64, now_nanos: u64) -> TokenBucket {
        let capacity_units = u128::from(burst) * NANOS_PER_SEC;
        TokenBucket {
            rate_per_sec,
            capacity_units,
            tokens_units: capacity_units,
            last_nanos: now_nanos,
        }
    }

    fn refill(&mut self, now_nanos: u64) {
        if now_nanos <= self.last_nanos {
            return;
        }
        let elapsed = u128::from(now_nanos - self.last_nanos);
        let added = u128::from(self.rate_per_sec) * elapsed;
        self.tokens_units = (self.tokens_units + added).min(self.capacity_units);
        self.last_nanos = now_nanos;
    }

    /// Advance to `now_nanos` and try to spend `cost` tokens.
    pub fn try_spend(&mut self, cost: u64, now_nanos: u64) -> Spend {
        self.refill(now_nanos);
        let cost_units = u128::from(cost) * NANOS_PER_SEC;
        if self.tokens_units >= cost_units {
            self.tokens_units -= cost_units;
            return Spend::Allowed;
        }
        let deficit = cost_units - self.tokens_units;
        let retry = if self.rate_per_sec == 0 {
            u64::MAX
        } else {
            // deficit is in units, rate is units/nanosecond; round up.
            let nanos = deficit.div_ceil(u128::from(self.rate_per_sec));
            u64::try_from(nanos).unwrap_or(u64::MAX)
        };
        Spend::Throttled {
            retry_after_nanos: retry,
        }
    }

    /// Whole tokens currently available, after refilling to `now_nanos`.
    pub fn available(&mut self, now_nanos: u64) -> u64 {
        self.refill(now_nanos);
        u64::try_from(self.tokens_units / NANOS_PER_SEC).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_full() {
        let mut b = TokenBucket::new(10, 5, 0);
        assert_eq!(b.available(0), 5);
    }

    #[test]
    fn spends_down_to_empty_then_throttles() {
        let mut b = TokenBucket::new(1, 3, 0);
        assert!(b.try_spend(1, 0).is_allowed());
        assert!(b.try_spend(1, 0).is_allowed());
        assert!(b.try_spend(1, 0).is_allowed());
        assert!(!b.try_spend(1, 0).is_allowed());
    }

    #[test]
    fn refills_at_rate() {
        let mut b = TokenBucket::new(2, 2, 0);
        assert!(b.try_spend(2, 0).is_allowed());
        assert!(!b.try_spend(1, 0).is_allowed());
        // 2 tokens/sec => 1 token after 500ms.
        assert!(b.try_spend(1, 500_000_000).is_allowed());
    }

    #[test]
    fn retry_after_is_exact() {
        let mut b = TokenBucket::new(4, 1, 0);
        assert!(b.try_spend(1, 0).is_allowed());
        // Need 1 token at 4/sec => 250ms.
        match b.try_spend(1, 0) {
            Spend::Throttled { retry_after_nanos } => assert_eq!(retry_after_nanos, 250_000_000),
            Spend::Allowed => panic!("should throttle"),
        }
    }

    #[test]
    fn capacity_caps_refill() {
        let mut b = TokenBucket::new(1_000_000, 5, 0);
        // Even after a long idle, never exceeds burst.
        assert_eq!(b.available(1_000_000_000_000), 5);
    }

    #[test]
    fn zero_rate_is_a_fixed_quota() {
        let mut b = TokenBucket::new(0, 2, 0);
        assert!(b.try_spend(2, 0).is_allowed());
        match b.try_spend(1, 10_000_000_000) {
            Spend::Throttled { retry_after_nanos } => assert_eq!(retry_after_nanos, u64::MAX),
            Spend::Allowed => panic!("fixed quota must not refill"),
        }
    }

    #[test]
    fn refill_uses_elapsed_since_last_not_sum() {
        // Start with a non-zero `last` so that confusing `now - last` with
        // `now + last` changes how much is refilled.
        let mut b = TokenBucket::new(1, 5, 1_000_000_000);
        assert!(b.try_spend(5, 1_000_000_000).is_allowed()); // drains, last = 1s
                                                             // One second later exactly one token has refilled (rate 1/s).
        assert!(b.try_spend(1, 2_000_000_000).is_allowed());
        // ...and no more: a second token this instant must be refused. With the
        // sign flipped, elapsed would be 3s and three tokens would be available.
        assert!(!b.try_spend(2, 2_000_000_000).is_allowed());
    }

    #[test]
    fn retry_after_scales_with_the_real_deficit() {
        // Throttle while the bucket still holds tokens, so the deficit is
        // cost - held, not cost + held.
        let mut b = TokenBucket::new(4, 5, 0);
        assert!(b.try_spend(3, 0).is_allowed()); // 2 tokens remain
        match b.try_spend(5, 0) {
            // deficit = 5 - 2 = 3 tokens at 4/s => 750ms.
            Spend::Throttled { retry_after_nanos } => assert_eq!(retry_after_nanos, 750_000_000),
            Spend::Allowed => panic!("should throttle"),
        }
    }

    #[test]
    fn refill_does_not_drift_across_small_steps() {
        // Spending one token every 100ms at exactly 10/sec must never throttle.
        let mut b = TokenBucket::new(10, 1, 0);
        let mut t = 0u64;
        for _ in 0..1000 {
            assert!(b.try_spend(1, t).is_allowed(), "throttled at t={t}");
            t += 100_000_000;
        }
    }
}
