//! Property tests for the exact token bucket. The laws that matter for a rate
//! limiter: it never hands out more than the burst, it refills by exactly
//! `rate * elapsed` with no drift, and spending is monotone in cost.

use deflect_ratelimit::{Spend, TokenBucket};
use proptest::prelude::*;

const NS: u64 = 1_000_000_000;

proptest! {
    #[test]
    fn starts_with_exactly_the_burst(rate in 0u64..100_000, burst in 0u64..100_000) {
        let mut b = TokenBucket::new(rate, burst, 0);
        prop_assert_eq!(b.available(0), burst);
    }

    #[test]
    fn never_exceeds_the_burst(rate in 1u64..100_000, burst in 1u64..10_000, secs in 0u64..3_600) {
        let mut b = TokenBucket::new(rate, burst, 0);
        // However long it sits idle, it never holds more than the burst.
        prop_assert_eq!(b.available(secs.saturating_mul(NS)), burst);
    }

    #[test]
    fn refills_exactly_rate_times_elapsed(rate in 1u64..10_000, secs in 0u64..100) {
        // A burst large enough never to cap, drained at t=0, refills to exactly
        // rate * secs after `secs` seconds.
        let burst = 10_000 * 100 + 1;
        let mut b = TokenBucket::new(rate, burst, 0);
        prop_assert!(b.try_spend(burst, 0).is_allowed());
        let expected = rate.saturating_mul(secs);
        prop_assert_eq!(b.available(secs.saturating_mul(NS)), expected);
    }

    #[test]
    fn spending_is_monotone_in_cost(rate in 0u64..1_000, burst in 1u64..1_000, cost in 1u64..1_000) {
        // If a larger cost is affordable now, so is any smaller one.
        let mut big = TokenBucket::new(rate, burst, 0);
        if big.try_spend(cost, 0) == Spend::Allowed {
            for smaller in 1..=cost {
                let mut b = TokenBucket::new(rate, burst, 0);
                prop_assert!(b.try_spend(smaller, 0).is_allowed());
            }
        }
    }

    #[test]
    fn affordable_iff_within_available(rate in 0u64..1_000, burst in 0u64..1_000, cost in 0u64..2_000) {
        let mut probe = TokenBucket::new(rate, burst, 0);
        let have = probe.available(0);
        let mut b = TokenBucket::new(rate, burst, 0);
        prop_assert_eq!(b.try_spend(cost, 0).is_allowed(), cost <= have);
    }

    #[test]
    fn zero_rate_never_refills(burst in 1u64..1_000, secs in 1u64..10_000) {
        let mut b = TokenBucket::new(0, burst, 0);
        prop_assert!(b.try_spend(burst, 0).is_allowed());
        // No refill ever, at any future time.
        prop_assert_eq!(b.available(secs.saturating_mul(NS)), 0);
    }
}
