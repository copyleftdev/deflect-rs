//! Property tests for the detection plane: the sliding window is an exact
//! counter, `from_high` never places a low mark above its high mark, and the
//! trigger's hysteresis never flaps while a rate stays at or above its low.

use deflect_detect::{Phase, SlidingWindow, Trigger, Watermarks};
use proptest::prelude::*;

const WINDOW: u64 = 1_000_000_000;

proptest! {
    #[test]
    fn window_sum_equals_total_recorded_within_one_window(
        amounts in prop::collection::vec(0u64..1_000, 0..200),
    ) {
        // All records land in the same 1s window, so the sum is their total.
        let mut w = SlidingWindow::new(WINDOW, 10);
        let mut total = 0u64;
        for (i, &a) in amounts.iter().enumerate() {
            w.record(a, u64::try_from(i).unwrap() * 1_000_000); // spread across < 1s
            total = total.saturating_add(a);
        }
        prop_assert_eq!(w.sum(199_000_000), total);
    }

    #[test]
    fn rate_equals_sum_for_a_one_second_window(n in 0u64..5_000) {
        // With a 1s window the per-second rate is exactly the in-window count.
        let mut w = SlidingWindow::new(WINDOW, 10);
        w.record(n, 0);
        prop_assert_eq!(w.rate_per_sec(0), n);
    }

    #[test]
    fn from_high_never_exceeds_the_high_mark(
        pps_high in any::<u64>(),
        bps_high in any::<u64>(),
        frac in 0u8..=255,
    ) {
        let m = Watermarks::from_high(pps_high, bps_high, frac);
        prop_assert!(m.pps_low <= m.pps_high);
        prop_assert!(m.bps_low <= m.bps_high);
    }

    #[test]
    fn mitigation_holds_in_the_hysteresis_band(hold in 200u64..500) {
        // High 500, low 200. Engage, then let only a `hold` rate in [low, high)
        // survive into the next window: too low to have engaged from calm, but
        // the hysteresis must keep it mitigating. The aging batch guarantees no
        // intermediate reassess dips below the low mark.
        let marks = Watermarks {
            pps_high: 500,
            pps_low: 200,
            bps_high: u64::MAX,
            bps_low: u64::MAX,
        };
        let mut t = Trigger::new(WINDOW, 10, marks);
        for _ in 0..500 {
            t.observe(1, 0); // ages out
        }
        for _ in 0..hold {
            t.observe(1, 900_000_000); // survives into the next window
        }
        prop_assert_eq!(t.phase(), Phase::Mitigating);
        prop_assert_eq!(t.reassess(WINDOW), Phase::Mitigating);
    }
}
