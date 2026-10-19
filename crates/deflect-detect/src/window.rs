const NANOS_PER_SEC: u128 = 1_000_000_000;

/// An exact, integer sliding-window rate counter.
///
/// Time is divided into `slots` buckets each covering an equal slice of the
/// window. Amounts land in the bucket for their timestamp; buckets older than
/// one full window are cleared lazily as time advances, so the running sum is
/// always the total over the trailing window with no floating point.
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    slot_nanos: u64,
    window_nanos: u128,
    buckets: Box<[u64]>,
    /// Absolute slot index last written to each bucket, to detect staleness.
    epochs: Box<[u64]>,
    last_slot: u64,
}

impl SlidingWindow {
    /// Build a window of `window_nanos` divided into `slots` buckets.
    ///
    /// # Panics
    /// Panics if `slots` is zero or does not divide `window_nanos` evenly.
    #[must_use]
    pub fn new(window_nanos: u64, slots: usize) -> SlidingWindow {
        assert!(slots > 0, "slots must be positive");
        assert!(
            window_nanos % slots as u64 == 0,
            "window must divide evenly into slots"
        );
        SlidingWindow {
            slot_nanos: window_nanos / slots as u64,
            window_nanos: u128::from(window_nanos),
            buckets: vec![0u64; slots].into_boxed_slice(),
            epochs: vec![0u64; slots].into_boxed_slice(),
            last_slot: 0,
        }
    }

    fn slot_index(&self, abs_slot: u64) -> usize {
        let len = self.buckets.len() as u64;
        usize::try_from(abs_slot % len).expect("modulo bucket count fits usize")
    }

    /// Expire buckets whose absolute slot is more than one window behind
    /// `abs_slot`, so stale counts do not survive an idle gap.
    fn expire_to(&mut self, abs_slot: u64) {
        let span = self.buckets.len() as u64;
        let first_live = abs_slot.saturating_sub(span - 1);
        for s in first_live..=abs_slot {
            let idx = self.slot_index(s);
            if self.epochs[idx] != s {
                self.buckets[idx] = 0;
                self.epochs[idx] = s;
            }
        }
        self.last_slot = abs_slot;
    }

    /// Add `amount` at time `now_nanos`.
    pub fn record(&mut self, amount: u64, now_nanos: u64) {
        let abs_slot = now_nanos / self.slot_nanos;
        self.expire_to(abs_slot);
        let idx = self.slot_index(abs_slot);
        self.buckets[idx] = self.buckets[idx].saturating_add(amount);
    }

    /// Total amount recorded within the trailing window ending at `now_nanos`.
    pub fn sum(&mut self, now_nanos: u64) -> u64 {
        let abs_slot = now_nanos / self.slot_nanos;
        self.expire_to(abs_slot);
        self.buckets.iter().sum()
    }

    /// Rate in amount-per-second over the trailing window.
    pub fn rate_per_sec(&mut self, now_nanos: u64) -> u64 {
        let total = u128::from(self.sum(now_nanos));
        u64::try_from(total * NANOS_PER_SEC / self.window_nanos).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_within_window() {
        let mut w = SlidingWindow::new(1_000_000_000, 10);
        for i in 0..10 {
            w.record(1, i * 100_000_000);
        }
        assert_eq!(w.sum(900_000_000), 10);
    }

    #[test]
    fn expires_old_counts() {
        let mut w = SlidingWindow::new(1_000_000_000, 10);
        w.record(100, 0);
        assert_eq!(w.sum(0), 100);
        // Two seconds later the count has fully aged out.
        assert_eq!(w.sum(2_000_000_000), 0);
    }

    #[test]
    fn rate_matches_steady_input() {
        let mut w = SlidingWindow::new(1_000_000_000, 10);
        // 1000 packets spread across a 1s window => ~1000 pps.
        let mut t = 0u64;
        for _ in 0..1000 {
            w.record(1, t);
            t += 1_000_000;
        }
        let r = w.rate_per_sec(999_000_000);
        assert!((990..=1000).contains(&r), "rate was {r}");
    }

    #[test]
    fn idle_gap_does_not_leave_stale_counts() {
        let mut w = SlidingWindow::new(1_000_000_000, 10);
        w.record(50, 0);
        // Jump far ahead, then record once; the old 50 must be gone.
        w.record(1, 10_000_000_000);
        assert_eq!(w.sum(10_000_000_000), 1);
    }
}
