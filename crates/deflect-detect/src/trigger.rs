use crate::window::SlidingWindow;

/// Whether the monitored target is currently judged to be under attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Rates are below the trigger; mitigation stages can idle.
    Calm,
    /// Rates crossed the high watermark; mitigation is engaged.
    Mitigating,
}

/// Dual high/low watermarks. Crossing `high` engages mitigation; the phase only
/// returns to calm once rates fall below `low`. Keeping `low < high` gives the
/// hysteresis that stops a detector from flapping around a single threshold.
#[derive(Debug, Clone, Copy)]
pub struct Watermarks {
    /// Packets-per-second rate at or above which mitigation engages.
    pub pps_high: u64,
    /// Packets-per-second rate the window must fall below to disengage.
    pub pps_low: u64,
    /// Bytes-per-second rate at or above which mitigation engages.
    pub bps_high: u64,
    /// Bytes-per-second rate the window must fall below to disengage.
    pub bps_low: u64,
}

impl Watermarks {
    /// Watermarks with the low marks set to `low_frac`/256 of the high marks.
    #[must_use]
    pub fn from_high(pps_high: u64, bps_high: u64, low_frac: u8) -> Watermarks {
        let scale =
            |v: u64| u64::try_from(u128::from(v) * u128::from(low_frac) / 256).unwrap_or(u64::MAX);
        Watermarks {
            pps_high,
            pps_low: scale(pps_high),
            bps_high,
            bps_low: scale(bps_high),
        }
    }
}

/// Monitors packet and byte rates over a sliding window and reports a stable
/// [`Phase`] with hysteresis. Either rate crossing its high watermark engages
/// mitigation; both must fall below their low watermarks to disengage.
#[derive(Debug, Clone)]
pub struct Trigger {
    packets: SlidingWindow,
    bytes: SlidingWindow,
    marks: Watermarks,
    phase: Phase,
    last_pps: u64,
    last_bps: u64,
}

impl Trigger {
    /// Build a trigger whose packet and byte windows each span `window_nanos`
    /// divided into `slots` buckets, judged against `marks`. Starts [`Phase::Calm`].
    #[must_use]
    pub fn new(window_nanos: u64, slots: usize, marks: Watermarks) -> Trigger {
        Trigger {
            packets: SlidingWindow::new(window_nanos, slots),
            bytes: SlidingWindow::new(window_nanos, slots),
            marks,
            phase: Phase::Calm,
            last_pps: 0,
            last_bps: 0,
        }
    }

    /// Record one packet of `wire_len` bytes at `now_nanos` and return the
    /// phase after this observation.
    pub fn observe(&mut self, wire_len: u32, now_nanos: u64) -> Phase {
        self.packets.record(1, now_nanos);
        self.bytes.record(u64::from(wire_len), now_nanos);
        self.reassess(now_nanos)
    }

    /// Re-evaluate the phase at `now_nanos` without recording traffic; lets a
    /// caller observe decay to calm during a lull with no packets.
    pub fn reassess(&mut self, now_nanos: u64) -> Phase {
        self.last_pps = self.packets.rate_per_sec(now_nanos);
        self.last_bps = self.bytes.rate_per_sec(now_nanos);
        self.phase = match self.phase {
            Phase::Calm => {
                if self.last_pps >= self.marks.pps_high || self.last_bps >= self.marks.bps_high {
                    Phase::Mitigating
                } else {
                    Phase::Calm
                }
            }
            Phase::Mitigating => {
                if self.last_pps < self.marks.pps_low && self.last_bps < self.marks.bps_low {
                    Phase::Calm
                } else {
                    Phase::Mitigating
                }
            }
        };
        self.phase
    }

    /// Current phase, as of the most recent [`observe`](Self::observe) or
    /// [`reassess`](Self::reassess) call.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Packets-per-second rate measured at the most recent assessment.
    #[must_use]
    pub fn last_pps(&self) -> u64 {
        self.last_pps
    }

    /// Bytes-per-second rate measured at the most recent assessment.
    #[must_use]
    pub fn last_bps(&self) -> u64 {
        self.last_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marks() -> Watermarks {
        Watermarks {
            pps_high: 1000,
            pps_low: 400,
            bps_high: u64::MAX,
            bps_low: u64::MAX - 1,
        }
    }

    #[test]
    fn engages_when_high_crossed() {
        let mut t = Trigger::new(1_000_000_000, 10, marks());
        let mut now = 0u64;
        // Drive ~2000 pps for a full window.
        for _ in 0..2000 {
            t.observe(64, now);
            now += 500_000;
        }
        assert_eq!(t.phase(), Phase::Mitigating);
    }

    #[test]
    fn hysteresis_holds_between_watermarks() {
        let mut t = Trigger::new(1_000_000_000, 10, marks());
        let mut now = 0u64;
        for _ in 0..2000 {
            t.observe(64, now);
            now += 500_000;
        }
        assert_eq!(t.phase(), Phase::Mitigating);
        // Now idle long enough that the rate falls to ~0 (below low mark).
        now += 2_000_000_000;
        assert_eq!(t.reassess(now), Phase::Calm);
    }

    #[test]
    fn does_not_flap_at_a_single_threshold() {
        // A rate parked just under high must never engage.
        let mut t = Trigger::new(1_000_000_000, 10, marks());
        let mut now = 0u64;
        for _ in 0..900 {
            assert_eq!(t.observe(64, now), Phase::Calm);
            now += 1_000_000;
        }
    }

    #[test]
    fn from_high_scales_low_marks_by_fraction() {
        // low_frac 128/256 = one half.
        let m = Watermarks::from_high(1000, 2_000_000, 128);
        assert_eq!(m.pps_high, 1000);
        assert_eq!(m.bps_high, 2_000_000);
        assert_eq!(m.pps_low, 500);
        assert_eq!(m.bps_low, 1_000_000);
    }

    #[test]
    fn stays_mitigating_when_pps_sits_exactly_on_the_low_mark() {
        // A 1-second window makes the measured rate equal the in-window count.
        // Fill one slot that will age out and one that survives, so a single
        // reassess a window later sees a rate of exactly the low mark with no
        // intermediate dip below it. bps is parked out of the way.
        let m = Watermarks {
            pps_high: 500,
            pps_low: 200,
            bps_high: u64::MAX,
            bps_low: u64::MAX,
        };
        let mut t = Trigger::new(1_000_000_000, 10, m);
        for _ in 0..300 {
            t.observe(1, 0); // ages out after one window
        }
        for _ in 0..200 {
            t.observe(1, 900_000_000); // survives; total 500 here => engages
        }
        assert_eq!(t.phase(), Phase::Mitigating);
        // One window on, only the 200 survivors remain: pps == pps_low exactly.
        assert_eq!(t.reassess(1_000_000_000), Phase::Mitigating);
        assert_eq!(t.last_pps(), 200);
        assert_eq!(t.last_bps(), 200);
    }

    #[test]
    fn stays_mitigating_when_bps_on_low_mark_and_pps_below() {
        // pps below its low AND bps exactly on its low: with `&&` the phase
        // holds (only one condition met); `||` or a `<=` on bps would disengage.
        let m = Watermarks {
            pps_high: 500,
            pps_low: 300,
            bps_high: 10_000,
            bps_low: 200,
        };
        let mut t = Trigger::new(1_000_000_000, 10, m);
        for _ in 0..200 {
            t.observe(100, 0); // 20_000 bytes at t=0 => engages via bytes, ages out
        }
        for _ in 0..2 {
            t.observe(100, 900_000_000); // 2 packets / 200 bytes survive
        }
        assert_eq!(t.phase(), Phase::Mitigating);
        // One window on: pps 2 (< 300) and bps 200 (== low) exactly.
        assert_eq!(t.reassess(1_000_000_000), Phase::Mitigating);
        assert_eq!(t.last_pps(), 2);
        assert_eq!(t.last_bps(), 200);
    }

    #[test]
    fn bandwidth_alone_can_engage() {
        let m = Watermarks {
            pps_high: u64::MAX,
            pps_low: u64::MAX - 1,
            bps_high: 1_000_000,
            bps_low: 400_000,
        };
        let mut t = Trigger::new(1_000_000_000, 10, m);
        let mut now = 0u64;
        // Few packets, but each very large => high bps, low pps.
        for _ in 0..100 {
            t.observe(65_535, now);
            now += 10_000_000;
        }
        assert_eq!(t.phase(), Phase::Mitigating);
    }
}
