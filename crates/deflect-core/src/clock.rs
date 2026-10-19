/// A source of monotonic time, in nanoseconds since an arbitrary epoch.
///
/// Every time-dependent primitive takes a `Clock` so it can be driven
/// deterministically in tests and simulation instead of sleeping.
pub trait Clock {
    fn now_nanos(&self) -> u64;
}

/// Wall-clock monotonic time from the host, available with `std`.
#[cfg(feature = "std")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MonotonicClock;

#[cfg(feature = "std")]
impl Clock for MonotonicClock {
    fn now_nanos(&self) -> u64 {
        use std::sync::OnceLock;
        use std::time::Instant;
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// A clock whose value is set explicitly, for deterministic tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    nanos: core::sync::atomic::AtomicU64,
}

impl ManualClock {
    #[must_use]
    pub fn new(start_nanos: u64) -> ManualClock {
        ManualClock {
            nanos: core::sync::atomic::AtomicU64::new(start_nanos),
        }
    }

    pub fn advance_nanos(&self, delta: u64) {
        self.nanos
            .fetch_add(delta, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn advance_millis(&self, delta: u64) {
        self.advance_nanos(delta.saturating_mul(1_000_000));
    }

    pub fn advance_secs(&self, delta: u64) {
        self.advance_nanos(delta.saturating_mul(1_000_000_000));
    }
}

impl Clock for ManualClock {
    fn now_nanos(&self) -> u64 {
        self.nanos.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now_nanos(&self) -> u64 {
        (**self).now_nanos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let c = ManualClock::new(0);
        assert_eq!(c.now_nanos(), 0);
        c.advance_secs(1);
        assert_eq!(c.now_nanos(), 1_000_000_000);
        c.advance_millis(500);
        assert_eq!(c.now_nanos(), 1_500_000_000);
    }

    #[test]
    fn reference_clock_delegates_to_inner() {
        fn read<C: Clock>(c: C) -> u64 {
            c.now_nanos()
        }
        let m = ManualClock::new(999);
        // Passing `&m` selects the blanket `impl Clock for &C`, which must
        // forward to the inner clock rather than returning a constant.
        assert_eq!(read(&m), 999);
    }

    #[cfg(feature = "std")]
    #[test]
    fn monotonic_clock_strictly_advances_over_real_work() {
        let c = MonotonicClock;
        let a = c.now_nanos();
        let mut acc = 0u64;
        for i in 0..2_000_000u64 {
            acc = acc.wrapping_add(i);
        }
        core::hint::black_box(acc);
        let b = c.now_nanos();
        assert!(b > a, "monotonic clock did not advance: {a} then {b}");
    }
}
