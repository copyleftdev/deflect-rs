use alloc::vec::Vec;

/// A bounded Misra–Gries frequency summary over a stream of values.
///
/// At most `capacity` distinct values are tracked at once. Any value whose true
/// frequency exceeds `total / (capacity + 1)` is guaranteed to still be held at
/// the end, and every stored count is a lower bound on the true count. The
/// error is therefore one-sided: a reported share never overstates reality, so
/// a dominance test built on it cannot produce a false fingerprint — only, at
/// worst, miss a marginal one.
#[derive(Debug, Clone)]
pub struct TopValues<V> {
    entries: Vec<(V, u64)>,
    capacity: usize,
    total: u64,
}

impl<V: Copy + PartialEq> TopValues<V> {
    /// # Panics
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> TopValues<V> {
        assert!(capacity > 0, "capacity must be positive");
        TopValues {
            entries: Vec::with_capacity(capacity),
            capacity,
            total: 0,
        }
    }

    pub fn observe(&mut self, value: V) {
        self.total += 1;
        if let Some(entry) = self.entries.iter_mut().find(|(v, _)| *v == value) {
            entry.1 += 1;
            return;
        }
        if self.entries.len() < self.capacity {
            self.entries.push((value, 1));
            return;
        }
        // All counters occupied by other values: decrement every counter and
        // drop any that reach zero, the Misra–Gries eviction step.
        for entry in &mut self.entries {
            entry.1 -= 1;
        }
        self.entries.retain(|(_, c)| *c > 0);
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The tracked value with the highest (lower-bound) count.
    #[must_use]
    pub fn leader(&self) -> Option<(V, u64)> {
        self.entries.iter().copied().max_by_key(|(_, c)| *c)
    }

    /// The leader's count as a percentage of the total stream, `0` when empty.
    #[must_use]
    pub fn leader_share_pct(&self) -> u8 {
        match (self.leader(), self.total) {
            (Some((_, count)), total) if total > 0 => {
                u8::try_from(count * 100 / total).unwrap_or(100)
            }
            _ => 0,
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.total = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_dominant_value_wins() {
        let mut t = TopValues::new(8);
        for _ in 0..90 {
            t.observe(7u16);
        }
        for v in 0..10u16 {
            t.observe(v);
        }
        assert_eq!(t.total(), 100);
        assert_eq!(t.leader().unwrap().0, 7);
        assert!(t.leader_share_pct() >= 80, "share {}", t.leader_share_pct());
    }

    #[test]
    fn diffuse_stream_has_low_share() {
        let mut t = TopValues::new(8);
        for v in 0..200u16 {
            t.observe(v);
        }
        // No value repeats, so under capacity pressure the leader share is tiny.
        assert!(t.leader_share_pct() < 20);
    }

    #[test]
    fn share_is_never_overstated() {
        // A true 60% hitter among noise: reported share must not exceed truth.
        let mut t = TopValues::new(4);
        for i in 0..100 {
            if i % 10 < 6 {
                t.observe(42u32);
            } else {
                t.observe(i);
            }
        }
        assert!(t.leader_share_pct() <= 60);
        assert_eq!(t.leader().unwrap().0, 42);
    }

    #[test]
    fn clear_resets() {
        let mut t = TopValues::new(4);
        t.observe(1u8);
        t.clear();
        assert_eq!(t.total(), 0);
        assert!(t.leader().is_none());
    }
}
