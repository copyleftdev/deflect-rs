//! Property tests for the Misra–Gries counter's defining guarantee: counts are
//! lower bounds, so the reported leader share never *overstates* the truth —
//! which is what makes a synthesized fingerprint trustworthy (it can miss a
//! marginal flood, but it cannot invent one).

use deflect_fingerprint::TopValues;
use proptest::prelude::*;

proptest! {
    #[test]
    fn total_counts_every_observation(values in prop::collection::vec(0u8..20, 0..400), cap in 1usize..16) {
        let mut t = TopValues::new(cap);
        for &v in &values {
            t.observe(v);
        }
        prop_assert_eq!(t.total(), u64::try_from(values.len()).unwrap());
    }

    #[test]
    fn reported_share_never_exceeds_the_truth(
        values in prop::collection::vec(0u8..20, 1..400), cap in 1usize..16,
    ) {
        let mut t = TopValues::new(cap);
        for &v in &values {
            t.observe(v);
        }
        let total = u64::try_from(values.len()).unwrap();
        if let Some((leader, count)) = t.leader() {
            let true_count = values.iter().filter(|&&v| v == leader).fold(0u64, |n, _| n + 1);
            // The stored count is a lower bound on the true count.
            prop_assert!(count <= true_count);
            // ...so the reported share never overstates the real share.
            prop_assert!(u64::from(t.leader_share_pct()) <= true_count * 100 / total);
        }
    }

    #[test]
    fn a_strict_majority_is_always_the_leader(
        majority in 0u8..5, noise in prop::collection::vec(5u8..20, 0..100),
    ) {
        // A value present in a strict majority exceeds total/(cap+1) for any
        // capacity >= 1, so Misra–Gries must retain it as the leader.
        let mut t = TopValues::new(8);
        let reps = noise.len() + 1; // strictly more than all the noise together
        for _ in 0..reps {
            t.observe(majority);
        }
        for &v in &noise {
            t.observe(v);
        }
        prop_assert_eq!(t.leader().map(|(v, _)| v), Some(majority));
    }
}
