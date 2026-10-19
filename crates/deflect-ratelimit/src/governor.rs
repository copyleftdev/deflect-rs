use std::sync::Mutex;

use deflect_core::{Aggregation, Observation, SourceKey, Stage, Verdict};

use crate::bucket::{Spend, TokenBucket};

/// How the cost of one observation is measured against the bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostMode {
    /// Each observation costs one token (packets-per-second limiting).
    Packet,
    /// Each observation costs its wire length in bytes (bandwidth limiting).
    Byte,
}

/// Configuration for a [`SourceGovernor`].
#[derive(Debug, Clone, Copy)]
pub struct GovernorConfig {
    pub rate_per_sec: u64,
    pub burst: u64,
    pub aggregation: Aggregation,
    pub cost: CostMode,
    /// Number of bucket slots; rounded up to a power of two, minimum 1.
    pub slots: usize,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        GovernorConfig {
            rate_per_sec: 1_000,
            burst: 2_000,
            aggregation: Aggregation::SUBNET,
            cost: CostMode::Packet,
            slots: 1 << 16,
        }
    }
}

/// A per-source rate limiter over a fixed-size table of token buckets.
///
/// Memory is bounded by the slot count regardless of how many distinct sources
/// are seen, so an attacker rotating source addresses cannot grow state. A hash
/// collision maps two sources onto one bucket: they then share a budget, which
/// can only throttle a bystander, never grant an attacker more than one
/// source's allowance. Limits are therefore conservative under collision.
pub struct SourceGovernor {
    config: GovernorConfig,
    mask: u64,
    slots: Box<[Mutex<TokenBucket>]>,
}

impl SourceGovernor {
    #[must_use]
    pub fn new(config: GovernorConfig) -> SourceGovernor {
        let n = config.slots.max(1).next_power_of_two();
        let slots: Vec<Mutex<TokenBucket>> = (0..n)
            .map(|_| Mutex::new(TokenBucket::new(config.rate_per_sec, config.burst, 0)))
            .collect();
        SourceGovernor {
            config,
            mask: (n - 1) as u64,
            slots: slots.into_boxed_slice(),
        }
    }

    fn slot_for(&self, key: SourceKey) -> usize {
        usize::try_from(fnv1a(key) & self.mask).expect("masked slot index fits usize")
    }

    fn cost_of(&self, wire_len: u32) -> u64 {
        match self.config.cost {
            CostMode::Packet => 1,
            CostMode::Byte => u64::from(wire_len).max(1),
        }
    }

    /// Charge `cost` to `key` at `now_nanos`, returning the bucket outcome.
    ///
    /// # Panics
    /// Panics only if a slot mutex was poisoned by a previous panic while held.
    #[must_use]
    pub fn charge(&self, key: SourceKey, cost: u64, now_nanos: u64) -> Spend {
        let slot = self.slot_for(key);
        let mut bucket = self.slots[slot].lock().expect("bucket mutex poisoned");
        bucket.try_spend(cost, now_nanos)
    }
}

impl Stage for SourceGovernor {
    fn evaluate(&self, obs: &Observation<'_>) -> Verdict {
        let key = obs.source_key(self.config.aggregation);
        let cost = self.cost_of(obs.packet.wire_len);
        match self.charge(key, cost, obs.ts_nanos) {
            Spend::Allowed => Verdict::Pass,
            Spend::Throttled { retry_after_nanos } => Verdict::RateLimit {
                retry_after: core::time::Duration::from_nanos(retry_after_nanos),
            },
        }
    }

    fn name(&self) -> &'static str {
        "source_governor"
    }
}

fn fnv1a(key: SourceKey) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x1000_0000_01b3;
    let mut h = OFFSET;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
    };
    match key {
        SourceKey::V4(o) => {
            mix(&[4]);
            mix(&o);
        }
        SourceKey::V6(o) => {
            mix(&[6]);
            mix(&o);
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::IpAddr;
    use deflect_core::{Packet, L4};

    fn obs<'a>(ip: &str, now: u64) -> (Packet<'a>, u64) {
        let addr: IpAddr = ip.parse().unwrap();
        (Packet::new(addr, addr, L4::Udp).with_wire_len(100), now)
    }

    #[test]
    fn independent_sources_do_not_share_budget() {
        let g = SourceGovernor::new(GovernorConfig {
            rate_per_sec: 0,
            burst: 1,
            slots: 1 << 12,
            ..Default::default()
        });
        let a = SourceKey::host("198.51.100.1".parse().unwrap());
        let b = SourceKey::host("198.51.100.2".parse().unwrap());
        assert!(g.charge(a, 1, 0).is_allowed());
        // a is now empty; b has its own budget.
        assert!(!g.charge(a, 1, 0).is_allowed());
        assert!(g.charge(b, 1, 0).is_allowed());
    }

    #[test]
    fn stage_throttles_a_flood_from_one_source() {
        let g = SourceGovernor::new(GovernorConfig {
            rate_per_sec: 10,
            burst: 5,
            cost: CostMode::Packet,
            aggregation: Aggregation::HOST,
            slots: 1 << 12,
        });
        let (p, _) = obs("203.0.113.9", 0);
        let mut allowed = 0;
        for _ in 0..100 {
            if Stage::evaluate(&g, &Observation::new(p, 0)).is_pass() {
                allowed += 1;
            }
        }
        // Only the burst of 5 should pass within the same instant.
        assert_eq!(allowed, 5);
    }

    #[test]
    fn byte_mode_charges_wire_length() {
        let g = SourceGovernor::new(GovernorConfig {
            rate_per_sec: 0,
            burst: 150,
            cost: CostMode::Byte,
            aggregation: Aggregation::HOST,
            slots: 1 << 12,
        });
        let (p, _) = obs("203.0.113.9", 0); // wire_len 100
        assert!(Stage::evaluate(&g, &Observation::new(p, 0)).is_pass());
        // Second 100-byte packet exceeds the 150-byte quota.
        assert!(Stage::evaluate(&g, &Observation::new(p, 0)).blocks());
    }

    #[test]
    fn subnet_aggregation_collapses_a_rotating_attacker() {
        let g = SourceGovernor::new(GovernorConfig {
            rate_per_sec: 0,
            burst: 3,
            aggregation: Aggregation::SUBNET,
            slots: 1 << 12,
            ..Default::default()
        });
        // Four distinct hosts in one /24 share the subnet budget of 3.
        let mut allowed = 0;
        for host in 1..=10 {
            let (p, _) = obs(&format!("203.0.113.{host}"), 0);
            if Stage::evaluate(&g, &Observation::new(p, 0)).is_pass() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3);
    }
}
