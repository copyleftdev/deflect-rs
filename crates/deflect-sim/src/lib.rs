//! Deterministic attack simulation over the real `deflect-rs` primitives.
//!
//! This is the engine behind the DST visualizer. It never approximates a
//! primitive: every verdict comes from the actual `deflect-*` crate defending
//! against synthetic traffic. All randomness is drawn from a single seeded PRNG
//! and all time is advanced explicitly, so a given `(seed, params)` replays to a
//! bit-identical event stream — which is exactly the determinism the primitives
//! were designed around.
//!
//! The native build is pure Rust and unit-tested; the `wasm32` build adds a thin
//! `wasm-bindgen` surface so a browser can step the same engine frame by frame.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use deflect_kit::prelude::*;

/// A packet's ground-truth class — what the traffic generator intended it to be.
/// The primitives never see this; it exists only to colour the visualization and
/// to let tests assert that the designed primitive caught the designed attack.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Class {
    /// Established, well-formed traffic that should reach the core.
    Legit = 0,
    /// Half-open SYN storm — the SYN-cookie's job when under attack.
    SynFlood = 1,
    /// Illegal TCP flag combination (NULL/XMAS/SYN+FIN) — a signature drop.
    FlagAnomaly = 2,
    /// Spoofed amplifier reply (DNS/NTP) — the reflection guard's job.
    Reflection = 3,
    /// High-volume flood concentrated in a few subnets — the rate governor's job.
    Volumetric = 4,
    /// Homogeneous flood spread across many subnets — only the learner catches it.
    NovelFlood = 5,
}

/// Which pipeline stage returned the decisive (first non-`Pass`) verdict.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Caught {
    /// Reached the core — no stage objected.
    None = 0,
    /// `deflect-signature`.
    Signature = 1,
    /// `deflect-reflect`.
    Reflect = 2,
    /// `deflect-syncookie`.
    SynCookie = 3,
    /// `deflect-ratelimit`.
    Governor = 4,
    /// `deflect-fingerprint`.
    Fingerprint = 5,
}

/// One packet's fate for the frame: ground-truth class, the primitive's verdict,
/// the stage that decided it, and a stable lane derived from the source address.
#[derive(Clone, Copy)]
pub struct Event {
    /// Ground-truth [`Class`] as a small integer.
    pub class: u32,
    /// Verdict code: `0` Pass, `1` Challenge, `2` `RateLimit`, `3` Drop.
    pub verdict: u32,
    /// Deciding [`Caught`] stage as a small integer.
    pub stage: u32,
    /// `0..256` spawn lane, hashed from the source `/24` so the same source
    /// always enters from the same place.
    pub lane: u32,
}

/// Deterministic splitmix64 PRNG — the single source of all randomness.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            u32::try_from(self.next_u64() % u64::from(n)).unwrap_or(0)
        }
    }

    fn unit(&mut self) -> f32 {
        // Top 24 bits → [0, 1); 2^24 is exact in f32.
        (self.next_u64() >> 40) as f32 / 16_777_216.0
    }
}

/// The knobs a viewer can mutate. Weights are relative; they need not sum to one.
#[derive(Clone, Copy)]
pub struct Params {
    /// Total offered load in packets per second.
    pub pps: u32,
    /// Fraction of reflection packets that are *solicited* (and so must pass),
    /// in parts per thousand.
    pub solicited_permil: u32,
    /// Relative weight of each [`Class`], indexed `0..6`.
    pub weights: [f32; 6],
}

impl Default for Params {
    fn default() -> Params {
        Params {
            pps: 6_000,
            solicited_permil: 120,
            weights: [1.0, 1.0, 0.6, 1.0, 1.2, 1.0],
        }
    }
}

const TICK_NANOS: u64 = 50_000_000; // 50 ms of simulated time per frame.
const MAX_PER_TICK: u32 = 600; // viewer-friendly cap on particles per frame.
const SYNTH_DOMINANCE: u8 = 55;

/// The simulation: the real primitives, the generator, and the deterministic clock.
pub struct Sim {
    seed: u64,
    params: Params,
    rng: Rng,
    now: u64,

    signatures: SignatureSet,
    reflect: ReflectionGuard,
    governor: SourceGovernor,
    fingerprinter: Fingerprinter,
    trigger: Trigger,
    cookie: SynCookie,

    active_fp: Option<Fingerprint>,
    totals: [u32; 24], // class-major 6x4 matrix of cumulative verdicts.
}

// Homogeneous payload that makes the novel flood learnable by its prefix.
static NOVEL_PAYLOAD: [u8; 8] = [0x13, 0x37, 0xC0, 0xDE, 0xDE, 0xAD, 0xBE, 0xEF];

impl Sim {
    /// Build a simulation for `seed` and `params`. Equal arguments yield equal runs.
    #[must_use]
    pub fn new(seed: u64, params: Params) -> Sim {
        let governor = SourceGovernor::new(GovernorConfig {
            rate_per_sec: 60,
            burst: 60,
            aggregation: Aggregation::SUBNET,
            cost: CostMode::Packet,
            slots: 4096,
        });
        let marks = Watermarks {
            pps_high: 1_500,
            pps_low: 600,
            bps_high: u64::MAX,
            bps_low: u64::MAX,
        };
        Sim {
            seed,
            params,
            rng: Rng::new(seed),
            now: 0,
            signatures: baseline(),
            reflect: ReflectionGuard::new(ReflectConfig::default()),
            governor,
            fingerprinter: Fingerprinter::with_defaults(),
            trigger: Trigger::new(1_000_000_000, 16, marks),
            cookie: SynCookie::with_defaults(CookieKey::from_u64s(seed, !seed)),
            active_fp: None,
            totals: [0; 24],
        }
    }

    /// Replace the knobs without reseeding — the generator keeps its stream, so a
    /// mid-run tweak stays reproducible from the same seed and tweak sequence.
    pub fn set_params(&mut self, params: Params) {
        self.params = params;
    }

    /// Reset to the initial state for `seed`/`params`: the canonical "replay".
    pub fn reset(&mut self) {
        *self = Sim::new(self.seed, self.params);
    }

    fn weighted_class(&mut self) -> Class {
        let total: f32 = self.params.weights.iter().map(|w| w.max(0.0)).sum();
        if total <= 0.0 {
            return Class::Legit;
        }
        let mut pick = self.rng.unit() * total;
        for (i, w) in self.params.weights.iter().enumerate() {
            pick -= w.max(0.0);
            if pick <= 0.0 {
                return CLASSES[i];
            }
        }
        Class::Legit
    }

    // Source address for a class. `pool` distinct /24s model source diversity:
    // volumetric is concentrated, the novel flood is spread wide.
    fn source(&mut self, class: Class) -> (core::net::IpAddr, u32) {
        let pool: u32 = match class {
            Class::Volumetric => 3,
            Class::Reflection => 24,
            Class::SynFlood | Class::FlagAnomaly => 2_000,
            Class::Legit => 4_000,
            Class::NovelFlood => 1_500,
        };
        let idx = self.rng.below(pool);
        let b = u8::try_from((idx >> 8) & 0xff).unwrap_or(0);
        let c = u8::try_from(idx & 0xff).unwrap_or(0);
        let host = u8::try_from(1 + self.rng.below(254)).unwrap_or(1);
        let addr = core::net::IpAddr::V4(core::net::Ipv4Addr::new(10, b, c, host));
        let lane = ((u32::from(b) << 8 | u32::from(c)) ^ class as u32) & 0xff;
        (addr, lane)
    }

    fn classify(&mut self, class: Class, src: core::net::IpAddr) -> (u32, Caught) {
        let server = core::net::IpAddr::V4(core::net::Ipv4Addr::new(198, 51, 100, 9));
        let engaged = matches!(self.trigger.phase(), Phase::Mitigating);

        let packet = match class {
            Class::Legit => {
                // Real clients spread across services and sizes, so legitimate
                // traffic presents no single dominant dimension for the learner
                // to lock onto — only a genuine flood does.
                let dports = [443u16, 80, 8443, 22, 993, 5222, 3000];
                let dport = dports[self.rng.below(dports.len() as u32) as usize];
                let wl = 180 + self.rng.below(1220);
                Packet::new(src, server, L4::Tcp)
                    .with_ports(
                        40000 + u16::try_from(self.rng.below(20000)).unwrap_or(0),
                        dport,
                    )
                    .with_flags(TcpFlags::ACK)
                    .with_wire_len(wl)
            }
            Class::SynFlood => Packet::new(src, server, L4::Tcp)
                .with_ports(
                    1024 + u16::try_from(self.rng.below(64000)).unwrap_or(0),
                    443,
                )
                .with_flags(TcpFlags::SYN)
                .with_wire_len(60),
            Class::FlagAnomaly => Packet::new(src, server, L4::Tcp)
                .with_ports(1024 + u16::try_from(self.rng.below(64000)).unwrap_or(0), 80)
                .with_flags(TcpFlags::SYN | TcpFlags::FIN)
                .with_wire_len(60),
            Class::Reflection => Packet::new(src, server, L4::Udp)
                .with_ports(
                    53,
                    40000 + u16::try_from(self.rng.below(20000)).unwrap_or(0),
                )
                .with_wire_len(1400),
            Class::Volumetric => Packet::new(src, server, L4::Udp)
                .with_ports(
                    1024 + u16::try_from(self.rng.below(64000)).unwrap_or(0),
                    443,
                )
                .with_wire_len(1200),
            Class::NovelFlood => Packet::new(src, server, L4::Udp)
                .with_ports(12345, 80)
                .with_wire_len(1400)
                .with_payload(&NOVEL_PAYLOAD),
        };

        self.trigger.observe(packet.wire_len, self.now);

        // 1. Signatures: illegal flag combinations die here at any load.
        if matches!(self.signatures.classify(&packet), Verdict::Drop(_)) {
            return (3, Caught::Signature);
        }

        // 2. Reflection: a solicited reply is recorded first and passes; an
        //    unsolicited amplifier reply is dropped.
        if class == Class::Reflection {
            let solicited = self.rng.below(1000) < self.params.solicited_permil;
            if solicited {
                let request = Packet::new(server, src, L4::Udp)
                    .with_ports(packet.dst_port, packet.src_port)
                    .with_wire_len(60);
                self.reflect.note_outbound(&request, self.now);
            }
            if matches!(self.reflect.classify(&packet, self.now), Verdict::Drop(_)) {
                return (3, Caught::Reflect);
            }
        }

        // 3. SYN cookies: when the trigger is engaged, a SYN is answered with a
        //    stateless cookie rather than state — a challenge, not an admission.
        if engaged && packet.l4 == L4::Tcp && packet.tcp_flags == TcpFlags::SYN {
            let tuple = FourTuple::new(packet.src, packet.dst, packet.src_port, packet.dst_port);
            let _ = self
                .cookie
                .issue(&tuple, self.rng.next_u64() as u32, 1460, self.now);
            return (1, Caught::SynCookie);
        }

        // 4. Rate governor: per-subnet budget. Concentrated floods exhaust it.
        let obs = Observation::new(packet, self.now);
        if matches!(self.governor.evaluate(&obs), Verdict::RateLimit { .. }) {
            return (2, Caught::Governor);
        }

        // 5. Fingerprint: everything that got this far is "unrecognized"; feed the
        //    learner, and drop anything a synthesized fingerprint now matches.
        self.fingerprinter.observe(&packet);
        if let Some(fp) = &self.active_fp {
            if fp.matches(&packet) {
                return (3, Caught::Fingerprint);
            }
        }

        (0, Caught::None)
    }

    /// Advance one 50 ms frame and return every packet's [`Event`].
    pub fn tick(&mut self) -> Vec<Event> {
        let per_sec = self.params.pps;
        let count = u64::from(per_sec) * TICK_NANOS / 1_000_000_000;
        let count = u32::try_from(count)
            .unwrap_or(MAX_PER_TICK)
            .min(MAX_PER_TICK);

        let step = if count == 0 {
            TICK_NANOS
        } else {
            TICK_NANOS / u64::from(count)
        };
        let mut events = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let class = self.weighted_class();
            let (src, lane) = self.source(class);
            let (verdict, stage) = self.classify(class, src);
            let idx = (class as usize) * 4 + verdict as usize;
            self.totals[idx] = self.totals[idx].saturating_add(1);
            events.push(Event {
                class: class as u32,
                verdict,
                stage: stage as u32,
                lane,
            });
            self.now += step;
        }

        // Re-assess the trigger and, while engaged, try to synthesize a fingerprint
        // of whatever now dominates the unrecognized traffic.
        let _ = self.trigger.reassess(self.now);
        if matches!(self.trigger.phase(), Phase::Mitigating) {
            if let Some(fp) = self.fingerprinter.synthesize(SYNTH_DOMINANCE) {
                self.active_fp = Some(fp);
            }
        }

        events
    }

    /// `true` once the detector has armed the adaptive stages.
    #[must_use]
    pub fn engaged(&self) -> bool {
        matches!(self.trigger.phase(), Phase::Mitigating)
    }

    /// `true` once the learner has a fingerprint it is actively enforcing.
    #[must_use]
    pub fn fingerprint_active(&self) -> bool {
        self.active_fp.is_some()
    }

    /// The cumulative class-major 6x4 verdict matrix.
    #[must_use]
    pub fn totals(&self) -> [u32; 24] {
        self.totals
    }
}

const CLASSES: [Class; 6] = [
    Class::Legit,
    Class::SynFlood,
    Class::FlagAnomaly,
    Class::Reflection,
    Class::Volumetric,
    Class::NovelFlood,
];

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::{Event, Params, Sim};
    use wasm_bindgen::prelude::wasm_bindgen;

    /// Browser-facing handle over the deterministic [`Sim`].
    #[wasm_bindgen]
    pub struct Simulation {
        inner: Sim,
    }

    #[wasm_bindgen]
    impl Simulation {
        /// Create a simulation from a seed and the initial knobs.
        #[wasm_bindgen(constructor)]
        #[must_use]
        pub fn new(seed: f64, pps: u32, solicited_permil: u32, weights: &[f32]) -> Simulation {
            Simulation {
                inner: Sim::new(seed_bits(seed), params(pps, solicited_permil, weights)),
            }
        }

        /// Update the knobs mid-run without reseeding.
        #[wasm_bindgen(js_name = setParams)]
        pub fn set_params(&mut self, pps: u32, solicited_permil: u32, weights: &[f32]) {
            self.inner
                .set_params(params(pps, solicited_permil, weights));
        }

        /// Reset to the canonical replay state.
        pub fn reset(&mut self) {
            self.inner.reset();
        }

        /// Step one frame; returns `[class, verdict, stage, lane]` per packet.
        pub fn tick(&mut self) -> Vec<u32> {
            self.inner
                .tick()
                .into_iter()
                .flat_map(
                    |Event {
                         class,
                         verdict,
                         stage,
                         lane,
                     }| [class, verdict, stage, lane],
                )
                .collect()
        }

        /// `1` when the detector is engaged, else `0`.
        #[must_use]
        pub fn engaged(&self) -> u32 {
            u32::from(self.inner.engaged())
        }

        /// `1` when a fingerprint is being enforced, else `0`.
        #[wasm_bindgen(js_name = fingerprintActive)]
        #[must_use]
        pub fn fingerprint_active(&self) -> u32 {
            u32::from(self.inner.fingerprint_active())
        }

        /// The cumulative class-major 6x4 verdict matrix (24 values).
        #[must_use]
        pub fn totals(&self) -> Vec<u32> {
            self.inner.totals().to_vec()
        }
    }

    fn seed_bits(seed: f64) -> u64 {
        // A JS number is an integer seed; take its bit pattern for the full range.
        if seed.fract() == 0.0 && seed.abs() < 9.007_199_254_740_992e15 {
            seed as i64 as u64
        } else {
            seed.to_bits()
        }
    }

    fn params(pps: u32, solicited_permil: u32, weights: &[f32]) -> Params {
        let mut w = [0.0f32; 6];
        for (slot, value) in w.iter_mut().zip(weights.iter()) {
            *slot = *value;
        }
        Params {
            pps,
            solicited_permil,
            weights: w,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Caught, Class, Params, Sim};

    fn run(seed: u64, params: Params, ticks: usize) -> (Vec<u32>, [u32; 24]) {
        let mut sim = Sim::new(seed, params);
        let mut stream = Vec::new();
        for _ in 0..ticks {
            for e in sim.tick() {
                stream.extend_from_slice(&[e.class, e.verdict, e.stage, e.lane]);
            }
        }
        (stream, sim.totals())
    }

    #[test]
    fn same_seed_same_params_is_bit_identical() {
        let p = Params::default();
        let a = run(0xDEAD_BEEF, p, 40);
        let b = run(0xDEAD_BEEF, p, 40);
        assert_eq!(a.0, b.0, "event streams diverged for one seed");
        assert_eq!(a.1, b.1, "verdict totals diverged for one seed");
    }

    #[test]
    fn different_seed_diverges() {
        let p = Params::default();
        let a = run(1, p, 40);
        let b = run(2, p, 40);
        assert_ne!(a.0, b.0, "two seeds produced identical streams");
    }

    #[test]
    fn reset_reproduces_the_run() {
        let p = Params::default();
        let mut sim = Sim::new(99, p);
        let first: Vec<_> = (0..20)
            .flat_map(|_| sim.tick())
            .map(|e| e.verdict)
            .collect();
        sim.reset();
        let again: Vec<_> = (0..20)
            .flat_map(|_| sim.tick())
            .map(|e| e.verdict)
            .collect();
        assert_eq!(first, again);
    }

    #[test]
    fn flag_anomalies_are_always_dropped_by_signatures() {
        // Only flag anomalies; every one must die at the signature stage.
        let p = Params {
            pps: 2_000,
            solicited_permil: 0,
            weights: [0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
        };
        let mut sim = Sim::new(7, p);
        let mut seen = 0;
        for _ in 0..20 {
            for e in sim.tick() {
                assert_eq!(e.class, Class::FlagAnomaly as u32);
                assert_eq!(e.verdict, 3, "flag anomaly not dropped");
                assert_eq!(e.stage, Caught::Signature as u32);
                seen += 1;
            }
        }
        assert!(seen > 0);
    }

    #[test]
    fn unsolicited_reflection_is_dropped_by_the_guard() {
        let p = Params {
            pps: 2_000,
            solicited_permil: 0,
            weights: [0.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        };
        let mut sim = Sim::new(5, p);
        let mut dropped = 0;
        let mut total = 0;
        for _ in 0..20 {
            for e in sim.tick() {
                total += 1;
                if e.stage == Caught::Reflect as u32 {
                    assert_eq!(e.verdict, 3);
                    dropped += 1;
                }
            }
        }
        assert!(total > 0);
        assert!(
            dropped * 10 > total * 9,
            "most unsolicited replies should drop"
        );
    }

    #[test]
    fn novel_flood_is_eventually_learned_and_dropped() {
        // A wide-spread homogeneous flood evades the per-subnet governor, so the
        // only stage that can catch it is the fingerprint learner.
        let p = Params {
            pps: 8_000,
            solicited_permil: 0,
            weights: [0.2, 0.0, 0.0, 0.0, 0.0, 1.0],
        };
        let mut sim = Sim::new(11, p);
        let mut fp_drops = 0;
        for _ in 0..80 {
            for e in sim.tick() {
                if e.stage == Caught::Fingerprint as u32 {
                    fp_drops += 1;
                }
            }
        }
        assert!(
            sim.fingerprint_active(),
            "learner never synthesized a fingerprint"
        );
        assert!(fp_drops > 0, "fingerprint never caught the novel flood");
    }
}
