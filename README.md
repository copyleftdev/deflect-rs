# deflect-rs

Composable, kernel-adjacent **DDoS-mitigation primitives** in Rust.

[![CI](https://img.shields.io/badge/ci-local-informational)](#)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Tip in tokens](https://img.shields.io/badge/tip-in%20tokens-blueviolet)](https://tokentip.to/@copyleftdev)

`deflect-rs` is a Rust rebuild of the ideas behind defensive DDoS tools such as
[NetDeflect](https://github.com/0vm/NetDeflect), factored into a library of
small, independently testable primitives rather than one daemon. It is a
**defensive** project: every primitive decides what to do with traffic arriving
at infrastructure the operator controls. Nothing here generates traffic.

## Model

Everything is a pipeline of **stages**. A parsed `Observation` (one packet or
flow record, plus a monotonic timestamp) flows through `Stage`s; each returns a
`Verdict`, and the pipeline keeps the most severe:

```
Pass  <  Challenge  <  RateLimit  <  Drop
```

The core types own no I/O and allocate nothing on the hot path, so the same
primitive runs in a userspace daemon, a kernel-adjacent fast path, or a
deterministic simulation. Time is always injected through a `Clock`, so every
time-dependent primitive is driven deterministically in tests.

## Crates

| Crate | Status | What it provides |
|---|---|---|
| `deflect-core` | ✅ | `Verdict`, `SourceKey` (+ subnet aggregation), `Packet`/`Observation`, `TcpFlags`, `Clock`, the `Stage` trait |
| `deflect-ratelimit` | ✅ | Exact integer `TokenBucket`; `SourceGovernor`, a fixed-size per-source/per-subnet limiter with bounded memory |
| `deflect-detect` | ✅ | `SlidingWindow` exact rate counter; `Trigger`, dual-watermark attack detection with hysteresis |
| `deflect-syncookie` | ✅ | Stateless SYN-cookie issuance and validation (SipHash-2-4 keyed) |
| `deflect-signature` | ⏳ | Protocol/port/flag/payload signature engine |
| `deflect-reflect` | ⏳ | Reflection/amplification defense |
| `deflect-fingerprint` | ⏳ | Learning fingerprints of unknown attacks |
| `deflect-enforce` | ⏳ | nftables / XDP enforcement backends behind a trait |
| `deflect-telemetry` | ⏳ | sFlow / NetFlow v5·v9 / IPFIX ingestion |
| `deflect-bgp` | ⏳ | Upstream RTBH / ExaBGP announcement |

## Design decisions worth knowing

- **Exact integer arithmetic on the data plane.** The token bucket holds tokens
  in fixed-point units where one token is `1e9` units, so a refill of `rate`
  tokens/sec adds exactly `rate` units per nanosecond — lossless, with no drift
  across calls and no floating point. The rate counter is likewise an exact
  integer sliding window.
- **Bounded state by construction.** `SourceGovernor` is a fixed-size table of
  buckets, not a growing map, so an attacker rotating source addresses cannot
  grow memory. A hash collision maps two sources onto one bucket — which can
  only *throttle a bystander*, never grant an attacker more than one source's
  allowance. Limits stay conservative under collision.
- **Subnet aggregation is a first-class key.** Attackers rotate within an
  allocation, so `SourceKey` masks to `/24` (v4) and `/64` (v6) by default; the
  rotating attacker collapses to one key.
- **Hysteresis, not a single threshold.** The attack `Trigger` engages at a high
  watermark and only disengages below a lower one, so it does not flap when a
  rate sits near the line.
- **Cookies authenticate the client ISN.** `deflect-syncookie` keeps the
  stateless Linux-style layout but folds the client's sequence number *into* the
  keyed MAC, so the cookie authenticates `(tuple, client_isn, epoch)` rather
  than binding the ISN only linearly. The secret is caller-supplied (seed it
  with `getrandom`) and rotates with a one-generation grace window.

## Status

Early. Four crates are implemented and tested (47 tests, `clippy -W pedantic`
clean, builds `no_std`). The remaining crates are scaffolded as roadmap.

## License

Licensed under either of Apache-2.0 or MIT at your option.
