# deflect-kit

[![Crates.io](https://img.shields.io/crates/v/deflect)](https://crates.io/crates/deflect)
[![Docs.rs](https://img.shields.io/docsrs/deflect)](https://docs.rs/deflect)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Composable, **defensive** DDoS-mitigation primitives — the umbrella crate for the
[`deflect-rs`](https://github.com/copyleftdev/deflect-rs) family.

`deflect` adds no logic of its own. It re-exports each primitive behind a feature
flag, so you take **one** dependency and compile only the parts you ask for:

```toml
# Just the rate limiter and the attack detector:
deflect-kit = { version = "0.1", features = ["ratelimit", "detect"] }

# Everything:
deflect-kit = { version = "0.1", features = ["full"] }
```

## The model

Every primitive speaks one contract from `deflect-core`: a parsed `Observation`
(a packet or flow record plus a monotonic timestamp) flows through `Stage`s, each
returns a `Verdict`, and the pipeline keeps the most severe.

```
Pass  <  Challenge  <  RateLimit  <  Drop
```

The core types own no I/O and allocate nothing on the hot path, and time is always
injected through a `Clock`, so the same primitive runs in a userspace daemon, a
kernel-adjacent fast path, or a deterministic simulation.

```rust
use deflect_kit::prelude::*;

let verdicts = [
    Verdict::Pass,
    Verdict::Challenge(ChallengeKind::SynCookie),
    Verdict::Drop(DropReason::Signature),
];
let outcome = verdicts.into_iter().fold(Verdict::Pass, Verdict::worst);
assert!(matches!(outcome, Verdict::Drop(DropReason::Signature)));
```

See `examples/pipeline.rs` (run with `--features full`) for a full multi-stage
composition driving one observation through several primitives.

## Features

| Feature | Re-exports | Provides |
|---|---|---|
| *(always on)* | `deflect-core` as `contract` | `Verdict`, `SourceKey`, `Observation`, `Packet`, `Clock`, `Stage` |
| `ratelimit` | `deflect-ratelimit` | Exact-integer token bucket + bounded per-source governor |
| `detect` | `deflect-detect` | Sliding-window rate counter + dual-watermark trigger |
| `syncookie` | `deflect-syncookie` | Stateless SYN-cookie issuance and validation |
| `signature` | `deflect-signature` | Protocol/port/flag/payload signature engine |
| `reflect` | `deflect-reflect` | Reflection/amplification defense by solicitation |
| `fingerprint` | `deflect-fingerprint` | Learned fingerprints of unknown attacks |
| `enforce` | `deflect-enforce` | Enforcement behind an `Enforcer` trait (nftables) |
| `telemetry` | `deflect-telemetry` | NetFlow v5/v9, IPFIX, sFlow v5 ingestion |
| `packet` | `deflect-packet` | Bounds-checked Ethernet/IP/L4 header parsing |
| `bgp` | `deflect-bgp` | Upstream RTBH blackhole announcement |
| `std` *(default)* | — | Propagates `std` to every enabled crate |
| `serde` | — | JSON rule loading on the crates that support it |

Each primitive is also publishable and usable on its own if you prefer to depend on
exactly one crate.

## License

Licensed under either of Apache-2.0 or MIT at your option.
