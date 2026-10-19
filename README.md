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
| `deflect-signature` | ✅ | Protocol/port/flag/payload signature engine; `methods.json`-style rules load via `serde` |
| `deflect-reflect` | ✅ | Reflection/amplification defense via request/response correlation |
| `deflect-fingerprint` | ✅ | Learning fingerprints of unknown attacks (bounded heavy-hitter counting) |
| `deflect-enforce` | ✅ | Enforcement behind an `Enforcer` trait: nftables sets (XDP/netlink planned) |
| `deflect-telemetry` | ◑ | NetFlow v5 / v9 / IPFIX ingestion (sFlow pending) |
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
- **Signatures ship conservative, extend freely.** The built-in `baseline()`
  set contains only *unambiguously* malicious patterns (illegal TCP flag
  combinations — NULL/XMAS/SYN+FIN/SYN+RST), which are safe to drop at any load.
  Port- and size-based amplifier heuristics can catch legitimate traffic (a
  source port of 53 is also a real DNS reply), so those live in the stateful
  `deflect-reflect` and rate-limiting primitives, not a blind signature. Payload
  search uses `memchr` (SIMD) because scanning bytes per-packet during a flood is
  a hot path; rules load from JSON via the optional `serde` feature.
- **Reflection defense keys on solicitation, not ports.** `deflect-reflect`
  records outbound requests to amplifier ports and drops only *unsolicited*
  inbound replies — so real DNS/NTP the host asked for passes, while a spoofed
  flood from the same ports is dropped. One request authorises one reply; the
  amplifier-port set is an 8 KiB bitmap and the request table is fixed-size. An
  inbound-only `size_only` mode falls back to a reply-size threshold when egress
  isn't visible.
- **Fingerprints are learned, not guessed — and conservatively.** When traffic
  is unrecognized but under attack, `deflect-fingerprint` finds what the flood
  has in common. Each feature dimension uses a Misra–Gries heavy-hitter summary
  whose error is one-sided (it never *overstates* a value's share), so a
  synthesized fingerprint reflects traffic that genuinely dominated the sample.
  It refuses to emit a fingerprint unless a *specific* dimension (port, length,
  or payload prefix) dominates, so it can never generate a rule as broad as
  "drop all UDP."
- **Enforcement separates policy from mechanism.** `deflect-enforce` builds the
  nftables scripts as pure, testable strings and runs them through a pluggable
  `NftRunner` (`nft -f -` in production, a recording runner in tests). Bans
  carry a TTL the kernel expires itself via `flags timeout`; the drop chain sits
  at priority -300 so banned sources are dropped before conntrack. A
  `NullEnforcer` gives watch/dry-run mode for free.
- **Telemetry parses untrusted input without ever panicking.** `deflect-telemetry`
  decodes NetFlow v5/v9 and IPFIX through a bounds-checked byte reader whose every
  read returns a `Result` — truncated or malformed datagrams yield the records
  decoded so far, never a crash. The template-based formats (v9, IPFIX) keep a
  `TemplateRegistry` across datagrams, so data arriving before its template is
  skipped and decoded once the template is learned, exactly as the RFCs require.

## Status

Early. Nine crates are implemented and tested (117 tests default, 119 with
`serde`; `clippy -W pedantic` clean; core primitives build `no_std`). The
remaining crates are scaffolded as roadmap.

## License

Licensed under either of Apache-2.0 or MIT at your option.
