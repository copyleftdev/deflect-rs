//! A multi-stage mitigation pipeline, end to end.
//!
//! Run with:
//!
//! ```text
//! cargo run -p deflect --example pipeline --features full
//! ```
//!
//! Three `Stage`s judge every observation independently; the pipeline keeps the
//! most severe verdict (`Pass < Challenge < RateLimit < Drop`). No stage knows
//! about the others — composition is just folding their verdicts.

use deflect::prelude::*;
use std::net::{IpAddr, Ipv4Addr};

fn verdict(stages: &[&dyn Stage], obs: &Observation<'_>) -> Verdict {
    stages.iter().fold(Verdict::Pass, |worst, stage| {
        worst.worst(stage.evaluate(obs))
    })
}

fn main() {
    // Signatures drop unambiguously malicious packets at any load.
    let signatures = baseline();

    // The governor allows a 2-packet burst per /24, then throttles.
    let governor = SourceGovernor::new(GovernorConfig {
        rate_per_sec: 2,
        burst: 2,
        aggregation: Aggregation::SUBNET,
        cost: CostMode::Packet,
        slots: 1024,
    });

    // The reflection guard drops amplifier replies nobody solicited.
    let reflection = ReflectionGuard::new(ReflectConfig::default());

    let stages: [&dyn Stage; 3] = [&signatures, &governor, &reflection];

    let attacker = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let flooder = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5));
    let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    // A well-formed SYN passes every stage.
    let syn = Packet::new(attacker, server, L4::Tcp)
        .with_ports(50000, 443)
        .with_flags(TcpFlags::SYN)
        .with_wire_len(60);
    println!(
        "well-formed SYN      -> {:?}",
        verdict(&stages, &Observation::new(syn, 0))
    );

    // An illegal SYN+FIN is dropped by the signature engine regardless of rate.
    let anomaly = Packet::new(attacker, server, L4::Tcp)
        .with_ports(50001, 443)
        .with_flags(TcpFlags::SYN | TcpFlags::FIN)
        .with_wire_len(60);
    println!(
        "SYN+FIN anomaly      -> {:?}",
        verdict(&stages, &Observation::new(anomaly, 1_000))
    );

    // A burst from a fresh source: the first two pass, the rest are rate-limited.
    for i in 0..4u64 {
        let flood = Packet::new(flooder, server, L4::Udp)
            .with_ports(50002, 123)
            .with_wire_len(1200);
        let v = verdict(&stages, &Observation::new(flood, 2_000 + i));
        println!("flood packet #{i}       -> {v:?}");
    }
}
