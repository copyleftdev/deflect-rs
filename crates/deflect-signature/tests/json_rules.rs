//! End-to-end check that a signature set loads from JSON the way the original
//! tool loads `methods.json`. Only built with the `serde` feature.
#![cfg(feature = "serde")]

use core::net::{IpAddr, Ipv4Addr};

use deflect_core::{DropReason, Packet, Verdict, L4};
use deflect_signature::{Signature, SignatureSet};

const RULES: &str = r#"
[
  {
    "id": 2001,
    "name": "memcached-amp",
    "priority": 5,
    "l4": "udp",
    "src_port": { "exact": 11211 },
    "payload": { "min_len": 1024 },
    "action": { "drop": "reflection" }
  },
  {
    "id": 2002,
    "name": "dns-anyquery-flood",
    "priority": 7,
    "l4": "udp",
    "dst_port": { "exact": 53 },
    "payload": { "contains": [102, 102, 102] },
    "action": { "drop": "signature" }
  }
]
"#;

fn pkt(l4: L4, src_port: u16, dst_port: u16, payload: &[u8]) -> Packet<'_> {
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    Packet::new(ip, ip, l4)
        .with_ports(src_port, dst_port)
        .with_payload(payload)
        .with_wire_len(u32::try_from(payload.len()).unwrap_or(u32::MAX))
}

#[test]
fn loads_and_classifies_from_json() {
    let sigs: Vec<Signature> = serde_json::from_str(RULES).expect("parse rules");
    let set = SignatureSet::new(sigs);
    assert_eq!(set.len(), 2);

    let big = vec![0u8; 2048];
    assert_eq!(
        set.classify(&pkt(L4::Udp, 11211, 40000, &big)),
        Verdict::Drop(DropReason::Reflection)
    );

    // Short memcached reply does not meet min_len, so it passes this set.
    assert_eq!(
        set.classify(&pkt(L4::Udp, 11211, 40000, &[0u8; 8])),
        Verdict::Pass
    );

    // DNS query carrying the "fff" marker in its payload is dropped.
    assert_eq!(
        set.classify(&pkt(L4::Udp, 33333, 53, b"xxfffxx")),
        Verdict::Drop(DropReason::Signature)
    );
    assert_eq!(
        set.classify(&pkt(L4::Udp, 33333, 53, b"normal")),
        Verdict::Pass
    );
}

#[test]
fn signature_round_trips_through_json() {
    let sigs: Vec<Signature> = serde_json::from_str(RULES).unwrap();
    let encoded = serde_json::to_string(&sigs).unwrap();
    let decoded: Vec<Signature> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(sigs, decoded);
}
