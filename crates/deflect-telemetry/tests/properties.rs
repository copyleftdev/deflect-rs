//! (Protocol names like NetFlow/IPFIX read as prose here, not code spans.)
#![allow(clippy::doc_markdown)]
//! Property tests for the ingestion plane. The datagrams are attacker-reachable,
//! so the overriding guarantee is that decoding *any* byte string returns rather
//! than panicking — no out-of-bounds read, no arithmetic overflow, however the
//! version byte, set lengths or field widths are chosen. A well-formed NetFlow
//! v5 datagram also round-trips to the record count it declares.

use deflect_telemetry::{parse_netflow_v5, Decoder};
use proptest::prelude::*;

proptest! {
    #[test]
    fn ingest_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut d = Decoder::new();
        let _ = d.ingest(&bytes);
        let _ = d.ingest_ipfix(&bytes);
        let _ = d.ingest_netflow_v9(&bytes);
        let _ = parse_netflow_v5(&bytes);
    }

    #[test]
    fn truncating_a_valid_ipfix_datagram_never_panics(
        body in prop::collection::vec(any::<u8>(), 0..300),
        cut in 0usize..320,
    ) {
        // A real IPFIX header followed by arbitrary body, cut at every offset.
        let mut dg = Vec::new();
        dg.extend(10u16.to_be_bytes());
        dg.extend((u16::try_from(body.len() + 16).unwrap_or(u16::MAX)).to_be_bytes());
        dg.extend(0u32.to_be_bytes());
        dg.extend(0u32.to_be_bytes());
        dg.extend(0u32.to_be_bytes());
        dg.extend(&body);
        let end = cut.min(dg.len());
        let mut d = Decoder::new();
        let _ = d.ingest(&dg[..end]);
    }

    #[test]
    fn netflow_v5_yields_the_declared_record_count(n in 0u16..40) {
        // Header (version 5, count n) followed by exactly n 48-byte records.
        let mut dg = vec![0u8; 24];
        dg[1] = 5;
        dg[2..4].copy_from_slice(&n.to_be_bytes());
        for i in 0..n {
            let mut rec = vec![0u8; 48];
            rec[34..36].copy_from_slice(&i.to_be_bytes()); // dst_port = i
            dg.extend(rec);
        }
        let flows = parse_netflow_v5(&dg).unwrap();
        prop_assert_eq!(flows.len(), usize::from(n));
        if n > 0 {
            prop_assert_eq!(flows[usize::from(n) - 1].dst_port, n - 1);
        }
    }
}
