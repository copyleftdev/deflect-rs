//! (Protocol names like NetFlow/IPFIX read as prose here, not code spans.)
#![allow(clippy::doc_markdown)]
//! Property tests for the ingestion plane. The datagrams are attacker-reachable,
//! so the overriding guarantee is that decoding *any* byte string returns rather
//! than panicking — no out-of-bounds read, no arithmetic overflow, however the
//! version byte, set lengths or field widths are chosen. A well-formed NetFlow
//! v5 datagram also round-trips to the record count it declares.

use deflect_telemetry::{parse_netflow_v5, parse_sflow, Decoder};
use proptest::prelude::*;

proptest! {
    #[test]
    fn ingest_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut d = Decoder::new();
        let _ = d.ingest(&bytes);
        let _ = d.ingest_ipfix(&bytes);
        let _ = d.ingest_netflow_v9(&bytes);
        let _ = parse_netflow_v5(&bytes);
        let _ = parse_sflow(&bytes);
    }

    #[test]
    fn truncating_a_valid_sflow_datagram_never_panics(
        rate in any::<u32>(),
        frame_len in any::<u32>(),
        body in prop::collection::vec(any::<u8>(), 0..200),
        cut in 0usize..320,
    ) {
        // A real sFlow v5 header and one flow sample wrapping an arbitrary raw
        // header, cut at every offset.
        let mut header = Vec::new();
        header.extend(1u32.to_be_bytes()); // header protocol (Ethernet)
        header.extend(frame_len.to_be_bytes());
        header.extend(0u32.to_be_bytes()); // stripped
        header.extend((u32::try_from(body.len()).unwrap_or(u32::MAX)).to_be_bytes());
        header.extend(&body);
        while header.len() % 4 != 0 {
            header.push(0);
        }
        let mut record = Vec::new();
        record.extend(1u32.to_be_bytes()); // raw packet header format
        record.extend((u32::try_from(header.len()).unwrap_or(u32::MAX)).to_be_bytes());
        record.extend(&header);

        let mut sample_body = Vec::new();
        sample_body.extend(0u32.to_be_bytes()); // sequence
        sample_body.extend(0u32.to_be_bytes()); // source id
        sample_body.extend(rate.to_be_bytes());
        sample_body.extend(0u32.to_be_bytes()); // pool
        sample_body.extend(0u32.to_be_bytes()); // drops
        sample_body.extend([0u8; 8]); // interfaces
        sample_body.extend(1u32.to_be_bytes()); // one record
        sample_body.extend(&record);

        let mut dg = Vec::new();
        dg.extend(5u32.to_be_bytes()); // version
        dg.extend(1u32.to_be_bytes()); // agent family IPv4
        dg.extend([10, 0, 0, 1]);
        dg.extend(0u32.to_be_bytes()); // sub-agent
        dg.extend(0u32.to_be_bytes()); // sequence
        dg.extend(0u32.to_be_bytes()); // uptime
        dg.extend(1u32.to_be_bytes()); // one sample
        dg.extend(1u32.to_be_bytes()); // sample type: flow sample
        dg.extend((u32::try_from(sample_body.len()).unwrap_or(u32::MAX)).to_be_bytes());
        dg.extend(&sample_body);

        let end = cut.min(dg.len());
        let _ = parse_sflow(&dg[..end]);
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
