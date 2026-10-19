use alloc::vec::Vec;

use deflect_core::TcpFlags;

use crate::reader::{Reader, Truncated};
use crate::record::FlowRecord;

const RECORD_LEN: usize = 48;

/// Parse a NetFlow v5 datagram into its flow records.
///
/// v5 is fixed-format: a 24-byte header declaring a flow count, then that many
/// 48-byte records. Records beyond what the buffer holds are dropped rather
/// than erroring, so a truncated datagram still yields the flows it did carry.
///
/// # Errors
/// Returns [`Truncated`] if the 24-byte header itself is incomplete, or
/// [`NotV5`](ParseV5Error::NotV5) if the version field is not 5.
pub fn parse(datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseV5Error> {
    let mut r = Reader::new(datagram);
    let version = r.u16().map_err(|_| ParseV5Error::Truncated)?;
    if version != 5 {
        return Err(ParseV5Error::NotV5(version));
    }
    let count = r.u16().map_err(|_| ParseV5Error::Truncated)?;
    // Remainder of the 24-byte header (we need none of these fields).
    r.skip(20).map_err(|_| ParseV5Error::Truncated)?;

    let mut out = Vec::new();
    for _ in 0..count {
        if r.remaining() < RECORD_LEN {
            break;
        }
        match parse_record(&mut r) {
            Ok(rec) => out.push(rec),
            Err(_) => break,
        }
    }
    Ok(out)
}

fn parse_record(r: &mut Reader<'_>) -> Result<FlowRecord, Truncated> {
    let src = r.ipv4()?;
    let dst = r.ipv4()?;
    r.skip(4)?; // nexthop
    r.skip(4)?; // input + output ifindex
    let packets = u64::from(r.u32()?);
    let bytes = u64::from(r.u32()?);
    r.skip(8)?; // first + last sysuptime
    let src_port = r.u16()?;
    let dst_port = r.u16()?;
    r.skip(1)?; // pad
    let tcp_flags = r.u8()?;
    let protocol = r.u8()?;
    r.skip(1)?; // tos
    r.skip(8)?; // src_as, dst_as, src_mask, dst_mask, pad2
    Ok(FlowRecord {
        src,
        dst,
        protocol,
        src_port,
        dst_port,
        tcp_flags: TcpFlags(tcp_flags),
        packets,
        bytes,
    })
}

/// Why a NetFlow v5 datagram could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseV5Error {
    /// The 24-byte header was incomplete.
    Truncated,
    /// The version field was not 5; carries the value found.
    NotV5(u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::net::IpAddr;

    fn header(count: u16) -> Vec<u8> {
        let mut h = vec![0u8; 24];
        h[0] = 0;
        h[1] = 5; // version = 5
        h[2..4].copy_from_slice(&count.to_be_bytes());
        h
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        src: [u8; 4],
        dst: [u8; 4],
        pkts: u32,
        octets: u32,
        sp: u16,
        dp: u16,
        flags: u8,
        proto: u8,
    ) -> Vec<u8> {
        let mut rec = vec![0u8; RECORD_LEN];
        rec[0..4].copy_from_slice(&src);
        rec[4..8].copy_from_slice(&dst);
        rec[16..20].copy_from_slice(&pkts.to_be_bytes());
        rec[20..24].copy_from_slice(&octets.to_be_bytes());
        rec[32..34].copy_from_slice(&sp.to_be_bytes());
        rec[34..36].copy_from_slice(&dp.to_be_bytes());
        rec[37] = flags;
        rec[38] = proto;
        rec
    }

    #[test]
    fn parses_two_records() {
        let mut dg = header(2);
        dg.extend(record(
            [203, 0, 113, 1],
            [198, 51, 100, 2],
            10,
            1500,
            1234,
            53,
            0x02,
            17,
        ));
        dg.extend(record(
            [203, 0, 113, 9],
            [198, 51, 100, 2],
            7,
            999,
            40000,
            443,
            0x10,
            6,
        ));
        let flows = parse(&dg).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].src, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(flows[0].dst_port, 53);
        assert_eq!(flows[0].protocol, 17);
        assert_eq!(flows[0].packets, 10);
        assert_eq!(flows[0].bytes, 1500);
        assert_eq!(flows[1].tcp_flags, TcpFlags(0x10));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut dg = header(0);
        dg[1] = 9;
        assert_eq!(parse(&dg), Err(ParseV5Error::NotV5(9)));
    }

    #[test]
    fn truncated_header_errors() {
        assert_eq!(parse(&[0, 5, 0, 1]), Err(ParseV5Error::Truncated));
    }

    #[test]
    fn count_larger_than_body_yields_available_records() {
        // Header claims 5 flows but only one record follows.
        let mut dg = header(5);
        dg.extend(record([10, 0, 0, 1], [10, 0, 0, 2], 1, 64, 1, 2, 0, 6));
        let flows = parse(&dg).unwrap();
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn empty_body_is_ok() {
        let flows = parse(&header(0)).unwrap();
        assert!(flows.is_empty());
    }
}
