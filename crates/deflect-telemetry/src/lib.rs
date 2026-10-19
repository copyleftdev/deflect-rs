//! Flow-telemetry ingestion for large links.
//!
//! On a link too fast to inspect every packet, routers export *flow records* —
//! aggregates of a 5-tuple with packet and byte counts — over NetFlow or IPFIX.
//! This crate decodes those datagrams into a unified [`FlowRecord`] that feeds
//! the detection plane (rate monitoring, fingerprinting) the same way sniffed
//! packets would, only pre-aggregated.
//!
//! Three wire formats are handled through one [`Decoder`]:
//! - **NetFlow v5** — fixed 48-byte records, stateless ([`parse_netflow_v5`]).
//! - **NetFlow v9** and **IPFIX** — template-based: a template record defines a
//!   data record's layout, and data records reference it by id. Templates arrive
//!   in their own sets and must persist across datagrams, so the `Decoder` holds
//!   a [`TemplateRegistry`]; data for a template not yet seen is skipped, as the
//!   standards require.
//!
//! Every read is bounds-checked (see [`reader`]): malformed or truncated input
//! yields the records decoded so far or a [`ParseError`], never a panic, because
//! the datagrams are attacker-reachable.
//!
//! **sFlow v5** is also handled ([`parse_sflow`]). Unlike the flow-export formats
//! it carries sampled *packet headers* rather than pre-aggregated flows, so it
//! parses each header with the [`deflect_packet`] primitive and scales the sample
//! up by its sampling rate into the same [`FlowRecord`].
//!
//! ```
//! use deflect_telemetry::Decoder;
//!
//! // A NetFlow v5 datagram: a 24-byte header declaring one flow, then one
//! // 48-byte record for 203.0.113.1 -> 198.51.100.2, UDP, dst port 53.
//! let mut datagram = vec![0u8; 24];
//! datagram[1] = 5; // version = 5
//! datagram[3] = 1; // flow count = 1
//! let mut record = vec![0u8; 48];
//! record[0..4].copy_from_slice(&[203, 0, 113, 1]); // source address
//! record[4..8].copy_from_slice(&[198, 51, 100, 2]); // destination address
//! record[16..20].copy_from_slice(&10u32.to_be_bytes()); // packet count
//! record[20..24].copy_from_slice(&1500u32.to_be_bytes()); // byte count
//! record[34..36].copy_from_slice(&53u16.to_be_bytes()); // destination port
//! record[38] = 17; // protocol = UDP
//! datagram.extend(record);
//!
//! // One Decoder handles every flow-telemetry format; ingest dispatches on
//! // the version field and yields unified `FlowRecord`s.
//! let mut decoder = Decoder::new();
//! let flows = decoder.ingest(&datagram).expect("valid v5 datagram");
//! assert_eq!(flows.len(), 1);
//! assert_eq!(flows[0].dst_port, 53);
//! assert_eq!(flows[0].packets, 10);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// The docs name protocols (NetFlow, IPFIX, sFlow) and hex constants as prose,
// not code, so the identifier-backtick lint only produces noise here.
#![allow(clippy::doc_markdown)]
// Test fixtures build small datagrams with length casts and empty-vec asserts;
// those pedantic lints add nothing to fixture code.
#![cfg_attr(test, allow(clippy::cast_possible_truncation, clippy::assert_is_empty))]

extern crate alloc;

#[cfg(not(feature = "std"))]
compile_error!("deflect-telemetry currently requires the `std` feature (template registry)");

mod netflow_v5;
pub mod reader;
mod record;
mod sflow;
mod template;

use alloc::vec::Vec;

pub use netflow_v5::ParseV5Error;
pub use record::{field, FlowRecord};
pub use template::{FieldSpec, Template, TemplateRegistry};

/// Stateless NetFlow v5 parse; re-exported for callers that only speak v5.
///
/// # Errors
/// See [`ParseV5Error`].
pub fn parse_netflow_v5(datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseV5Error> {
    netflow_v5::parse(datagram)
}

/// Stateless sFlow v5 parse; re-exported for callers that only speak sFlow.
///
/// # Errors
/// Returns [`ParseError`] on a truncated header, a version other than 5, or an
/// unknown agent address family.
pub fn parse_sflow(datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
    sflow::parse(datagram)
}

/// Why a template-based or sFlow datagram could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The fixed header was incomplete.
    Truncated,
    /// The version field did not match the expected protocol.
    BadVersion(u16),
    /// The header was complete but structurally invalid (e.g. an sFlow agent
    /// address family that is neither IPv4 nor IPv6, leaving sample offsets
    /// unknowable).
    Malformed,
}

/// Decodes NetFlow v9 and IPFIX, retaining templates between datagrams.
#[derive(Debug, Clone, Default)]
pub struct Decoder {
    registry: TemplateRegistry,
}

impl Decoder {
    /// Create a decoder with an empty template registry.
    #[must_use]
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Number of templates currently learned.
    #[must_use]
    pub fn template_count(&self) -> usize {
        self.registry.len()
    }

    /// Decode one datagram, dispatching on its version field: 5 → NetFlow v5,
    /// 9 → NetFlow v9, 10 → IPFIX, and a leading `0x0000` → sFlow v5 (whose
    /// version is a 32-bit `5`, so its first two bytes are zero).
    ///
    /// # Errors
    /// Returns [`ParseError`] on a truncated header or an unrecognised version.
    pub fn ingest(&mut self, datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
        let version = peek_version(datagram)?;
        match version {
            0 => parse_sflow(datagram),
            5 => parse_netflow_v5(datagram).map_err(|_| ParseError::Truncated),
            9 => self.ingest_netflow_v9(datagram),
            10 => self.ingest_ipfix(datagram),
            other => Err(ParseError::BadVersion(other)),
        }
    }

    /// Decode an sFlow v5 datagram. sFlow is stateless (no template registry), so
    /// this delegates to the free [`parse_sflow`] and is offered on [`Decoder`]
    /// only so one object handles every flow-telemetry format.
    ///
    /// # Errors
    /// See [`parse_sflow`].
    #[allow(clippy::unused_self)]
    pub fn ingest_sflow(&self, datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
        parse_sflow(datagram)
    }

    /// Decode an IPFIX (version 10) message.
    ///
    /// # Errors
    /// Returns [`ParseError`] on a truncated header or wrong version.
    pub fn ingest_ipfix(&mut self, datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
        let mut r = reader::Reader::new(datagram);
        let version = r.u16().map_err(|_| ParseError::Truncated)?;
        if version != 10 {
            return Err(ParseError::BadVersion(version));
        }
        // length, export_time, sequence, then observation domain id.
        r.u16().map_err(|_| ParseError::Truncated)?;
        r.u32().map_err(|_| ParseError::Truncated)?;
        r.u32().map_err(|_| ParseError::Truncated)?;
        let domain = r.u32().map_err(|_| ParseError::Truncated)?;

        let mut out = Vec::new();
        template::decode_sets(&mut r, domain, true, &mut self.registry, &mut out);
        Ok(out)
    }

    /// Decode a NetFlow v9 (version 9) message.
    ///
    /// # Errors
    /// Returns [`ParseError`] on a truncated header or wrong version.
    pub fn ingest_netflow_v9(&mut self, datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
        let mut r = reader::Reader::new(datagram);
        let version = r.u16().map_err(|_| ParseError::Truncated)?;
        if version != 9 {
            return Err(ParseError::BadVersion(version));
        }
        // count, sys_uptime, unix_secs, sequence, then source id.
        r.u16().map_err(|_| ParseError::Truncated)?;
        r.u32().map_err(|_| ParseError::Truncated)?;
        r.u32().map_err(|_| ParseError::Truncated)?;
        r.u32().map_err(|_| ParseError::Truncated)?;
        let source_id = r.u32().map_err(|_| ParseError::Truncated)?;

        let mut out = Vec::new();
        template::decode_sets(&mut r, source_id, false, &mut self.registry, &mut out);
        Ok(out)
    }
}

fn peek_version(datagram: &[u8]) -> Result<u16, ParseError> {
    let mut r = reader::Reader::new(datagram);
    r.u16().map_err(|_| ParseError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::net::IpAddr;
    use deflect_core::L4;
    use record::field;

    // Build an IPFIX template set (set id 2) defining a template with the given
    // (field_id, length) pairs.
    fn ipfix_template_set(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(template_id.to_be_bytes());
        body.extend((fields.len() as u16).to_be_bytes());
        for (id, len) in fields {
            body.extend(id.to_be_bytes());
            body.extend(len.to_be_bytes());
        }
        let mut set = Vec::new();
        set.extend(2u16.to_be_bytes());
        set.extend(((body.len() + 4) as u16).to_be_bytes());
        set.extend(body);
        set
    }

    fn ipfix_data_set(template_id: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for rec in records {
            body.extend_from_slice(rec);
        }
        let mut set = Vec::new();
        set.extend(template_id.to_be_bytes());
        set.extend(((body.len() + 4) as u16).to_be_bytes());
        set.extend(body);
        set
    }

    fn ipfix_header(domain: u32, body_len: usize) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend(10u16.to_be_bytes());
        h.extend(((body_len + 16) as u16).to_be_bytes());
        h.extend(0u32.to_be_bytes()); // export time
        h.extend(0u32.to_be_bytes()); // sequence
        h.extend(domain.to_be_bytes());
        h
    }

    #[test]
    fn ipfix_template_then_data_decodes() {
        // Template 256: srcIPv4, dstIPv4, protocol(1), srcPort(2), dstPort(2),
        // packets(4), octets(4).
        let fields = [
            (field::SRC_IPV4, 4),
            (field::DST_IPV4, 4),
            (field::PROTOCOL, 1),
            (field::SRC_PORT, 2),
            (field::DST_PORT, 2),
            (field::PACKET_DELTA_COUNT, 4),
            (field::OCTET_DELTA_COUNT, 4),
        ];
        let tset = ipfix_template_set(256, &fields);

        let mut rec = Vec::new();
        rec.extend([203, 0, 113, 7]);
        rec.extend([198, 51, 100, 1]);
        rec.push(17); // UDP
        rec.extend(53u16.to_be_bytes());
        rec.extend(40000u16.to_be_bytes());
        rec.extend(12u32.to_be_bytes()); // packets
        rec.extend(9000u32.to_be_bytes()); // bytes
        let dset = ipfix_data_set(256, &[rec]);

        let mut body = tset.clone();
        body.extend(dset);
        let mut dg = ipfix_header(1, body.len());
        dg.extend(body);

        let mut d = Decoder::new();
        let flows = d.ingest(&dg).unwrap();
        assert_eq!(d.template_count(), 1);
        assert_eq!(flows.len(), 1);
        let f = flows[0];
        assert_eq!(f.src, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(f.dst, "198.51.100.1".parse::<IpAddr>().unwrap());
        assert_eq!(f.l4(), L4::Udp);
        assert_eq!(f.src_port, 53);
        assert_eq!(f.dst_port, 40000);
        assert_eq!(f.packets, 12);
        assert_eq!(f.bytes, 9000);
    }

    #[test]
    fn data_before_template_is_skipped_then_decoded_after() {
        let fields = [
            (field::SRC_IPV4, 4),
            (field::DST_IPV4, 4),
            (field::PACKET_DELTA_COUNT, 4),
        ];

        let mut rec = Vec::new();
        rec.extend([10, 0, 0, 1]);
        rec.extend([10, 0, 0, 2]);
        rec.extend(5u32.to_be_bytes());

        // First datagram: data only, no template yet -> nothing decoded.
        let dset = ipfix_data_set(300, &[rec.clone()]);
        let mut dg1 = ipfix_header(1, dset.len());
        dg1.extend(dset);

        let mut d = Decoder::new();
        assert!(d.ingest(&dg1).unwrap().is_empty());

        // Second datagram carries the template then the same data.
        let tset = ipfix_template_set(300, &fields);
        let dset2 = ipfix_data_set(300, &[rec]);
        let mut body = tset;
        body.extend(dset2);
        let mut dg2 = ipfix_header(1, body.len());
        dg2.extend(body);

        let flows = d.ingest(&dg2).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].packets, 5);
    }

    #[test]
    fn multiple_records_in_one_data_set() {
        let fields = [(field::SRC_IPV4, 4), (field::DST_PORT, 2)];
        let tset = ipfix_template_set(256, &fields);
        let mk = |a: u8, port: u16| {
            let mut rec = vec![a, a, a, a];
            rec.extend(port.to_be_bytes());
            rec
        };
        let dset = ipfix_data_set(256, &[mk(1, 80), mk(2, 443), mk(3, 53)]);
        let mut body = tset;
        body.extend(dset);
        let mut dg = ipfix_header(7, body.len());
        dg.extend(body);

        let mut d = Decoder::new();
        let flows = d.ingest(&dg).unwrap();
        assert_eq!(flows.len(), 3);
        assert_eq!(flows[2].dst_port, 53);
    }

    #[test]
    fn template_withdrawal_forgets_it() {
        let fields = [(field::SRC_IPV4, 4)];
        let tset = ipfix_template_set(256, &fields);
        let mut body = tset;
        // Withdrawal: field_count 0 for template 256.
        let mut wbody = Vec::new();
        wbody.extend(256u16.to_be_bytes());
        wbody.extend(0u16.to_be_bytes());
        let mut wset = Vec::new();
        wset.extend(2u16.to_be_bytes());
        wset.extend(((wbody.len() + 4) as u16).to_be_bytes());
        wset.extend(wbody);
        body.extend(wset);

        let mut dg = ipfix_header(1, body.len());
        dg.extend(body);
        let mut d = Decoder::new();
        d.ingest(&dg).unwrap();
        assert_eq!(d.template_count(), 0);
    }

    #[test]
    fn wrong_version_is_rejected() {
        let dg = ipfix_header(1, 0); // version 10...
        let mut d = Decoder::new();
        assert_eq!(d.ingest_netflow_v9(&dg), Err(ParseError::BadVersion(10)));
    }

    #[test]
    fn truncated_datagram_does_not_panic() {
        let mut d = Decoder::new();
        for cut in 0..18 {
            let dg = ipfix_header(1, 0);
            let _ = d.ingest_ipfix(&dg[..cut.min(dg.len())]);
        }
    }

    #[test]
    fn garbage_sets_are_ignored() {
        // Valid header, then a set claiming length 4 (empty body) and junk.
        let mut dg = ipfix_header(1, 8);
        dg.extend(2u16.to_be_bytes());
        dg.extend(4u16.to_be_bytes()); // empty template set
        dg.extend([0xAB, 0xCD, 0xEF, 0x01]); // trailing junk < 4 handled
        let mut d = Decoder::new();
        assert!(d.ingest(&dg).unwrap().is_empty());
    }

    // A one-record IPFIX datagram from a field layout and a record body.
    fn ipfix_one(fields: &[(u16, u16)], rec: Vec<u8>) -> Vec<u8> {
        let tset = ipfix_template_set(256, fields);
        let dset = ipfix_data_set(256, &[rec]);
        let mut body = tset;
        body.extend(dset);
        let mut dg = ipfix_header(1, body.len());
        dg.extend(body);
        dg
    }

    #[test]
    fn decoder_dispatches_netflow_v5() {
        let mut dg = vec![0u8; 24];
        dg[1] = 5; // version
        dg[3] = 1; // count
        let mut rec = vec![0u8; 48];
        rec[0..4].copy_from_slice(&[203, 0, 113, 1]);
        rec[34..36].copy_from_slice(&53u16.to_be_bytes());
        rec[38] = 17;
        dg.extend(rec);
        // The re-exported wrapper and the Decoder dispatch both yield the flow.
        let flows = parse_netflow_v5(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].dst_port, 53);
        let mut d = Decoder::new();
        assert_eq!(d.ingest(&dg).unwrap().len(), 1);
    }

    #[test]
    fn ipv6_addresses_decode() {
        let fields = [
            (field::SRC_IPV6, 16),
            (field::DST_IPV6, 16),
            (field::DST_PORT, 2),
        ];
        let src: core::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: core::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut rec = Vec::new();
        rec.extend(src.octets());
        rec.extend(dst.octets());
        rec.extend(443u16.to_be_bytes());
        let mut d = Decoder::new();
        let f = d.ingest(&ipfix_one(&fields, rec)).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].src, IpAddr::V6(src));
        assert_eq!(f[0].dst, IpAddr::V6(dst));
        assert_eq!(f[0].dst_port, 443);
    }

    #[test]
    fn tcp_control_bits_field_decodes() {
        let fields = [(field::DST_PORT, 2), (field::TCP_CONTROL_BITS, 1)];
        let mut rec = Vec::new();
        rec.extend(80u16.to_be_bytes());
        rec.push(0x12); // SYN+ACK
        let mut d = Decoder::new();
        let f = d.ingest(&ipfix_one(&fields, rec)).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tcp_flags, deflect_core::TcpFlags(0x12));
    }

    #[test]
    fn wrong_length_address_fields_are_skipped() {
        // SRC_IPV4/DST_IPV4 declared 6 bytes and SRC_IPV6 declared 18: each must
        // be skipped (not misread) so the address stays at its default.
        let unspecified = "0.0.0.0".parse::<IpAddr>().unwrap();
        let fields4 = [
            (field::SRC_IPV4, 6),
            (field::DST_IPV4, 6),
            (field::DST_PORT, 2),
        ];
        let mut rec = Vec::new();
        rec.extend([203, 0, 113, 7, 0xAA, 0xBB]);
        rec.extend([198, 51, 100, 1, 0xCC, 0xDD]);
        rec.extend(53u16.to_be_bytes());
        let mut d = Decoder::new();
        let f = d.ingest(&ipfix_one(&fields4, rec)).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].src, unspecified);
        assert_eq!(f[0].dst, unspecified);
        assert_eq!(f[0].dst_port, 53);

        let fields6 = [
            (field::SRC_IPV6, 18),
            (field::DST_IPV6, 18),
            (field::DST_PORT, 2),
        ];
        let mut rec6 = vec![0x20u8; 18];
        let mut rec6b = vec![0x20u8; 18];
        rec6.append(&mut rec6b);
        rec6.extend(53u16.to_be_bytes());
        let mut d6 = Decoder::new();
        let f6 = d6.ingest(&ipfix_one(&fields6, rec6)).unwrap();
        assert_eq!(f6.len(), 1);
        assert_eq!(f6[0].src, unspecified);
        assert_eq!(f6[0].dst, unspecified);
        assert_eq!(f6[0].dst_port, 53);
    }

    #[test]
    fn variable_length_short_form_is_measured() {
        // A varlen field (unknown id) with a <255 length prefix: the length is
        // that single byte, and the following dst_port must still be found.
        let fields = [(999u16, 0xffff), (field::DST_PORT, 2)];
        let mut rec = Vec::new();
        rec.push(3);
        rec.extend([0xDE, 0xAD, 0xBE]);
        rec.extend(53u16.to_be_bytes());
        let mut d = Decoder::new();
        let f = d.ingest(&ipfix_one(&fields, rec)).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].dst_port, 53);
    }

    #[test]
    fn variable_length_long_form_is_measured() {
        // The 255 escape means a 2-byte length follows.
        let fields = [(999u16, 0xffff), (field::DST_PORT, 2)];
        let mut rec = Vec::new();
        rec.push(255);
        rec.extend(2u16.to_be_bytes());
        rec.extend([0xDE, 0xAD]);
        rec.extend(53u16.to_be_bytes());
        let mut d = Decoder::new();
        let f = d.ingest(&ipfix_one(&fields, rec)).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].dst_port, 53);
    }

    #[test]
    fn empty_set_is_stepped_over() {
        // A set of length 4 (header only, no body) must not halt processing of
        // the real template and data sets that follow it.
        let fields = [(field::SRC_IPV4, 4), (field::DST_PORT, 2)];
        let tset = ipfix_template_set(256, &fields);
        let mut rec = vec![10, 0, 0, 1];
        rec.extend(53u16.to_be_bytes());
        let dset = ipfix_data_set(256, &[rec]);
        let mut body = Vec::new();
        body.extend(4u16.to_be_bytes()); // reserved set id
        body.extend(4u16.to_be_bytes()); // length 4 = empty
        body.extend(tset);
        body.extend(dset);
        let mut dg = ipfix_header(1, body.len());
        dg.extend(body);
        let mut d = Decoder::new();
        let f = d.ingest(&dg).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].dst_port, 53);
    }

    #[test]
    fn data_set_at_a_reserved_id_is_not_decoded() {
        // A template registered at id 200 (reserved, < 256) must not be used to
        // decode a data set sharing that id.
        let fields = [(field::SRC_IPV4, 4), (field::DST_PORT, 2)];
        let tset = ipfix_template_set(200, &fields);
        let mut rec = vec![10, 0, 0, 1];
        rec.extend(53u16.to_be_bytes());
        let dset = ipfix_data_set(200, &[rec]);
        let mut body = tset;
        body.extend(dset);
        let mut dg = ipfix_header(1, body.len());
        dg.extend(body);
        let mut d = Decoder::new();
        let f = d.ingest(&dg).unwrap();
        assert_eq!(d.template_count(), 1);
        assert!(f.is_empty());
    }

    // --- sFlow v5 -----------------------------------------------------------

    fn pad4(mut v: Vec<u8>) -> Vec<u8> {
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    // A sampled header carrying a bare IPv4+TCP packet (sFlow header protocol 11).
    fn ipv4_tcp_header(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut l4 = vec![0u8; 14];
        l4[0..2].copy_from_slice(&sport.to_be_bytes());
        l4[2..4].copy_from_slice(&dport.to_be_bytes());
        l4[13] = flags;
        let mut p = Vec::new();
        p.push(0x45);
        p.push(0);
        p.extend((20u16 + l4.len() as u16).to_be_bytes());
        p.extend(0u16.to_be_bytes());
        p.extend(0u16.to_be_bytes());
        p.push(64);
        p.push(6); // TCP
        p.extend(0u16.to_be_bytes());
        p.extend(src);
        p.extend(dst);
        p.extend(l4);
        p
    }

    // An sFlow raw-packet-header flow record (format 1), header bytes padded to
    // a 4-byte boundary as XDR requires. `declared_header_len` lets a test claim
    // more header than is present to exercise truncation handling.
    fn raw_header_record(frame_len: u32, header_protocol: u32, header: &[u8]) -> Vec<u8> {
        raw_header_record_declaring(frame_len, header_protocol, header, header.len() as u32)
    }

    fn raw_header_record_declaring(
        frame_len: u32,
        header_protocol: u32,
        header: &[u8],
        declared_header_len: u32,
    ) -> Vec<u8> {
        // flow_format 1 = standard-enterprise raw packet header.
        flow_record(1, frame_len, header_protocol, header, declared_header_len)
    }

    fn flow_record(
        flow_format: u32,
        frame_len: u32,
        header_protocol: u32,
        header: &[u8],
        declared_header_len: u32,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(header_protocol.to_be_bytes());
        body.extend(frame_len.to_be_bytes());
        body.extend(0u32.to_be_bytes()); // stripped
        body.extend(declared_header_len.to_be_bytes());
        body.extend_from_slice(header);
        let body = pad4(body);
        let mut rec = Vec::new();
        rec.extend(flow_format.to_be_bytes());
        rec.extend((body.len() as u32).to_be_bytes());
        rec.extend(body);
        rec
    }

    fn flow_sample(sample_format: u32, rate: u32, records: &[Vec<u8>]) -> Vec<u8> {
        let expanded = sample_format == 3;
        let mut body = Vec::new();
        body.extend(0u32.to_be_bytes()); // sample sequence number
        if expanded {
            body.extend(0u32.to_be_bytes()); // source id type
            body.extend(0u32.to_be_bytes()); // source id index
        } else {
            body.extend(0u32.to_be_bytes()); // source id
        }
        body.extend(rate.to_be_bytes());
        body.extend(0u32.to_be_bytes()); // sample pool
        body.extend(0u32.to_be_bytes()); // drops
        if expanded {
            body.extend([0u8; 16]); // input fmt+val, output fmt+val
        } else {
            body.extend([0u8; 8]); // input, output interface
        }
        body.extend((records.len() as u32).to_be_bytes());
        for r in records {
            body.extend_from_slice(r);
        }
        sample(sample_format, &body)
    }

    fn sample(sample_type: u32, body: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend(sample_type.to_be_bytes());
        s.extend((body.len() as u32).to_be_bytes());
        s.extend_from_slice(body);
        s
    }

    fn sflow_datagram(agent_family: u32, samples: &[Vec<u8>]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend(5u32.to_be_bytes()); // version
        d.extend(agent_family.to_be_bytes());
        match agent_family {
            2 => d.extend([0u8; 16]),
            _ => d.extend([10, 0, 0, 1]),
        }
        d.extend(0u32.to_be_bytes()); // sub-agent id
        d.extend(0u32.to_be_bytes()); // sequence
        d.extend(0u32.to_be_bytes()); // uptime
        d.extend((samples.len() as u32).to_be_bytes());
        for s in samples {
            d.extend_from_slice(s);
        }
        d
    }

    #[test]
    fn sflow_flow_sample_scales_by_the_sampling_rate() {
        let hdr = ipv4_tcp_header([203, 0, 113, 9], [198, 51, 100, 2], 1234, 80, 0x02);
        let rec = raw_header_record(1500, 11, &hdr);
        let dg = sflow_datagram(1, &[flow_sample(1, 512, &[rec])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        let f = flows[0];
        assert_eq!(f.src, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(f.dst, "198.51.100.2".parse::<IpAddr>().unwrap());
        assert_eq!(f.l4(), L4::Tcp);
        assert_eq!(f.src_port, 1234);
        assert_eq!(f.dst_port, 80);
        assert_eq!(f.tcp_flags, deflect_core::TcpFlags::SYN);
        assert_eq!(f.packets, 512);
        assert_eq!(f.bytes, 512 * 1500);
    }

    #[test]
    fn sflow_expanded_flow_sample_decodes() {
        let hdr = ipv4_tcp_header([10, 0, 0, 5], [10, 0, 0, 6], 5555, 443, 0x10);
        let rec = raw_header_record(64, 11, &hdr);
        let dg = sflow_datagram(1, &[flow_sample(3, 1, &[rec])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].src_port, 5555);
        assert_eq!(flows[0].dst_port, 443);
        assert_eq!(flows[0].packets, 1);
        assert_eq!(flows[0].bytes, 64);
    }

    #[test]
    fn sflow_zero_rate_counts_the_sample_once() {
        let hdr = ipv4_tcp_header([1, 1, 1, 1], [2, 2, 2, 2], 7, 8, 0x02);
        let rec = raw_header_record(100, 11, &hdr);
        let dg = sflow_datagram(1, &[flow_sample(1, 0, &[rec])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows[0].packets, 1);
        assert_eq!(flows[0].bytes, 100);
    }

    #[test]
    fn sflow_multiple_records_in_one_sample() {
        let a = raw_header_record(
            100,
            11,
            &ipv4_tcp_header([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x02),
        );
        let b = raw_header_record(
            200,
            11,
            &ipv4_tcp_header([3, 3, 3, 3], [4, 4, 4, 4], 3, 4, 0x10),
        );
        let dg = sflow_datagram(1, &[flow_sample(1, 1, &[a, b])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].dst_port, 2);
        assert_eq!(flows[1].dst_port, 4);
        assert_eq!(flows[1].bytes, 200);
    }

    #[test]
    fn sflow_counter_samples_are_ignored() {
        // A counter sample (format 2) carries no flow records.
        let counter = sample(2, &[0u8; 32]);
        let hdr = ipv4_tcp_header([9, 9, 9, 9], [8, 8, 8, 8], 10, 20, 0x02);
        let flow = flow_sample(1, 1, &[raw_header_record(40, 11, &hdr)]);
        let dg = sflow_datagram(1, &[counter, flow]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].dst_port, 20);
    }

    #[test]
    fn sflow_non_raw_flow_records_are_ignored() {
        // A flow record of an unhandled format (e.g. 2 = extended switch data).
        let mut other = Vec::new();
        other.extend(2u32.to_be_bytes()); // flow_format
        other.extend(8u32.to_be_bytes()); // flow_len
        other.extend([0u8; 8]);
        let hdr = ipv4_tcp_header([9, 9, 9, 9], [8, 8, 8, 8], 10, 20, 0x02);
        let raw = raw_header_record(40, 11, &hdr);
        let dg = sflow_datagram(1, &[flow_sample(1, 1, &[other, raw])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].dst_port, 20);
    }

    #[test]
    fn sflow_non_standard_enterprise_sample_is_ignored() {
        // data_format = enterprise 1, format 1: the format matches a flow sample,
        // but a non-zero enterprise is a vendor extension and must be skipped.
        // Pins the `enterprise == 0 && ...` guard against becoming `||`.
        let hdr = ipv4_tcp_header([1, 1, 1, 1], [2, 2, 2, 2], 10, 20, 0x02);
        let data_format = (1u32 << 12) | 1;
        let dg = sflow_datagram(
            1,
            &[flow_sample(
                data_format,
                1,
                &[raw_header_record(100, 11, &hdr)],
            )],
        );
        assert!(parse_sflow(&dg).unwrap().is_empty());
    }

    #[test]
    fn sflow_non_standard_enterprise_flow_record_is_ignored() {
        // Same for a flow record: enterprise 1 with the raw-header format must be
        // skipped, pinning the record-level `enterprise == 0 && ...` guard.
        let hdr = ipv4_tcp_header([1, 1, 1, 1], [2, 2, 2, 2], 10, 20, 0x02);
        let rec = flow_record((1u32 << 12) | 1, 100, 11, &hdr, hdr.len() as u32);
        let dg = sflow_datagram(1, &[flow_sample(1, 1, &[rec])]);
        assert!(parse_sflow(&dg).unwrap().is_empty());
    }

    #[test]
    fn sflow_dispatches_through_ingest() {
        let hdr = ipv4_tcp_header([203, 0, 113, 1], [203, 0, 113, 2], 100, 200, 0x02);
        let dg = sflow_datagram(1, &[flow_sample(1, 1, &[raw_header_record(60, 11, &hdr)])]);
        let mut d = Decoder::new();
        let flows = d.ingest(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].src_port, 100);
        // The convenience method on Decoder agrees with the free function.
        assert_eq!(d.ingest_sflow(&dg), parse_sflow(&dg));
    }

    #[test]
    fn sflow_ipv6_agent_address_is_stepped_over() {
        let hdr = ipv4_tcp_header([5, 5, 5, 5], [6, 6, 6, 6], 11, 22, 0x02);
        let dg = sflow_datagram(2, &[flow_sample(1, 4, &[raw_header_record(100, 11, &hdr)])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].dst_port, 22);
        assert_eq!(flows[0].packets, 4);
    }

    #[test]
    fn sflow_wrong_version_is_rejected() {
        let mut dg = sflow_datagram(1, &[]);
        dg[0..4].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(parse_sflow(&dg), Err(ParseError::BadVersion(4)));
    }

    #[test]
    fn sflow_unknown_agent_family_is_malformed() {
        let mut dg = sflow_datagram(1, &[]);
        dg[4..8].copy_from_slice(&3u32.to_be_bytes()); // neither IPv4 nor IPv6
        assert_eq!(parse_sflow(&dg), Err(ParseError::Malformed));
    }

    #[test]
    fn sflow_truncated_header_still_yields_the_tuple() {
        // Only the 20-byte IPv4 header is present, but the record claims 40
        // bytes; the decoder takes what is there and recovers the addresses.
        let ip_only = ipv4_tcp_header([203, 0, 113, 7], [198, 51, 100, 9], 0, 0, 0);
        let ip_only = &ip_only[..20];
        let rec = raw_header_record_declaring(1500, 11, ip_only, 40);
        let dg = sflow_datagram(1, &[flow_sample(1, 8, &[rec])]);
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].src, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(flows[0].protocol, 6);
        assert_eq!(flows[0].src_port, 0); // layer 4 was not captured
        assert_eq!(flows[0].packets, 8);
    }

    #[test]
    fn sflow_truncated_datagram_never_panics() {
        let hdr = ipv4_tcp_header([1, 2, 3, 4], [5, 6, 7, 8], 9, 10, 0x02);
        let dg = sflow_datagram(1, &[flow_sample(1, 1, &[raw_header_record(100, 11, &hdr)])]);
        for cut in 0..dg.len() {
            let _ = parse_sflow(&dg[..cut]);
        }
    }

    #[test]
    fn sflow_sample_count_larger_than_body_stops_cleanly() {
        let hdr = ipv4_tcp_header([1, 2, 3, 4], [5, 6, 7, 8], 9, 10, 0x02);
        let mut dg = sflow_datagram(1, &[flow_sample(1, 1, &[raw_header_record(100, 11, &hdr)])]);
        // Claim 1000 samples though only one is present.
        let count_at = dg.len()
            - {
                let one = flow_sample(1, 1, &[raw_header_record(100, 11, &hdr)]);
                one.len()
            }
            - 4;
        dg[count_at..count_at + 4].copy_from_slice(&1000u32.to_be_bytes());
        let flows = parse_sflow(&dg).unwrap();
        assert_eq!(flows.len(), 1);
    }
}
