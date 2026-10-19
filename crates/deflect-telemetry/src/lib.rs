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
//! sFlow is not yet handled; its samples carry raw packet headers and so need an
//! Ethernet/IP/L4 header parser, planned as a separate primitive.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
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

/// Why a template-based datagram could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The fixed header was incomplete.
    Truncated,
    /// The version field did not match the expected protocol.
    BadVersion(u16),
}

/// Decodes NetFlow v9 and IPFIX, retaining templates between datagrams.
#[derive(Debug, Clone, Default)]
pub struct Decoder {
    registry: TemplateRegistry,
}

impl Decoder {
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
    /// 9 → NetFlow v9, 10 → IPFIX.
    ///
    /// # Errors
    /// Returns [`ParseError`] on a truncated header or an unrecognised version.
    pub fn ingest(&mut self, datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
        let version = peek_version(datagram)?;
        match version {
            5 => parse_netflow_v5(datagram).map_err(|_| ParseError::Truncated),
            9 => self.ingest_netflow_v9(datagram),
            10 => self.ingest_ipfix(datagram),
            other => Err(ParseError::BadVersion(other)),
        }
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
}
