use alloc::vec::Vec;

use deflect_packet::{parse_sampled_header, FiveTuple};

use crate::reader::Reader;
use crate::record::FlowRecord;
use crate::ParseError;

const SFLOW_VERSION: u32 = 5;

// Standard-enterprise (0) sample formats carried in a datagram.
const SAMPLE_FLOW: u32 = 1;
const SAMPLE_FLOW_EXPANDED: u32 = 3;

// Standard-enterprise (0) flow-record format: a verbatim sampled packet header.
const FLOW_RAW_PACKET_HEADER: u32 = 1;

// Agent address families in the datagram header.
const AGENT_ADDR_IPV4: u32 = 1;
const AGENT_ADDR_IPV6: u32 = 2;

/// A `data_format` word splits into a 20-bit enterprise number and a 12-bit
/// format; only the standard enterprise (0) is decoded here.
fn split_format(data_format: u32) -> (u32, u32) {
    (data_format >> 12, data_format & 0x0fff)
}

/// Decode an sFlow v5 datagram into flow records.
///
/// sFlow carries sampled *packets*, not pre-aggregated flows: each flow sample
/// holds a slice of a real packet's header, which the packet parser turns into a
/// 5-tuple. The sampling rate scales one sample up to the traffic it represents,
/// so `packets` is set to the rate and `bytes` to `rate * frame_length`.
///
/// Every length is XDR-encoded as a multiple of four bytes, so each structure is
/// bounded by its declared length (via [`Reader::sub`]) with no realignment; a
/// truncated or malformed datagram yields the records decoded so far.
pub(crate) fn parse(datagram: &[u8]) -> Result<Vec<FlowRecord>, ParseError> {
    let mut r = Reader::new(datagram);
    let version = r.u32().map_err(|_| ParseError::Truncated)?;
    if version != SFLOW_VERSION {
        return Err(ParseError::BadVersion(
            u16::try_from(version).unwrap_or(u16::MAX),
        ));
    }
    let agent_family = r.u32().map_err(|_| ParseError::Truncated)?;
    let agent_addr_len = match agent_family {
        AGENT_ADDR_IPV4 => 4,
        AGENT_ADDR_IPV6 => 16,
        _ => return Err(ParseError::Malformed),
    };
    r.skip(agent_addr_len).map_err(|_| ParseError::Truncated)?;
    r.u32().map_err(|_| ParseError::Truncated)?; // sub-agent id
    r.u32().map_err(|_| ParseError::Truncated)?; // datagram sequence number
    r.u32().map_err(|_| ParseError::Truncated)?; // agent uptime (ms)
    let sample_count = r.u32().map_err(|_| ParseError::Truncated)?;

    let mut out = Vec::new();
    decode_samples(&mut r, sample_count, &mut out);
    Ok(out)
}

fn decode_samples(r: &mut Reader<'_>, sample_count: u32, out: &mut Vec<FlowRecord>) {
    for _ in 0..sample_count {
        let Ok(sample_type) = r.u32() else { break };
        let Ok(sample_len) = r.u32() else { break };
        let Ok(mut body) = r.sub(sample_len as usize) else {
            break;
        };
        let (enterprise, format) = split_format(sample_type);
        if enterprise == 0 && (format == SAMPLE_FLOW || format == SAMPLE_FLOW_EXPANDED) {
            decode_flow_sample(&mut body, format == SAMPLE_FLOW_EXPANDED, out);
        }
    }
}

/// Decode a flow sample's fixed prologue, then its flow records. The expanded
/// form (format 3) widens the source id and each interface into two words.
fn decode_flow_sample(r: &mut Reader<'_>, expanded: bool, out: &mut Vec<FlowRecord>) {
    if r.u32().is_err() {
        return; // sample sequence number
    }
    if expanded {
        if r.skip(8).is_err() {
            return; // source id type + index
        }
    } else if r.u32().is_err() {
        return; // source id (type and index packed)
    }
    let Ok(sampling_rate) = r.u32() else { return };
    if r.u32().is_err() {
        return; // sample pool
    }
    if r.u32().is_err() {
        return; // dropped packets
    }
    let interface_bytes = if expanded { 16 } else { 8 };
    if r.skip(interface_bytes).is_err() {
        return; // input + output interface
    }
    let Ok(record_count) = r.u32() else { return };
    decode_flow_records(r, record_count, sampling_rate, out);
}

fn decode_flow_records(
    r: &mut Reader<'_>,
    record_count: u32,
    sampling_rate: u32,
    out: &mut Vec<FlowRecord>,
) {
    for _ in 0..record_count {
        let Ok(flow_format) = r.u32() else { break };
        let Ok(flow_len) = r.u32() else { break };
        let Ok(mut body) = r.sub(flow_len as usize) else {
            break;
        };
        let (enterprise, format) = split_format(flow_format);
        if enterprise == 0 && format == FLOW_RAW_PACKET_HEADER {
            if let Some(rec) = decode_raw_header(&mut body, sampling_rate) {
                out.push(rec);
            }
        }
    }
}

fn decode_raw_header(r: &mut Reader<'_>, sampling_rate: u32) -> Option<FlowRecord> {
    let header_protocol = r.u32().ok()?;
    let frame_length = r.u32().ok()?;
    r.u32().ok()?; // bytes stripped from the original frame (e.g. the FCS)
    let header_length = r.u32().ok()? as usize;
    // A sampler may declare more header than it captured; take what is present so
    // a truncated header still yields its 5-tuple.
    let available = header_length.min(r.remaining());
    let header = r.bytes(available).ok()?;
    let tuple = parse_sampled_header(header_protocol, header)?;
    Some(flow_record(&tuple, sampling_rate, frame_length))
}

/// Build a flow record from one sample, scaling by the sampling rate. A rate of
/// zero is treated as one, so an unknown rate counts the observed sample itself
/// rather than discarding it.
fn flow_record(tuple: &FiveTuple, sampling_rate: u32, frame_length: u32) -> FlowRecord {
    let rate = u64::from(sampling_rate.max(1));
    FlowRecord {
        src: tuple.src,
        dst: tuple.dst,
        protocol: tuple.protocol,
        src_port: tuple.src_port,
        dst_port: tuple.dst_port,
        tcp_flags: tuple.tcp_flags,
        packets: rate,
        bytes: rate.saturating_mul(u64::from(frame_length)),
    }
}
