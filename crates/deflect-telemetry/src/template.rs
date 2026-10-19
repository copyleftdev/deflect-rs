use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;

use crate::reader::{Reader, Truncated};
use crate::record::{field, FlowBuilder, FlowRecord};

const VARIABLE_LEN: u16 = 0xffff;
const ENTERPRISE_BIT: u16 = 0x8000;

/// One field in a template: an information-element id and its wire length.
/// A length of `0xffff` marks a variable-length field (IPFIX only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub id: u16,
    pub length: u16,
}

/// The field layout a data record follows, learned from a template record.
#[derive(Debug, Clone, Default)]
pub struct Template {
    pub fields: Vec<FieldSpec>,
}

impl Template {
    /// Minimum bytes a data record of this template occupies; a variable field
    /// contributes its single length-prefix byte.
    fn min_record_len(&self) -> usize {
        self.fields
            .iter()
            .map(|f| {
                if f.length == VARIABLE_LEN {
                    1
                } else {
                    f.length as usize
                }
            })
            .sum()
    }
}

/// Stores templates across datagrams, keyed by observation domain (IPFIX) or
/// source id (NetFlow v9) and template id.
#[derive(Debug, Clone, Default)]
pub struct TemplateRegistry {
    map: HashMap<(u32, u16), Template>,
}

impl TemplateRegistry {
    #[must_use]
    pub fn new() -> TemplateRegistry {
        TemplateRegistry::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn insert(&mut self, domain: u32, id: u16, template: Template) {
        self.map.insert((domain, id), template);
    }

    fn remove(&mut self, domain: u32, id: u16) {
        self.map.remove(&(domain, id));
    }

    fn get(&self, domain: u32, id: u16) -> Option<&Template> {
        self.map.get(&(domain, id))
    }
}

/// Decode every set in a v9/IPFIX message body, updating templates and
/// returning the flow records from data sets whose template is known.
///
/// `enterprise` selects IPFIX field-record parsing (the enterprise bit and
/// 32-bit enterprise number); false parses NetFlow v9 field records.
pub(crate) fn decode_sets(
    r: &mut Reader<'_>,
    domain: u32,
    enterprise: bool,
    registry: &mut TemplateRegistry,
    out: &mut Vec<FlowRecord>,
) {
    // Reserved set ids: 2 (IPFIX template) / 0 (v9 template); 3 / 1 options.
    let (template_set_id, options_set_id) = if enterprise {
        (2u16, 3u16)
    } else {
        (0u16, 1u16)
    };

    while r.remaining() >= 4 {
        let Ok(set_id) = r.u16() else { break };
        let Ok(set_len) = r.u16() else { break };
        if (set_len as usize) < 4 {
            break;
        }
        let Ok(mut body) = r.sub(set_len as usize - 4) else {
            break;
        };

        if set_id == template_set_id {
            decode_template_set(&mut body, domain, enterprise, registry);
        } else if set_id == options_set_id || set_id < 256 {
            // Options templates and other reserved sets: skipped (body dropped).
        } else if let Some(template) = registry.get(domain, set_id).cloned() {
            decode_data_set(&mut body, &template, out);
        }
    }
}

fn decode_template_set(
    body: &mut Reader<'_>,
    domain: u32,
    enterprise: bool,
    registry: &mut TemplateRegistry,
) {
    while body.remaining() >= 4 {
        let Ok(template_id) = body.u16() else { break };
        let Ok(field_count) = body.u16() else { break };
        if field_count == 0 {
            // Template withdrawal.
            registry.remove(domain, template_id);
            continue;
        }
        let mut fields = Vec::with_capacity(field_count as usize);
        let mut ok = true;
        for _ in 0..field_count {
            let Ok(id) = body.u16() else {
                ok = false;
                break;
            };
            let Ok(length) = body.u16() else {
                ok = false;
                break;
            };
            if enterprise && (id & ENTERPRISE_BIT != 0) {
                // Enterprise field: consume the 32-bit enterprise number. The
                // id keeps its high bit set so it matches no standard field and
                // is skipped by length at decode time.
                if body.u32().is_err() {
                    ok = false;
                    break;
                }
            }
            fields.push(FieldSpec { id, length });
        }
        if ok {
            registry.insert(domain, template_id, Template { fields });
        } else {
            break;
        }
    }
}

fn decode_data_set(body: &mut Reader<'_>, template: &Template, out: &mut Vec<FlowRecord>) {
    let min = template.min_record_len();
    if min == 0 {
        return; // No fields: nothing to decode, and would not make progress.
    }
    while body.remaining() >= min {
        let start = body.position();
        match decode_record(body, template) {
            Ok(rec) => out.push(rec),
            Err(_) => break,
        }
        if body.position() == start {
            break; // Defensive: guarantee forward progress.
        }
    }
}

fn decode_record(body: &mut Reader<'_>, template: &Template) -> Result<FlowRecord, Truncated> {
    let mut b = FlowBuilder::default();
    for &spec in &template.fields {
        let len = field_value_len(body, spec)?;
        let data = body.bytes(len)?;
        apply_field(&mut b, spec.id, data);
    }
    Ok(b.build())
}

/// Resolve the on-wire value length of a field, reading the IPFIX
/// variable-length prefix when the template marks the field variable.
fn field_value_len(body: &mut Reader<'_>, spec: FieldSpec) -> Result<usize, Truncated> {
    if spec.length != VARIABLE_LEN {
        return Ok(spec.length as usize);
    }
    let first = body.u8()?;
    if first < 255 {
        Ok(first as usize)
    } else {
        Ok(body.u16()? as usize)
    }
}

// Protocol, ports, and flags are defined to occupy their low bytes; taking the
// low bits of the decoded integer is the field semantics, not a lossy cast.
#[allow(clippy::cast_possible_truncation)]
fn apply_field(b: &mut FlowBuilder, id: u16, data: &[u8]) {
    match id {
        field::SRC_IPV4 if data.len() == 4 => b.set_src(ipv4(data)),
        field::DST_IPV4 if data.len() == 4 => b.set_dst(ipv4(data)),
        field::SRC_IPV6 if data.len() == 16 => b.set_src(ipv6(data)),
        field::DST_IPV6 if data.len() == 16 => b.set_dst(ipv6(data)),
        field::PROTOCOL => b.set_protocol(be_uint(data) as u8),
        field::SRC_PORT => b.set_src_port(be_uint(data) as u16),
        field::DST_PORT => b.set_dst_port(be_uint(data) as u16),
        field::TCP_CONTROL_BITS => b.set_tcp_flags(be_uint(data) as u8),
        field::OCTET_DELTA_COUNT => b.set_bytes(be_uint(data)),
        field::PACKET_DELTA_COUNT => b.set_packets(be_uint(data)),
        _ => {}
    }
}

fn be_uint(data: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in data.iter().take(8) {
        v = (v << 8) | u64::from(byte);
    }
    v
}

fn ipv4(data: &[u8]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

fn ipv6(data: &[u8]) -> IpAddr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&data[..16]);
    IpAddr::V6(Ipv6Addr::from(o))
}
