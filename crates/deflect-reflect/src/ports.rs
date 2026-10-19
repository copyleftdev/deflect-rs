/// The UDP service ports commonly abused for reflection/amplification, as a
/// dense bitmap over the whole 16-bit port space (8 KiB, O(1) lookup).
///
/// The default set follows the widely published amplifier list (US-CERT
/// TA14-017A and later additions). A port being in the set does not by itself
/// condemn a packet — [`crate::ReflectionGuard`] only acts on *unsolicited*
/// replies from these ports.
#[derive(Clone)]
pub struct AmplifierPorts {
    bits: [u64; 1024],
}

/// Default amplifier UDP ports.
const DEFAULT_PORTS: &[u16] = &[
    17,    // QOTD
    19,    // CharGen
    53,    // DNS
    69,    // TFTP
    111,   // Portmapper / RPCbind
    123,   // NTP
    137,   // NetBIOS Name Service
    138,   // NetBIOS Datagram
    161,   // SNMP
    389,   // CLDAP
    500,   // ISAKMP / IKE
    520,   // RIPv1
    623,   // IPMI / RMCP
    1194,  // OpenVPN
    1434,  // MS-SQL Monitor
    1900,  // SSDP
    3283,  // Apple ARMS / Net Assistant
    3702,  // WS-Discovery
    5060,  // SIP
    5351,  // NAT-PMP
    5353,  // mDNS
    5683,  // CoAP
    10001, // Ubiquiti discovery
    11211, // memcached
    26000, // Quake
    27015, // Steam / Source engine
    32414, // Plex media server (GDM)
    37810, // DVR / DHDiscover
];

impl AmplifierPorts {
    /// An empty set; no port is an amplifier.
    #[must_use]
    pub const fn empty() -> AmplifierPorts {
        AmplifierPorts { bits: [0; 1024] }
    }

    /// The published default amplifier-port set (US-CERT TA14-017A and later).
    #[must_use]
    pub fn with_defaults() -> AmplifierPorts {
        let mut p = AmplifierPorts::empty();
        for &port in DEFAULT_PORTS {
            p.insert(port);
        }
        p
    }

    /// Adds `port` to the set; idempotent.
    pub fn insert(&mut self, port: u16) {
        let (word, bit) = Self::index(port);
        self.bits[word] |= 1u64 << bit;
    }

    /// Removes `port` from the set; idempotent.
    pub fn remove(&mut self, port: u16) {
        let (word, bit) = Self::index(port);
        self.bits[word] &= !(1u64 << bit);
    }

    /// Whether `port` is in the set; O(1) bitmap lookup.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        let (word, bit) = Self::index(port);
        self.bits[word] & (1u64 << bit) != 0
    }

    const fn index(port: u16) -> (usize, usize) {
        let p = port as usize;
        (p / 64, p % 64)
    }
}

impl Default for AmplifierPorts {
    fn default() -> Self {
        AmplifierPorts::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_contain_known_amplifiers() {
        let p = AmplifierPorts::with_defaults();
        for &port in &[53u16, 123, 1900, 11211, 389, 19] {
            assert!(p.contains(port), "missing {port}");
        }
    }

    #[test]
    fn defaults_exclude_ordinary_ports() {
        let p = AmplifierPorts::with_defaults();
        assert!(!p.contains(443));
        assert!(!p.contains(22));
        assert!(!p.contains(40000));
    }

    #[test]
    fn insert_remove_roundtrip() {
        let mut p = AmplifierPorts::empty();
        assert!(!p.contains(9999));
        p.insert(9999);
        assert!(p.contains(9999));
        p.remove(9999);
        assert!(!p.contains(9999));
    }

    #[test]
    fn boundary_ports() {
        let mut p = AmplifierPorts::empty();
        p.insert(0);
        p.insert(65535);
        assert!(p.contains(0));
        assert!(p.contains(65535));
        assert!(!p.contains(65534));
    }
}
