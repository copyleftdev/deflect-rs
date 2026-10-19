use core::hash::Hasher;
use core::net::IpAddr;

use siphasher::sip::SipHasher24;

use crate::FourTuple;

/// The 128-bit secret keying every cookie MAC.
///
/// Supplied by the caller rather than generated here, so key management and
/// entropy (e.g. `getrandom`) stay the caller's concern. Rotate it no faster
/// than the cookie validity window so in-flight handshakes survive.
#[derive(Clone, Copy)]
pub struct CookieKey {
    k0: u64,
    k1: u64,
}

impl CookieKey {
    #[must_use]
    pub const fn from_u64s(k0: u64, k1: u64) -> CookieKey {
        CookieKey { k0, k1 }
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> CookieKey {
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&bytes[0..8]);
        hi.copy_from_slice(&bytes[8..16]);
        CookieKey {
            k0: u64::from_le_bytes(lo),
            k1: u64::from_le_bytes(hi),
        }
    }
}

impl core::fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CookieKey(..)")
    }
}

/// Keyed MAC of a connection tuple under a `domain` separator, `count`, and a
/// bound `isn`.
///
/// `domain` separates the two independent hashes a cookie needs (`0` blinds the
/// client ISN, `1` authenticates the encoded data) so they can never collide.
/// The full `count` binds the cookie to its issuing epoch, and `isn` binds the
/// authenticating hash to the client's sequence number so a shifted ISN does
/// not verify.
pub(crate) fn mac(key: CookieKey, tuple: &FourTuple, domain: u8, count: u64, isn: u32) -> u32 {
    let mut h = SipHasher24::new_with_keys(key.k0, key.k1);
    h.write_u8(domain);
    write_addr(&mut h, tuple.src);
    write_addr(&mut h, tuple.dst);
    h.write_u16(tuple.src_port);
    h.write_u16(tuple.dst_port);
    h.write_u64(count);
    h.write_u32(isn);
    // Fold the 64-bit SipHash output into the 32 bits a cookie carries; the
    // narrowing to u32 is the fold, not a lossy accident.
    let out = h.finish();
    #[allow(clippy::cast_possible_truncation)]
    {
        ((out >> 32) ^ out) as u32
    }
}

fn write_addr<H: Hasher>(h: &mut H, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            h.write_u8(4);
            h.write(&v4.octets());
        }
        IpAddr::V6(v6) => {
            h.write_u8(6);
            h.write(&v6.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    fn tuple() -> FourTuple {
        FourTuple {
            src: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            src_port: 51_000,
            dst_port: 443,
        }
    }

    #[test]
    fn mac_is_deterministic() {
        let k = CookieKey::from_u64s(1, 2);
        assert_eq!(mac(k, &tuple(), 0, 10, 0), mac(k, &tuple(), 0, 10, 0));
    }

    #[test]
    fn domain_separates() {
        let k = CookieKey::from_u64s(1, 2);
        assert_ne!(mac(k, &tuple(), 0, 10, 0), mac(k, &tuple(), 1, 10, 0));
    }

    #[test]
    fn count_changes_mac() {
        let k = CookieKey::from_u64s(1, 2);
        assert_ne!(mac(k, &tuple(), 1, 10, 0), mac(k, &tuple(), 1, 11, 0));
    }

    #[test]
    fn key_changes_mac() {
        let a = CookieKey::from_u64s(1, 2);
        let b = CookieKey::from_u64s(9, 9);
        assert_ne!(mac(a, &tuple(), 1, 10, 0), mac(b, &tuple(), 1, 10, 0));
    }

    #[test]
    fn tuple_changes_mac() {
        let k = CookieKey::from_u64s(1, 2);
        let mut t2 = tuple();
        t2.src_port = 51_001;
        assert_ne!(mac(k, &tuple(), 1, 10, 0), mac(k, &t2, 1, 10, 0));
    }

    #[test]
    fn source_address_changes_mac() {
        // Vary the address, not a port, so dropping the address from the hash
        // (not just reordering ports) is caught.
        let k = CookieKey::from_u64s(1, 2);
        let mut t2 = tuple();
        t2.src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        assert_ne!(mac(k, &tuple(), 1, 10, 0), mac(k, &t2, 1, 10, 0));
    }

    #[test]
    fn isn_changes_mac() {
        let k = CookieKey::from_u64s(1, 2);
        assert_ne!(mac(k, &tuple(), 1, 10, 7), mac(k, &tuple(), 1, 10, 9));
    }

    #[test]
    fn fold_is_pinned() {
        // A golden value pins the 64->32 fold (`(out >> 32) ^ out`), so flipping
        // the shift or the xor cannot pass unnoticed. SipHash-2-4 is stable, so
        // this value is fixed for these fixed inputs.
        let k = CookieKey::from_u64s(1, 2);
        assert_eq!(mac(k, &tuple(), 0, 10, 0), 0xE0B7_EDDD);
    }

    #[test]
    fn debug_is_redacted() {
        let k = CookieKey::from_u64s(0xdead_beef, 0x0bad_f00d);
        assert_eq!(format!("{k:?}"), "CookieKey(..)");
    }
}
