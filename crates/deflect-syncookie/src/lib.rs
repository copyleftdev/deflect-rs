//! Stateless SYN-cookie issuance and validation.
//!
//! A SYN flood is cheap because a normal server allocates connection state on
//! the SYN and holds it until the handshake completes or times out. A SYN
//! cookie removes that state: the server encodes everything it needs into the
//! SYN-ACK's initial sequence number and allocates nothing. When the client's
//! ACK returns, the acknowledgement number carries the cookie back, and the
//! server reconstructs and authenticates the connection from it alone.
//!
//! The 32-bit cookie is laid out as Linux's: the client ISN and a tuple-keyed
//! hash blind the value, the top 8 bits carry the issuing epoch (mod 256) so it
//! can be reconstructed within the validity window, and a 24-bit keyed MAC over
//! the tuple and epoch authenticates it while hiding the 3-bit encoded MSS.
//! Forging a cookie means guessing that 24-bit MAC.
//!
//! This crate is the stateless engine. Deciding *when* to answer a bare SYN
//! with a cookie — typically only once a [`deflect_detect::Trigger`] reports an
//! attack — belongs to the pipeline that assembles these primitives.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use core::net::IpAddr;

mod mac;
mod mss;

pub use mac::CookieKey;
pub use mss::{decode_mss, encode_mss, MSS_TABLE};

const DATA_MASK: u32 = 0x00ff_ffff;
const EPOCH_SHIFT: u32 = 24;

/// The TCP four-tuple a cookie is bound to. A cookie authenticates exactly this
/// tuple; a packet for any other tuple cannot reuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FourTuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FourTuple {
    #[must_use]
    pub fn new(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> FourTuple {
        FourTuple {
            src,
            dst,
            src_port,
            dst_port,
        }
    }
}

/// Why a returning ACK's cookie was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    /// The encoded epoch is older than the configured validity window, or lies
    /// in the future (a clock reversal or a replay from a different epoch).
    Expired,
    /// The MAC did not verify: the cookie was forged, corrupted, or issued for
    /// a different tuple or under a key no longer accepted.
    BadMac,
}

/// A recovered, authenticated connection, returned by [`SynCookie::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovered {
    /// The MSS to restore for the connection.
    pub mss: u16,
    /// How many epochs old the accepted cookie was (0 = current epoch).
    pub age_epochs: u8,
    /// `true` if it validated under the previous key during rotation.
    pub via_previous_key: bool,
}

/// The stateless cookie engine: a secret, an optional previous secret for
/// rotation, and the epoch clock that bounds validity.
#[derive(Debug, Clone)]
pub struct SynCookie {
    key: CookieKey,
    prev_key: Option<CookieKey>,
    epoch_nanos: u64,
    max_age_epochs: u8,
}

impl SynCookie {
    /// Create an engine whose cookies remain valid for `max_age_epochs` epochs
    /// of `epoch_nanos` each.
    ///
    /// # Panics
    /// Panics if `epoch_nanos` is zero or `max_age_epochs` is zero or `>= 255`;
    /// the epoch is reconstructed modulo 256, so the window must stay inside it.
    #[must_use]
    pub fn new(key: CookieKey, epoch_nanos: u64, max_age_epochs: u8) -> SynCookie {
        assert!(epoch_nanos > 0, "epoch_nanos must be positive");
        assert!(
            max_age_epochs > 0 && max_age_epochs < 255,
            "max_age_epochs must be in 1..255"
        );
        SynCookie {
            key,
            prev_key: None,
            epoch_nanos,
            max_age_epochs,
        }
    }

    /// Engine with a ~64 s epoch and a two-epoch (~128 s) validity window, the
    /// customary SYN-cookie lifetime.
    #[must_use]
    pub fn with_defaults(key: CookieKey) -> SynCookie {
        SynCookie::new(key, 64 * 1_000_000_000, 2)
    }

    /// Rotate the secret: the current key becomes the previous key (still
    /// accepted on validation during the grace window) and `new_key` takes
    /// over for issuance. Rotate no more often than the validity window.
    pub fn rotate(&mut self, new_key: CookieKey) {
        self.prev_key = Some(self.key);
        self.key = new_key;
    }

    fn epoch(&self, now_nanos: u64) -> u64 {
        now_nanos / self.epoch_nanos
    }

    /// Issue the cookie to place as the SYN-ACK initial sequence number.
    ///
    /// `client_isn` is the SYN's sequence number; `mss` is the connection MSS
    /// to preserve. The result encodes both statelessly.
    // The cookie is 32-bit modular arithmetic by construction; the epoch-byte
    // and index narrowings below are the encoding, not lossy accidents.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn issue(&self, tuple: &FourTuple, client_isn: u32, mss: u16, now_nanos: u64) -> u32 {
        let epoch = self.epoch(now_nanos);
        let h0 = mac::mac(self.key, tuple, 0, 0, 0);
        let hc = mac::mac(self.key, tuple, 1, epoch, client_isn);
        let mss_idx = u32::from(encode_mss(mss));
        let data = hc.wrapping_add(mss_idx) & DATA_MASK;
        let epoch_bits = (epoch as u32 & 0xff) << EPOCH_SHIFT;
        h0.wrapping_add(client_isn)
            .wrapping_add(epoch_bits)
            .wrapping_add(data)
    }

    /// Validate a returning ACK's cookie and recover the connection.
    ///
    /// `client_isn` is the ACK's sequence number minus one (the SYN's ISN) and
    /// `cookie` is the ACK's acknowledgement number minus one (the value
    /// [`issue`](Self::issue) produced). Tries the current key, then the
    /// previous key if one is held.
    ///
    /// # Errors
    /// Returns [`CookieError::Expired`] if no accepted key places the cookie
    /// inside the validity window, or [`CookieError::BadMac`] if the MAC fails
    /// under every accepted key.
    pub fn validate(
        &self,
        tuple: &FourTuple,
        client_isn: u32,
        cookie: u32,
        now_nanos: u64,
    ) -> Result<Recovered, CookieError> {
        let current = self.epoch(now_nanos);
        let primary = self.check_key(self.key, tuple, client_isn, cookie, current, false);
        if primary.is_ok() {
            return primary;
        }
        if let Some(prev) = self.prev_key {
            let secondary = self.check_key(prev, tuple, client_isn, cookie, current, true);
            if secondary.is_ok() {
                return secondary;
            }
            // Prefer reporting expiry over a bad MAC when either key saw it.
            if primary == Err(CookieError::Expired) || secondary == Err(CookieError::Expired) {
                return Err(CookieError::Expired);
            }
        }
        primary
    }

    // Mirror of the modular encoding in `issue`; the narrowings reconstruct the
    // epoch byte and MSS index and are intentional.
    #[allow(clippy::cast_possible_truncation)]
    fn check_key(
        &self,
        key: CookieKey,
        tuple: &FourTuple,
        client_isn: u32,
        cookie: u32,
        current_epoch: u64,
        via_previous_key: bool,
    ) -> Result<Recovered, CookieError> {
        let h0 = mac::mac(key, tuple, 0, 0, 0);
        let v = cookie.wrapping_sub(h0).wrapping_sub(client_isn);
        let issued_bits = (v >> EPOCH_SHIFT) & 0xff;
        let data = v & DATA_MASK;

        let age = (current_epoch as u8).wrapping_sub(issued_bits as u8);
        if age > self.max_age_epochs {
            return Err(CookieError::Expired);
        }
        let issued_epoch = current_epoch - u64::from(age);

        let hc = mac::mac(key, tuple, 1, issued_epoch, client_isn);
        let mss_idx = data.wrapping_sub(hc) & DATA_MASK;
        if mss_idx >= MSS_TABLE.len() as u32 {
            return Err(CookieError::BadMac);
        }
        Ok(Recovered {
            mss: decode_mss(mss_idx as u8),
            age_epochs: age,
            via_previous_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    fn tuple() -> FourTuple {
        FourTuple::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            51_000,
            443,
        )
    }

    fn engine() -> SynCookie {
        SynCookie::with_defaults(CookieKey::from_u64s(0xdead_beef, 0x0bad_f00d))
    }

    #[test]
    fn roundtrip_recovers_mss() {
        let e = engine();
        let c = e.issue(&tuple(), 0x1234_5678, 1460, 1_000);
        let r = e.validate(&tuple(), 0x1234_5678, c, 1_000).unwrap();
        assert_eq!(r.mss, 1460);
        assert_eq!(r.age_epochs, 0);
        assert!(!r.via_previous_key);
    }

    #[test]
    fn valid_within_window_across_epochs() {
        let e = engine();
        let c = e.issue(&tuple(), 42, 1440, 0);
        // One epoch later (64s) still inside the two-epoch window.
        let later = 64 * 1_000_000_000 + 5;
        let r = e.validate(&tuple(), 42, c, later).unwrap();
        assert_eq!(r.mss, 1440);
        assert_eq!(r.age_epochs, 1);
    }

    #[test]
    fn expires_past_window() {
        let e = engine();
        let c = e.issue(&tuple(), 42, 1440, 0);
        let way_later = 4 * 64 * 1_000_000_000;
        assert_eq!(
            e.validate(&tuple(), 42, c, way_later),
            Err(CookieError::Expired)
        );
    }

    #[test]
    fn wrong_tuple_is_rejected() {
        // A different tuple randomises the whole word, so rejection may be
        // reported as BadMac or Expired; the guarantee is that it is rejected.
        let e = engine();
        let c = e.issue(&tuple(), 42, 1460, 1_000);
        let mut other = tuple();
        other.src_port = 51_001;
        assert!(e.validate(&other, 42, c, 1_000).is_err());
    }

    #[test]
    fn wrong_client_isn_is_rejected() {
        // The client ISN is bound inside the MAC, so a shifted ISN cannot
        // verify even though it perturbs the cookie only slightly.
        let e = engine();
        let c = e.issue(&tuple(), 42, 1460, 1_000);
        assert!(e.validate(&tuple(), 43, c, 1_000).is_err());
    }

    #[test]
    fn tampered_low_bits_are_bad_mac() {
        // Flipping low-byte bits leaves the epoch byte intact, so the failure
        // is deterministically a MAC failure rather than an expiry.
        let e = engine();
        let c = e.issue(&tuple(), 42, 1460, 1_000);
        assert_eq!(
            e.validate(&tuple(), 42, c ^ 0x55, 1_000),
            Err(CookieError::BadMac)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = engine();
        let b = SynCookie::with_defaults(CookieKey::from_u64s(1, 1));
        let c = a.issue(&tuple(), 42, 1460, 1_000);
        assert!(b.validate(&tuple(), 42, c, 1_000).is_err());
    }

    #[test]
    fn previous_key_accepted_after_rotation() {
        let mut e = engine();
        let c = e.issue(&tuple(), 42, 1460, 1_000);
        e.rotate(CookieKey::from_u64s(7, 7));
        // New issuance uses the new key...
        let c2 = e.issue(&tuple(), 42, 1460, 1_000);
        assert_ne!(c, c2);
        // ...but the old cookie still validates via the previous key.
        let r = e.validate(&tuple(), 42, c, 1_000).unwrap();
        assert_eq!(r.mss, 1460);
        assert!(r.via_previous_key);
    }

    #[test]
    fn two_rotations_drop_the_oldest_key() {
        let mut e = engine();
        let c = e.issue(&tuple(), 42, 1460, 1_000);
        e.rotate(CookieKey::from_u64s(7, 7));
        e.rotate(CookieKey::from_u64s(8, 8));
        assert!(e.validate(&tuple(), 42, c, 1_000).is_err());
    }
}
