//! Property tests for the SYN-cookie engine: a cookie always round-trips to its
//! (quantised) MSS within the window, and validation never panics on arbitrary
//! attacker-controlled input — the robustness that matters when the ACK's
//! acknowledgement number is wholly under the attacker's control.

use core::net::{IpAddr, Ipv4Addr};

use deflect_syncookie::{decode_mss, encode_mss, CookieKey, FourTuple, SynCookie};
use proptest::prelude::*;

fn tuple(a: [u8; 4], b: [u8; 4], sp: u16, dp: u16) -> FourTuple {
    FourTuple::new(
        IpAddr::V4(Ipv4Addr::from(a)),
        IpAddr::V4(Ipv4Addr::from(b)),
        sp,
        dp,
    )
}

proptest! {
    #[test]
    fn roundtrips_to_quantised_mss(
        a in any::<[u8; 4]>(), b in any::<[u8; 4]>(),
        sp in any::<u16>(), dp in any::<u16>(),
        isn in any::<u32>(), mss in any::<u16>(),
        now in 0u64..10_000_000_000_000,
    ) {
        let e = SynCookie::with_defaults(CookieKey::from_u64s(0x1111_2222, 0x3333_4444));
        let t = tuple(a, b, sp, dp);
        let cookie = e.issue(&t, isn, mss, now);
        let r = e.validate(&t, isn, cookie, now).expect("fresh cookie validates");
        // The restored MSS is the table-quantised value, never larger than asked.
        prop_assert_eq!(r.mss, decode_mss(encode_mss(mss)));
        prop_assert!(r.mss <= mss.max(decode_mss(0)));
        prop_assert_eq!(r.age_epochs, 0);
    }

    #[test]
    fn validation_never_panics_on_arbitrary_input(
        a in any::<[u8; 4]>(), b in any::<[u8; 4]>(),
        sp in any::<u16>(), dp in any::<u16>(),
        isn in any::<u32>(), cookie in any::<u32>(),
        now in any::<u64>(),
    ) {
        let e = SynCookie::with_defaults(CookieKey::from_u64s(1, 2));
        let t = tuple(a, b, sp, dp);
        // Only requirement: it returns, never panics (no epoch-subtraction
        // underflow, no index out of range).
        let _ = e.validate(&t, isn, cookie, now);
    }

    #[test]
    fn tampering_never_recovers_the_same_connection(
        isn in any::<u32>(), mss in any::<u16>(), now in 0u64..10_000_000_000_000,
        flip in 1u32..=0x00ff_ffff,
    ) {
        // A 24-bit MAC admits a ~2^-21 forgery, so a flip can occasionally still
        // validate — but never back to the original MSS. The guarantee is:
        // reject, or recover a *different* connection, never silently the same.
        let e = SynCookie::with_defaults(CookieKey::from_u64s(9, 9));
        let t = tuple([203, 0, 113, 7], [198, 51, 100, 1], 51_000, 443);
        let cookie = e.issue(&t, isn, mss, now);
        let original = e.validate(&t, isn, cookie, now).unwrap().mss;
        let tampered = cookie ^ (flip & 0x00ff_ffff);
        prop_assume!(tampered != cookie);
        if let Ok(r) = e.validate(&t, isn, tampered, now) {
            prop_assert_ne!(r.mss, original);
        }
    }
}
