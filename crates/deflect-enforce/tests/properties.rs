//! Property tests for the nftables script builders: the scripts are pure
//! strings, so these assert the invariants an operator relies on — the right
//! family set, a correct CIDR/host element, a kernel-enforced timeout of at
//! least one second, and a withdrawal that targets the same element it banned.
//!
//! Needles are bound to `let`s before each `prop_assert!`, because that macro
//! splits its arguments on the first comma and a `format!(…, x)` inside it would
//! be misparsed.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::time::Duration;

use deflect_enforce::nft;
use proptest::prelude::*;

proptest! {
    #[test]
    fn v4_ban_names_the_v4_set_and_element(o in any::<[u8; 4]>(), len in 0u8..=32) {
        let addr = IpAddr::V4(Ipv4Addr::from(o));
        let s = nft::ban_script("deflect", addr, len, None);
        prop_assert!(s.contains("banned4"));
        prop_assert!(!s.contains("banned6"));
        if len >= 32 {
            // Host: bare address, no CIDR suffix.
            let host = addr.to_string();
            let cidr = format!("{addr}/");
            prop_assert!(s.contains(&host));
            prop_assert!(!s.contains(&cidr));
        } else {
            let elem = format!("{addr}/{len}");
            prop_assert!(s.contains(&elem));
        }
    }

    #[test]
    fn v6_ban_names_the_v6_set(segs in any::<[u16; 8]>(), len in 0u8..=128) {
        let addr = IpAddr::V6(Ipv6Addr::new(
            segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
        ));
        let s = nft::ban_script("deflect", addr, len, None);
        prop_assert!(s.contains("banned6"));
        prop_assert!(!s.contains("banned4"));
    }

    #[test]
    fn timeout_is_at_least_one_second(o in any::<[u8; 4]>(), millis in 0u64..5_000) {
        let addr = IpAddr::V4(Ipv4Addr::from(o));
        let s = nft::ban_script("deflect", addr, 32, Some(Duration::from_millis(millis)));
        let secs = (millis / 1_000).max(1);
        let needle = format!("timeout {secs}s");
        prop_assert!(s.contains(&needle));
    }

    #[test]
    fn unban_targets_the_same_element_it_banned(o in any::<[u8; 4]>(), len in 0u8..=32) {
        let addr = IpAddr::V4(Ipv4Addr::from(o));
        let expected = if len >= 32 {
            addr.to_string()
        } else {
            format!("{addr}/{len}")
        };
        let ban = nft::ban_script("deflect", addr, len, None);
        let unban = nft::unban_script("deflect", addr, len);
        prop_assert!(ban.contains("add element"));
        prop_assert!(ban.contains(&expected));
        prop_assert!(unban.contains("delete element"));
        prop_assert!(unban.contains(&expected));
    }
}
