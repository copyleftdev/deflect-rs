use core::fmt::Write as _;
use core::net::IpAddr;
use core::time::Duration;

/// Which set an address belongs to, by family.
pub(crate) fn set_name(addr: IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(_) => "banned4",
        IpAddr::V6(_) => "banned6",
    }
}

fn is_host(addr: IpAddr, prefix_len: u8) -> bool {
    match addr {
        IpAddr::V4(_) => prefix_len >= 32,
        IpAddr::V6(_) => prefix_len >= 128,
    }
}

/// Render an address and prefix length as an nftables set element, e.g.
/// `203.0.113.0/24` or a bare `198.51.100.7` for a host.
pub(crate) fn element(addr: IpAddr, prefix_len: u8) -> alloc::string::String {
    use alloc::string::ToString;
    if is_host(addr, prefix_len) {
        addr.to_string()
    } else {
        let mut s = addr.to_string();
        let _ = write!(s, "/{prefix_len}");
        s
    }
}

/// Idempotent, atomic setup: (re)create the table, its timeout-capable sets, and
/// the chain that drops banned sources before conntrack.
///
/// `add table` then `delete table` then `add table` guarantees a clean slate
/// whether or not the table already existed, in a single atomic `nft -f` script
/// — safe because setup runs at startup when no bans exist yet.
#[must_use]
pub fn setup_script(table: &str) -> alloc::string::String {
    use alloc::format;
    format!(
        "add table inet {table}\n\
         delete table inet {table}\n\
         add table inet {table}\n\
         add set inet {table} banned4 {{ type ipv4_addr; flags interval, timeout; }}\n\
         add set inet {table} banned6 {{ type ipv6_addr; flags interval, timeout; }}\n\
         add chain inet {table} input {{ type filter hook input priority -300; policy accept; }}\n\
         add rule inet {table} input ip saddr @banned4 drop\n\
         add rule inet {table} input ip6 saddr @banned6 drop\n"
    )
}

/// Script to ban one address/prefix, with an optional kernel-enforced timeout.
#[must_use]
pub fn ban_script(
    table: &str,
    addr: IpAddr,
    prefix_len: u8,
    ttl: Option<Duration>,
) -> alloc::string::String {
    use alloc::format;
    let set = set_name(addr);
    let elem = element(addr, prefix_len);
    match ttl {
        Some(d) => {
            let secs = d.as_secs().max(1);
            format!("add element inet {table} {set} {{ {elem} timeout {secs}s }}\n")
        }
        None => format!("add element inet {table} {set} {{ {elem} }}\n"),
    }
}

/// Script to remove one address/prefix from its ban set.
#[must_use]
pub fn unban_script(table: &str, addr: IpAddr, prefix_len: u8) -> alloc::string::String {
    use alloc::format;
    let set = set_name(addr);
    let elem = element(addr, prefix_len);
    format!("delete element inet {table} {set} {{ {elem} }}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn host_element_is_bare() {
        assert_eq!(element(v4(198, 51, 100, 7), 32), "198.51.100.7");
    }

    #[test]
    fn prefix_element_has_cidr() {
        assert_eq!(element(v4(203, 0, 113, 0), 24), "203.0.113.0/24");
    }

    #[test]
    fn v6_set_and_element() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        assert_eq!(set_name(a), "banned6");
        assert_eq!(element(a, 64), "2001:db8::/64");
        assert_eq!(element(a, 128), "2001:db8::");
    }

    #[test]
    fn ban_script_with_ttl() {
        let s = ban_script(
            "deflect",
            v4(203, 0, 113, 0),
            24,
            Some(Duration::from_secs(60)),
        );
        assert_eq!(
            s,
            "add element inet deflect banned4 { 203.0.113.0/24 timeout 60s }\n"
        );
    }

    #[test]
    fn ban_script_without_ttl() {
        let s = ban_script("deflect", v4(198, 51, 100, 7), 32, None);
        assert_eq!(s, "add element inet deflect banned4 { 198.51.100.7 }\n");
    }

    #[test]
    fn ttl_rounds_up_to_at_least_one_second() {
        let s = ban_script(
            "deflect",
            v4(1, 2, 3, 4),
            32,
            Some(Duration::from_millis(10)),
        );
        assert!(s.contains("timeout 1s"), "{s}");
    }

    #[test]
    fn unban_script_targets_the_element() {
        let s = unban_script("deflect", v4(203, 0, 113, 0), 24);
        assert_eq!(
            s,
            "delete element inet deflect banned4 { 203.0.113.0/24 }\n"
        );
    }

    #[test]
    fn setup_is_atomic_reset() {
        let s = setup_script("deflect");
        // The reset idiom and both family sets and drop rules are present.
        assert!(s.contains(
            "add table inet deflect\ndelete table inet deflect\nadd table inet deflect\n"
        ));
        assert!(s.contains("flags interval, timeout"));
        assert!(s.contains("ip saddr @banned4 drop"));
        assert!(s.contains("ip6 saddr @banned6 drop"));
        assert!(s.contains("priority -300"));
    }
}
