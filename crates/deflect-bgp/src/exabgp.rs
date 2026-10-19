use alloc::string::{String, ToString};
use core::fmt::Write as _;

use crate::route::Blackhole;

/// The next-hop token for an ExaBGP command: the explicit discard next hop when
/// one is set (legacy next-hop RTBH), otherwise `self` so the speaker advertises
/// the route with its own peering address and relies on the community.
fn next_hop_token(route: &Blackhole) -> String {
    route
        .next_hop
        .map_or_else(|| "self".to_string(), |ip| ip.to_string())
}

/// Build the ExaBGP `announce route` command line for a blackhole, terminated
/// with a newline (ExaBGP reads one command per line on its control input).
///
/// e.g. `announce route 203.0.113.9/32 next-hop self community [65535:666 65535:65281]`
#[must_use]
pub fn announce_command(route: &Blackhole) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "announce route {} next-hop {}",
        route.prefix,
        next_hop_token(route)
    );
    if !route.communities.is_empty() {
        let _ = write!(s, " community [");
        for (i, c) in route.communities.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            let _ = write!(s, "{c}");
        }
        s.push(']');
    }
    s.push('\n');
    s
}

/// Build the matching `withdraw route` command line. ExaBGP matches the
/// withdrawal on prefix and next hop, so both are reproduced from the route.
#[must_use]
pub fn withdraw_command(route: &Blackhole) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "withdraw route {} next-hop {}",
        route.prefix,
        next_hop_token(route)
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cidr::Cidr;
    use crate::community::Community;
    use crate::route::Blackhole;
    use alloc::vec;

    fn host() -> Cidr {
        Cidr::host("203.0.113.9".parse().unwrap())
    }

    #[test]
    fn community_announce_uses_self_next_hop() {
        let cmd = announce_command(&Blackhole::destination(host()));
        assert_eq!(
            cmd,
            "announce route 203.0.113.9/32 next-hop self community [65535:666 65535:65281]\n"
        );
    }

    #[test]
    fn explicit_next_hop_rendered() {
        let b = Blackhole::destination(host())
            .with_next_hop("192.0.2.1".parse().unwrap())
            .with_communities(vec![]);
        assert_eq!(
            announce_command(&b),
            "announce route 203.0.113.9/32 next-hop 192.0.2.1\n"
        );
    }

    #[test]
    fn withdraw_matches_prefix_and_next_hop() {
        let b = Blackhole::destination(host());
        assert_eq!(
            withdraw_command(&b),
            "withdraw route 203.0.113.9/32 next-hop self\n"
        );
    }

    #[test]
    fn multiple_communities_space_separated() {
        let b = Blackhole::destination(host()).add_community(Community::new(64500, 100));
        assert!(announce_command(&b).contains("community [65535:666 65535:65281 64500:100]"));
    }
}
