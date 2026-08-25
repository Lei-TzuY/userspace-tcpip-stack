mod common;

use common::bgp_lab::{AS2, AS3, build_linear_lab, converge_sessions, ip, run_until};
use std::str::FromStr;
use toy_tcpip::bgp_caps::AfiSafi;
use toy_tcpip::bgp_ipv6::Ipv6Prefix;
use toy_tcpip::ipv6::Ipv6Address;

fn v6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn v6prefix(text: &str, length: u8) -> Ipv6Prefix {
    Ipv6Prefix::new(v6(text), length)
}

fn enable_ipv6(lab: &mut toy_tcpip::lab::VirtualLab) {
    for (router, next_hop) in [
        ("r1", v6("2001:db8:12::1")),
        ("r2", v6("2001:db8:12::2")),
        ("r3", v6("2001:db8:23::3")),
    ] {
        let bgp = lab.router_mut(router).unwrap().bgp.as_mut().unwrap();
        bgp.enable_family(AfiSafi::IPV6_UNICAST);
        bgp.set_ipv6_next_hop(next_hop);
    }
}

#[test]
fn ipv6_unicast_negotiates_and_converges_over_ipv4_bgp_transport() {
    let mut lab = build_linear_lab();
    enable_ipv6(&mut lab);
    let remote = v6prefix("2001:db8:300::", 48);
    lab.router_mut("r3")
        .unwrap()
        .bgp
        .as_mut()
        .unwrap()
        .originate_ipv6(remote, v6("2001:db8:23::3"));

    assert!(converge_sessions(&mut lab, 60_000));
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .ipv6_loc_rib
            .get(&remote)
            .is_some_and(|path| path.as_path.flatten() == vec![AS2, AS3])
    }));

    let r1 = lab.router("r1").unwrap().bgp().unwrap();
    let r2_peer = r1.peer(ip(10, 12, 0, 2)).unwrap();
    assert!(r2_peer.negotiated.supports(AfiSafi::IPV6_UNICAST));
    let best = r1.ipv6_loc_rib.get(&remote).unwrap();
    assert_eq!(best.next_hop, v6("2001:db8:12::2"));
    assert_eq!(best.as_path.flatten(), vec![AS2, AS3]);
    assert!(r2_peer.counters.ipv6_received > 0);
}

#[test]
fn ipv6_withdrawal_propagates_without_resetting_the_session() {
    let mut lab = build_linear_lab();
    enable_ipv6(&mut lab);
    let remote = v6prefix("2001:db8:400::", 48);
    lab.router_mut("r3")
        .unwrap()
        .bgp
        .as_mut()
        .unwrap()
        .originate_ipv6(remote, v6("2001:db8:23::3"));
    assert!(converge_sessions(&mut lab, 60_000));
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .ipv6_loc_rib
            .contains(&remote)
    }));

    let before = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap()
        .establishment_count;
    assert!(
        lab.router_mut("r3")
            .unwrap()
            .bgp
            .as_mut()
            .unwrap()
            .withdraw_originated_ipv6(remote)
    );
    assert!(run_until(&mut lab, 20_000, |l| {
        !l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .ipv6_loc_rib
            .contains(&remote)
    }));
    assert_eq!(
        lab.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 12, 0, 2))
            .unwrap()
            .establishment_count,
        before
    );
}

#[test]
fn ipv6_route_refresh_replays_inside_borr_eorr() {
    let mut lab = build_linear_lab();
    enable_ipv6(&mut lab);
    let remote = v6prefix("2001:db8:500::", 48);
    lab.router_mut("r3")
        .unwrap()
        .bgp
        .as_mut()
        .unwrap()
        .originate_ipv6(remote, v6("2001:db8:23::3"));
    assert!(converge_sessions(&mut lab, 60_000));
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .ipv6_loc_rib
            .contains(&remote)
    }));

    let r2 = ip(10, 12, 0, 2);
    let (before_updates, before_eorr) = {
        let peer = lab.router("r1").unwrap().bgp().unwrap().peer(r2).unwrap();
        (
            peer.counters.updates_received,
            peer.counters.enhanced_refresh_eorr_received,
        )
    };
    let sent = {
        let r1 = lab.router_mut("r1").unwrap();
        let now = r1.current_time_ms;
        let (bgp, sockets) = (&mut r1.bgp, &mut r1.sockets);
        bgp.as_mut().unwrap().request_route_refresh(
            r2,
            AfiSafi::IPV6_UNICAST,
            now,
            sockets.as_mut().unwrap(),
        )
    };
    assert!(sent);
    assert!(lab.run_until(50, 10_000, |l| {
        let peer = l.router("r1").unwrap().bgp().unwrap().peer(r2).unwrap();
        peer.counters.updates_received > before_updates
            && peer.counters.enhanced_refresh_eorr_received > before_eorr
    }));
    assert!(
        lab.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .ipv6_loc_rib
            .contains(&remote)
    );
}
