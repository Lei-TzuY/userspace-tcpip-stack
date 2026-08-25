//! RFC 2918 BGP Route Refresh over the stack's real TCP control plane.
//!
//! A refresh must replay the current outbound view without resetting the BGP
//! session and without discarding Adj-RIB-Out state needed for withdrawals.

mod common;

use common::bgp_lab::{
    AS1, AS2, AS3, best_as_path, build_linear_lab, converge_sessions, ip, prefix, run_until,
};
use toy_tcpip::bgp::{BGP_HEADER_LEN, BGP_MSG_ROUTE_REFRESH, BgpPdu, BgpRouteRefreshMessage};
use toy_tcpip::bgp_caps::AfiSafi;
use toy_tcpip::lab::build_evpn_fabric;

#[test]
fn test_route_refresh_wire_message_is_type_five() {
    let sent = BgpPdu::RouteRefresh(BgpRouteRefreshMessage::new(AfiSafi::IPV4_UNICAST));
    let raw = sent.serialize();
    assert_eq!(raw.len(), BGP_HEADER_LEN + 4);
    assert_eq!(raw[18], BGP_MSG_ROUTE_REFRESH);
    assert_eq!(BgpPdu::parse(&raw).unwrap(), sent);
}

#[test]
fn test_route_refresh_capability_is_negotiated_on_live_sessions() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));

    for router in ["r1", "r2", "r3"] {
        for peer in lab.router(router).unwrap().bgp().unwrap().peers() {
            assert!(
                peer.negotiated.supports_route_refresh(),
                "{} did not negotiate Route Refresh with {}",
                router,
                peer.addr
            );
        }
    }
}

#[test]
fn test_ipv4_refresh_replays_routes_without_reset_or_decision_churn() {
    let mut lab = build_linear_lab();
    let remote_prefix = prefix(10, 3, 0, 0, 24);
    let r2_addr = ip(10, 12, 0, 2);
    let r1_addr = ip(10, 12, 0, 1);

    assert!(converge_sessions(&mut lab, 60_000));
    assert!(run_until(&mut lab, 60_000, |l| {
        best_as_path(l, "r1", remote_prefix) == Some(vec![AS2, AS3])
    }));
    // Let any convergence tail finish before taking no-churn snapshots.
    lab.run_until(250, 2_000, |_| false);

    let (before_updates, before_received_at, before_decisions, before_establishments) = {
        let bgp = lab.router("r1").unwrap().bgp().unwrap();
        let peer = bgp.peer(r2_addr).unwrap();
        let path = bgp
            .adj_rib_in
            .peer_table(r2_addr)
            .unwrap()
            .get(&remote_prefix)
            .unwrap();
        (
            peer.counters.updates_received,
            path.received_at_ms,
            bgp.decision_runs,
            peer.establishment_count,
        )
    };

    let sent = {
        let r1 = lab.router_mut("r1").unwrap();
        let now = r1.current_time_ms;
        let (bgp, sockets) = (&mut r1.bgp, &mut r1.sockets);
        bgp.as_mut().unwrap().request_route_refresh(
            r2_addr,
            AfiSafi::IPV4_UNICAST,
            now,
            sockets.as_mut().unwrap(),
        )
    };
    assert!(sent, "R1 could not send a negotiated Route Refresh");

    assert!(lab.run_until(250, 10_000, |l| {
        let r1 = l.router("r1").unwrap().bgp().unwrap();
        let r2 = l.router("r2").unwrap().bgp().unwrap();
        r1.peer(r2_addr).unwrap().counters.updates_received > before_updates
            && r2.peer(r1_addr).unwrap().counters.route_refreshes_received == 1
    }));

    let r1 = lab.router("r1").unwrap().bgp().unwrap();
    let peer = r1.peer(r2_addr).unwrap();
    let refreshed = r1
        .adj_rib_in
        .peer_table(r2_addr)
        .unwrap()
        .get(&remote_prefix)
        .unwrap();
    assert!(refreshed.received_at_ms > before_received_at);
    assert_eq!(best_as_path(&lab, "r1", remote_prefix), Some(vec![AS2, AS3]));
    assert_eq!(peer.establishment_count, before_establishments);
    assert_eq!(r1.decision_runs, before_decisions, "identical replay caused churn");
    assert_eq!(peer.counters.route_refreshes_sent, 1);
}

#[test]
fn test_evpn_refresh_replays_mp_bgp_routes_without_reset() {
    let mut lab = build_evpn_fabric(AS1, AS2);
    let leaf2 = ip(10, 0, 0, 2);
    let leaf1 = ip(10, 0, 0, 1);

    assert!(lab.run_until(250, 60_000, |l| {
        l.router("leaf1")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(leaf2)
            .is_some_and(|p| p.carries_evpn() && p.negotiated.supports_route_refresh())
            && l.router("leaf2")
                .unwrap()
                .bgp()
                .unwrap()
                .peer(leaf1)
                .is_some_and(|p| p.carries_evpn() && p.negotiated.supports_route_refresh())
    }));
    assert!(lab.run_until(250, 30_000, |l| {
        l.router("leaf1")
            .unwrap()
            .bgp()
            .unwrap()
            .evpn_adj_rib_in
            .total_routes()
            > 0
    }), "leaf1 never received the baseline EVPN routes");
    lab.run_until(250, 2_000, |_| false);

    let (before_updates, before_routes, before_decisions, before_establishments) = {
        let bgp = lab.router("leaf1").unwrap().bgp().unwrap();
        let peer = bgp.peer(leaf2).unwrap();
        (
            peer.counters.updates_received,
            bgp.evpn_adj_rib_in.total_routes(),
            bgp.evpn_decision_runs,
            peer.establishment_count,
        )
    };

    let sent = {
        let r = lab.router_mut("leaf1").unwrap();
        let now = r.current_time_ms;
        let (bgp, sockets) = (&mut r.bgp, &mut r.sockets);
        bgp.as_mut().unwrap().request_route_refresh(
            leaf2,
            AfiSafi::L2VPN_EVPN,
            now,
            sockets.as_mut().unwrap(),
        )
    };
    assert!(sent);

    assert!(lab.run_until(250, 10_000, |l| {
        let l1 = l.router("leaf1").unwrap().bgp().unwrap();
        let l2 = l.router("leaf2").unwrap().bgp().unwrap();
        l1.peer(leaf2).unwrap().counters.updates_received > before_updates
            && l2.peer(leaf1).unwrap().counters.route_refreshes_received == 1
    }));

    let l1 = lab.router("leaf1").unwrap().bgp().unwrap();
    let peer = l1.peer(leaf2).unwrap();
    assert_eq!(l1.evpn_adj_rib_in.total_routes(), before_routes);
    assert_eq!(peer.establishment_count, before_establishments);
    assert_eq!(
        l1.evpn_decision_runs, before_decisions,
        "identical EVPN replay reran the decision process"
    );
    assert_eq!(peer.counters.route_refreshes_sent, 1);
}
