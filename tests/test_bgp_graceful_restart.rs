//! RFC 4724 Graceful Restart helper-mode integration tests.
//!
//! The failure path is a real TCP transport loss in the virtual lab. Nothing
//! directly edits the BGP RIBs: the helper must decide to retain or purge them.

mod common;

use common::bgp_lab::{build_linear_lab, converge_sessions, ip, prefix, run_until};
use toy_tcpip::bgp_caps::{AfiSafi, BGP_GR_MAX_RESTART_TIME};
use toy_tcpip::bgp_router::{BgpState, DEFAULT_GRACEFUL_RESTART_TIME};

#[test]
fn test_open_advertises_rfc4724_for_negotiated_families() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));

    let peer = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap();
    let gr = peer
        .negotiated
        .peer
        .graceful_restart()
        .expect("peer did not advertise RFC 4724");
    assert_eq!(gr.restart_time, DEFAULT_GRACEFUL_RESTART_TIME);
    assert!(!gr.restarting);
    assert!(gr.supports(AfiSafi::IPV4_UNICAST));
}

#[test]
fn test_transport_failure_retains_routes_until_restart_time_expires() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));
    let learned = prefix(10, 3, 0, 0, 24);
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned)
    }));

    let now = lab.current_time_ms;
    let stream = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap()
        .stream
        .expect("session has no TCP stream");

    // Prevent an immediate reconnect, then kill the live transport from underneath
    // BGP. This exercises Teardown::Transport rather than an administrative Cease.
    lab.link_mut("r1r2").unwrap().set_blackhole(true);
    lab.router_mut("r1")
        .unwrap()
        .sockets
        .as_mut()
        .unwrap()
        .tcp_abort(stream, now);
    lab.run_pumped(50);

    let peer = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap();
    assert_ne!(peer.state, BgpState::Established);
    assert!(peer.graceful_restart_active());
    assert_eq!(peer.counters.graceful_restarts_started, 1);
    assert!(peer.graceful_restart_stale_families().contains(&AfiSafi::IPV4_UNICAST));
    assert!(
        lab.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned),
        "helper dropped a route immediately instead of retaining it"
    );

    // It remains usable well inside the peer-advertised Restart Time.
    lab.advance_time((DEFAULT_GRACEFUL_RESTART_TIME as u64 * 1_000) / 2);
    lab.run_pumped(50);
    assert!(lab.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned));

    // Once the deadline passes, stale state is purged and the decision process
    // removes the route normally.
    lab.advance_time((DEFAULT_GRACEFUL_RESTART_TIME as u64 * 1_000) / 2 + 1_000);
    lab.run_pumped(100);
    let bgp = lab.router("r1").unwrap().bgp().unwrap();
    assert!(!bgp.loc_rib.contains(&learned));
    let peer = bgp.peer(ip(10, 12, 0, 2)).unwrap();
    assert!(!peer.graceful_restart_active());
    assert_eq!(peer.counters.graceful_restart_expirations, 1);
}

#[test]
fn test_peer_without_graceful_restart_is_purged_immediately() {
    let mut lab = build_linear_lab();
    lab.router_mut("r2")
        .unwrap()
        .bgp_mut()
        .unwrap()
        .set_graceful_restart_enabled(false);
    assert!(converge_sessions(&mut lab, 60_000));
    let learned = prefix(10, 3, 0, 0, 24);
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned)
    }));

    let now = lab.current_time_ms;
    let stream = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap()
        .stream
        .unwrap();
    lab.link_mut("r1r2").unwrap().set_blackhole(true);
    lab.router_mut("r1")
        .unwrap()
        .sockets
        .as_mut()
        .unwrap()
        .tcp_abort(stream, now);
    lab.run_pumped(100);

    let bgp = lab.router("r1").unwrap().bgp().unwrap();
    assert!(!bgp.peer(ip(10, 12, 0, 2)).unwrap().graceful_restart_active());
    assert!(!bgp.loc_rib.contains(&learned));
}

#[test]
fn test_restart_time_is_bounded_to_the_rfc_field_width() {
    let mut lab = build_linear_lab();
    lab.router_mut("r1")
        .unwrap()
        .bgp_mut()
        .unwrap()
        .set_graceful_restart_time(u16::MAX);
    assert_eq!(
        lab.router("r1").unwrap().bgp().unwrap().graceful_restart_time,
        BGP_GR_MAX_RESTART_TIME
    );
}
