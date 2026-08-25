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
        l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned)
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
    assert!(
        peer.graceful_restart_stale_families()
            .contains(&AfiSafi::IPV4_UNICAST)
    );
    assert!(
        lab.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned),
        "helper dropped a route immediately instead of retaining it"
    );

    // It remains usable well inside the peer-advertised Restart Time.
    lab.advance_time((DEFAULT_GRACEFUL_RESTART_TIME as u64 * 1_000) / 2);
    lab.run_pumped(50);
    assert!(
        lab.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned)
    );

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
        l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned)
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
    assert!(
        !bgp.peer(ip(10, 12, 0, 2))
            .unwrap()
            .graceful_restart_active()
    );
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
        lab.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .graceful_restart_time,
        BGP_GR_MAX_RESTART_TIME
    );
}

#[test]
fn test_restarting_speaker_sets_restart_state_and_finishes_with_eor() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));
    let learned = prefix(10, 3, 0, 0, 24);
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned)
    }));

    let now = lab.current_time_ms;
    {
        let r3 = lab.router_mut("r3").unwrap();
        let (bgp, sockets) = (&mut r3.bgp, &mut r3.sockets);
        let bgp = bgp.as_mut().unwrap();
        assert!(bgp.begin_graceful_restart(now, sockets.as_mut().unwrap()));
        assert!(bgp.graceful_restart_restarting());
        assert_eq!(
            bgp.graceful_restart_recovery_pending(),
            vec![AfiSafi::IPV4_UNICAST]
        );
    }

    // Let the TCP close reach r2. Its helper must keep r3's route while the
    // restarting speaker is away.
    lab.run_pumped(100);
    let helper_peer = lab
        .router("r2")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 23, 0, 3))
        .unwrap();
    assert!(helper_peer.graceful_restart_active());
    assert!(
        lab.router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned)
    );

    // Hold the link down briefly so the helper state is observable, then allow the
    // active r2 side to reconnect. The replacement OPEN from r3 must carry R=1.
    lab.link_mut("r2r3").unwrap().set_blackhole(true);
    lab.advance_time(1_000);
    lab.run_pumped(50);
    lab.link_mut("r2r3").unwrap().set_blackhole(false);
    assert!(converge_sessions(&mut lab, 60_000));

    let helper_peer = lab
        .router("r2")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 23, 0, 3))
        .unwrap();
    let restart_cap = helper_peer
        .negotiated
        .peer
        .graceful_restart()
        .expect("replacement OPEN omitted RFC 4724");
    assert!(
        restart_cap.restarting,
        "replacement OPEN did not set Restart State"
    );
    assert!(helper_peer.graceful_restart_active());

    let now = lab.current_time_ms;
    {
        let r3 = lab.router_mut("r3").unwrap();
        let bgp = r3.bgp.as_mut().unwrap();
        assert!(bgp.mark_graceful_restart_family_recovered(AfiSafi::IPV4_UNICAST, now));
        assert!(bgp.graceful_restart_restarting());
    }

    assert!(run_until(&mut lab, 20_000, |l| {
        let helper_done = !l
            .router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 23, 0, 3))
            .unwrap()
            .graceful_restart_active();
        let speaker_done = !l
            .router("r3")
            .unwrap()
            .bgp()
            .unwrap()
            .graceful_restart_restarting();
        helper_done && speaker_done
    }));

    assert!(
        lab.router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .loc_rib
            .contains(&learned)
    );
    assert!(
        lab.router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 23, 0, 3))
            .unwrap()
            .counters
            .graceful_restart_eors
            >= 1
    );
    assert!(
        lab.router("r3")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 23, 0, 2))
            .unwrap()
            .counters
            .graceful_restart_eors_sent
            >= 1
    );
}
