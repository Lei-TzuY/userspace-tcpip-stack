//! Integration tests for BGP Graceful Restart (RFC 4724 / RFC 8538)

use std::net::Ipv4Addr;
use toy_tcpip::bgp_graceful_restart::{
    AddressFamily, BgpGracefulRestartEngine, EorMarkerResult, GrCapability, GrSessionState,
    StaleRoute, AFI_IPV4, AFI_IPV6, AFI_L2VPN, DEFAULT_RESTART_TIME_SECS, GR_FLAG_NOTIFICATION,
    GR_FLAG_RESTART, SAFI_EVPN, SAFI_UNICAST,
};

#[test]
fn test_bgp_gr_capability_negotiation_multi_af() {
    let mut cap = GrCapability::new(DEFAULT_RESTART_TIME_SECS, true, true);
    cap.add_family(AddressFamily::ipv4_unicast(), true);
    cap.add_family(AddressFamily::ipv6_unicast(), true);
    cap.add_family(AddressFamily::l2vpn_evpn(), false);

    assert!(cap.is_restarting());
    assert!(cap.supports_notification_gr());
    assert_eq!(cap.restart_time_secs, 120);
    assert_eq!(cap.families.len(), 3);

    // Test serialization and parsing roundtrip
    let wire_bytes = cap.serialize();
    let parsed = GrCapability::parse(&wire_bytes).expect("Failed to parse GR capability");

    assert_eq!(parsed.flags, GR_FLAG_RESTART | GR_FLAG_NOTIFICATION);
    assert_eq!(parsed.restart_time_secs, 120);
    assert_eq!(parsed.families.len(), 3);
    assert_eq!(parsed.families[0].af, AddressFamily::new(AFI_IPV4, SAFI_UNICAST));
    assert!(parsed.families[0].forwarding_preserved);
    assert_eq!(parsed.families[1].af, AddressFamily::new(AFI_IPV6, SAFI_UNICAST));
    assert!(parsed.families[1].forwarding_preserved);
    assert_eq!(parsed.families[2].af, AddressFamily::new(AFI_L2VPN, SAFI_EVPN));
    assert!(!parsed.families[2].forwarding_preserved);
}

#[test]
fn test_bgp_gr_helper_session_lifecycle() {
    let local_cap = GrCapability::new(120, false, true);
    let mut engine = BgpGracefulRestartEngine::new(local_cap);

    let peer: Ipv4Addr = "192.0.2.1".parse().unwrap();
    let mut peer_cap = GrCapability::new(90, true, true);
    peer_cap.add_family(AddressFamily::ipv4_unicast(), true);
    peer_cap.add_family(AddressFamily::ipv6_unicast(), true);

    engine.register_peer(peer, peer_cap);
    assert!(engine.peer_supports_af(&peer, &AddressFamily::ipv4_unicast()));
    assert!(engine.peer_supports_af(&peer, &AddressFamily::ipv6_unicast()));
    assert!(!engine.peer_supports_af(&peer, &AddressFamily::l2vpn_evpn()));

    // Seed 3 routing table entries learned from peer
    let routes = vec![
        StaleRoute {
            prefix: "198.51.100.0".parse().unwrap(),
            prefix_len: 24,
            next_hop: peer,
            as_path: vec![65001, 65010],
            local_pref: 100,
            forwarding_preserved: false,
            stale_since: 0,
        },
        StaleRoute {
            prefix: "203.0.113.0".parse().unwrap(),
            prefix_len: 24,
            next_hop: peer,
            as_path: vec![65001, 65020],
            local_pref: 100,
            forwarding_preserved: false,
            stale_since: 0,
        },
        StaleRoute {
            prefix: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            next_hop: peer,
            as_path: vec![65001],
            local_pref: 200,
            forwarding_preserved: false,
            stale_since: 0,
        },
    ];

    let t0 = 10_000u64;
    let state = engine.handle_peer_down(peer, t0, routes).unwrap();
    match state {
        GrSessionState::Helper { restart_deadline, eor_received } => {
            assert_eq!(restart_deadline, t0 + 90);
            assert!(eor_received.is_empty());
        }
        _ => panic!("Expected Helper state"),
    }

    assert_eq!(engine.stale_route_count(&peer), 3);

    // Peer re-establishes session before restart deadline
    let mut reestablished_cap = GrCapability::new(90, true, true);
    reestablished_cap.add_family(AddressFamily::ipv4_unicast(), true);
    reestablished_cap.add_family(AddressFamily::ipv6_unicast(), true);
    engine.handle_peer_reestablished(&peer, reestablished_cap).unwrap();

    // Check End-of-RIB marker detection
    let eor_v4 = engine.detect_eor(0, 0, 0, AddressFamily::ipv4_unicast());
    assert_eq!(eor_v4, EorMarkerResult::IsEor(AddressFamily::ipv4_unicast()));

    let not_eor = engine.detect_eor(0, 10, 4, AddressFamily::ipv4_unicast());
    assert_eq!(not_eor, EorMarkerResult::NotEor);

    // Record EoR for IPv4 unicast
    let gr_done_v4 = engine.record_eor_received(&peer, AddressFamily::ipv4_unicast()).unwrap();
    assert!(!gr_done_v4, "GR should not be done until all AFIs receive EoR");

    // Record EoR for IPv6 unicast
    let gr_done_v6 = engine.record_eor_received(&peer, AddressFamily::ipv6_unicast()).unwrap();
    assert!(gr_done_v6, "GR should be complete once all negotiated AFIs received EoR");

    // Complete GR and ensure stale routes are cleared
    let purged = engine.complete_gr(&peer).unwrap();
    assert_eq!(purged, 3);
    assert_eq!(engine.stale_route_count(&peer), 0);
    assert_eq!(engine.peer_states.get(&peer), Some(&GrSessionState::Normal));
}

#[test]
fn test_bgp_gr_restart_timer_expiry() {
    let local_cap = GrCapability::new(60, false, false);
    let mut engine = BgpGracefulRestartEngine::new(local_cap);

    let peer: Ipv4Addr = "192.0.2.2".parse().unwrap();
    let mut peer_cap = GrCapability::new(45, true, false);
    peer_cap.add_family(AddressFamily::ipv4_unicast(), true);
    engine.register_peer(peer, peer_cap);

    let stale = vec![StaleRoute {
        prefix: "192.168.10.0".parse().unwrap(),
        prefix_len: 24,
        next_hop: peer,
        as_path: vec![65100],
        local_pref: 100,
        forwarding_preserved: true,
        stale_since: 1_000,
    }];

    engine.handle_peer_down(peer, 1_000, stale).unwrap();
    assert_eq!(engine.stale_route_count(&peer), 1);

    // At t=1040 (before t=1045 deadline), timer should not expire
    let check_pre = engine.check_restart_timer(&peer, 1_040).unwrap();
    assert_eq!(check_pre, None);
    assert_eq!(engine.stale_route_count(&peer), 1);

    // At t=1045 (at deadline), timer expires and purges routes
    let check_post = engine.check_restart_timer(&peer, 1_045).unwrap();
    assert_eq!(check_post, Some(1));
    assert_eq!(engine.stale_route_count(&peer), 0);
    assert_eq!(engine.peer_states.get(&peer), Some(&GrSessionState::Normal));
}

#[test]
fn test_bgp_gr_stale_route_retention_purge() {
    let local_cap = GrCapability::new(300, false, true);
    let mut engine = BgpGracefulRestartEngine::new(local_cap);
    engine.stale_routes_time_secs = 120; // 2 minutes stale retention

    let peer: Ipv4Addr = "192.0.2.3".parse().unwrap();
    let mut peer_cap = GrCapability::new(300, true, true);
    peer_cap.add_family(AddressFamily::ipv4_unicast(), true);
    engine.register_peer(peer, peer_cap);

    let stale = vec![
        StaleRoute {
            prefix: "10.1.0.0".parse().unwrap(),
            prefix_len: 16,
            next_hop: peer,
            as_path: vec![64512],
            local_pref: 100,
            forwarding_preserved: false,
            stale_since: 500,
        },
        StaleRoute {
            prefix: "10.2.0.0".parse().unwrap(),
            prefix_len: 16,
            next_hop: peer,
            as_path: vec![64512],
            local_pref: 100,
            forwarding_preserved: false,
            stale_since: 600,
        },
    ];

    engine.handle_peer_down(peer, 500, stale).unwrap();

    // At t=650: route 1 (stale since 500) has elapsed 150s (> 120s limit)
    // route 2 (stale since 500 originally in handle_peer_down)
    let purged = engine.purge_expired_stale_routes(&peer, 650);
    assert_eq!(purged, 2);
    assert_eq!(engine.stale_route_count(&peer), 0);
}

#[test]
fn test_bgp_gr_multi_peer_isolation() {
    let local_cap = GrCapability::new(120, false, true);
    let mut engine = BgpGracefulRestartEngine::new(local_cap);

    let peer1: Ipv4Addr = "192.0.2.11".parse().unwrap();
    let peer2: Ipv4Addr = "192.0.2.12".parse().unwrap();

    let mut cap1 = GrCapability::new(60, true, true);
    cap1.add_family(AddressFamily::ipv4_unicast(), true);
    let mut cap2 = GrCapability::new(60, true, true);
    cap2.add_family(AddressFamily::ipv4_unicast(), true);

    engine.register_peer(peer1, cap1);
    engine.register_peer(peer2, cap2);

    let routes1 = vec![StaleRoute {
        prefix: "172.16.1.0".parse().unwrap(),
        prefix_len: 24,
        next_hop: peer1,
        as_path: vec![65011],
        local_pref: 100,
        forwarding_preserved: true,
        stale_since: 0,
    }];

    engine.handle_peer_down(peer1, 200, routes1).unwrap();

    assert!(matches!(engine.peer_states.get(&peer1), Some(GrSessionState::Helper { .. })));
    assert_eq!(engine.peer_states.get(&peer2), Some(&GrSessionState::Normal));
    assert_eq!(engine.stale_route_count(&peer1), 1);
    assert_eq!(engine.stale_route_count(&peer2), 0);
}
