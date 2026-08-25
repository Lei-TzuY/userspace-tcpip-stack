use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_frr_protection::{EvpnFrrEngine, EvpnProtectedRoute, FrrPathState};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_frr_protection_primary_to_backup_steering() {
    let mut engine = EvpnFrrEngine::new();
    let mac1 = MacAddress([0x52, 0x54, 0x00, 0x01, 0x02, 0x03]);
    let mac2 = MacAddress([0x52, 0x54, 0x00, 0x01, 0x02, 0x04]);

    let pe1_primary = Ipv4Address::new(10, 0, 0, 1);
    let pe2_backup = Ipv4Address::new(10, 0, 0, 2);

    let pe3_primary = Ipv4Address::new(10, 0, 0, 3);
    let pe4_backup = Ipv4Address::new(10, 0, 0, 4);

    engine.add_protected_route(EvpnProtectedRoute::new(
        100,
        mac1,
        None,
        pe1_primary,
        pe2_backup,
        100,
    ));
    engine.add_protected_route(EvpnProtectedRoute::new(
        100,
        mac2,
        None,
        pe3_primary,
        pe4_backup,
        100,
    ));

    // Both primary paths active
    assert_eq!(engine.forward_frame(100, mac1), Some((pe1_primary, 100)));
    assert_eq!(engine.forward_frame(100, mac2), Some((pe3_primary, 100)));
    assert_eq!(engine.backup_active_count(), 0);

    // Fail PE1 link
    let affected = engine.trigger_link_down(pe1_primary);
    assert_eq!(affected, 1);
    assert_eq!(engine.backup_active_count(), 1);

    // mac1 steers to backup PE2, mac2 still uses primary PE3
    assert_eq!(engine.forward_frame(100, mac1), Some((pe2_backup, 100)));
    assert_eq!(engine.forward_frame(100, mac2), Some((pe3_primary, 100)));

    // Verify statistics on mac1
    let r1 = engine.routes.iter().find(|r| r.mac == mac1).unwrap();
    assert_eq!(r1.state, FrrPathState::BackupActive);
    assert_eq!(r1.packets_primary, 1);
    assert_eq!(r1.packets_backup, 1);
    assert_eq!(r1.switchover_count, 1);
}

#[test]
fn test_evpn_frr_all_paths_down_drop() {
    let mut engine = EvpnFrrEngine::new();
    let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let primary = Ipv4Address::new(172, 16, 0, 1);
    let backup = Ipv4Address::new(172, 16, 0, 2);

    let mut route = EvpnProtectedRoute::new(500, mac, None, primary, backup, 500);
    route.set_primary_health(false);
    route.set_backup_health(false);
    engine.add_protected_route(route);

    assert_eq!(engine.forward_frame(500, mac), None);
    assert_eq!(engine.routes[0].state, FrrPathState::AllDown);
    assert_eq!(engine.routes[0].packets_dropped, 1);
}
