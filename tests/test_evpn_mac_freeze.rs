use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_mac_freeze::{EvpnMacFreezeEngine, MacMobilityState, MacMoveVerdict};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_mac_mobility_freeze_and_dampening() {
    let mut engine = EvpnMacFreezeEngine::new(4, 100, 300); // 4 moves within 100s -> freeze 300s

    let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let vni = 500;

    let vtep1 = Ipv4Address::new(10, 0, 0, 1);
    let vtep2 = Ipv4Address::new(10, 0, 0, 2);
    let vtep3 = Ipv4Address::new(10, 0, 0, 3);
    let vtep4 = Ipv4Address::new(10, 0, 0, 4);
    let vtep5 = Ipv4Address::new(10, 0, 0, 5);

    // Initial learn at t = 10s
    engine.learn_initial(vni, mac, vtep1, 10);

    // Move 1 to VTEP2 at t = 20s
    let v1 = engine.record_move(vni, mac, vtep2, 20);
    assert_eq!(v1, MacMoveVerdict::Accepted { new_seq: 1 });

    // Move 2 to VTEP3 at t = 30s
    let v2 = engine.record_move(vni, mac, vtep3, 30);
    assert_eq!(v2, MacMoveVerdict::Accepted { new_seq: 2 });

    // Move 3 to VTEP4 at t = 40s
    let v3 = engine.record_move(vni, mac, vtep4, 40);
    assert_eq!(v3, MacMoveVerdict::Accepted { new_seq: 3 });

    // Move 4 to VTEP5 at t = 50s -> 5 total moves within 100s window (> 4) -> FREEZE!
    let v4 = engine.record_move(vni, mac, vtep5, 50);
    assert_eq!(v4, MacMoveVerdict::FreezeTriggered { moves_in_window: 5 });

    let entry = engine.get_entry(vni, mac).expect("entry exists");
    assert_eq!(
        entry.state,
        MacMobilityState::Frozen {
            frozen_until_secs: 350
        }
    );

    // Further move while frozen at t = 60s -> Suppressed
    let v5 = engine.record_move(vni, mac, vtep1, 60);
    assert_eq!(v5, MacMoveVerdict::SuppressedFrozen);

    // Administrative unfreeze at t = 70s
    assert!(engine.unfreeze_mac(vni, mac));
    let entry_unfrozen = engine.get_entry(vni, mac).unwrap();
    assert_eq!(entry_unfrozen.state, MacMobilityState::Normal);

    // Move allowed after unfreeze
    let v6 = engine.record_move(vni, mac, vtep1, 75);
    assert!(matches!(v6, MacMoveVerdict::Accepted { .. }));
}
