use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_mac_flush::{EthernetSegmentId, EvpnMacEntry, EvpnMacFlushEngine, MacFlushScope};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_mac_flush_lag_down_burst_purge() {
    let mut engine = EvpnMacFlushEngine::new();
    let esi_es1 = EthernetSegmentId::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
    let esi_es2 = EthernetSegmentId::new([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13]);

    let vtep = Ipv4Address::new(192, 168, 10, 1);

    // Learn 10 MACs on ES1 and 5 MACs on ES2
    for i in 0..10u8 {
        engine.learn_mac(EvpnMacEntry {
            vni: 1000 + (i as u32 % 3),
            mac: MacAddress([0x52, 0x54, 0x00, 0x01, 0x00, i]),
            esi: esi_es1,
            remote_vtep: vtep,
            is_local: false,
            is_static: false,
        });
    }

    for i in 0..5u8 {
        engine.learn_mac(EvpnMacEntry {
            vni: 1000,
            mac: MacAddress([0x52, 0x54, 0x00, 0x02, 0x00, i]),
            esi: esi_es2,
            remote_vtep: vtep,
            is_local: false,
            is_static: false,
        });
    }

    assert_eq!(engine.active_mac_count(), 15);

    // Primary link on ES1 goes down -> Flush all MACs on ES1 instantly
    let flushed = engine.handle_local_link_down(esi_es1);
    assert_eq!(flushed, 10);
    assert_eq!(engine.active_mac_count(), 5);
    assert_eq!(engine.link_down_events, 1);

    // Verify ES2 MACs are untouched
    for i in 0..5u8 {
        assert!(engine.lookup(1000, MacAddress([0x52, 0x54, 0x00, 0x02, 0x00, i])).is_some());
    }
}

#[test]
fn test_evpn_mac_flush_specific_mac_scope() {
    let mut engine = EvpnMacFlushEngine::new();
    let mac = MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let esi = EthernetSegmentId::new([0xFF; 10]);

    engine.learn_mac(EvpnMacEntry {
        vni: 500,
        mac,
        esi,
        remote_vtep: Ipv4Address::new(10, 0, 0, 1),
        is_local: true,
        is_static: false,
    });

    assert_eq!(engine.active_mac_count(), 1);
    let flushed = engine.execute_flush(MacFlushScope::SpecificMac { vni: 500, mac });
    assert_eq!(flushed, 1);
    assert_eq!(engine.active_mac_count(), 0);
}
