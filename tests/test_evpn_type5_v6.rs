use toy_tcpip::Ipv6Address;
use toy_tcpip::evpn::RouteDistinguisher;
use toy_tcpip::evpn_type5_v6::{EVPN_ROUTE_TYPE_IP_PREFIX, EvpnType5V6Rib, EvpnType5V6Route};

#[test]
fn test_evpn_type5_v6_constants_and_codec() {
    assert_eq!(EVPN_ROUTE_TYPE_IP_PREFIX, 5);

    let rd = RouteDistinguisher {
        admin: 65100,
        assigned: 42,
    };
    let prefix = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let gw = Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01]);

    let route = EvpnType5V6Route::new(rd.clone(), prefix, 64, gw, 100500);
    let bytes = route.serialize();
    assert_eq!(bytes.len(), 60);

    let parsed = EvpnType5V6Route::parse(&bytes).expect("Valid parse");
    assert_eq!(parsed.rd, rd);
    assert_eq!(parsed.ip_prefix, prefix);
    assert_eq!(parsed.prefix_len, 64);
    assert_eq!(parsed.gw_ip, gw);
    assert_eq!(parsed.label_or_vni, 100500);
}

#[test]
fn test_evpn_type5_v6_rib_lifecycle_and_withdrawal() {
    let mut rib = EvpnType5V6Rib::new();
    let rd = RouteDistinguisher {
        admin: 65100,
        assigned: 1,
    };

    let p1 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let p2 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let gw = Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    rib.add_route(EvpnType5V6Route::new(rd.clone(), p1, 64, gw, 20001));
    rib.add_route(EvpnType5V6Route::new(rd.clone(), p2, 64, gw, 20002));
    assert_eq!(rib.routes.len(), 2);

    // Lookup within p1
    let target1 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
    ]);
    let hit = rib.lookup(&rd, &target1).unwrap();
    assert_eq!(hit.label_or_vni, 20001);

    // Withdraw p1
    let withdrawn = rib.withdraw_route(&rd, &p1, 64);
    assert!(withdrawn);
    assert_eq!(rib.routes.len(), 1);

    // Lookup p1 should now fail
    assert!(rib.lookup(&rd, &target1).is_none());
}
