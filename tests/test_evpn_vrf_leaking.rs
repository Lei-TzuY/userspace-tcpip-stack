use toy_tcpip::evpn_vrf_leaking::EvpnVrfLeakingEngine;
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_vrf_leaking_and_cross_vrf_lpm() {
    let mut engine = EvpnVrfLeakingEngine::new();

    // Tenant VRF 10 (Red)
    engine.add_vrf(10, "VRF_TENANT_RED", &["65000:10"], &["65000:10", "65000:999"]);
    // Tenant VRF 20 (Blue)
    engine.add_vrf(20, "VRF_TENANT_BLUE", &["65000:20"], &["65000:20", "65000:999"]);
    // Shared Services VRF 999 (Internet / DNS Gateway)
    engine.add_vrf(999, "VRF_SHARED_SERVICES", &["65000:999"], &["65000:999"]);

    let gw_ip = Ipv4Address::new(192, 168, 99, 1);
    // Direct shared route in VRF 999: 8.8.8.8/32 -> NextHop 192.168.99.1
    engine.add_direct_route(999, Ipv4Address::new(8, 8, 8, 8), 32, gw_ip);

    // Direct local tenant route in VRF 10: 10.10.1.0/24 -> 10.10.1.1
    engine.add_direct_route(10, Ipv4Address::new(10, 10, 1, 0), 24, Ipv4Address::new(10, 10, 1, 1));

    // Before sync: VRF 10 doesn't have 8.8.8.8
    assert_eq!(engine.lookup_vrf_lpm(10, Ipv4Address::new(8, 8, 8, 8)), None);

    // Run RT intersection route leaking sync
    engine.sync_route_leaking();

    // After sync: 8.8.8.8/32 is leaked into both VRF 10 and VRF 20
    assert_eq!(
        engine.lookup_vrf_lpm(10, Ipv4Address::new(8, 8, 8, 8)),
        Some(gw_ip)
    );
    assert_eq!(
        engine.lookup_vrf_lpm(20, Ipv4Address::new(8, 8, 8, 8)),
        Some(gw_ip)
    );

    // Tenant 10's private route 10.10.1.0/24 is NOT leaked to Tenant 20 (strict tenant isolation)
    assert_eq!(
        engine.lookup_vrf_lpm(20, Ipv4Address::new(10, 10, 1, 5)),
        None
    );
}
