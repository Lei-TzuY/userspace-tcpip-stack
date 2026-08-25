use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_irb_anycast::{DEFAULT_ANYCAST_GATEWAY_MAC, EvpnAnycastIrbEngine, IrbMode};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_irb_anycast_dual_mode_routing() {
    let local_vtep = Ipv4Address::new(192, 168, 100, 1);
    let router_mac = MacAddress([0x52, 0x54, 0x00, 0x01, 0x02, 0x03]);
    let mut engine = EvpnAnycastIrbEngine::new(local_vtep, router_mac, 5000);

    engine.add_anycast_gateway(10, Ipv4Address::new(10, 10, 0, 1));
    engine.add_anycast_gateway(20, Ipv4Address::new(10, 20, 0, 1));

    let target_host_ip = Ipv4Address::new(10, 20, 0, 100);
    let target_host_mac = MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let remote_leaf = Ipv4Address::new(192, 168, 100, 2);

    engine.learn_host(target_host_ip, target_host_mac, 20, remote_leaf);

    // Symmetric routing: overlay VNI is Transit L3VNI (5000)
    let sym = engine
        .route_inter_subnet(10, target_host_ip, IrbMode::Symmetric)
        .unwrap();
    assert_eq!(sym.overlay_vni, 5000);
    assert_eq!(sym.target_vtep, remote_leaf);
    assert_eq!(sym.inner_src_mac, router_mac);

    // Asymmetric routing: overlay VNI is Destination L2VNI (20)
    let asym = engine
        .route_inter_subnet(10, target_host_ip, IrbMode::Asymmetric)
        .unwrap();
    assert_eq!(asym.overlay_vni, 20);
    assert_eq!(asym.inner_src_mac, DEFAULT_ANYCAST_GATEWAY_MAC);
    assert_eq!(asym.inner_dst_mac, target_host_mac);
}
