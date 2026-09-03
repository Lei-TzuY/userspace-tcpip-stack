use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_umrt_prune::{EvpnUmrtEngine, IngressDomain};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_umrt_pruning_lifecycle() {
    let local_vtep = Ipv4Address::new(172, 16, 0, 1);
    let mut engine = EvpnUmrtEngine::new(local_vtep);

    let vni = 300;

    // Local access ports
    engine.add_local_port(1, vni, false); // Host A
    engine.add_local_port(2, vni, true); // Host B (Pruned unknown multicast)
    engine.add_local_port(3, vni, false); // Host C
    engine.add_local_port(4, 999, false); // Host D (Different VNI)

    // Remote Leaf VTEPs
    let remote_vtep_1 = Ipv4Address::new(172, 16, 0, 2);
    let remote_vtep_2 = Ipv4Address::new(172, 16, 0, 3);
    engine.register_remote_vtep(remote_vtep_1, &[vni, 999]);
    engine.register_remote_vtep(remote_vtep_2, &[999]); // Does not participate in VNI 300

    let mcast_mac = MacAddress([0x01, 0x00, 0x5E, 0x01, 0x02, 0x03]);

    // 1. Frame arrives on Local Port 1
    let plan1 = engine.compute_replication_plan(vni, IngressDomain::LocalPort(1), mcast_mac);
    assert_eq!(plan1.local_egress_ports, vec![3]); // Excludes Port 1 (ingress) and Port 2 (pruned)
    assert_eq!(plan1.remote_vteps, vec![remote_vtep_1]); // Only remote_vtep_1 is subscribed to VNI 300

    // 2. Frame arrives from Overlay VTEP 1
    let plan2 =
        engine.compute_replication_plan(vni, IngressDomain::OverlayVtep(remote_vtep_1), mcast_mac);
    assert_eq!(plan2.local_egress_ports, vec![1, 3]); // Replicates to all non-pruned local ports in VNI 300
    assert!(plan2.remote_vteps.is_empty()); // Split-horizon: No reflection back to overlay core
}
