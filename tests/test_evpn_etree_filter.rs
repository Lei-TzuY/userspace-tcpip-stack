use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_etree::ETreeRole;
use toy_tcpip::evpn_etree_filter::{ETreeForwardVerdict, EvpnETreeFilterEngine};

#[test]
fn test_evpn_etree_known_unicast_and_overlay_filtering() {
    let mut engine = EvpnETreeFilterEngine::new();
    let vni = 20000;

    let root_mac = MacAddress::new([0x00, 0x10, 0x10, 0x10, 0x10, 0x10]);
    let leaf1_mac = MacAddress::new([0x00, 0x20, 0x20, 0x20, 0x20, 0x20]);
    let leaf2_mac = MacAddress::new([0x00, 0x30, 0x30, 0x30, 0x30, 0x30]);

    engine.add_access_port(vni, "port-root", 200, ETreeRole::Root);
    engine.add_access_port(vni, "port-leaf1", 200, ETreeRole::Leaf);
    engine.add_access_port(vni, "port-leaf2", 200, ETreeRole::Leaf);

    engine.learn_mac(vni, root_mac, "port-root", ETreeRole::Root);
    engine.learn_mac(vni, leaf1_mac, "port-leaf1", ETreeRole::Leaf);
    engine.learn_mac(vni, leaf2_mac, "port-leaf2", ETreeRole::Leaf);

    // 1. Leaf1 to Root -> Permitted
    let verdict_leaf_to_root =
        engine.evaluate_known_unicast(vni, "port-leaf1", 200, leaf1_mac, root_mac);
    assert_eq!(
        verdict_leaf_to_root,
        ETreeForwardVerdict::Forward {
            local_egress_ports: vec!["port-root".to_string()],
            remote_vteps: Vec::new(),
        }
    );

    // 2. Leaf1 to Leaf2 -> Dropped Leaf-to-Leaf
    let verdict_leaf_to_leaf =
        engine.evaluate_known_unicast(vni, "port-leaf1", 200, leaf1_mac, leaf2_mac);
    match verdict_leaf_to_leaf {
        ETreeForwardVerdict::DropLeafToLeaf(reason) => {
            assert!(reason.contains("port-leaf1"));
        }
        other => panic!("Expected DropLeafToLeaf, got {:?}", other),
    }

    // 3. Root to Leaf1 -> Permitted
    let verdict_root_to_leaf =
        engine.evaluate_known_unicast(vni, "port-root", 200, root_mac, leaf1_mac);
    assert_eq!(
        verdict_root_to_leaf,
        ETreeForwardVerdict::Forward {
            local_egress_ports: vec!["port-leaf1".to_string()],
            remote_vteps: Vec::new(),
        }
    );

    // 4. Remote overlay packet filtering
    // Inbound from remote Leaf destined to local Leaf -> Blocked
    assert!(!engine.filter_overlay_ingress_packet(vni, true, leaf2_mac));
    // Inbound from remote Leaf destined to local Root -> Allowed
    assert!(engine.filter_overlay_ingress_packet(vni, true, root_mac));
    // Inbound from remote Root destined to local Leaf -> Allowed
    assert!(engine.filter_overlay_ingress_packet(vni, false, leaf2_mac));
}
