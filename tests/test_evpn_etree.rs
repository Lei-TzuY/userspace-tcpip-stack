use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_etree::{
    ETreeDecision, ETreeRole, EvpnETreeEngine, EvpnETreeExtCommunity,
    BGP_EXT_COMM_SUBTYPE_ETREE, BGP_EXT_COMM_TYPE_EVPN,
};

#[test]
fn test_evpn_etree_extended_community_codec() {
    let comm_leaf = EvpnETreeExtCommunity::new_leaf(5001);
    let wire = comm_leaf.serialize();
    assert_eq!(wire.len(), 8);
    assert_eq!(wire[0], BGP_EXT_COMM_TYPE_EVPN);
    assert_eq!(wire[1], BGP_EXT_COMM_SUBTYPE_ETREE);
    assert_eq!(wire[2] & 0x04, 0x04); // L-bit

    let parsed = EvpnETreeExtCommunity::parse(&wire).expect("parse E-Tree ext community");
    assert_eq!(parsed.is_leaf, true);
    assert_eq!(parsed.leaf_label, 5001);

    let comm_root = EvpnETreeExtCommunity::new_root();
    let wire_root = comm_root.serialize();
    assert_eq!(wire_root[2] & 0x04, 0x00);
    let parsed_root = EvpnETreeExtCommunity::parse(&wire_root).expect("parse root community");
    assert_eq!(parsed_root.is_leaf, false);
}

#[test]
fn test_evpn_etree_forwarding_and_split_horizon_drop() {
    let mut engine = EvpnETreeEngine::new();
    let vni = 200;

    let root = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);
    let leaf_a = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0A]);
    let leaf_b = MacAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x0B]);

    engine.register_endpoint(vni, root, ETreeRole::Root);
    engine.register_endpoint(vni, leaf_a, ETreeRole::Leaf);
    engine.register_endpoint(vni, leaf_b, ETreeRole::Leaf);

    // 1. Root to Leaf: Allowed
    assert_eq!(
        engine.evaluate_forwarding(vni, root, leaf_a),
        ETreeDecision::Permitted
    );

    // 2. Leaf to Root: Allowed
    assert_eq!(
        engine.evaluate_forwarding(vni, leaf_a, root),
        ETreeDecision::Permitted
    );

    // 3. Leaf to Leaf: Blocked
    assert_eq!(
        engine.evaluate_forwarding(vni, leaf_a, leaf_b),
        ETreeDecision::DroppedLeafToLeaf
    );
    assert_eq!(engine.blocked_leaf_to_leaf_count, 1);
    assert_eq!(engine.forwarded_packets_count, 2);
}
