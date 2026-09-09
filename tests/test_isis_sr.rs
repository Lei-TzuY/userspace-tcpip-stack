//! Integration tests for IS-IS Segment Routing Extensions (RFC 8667)

use toy_tcpip::isis_sr::{
    IsisAdjacencySid, IsisPrefixSid, IsisSegmentRoutingCapability, IsisSegmentRoutingDatabase,
    SrgbRange, ADJ_SID_FLAG_B, ADJ_SID_FLAG_L, ADJ_SID_FLAG_V, ISIS_SUBTLV_ADJ_SID,
    ISIS_SUBTLV_LAN_ADJ_SID, ISIS_SUBTLV_PREFIX_SID, ISIS_SUBTLV_SR_CAPABILITY, PREFIX_SID_FLAG_E,
    PREFIX_SID_FLAG_N, PREFIX_SID_FLAG_P, PREFIX_SID_FLAG_R, PREFIX_SID_FLAG_V, SR_ALGORITHM_SPF,
    SR_ALGORITHM_STRICT_SPF, SR_CAP_FLAG_IPV4_MPLS, SR_CAP_FLAG_IPV6_MPLS,
};

#[test]
fn test_isis_srgb_range_calculations() {
    let srgb = SrgbRange::new(16_000, 8_000);
    assert_eq!(srgb.range_base, 16_000);
    assert_eq!(srgb.range_size, 8_000);

    // Within bounds
    assert!(srgb.contains_index(0));
    assert_eq!(srgb.index_to_label(0), Some(16_000));
    assert!(srgb.contains_index(500));
    assert_eq!(srgb.index_to_label(500), Some(16_500));
    assert!(srgb.contains_index(7_999));
    assert_eq!(srgb.index_to_label(7_999), Some(23_999));

    // Out of bounds
    assert!(!srgb.contains_index(8_000));
    assert_eq!(srgb.index_to_label(8_000), None);
    assert!(!srgb.contains_index(10_000));
    assert_eq!(srgb.index_to_label(10_000), None);
}

#[test]
fn test_isis_sr_capability_subtlv_serialization() {
    let mut cap = IsisSegmentRoutingCapability::new(SR_CAP_FLAG_IPV4_MPLS | SR_CAP_FLAG_IPV6_MPLS);
    cap.add_srgb(SrgbRange::new(16_000, 8_000));
    cap.add_srgb(SrgbRange::new(24_000, 4_000));

    assert!(cap.ipv4_mpls());
    assert!(cap.ipv6_mpls());
    assert_eq!(cap.srgb_ranges.len(), 2);

    let bytes = cap.serialize();
    assert_eq!(bytes[0], ISIS_SUBTLV_SR_CAPABILITY);
    let subtlv_len = bytes[1] as usize;
    assert_eq!(bytes.len(), subtlv_len + 2);

    // Flags byte is at index 2
    assert_eq!(bytes[2], SR_CAP_FLAG_IPV4_MPLS | SR_CAP_FLAG_IPV6_MPLS);
}

#[test]
fn test_isis_prefix_sid_subtlv_variations() {
    // 1. Node-SID with index
    let node_sid = IsisPrefixSid::node_sid(50, SR_ALGORITHM_SPF);
    assert!(node_sid.is_node_sid());
    assert!(node_sid.no_php());
    assert!(!node_sid.is_absolute());
    assert!(!node_sid.explicit_null());

    let bytes = node_sid.serialize();
    assert_eq!(bytes[0], ISIS_SUBTLV_PREFIX_SID);
    assert_eq!(bytes[1], 6); // Length: flags(1) + algo(1) + index(4)
    assert_eq!(bytes[2], PREFIX_SID_FLAG_R | PREFIX_SID_FLAG_N | PREFIX_SID_FLAG_P);
    assert_eq!(bytes[3], SR_ALGORITHM_SPF);
    let index_val = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    assert_eq!(index_val, 50);

    // 2. Absolute Prefix-SID with Explicit Null
    let abs_sid = IsisPrefixSid::new(
        PREFIX_SID_FLAG_V | PREFIX_SID_FLAG_E,
        SR_ALGORITHM_STRICT_SPF,
        18_000,
    );
    assert!(abs_sid.is_absolute());
    assert!(abs_sid.explicit_null());
    assert!(!abs_sid.is_node_sid());

    let abs_bytes = abs_sid.serialize();
    assert_eq!(abs_bytes[0], ISIS_SUBTLV_PREFIX_SID);
    assert_eq!(abs_bytes[1], 5); // Length: flags(1) + algo(1) + label(3)
    assert_eq!(abs_bytes[2], PREFIX_SID_FLAG_V | PREFIX_SID_FLAG_E);
    assert_eq!(abs_bytes[3], SR_ALGORITHM_STRICT_SPF);
    let label_val = ((abs_bytes[4] as u32) << 16) | ((abs_bytes[5] as u32) << 8) | (abs_bytes[6] as u32);
    assert_eq!(label_val, 18_000);
}

#[test]
fn test_isis_adj_sid_p2p_and_lan_subtlv() {
    // Point-to-point Adj-SID
    let p2p_adj = IsisAdjacencySid::new(
        ADJ_SID_FLAG_V | ADJ_SID_FLAG_L,
        10,
        24001,
    );
    assert!(!p2p_adj.is_backup());
    assert!(p2p_adj.is_local());

    let p2p_bytes = p2p_adj.serialize();
    assert_eq!(p2p_bytes[0], ISIS_SUBTLV_ADJ_SID);
    assert_eq!(p2p_bytes[1], 5); // flags(1) + weight(1) + label(3)
    assert_eq!(p2p_bytes[2], ADJ_SID_FLAG_V | ADJ_SID_FLAG_L);
    assert_eq!(p2p_bytes[3], 10); // weight

    // LAN Adj-SID with neighbor System ID and Backup protection flag (B)
    let lan_neighbor = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let lan_adj = IsisAdjacencySid::lan_adj_sid(
        ADJ_SID_FLAG_V | ADJ_SID_FLAG_L | ADJ_SID_FLAG_B,
        20,
        24002,
        lan_neighbor,
    );
    assert!(lan_adj.is_backup());
    assert!(lan_adj.is_local());

    let lan_bytes = lan_adj.serialize();
    assert_eq!(lan_bytes[0], ISIS_SUBTLV_LAN_ADJ_SID);
    assert_eq!(lan_bytes[1], 11); // flags(1) + weight(1) + sys_id(6) + label(3)
    assert_eq!(lan_bytes[2], ADJ_SID_FLAG_V | ADJ_SID_FLAG_L | ADJ_SID_FLAG_B);
    assert_eq!(lan_bytes[3], 20);
    assert_eq!(&lan_bytes[4..10], &lan_neighbor);
}

#[test]
fn test_isis_srdb_multi_node_topology() {
    let local_srgb = SrgbRange::new(16_000, 8_000);
    let mut srdb = IsisSegmentRoutingDatabase::new(local_srgb);

    let sys_id_1 = [0x19, 0x21, 0x68, 0x00, 0x00, 0x01];
    let sys_id_2 = [0x19, 0x21, 0x68, 0x00, 0x00, 0x02];
    let sys_id_3 = [0x19, 0x21, 0x68, 0x00, 0x00, 0x03];

    // Node 1
    let mut cap1 = IsisSegmentRoutingCapability::new(SR_CAP_FLAG_IPV4_MPLS);
    cap1.add_srgb(SrgbRange::new(16_000, 8_000));
    srdb.register_node(sys_id_1, cap1, vec![SR_ALGORITHM_SPF]);
    srdb.add_prefix_sid(&sys_id_1, 0x0A000101, 32, IsisPrefixSid::node_sid(101, SR_ALGORITHM_SPF));
    srdb.add_adjacency_sid(&sys_id_1, IsisAdjacencySid::new(ADJ_SID_FLAG_V | ADJ_SID_FLAG_L, 0, 24012));

    // Node 2 (uses a different SRGB: 30_000..38_000)
    let mut cap2 = IsisSegmentRoutingCapability::new(SR_CAP_FLAG_IPV4_MPLS);
    cap2.add_srgb(SrgbRange::new(30_000, 8_000));
    srdb.register_node(sys_id_2, cap2, vec![SR_ALGORITHM_SPF, SR_ALGORITHM_STRICT_SPF]);
    srdb.add_prefix_sid(&sys_id_2, 0x0A000202, 32, IsisPrefixSid::node_sid(102, SR_ALGORITHM_SPF));
    srdb.add_adjacency_sid(&sys_id_2, IsisAdjacencySid::new(ADJ_SID_FLAG_V | ADJ_SID_FLAG_L, 0, 24023));

    // Node 3
    let mut cap3 = IsisSegmentRoutingCapability::new(SR_CAP_FLAG_IPV4_MPLS | SR_CAP_FLAG_IPV6_MPLS);
    cap3.add_srgb(SrgbRange::new(16_000, 8_000));
    srdb.register_node(sys_id_3, cap3, vec![SR_ALGORITHM_SPF]);
    srdb.add_prefix_sid(&sys_id_3, 0x0A000303, 32, IsisPrefixSid::node_sid(103, SR_ALGORITHM_SPF));

    // Verify topology counts
    assert_eq!(srdb.node_count(), 3);
    assert_eq!(srdb.total_prefix_sids(), 3);
    assert_eq!(srdb.total_adjacency_sids(), 2);

    // Resolve SIDs locally
    assert_eq!(srdb.resolve_sid_to_label(101), Some(16_101));
    assert_eq!(srdb.resolve_sid_to_label(102), Some(16_102));

    // Resolve SID at remote Node 2 with different SRGB base (30000)
    assert_eq!(srdb.resolve_remote_sid(&sys_id_2, 102), Some(30_102));

    // Verify Node-SID lookup
    let node1_sid = srdb.find_node_sid(&sys_id_1).unwrap();
    assert_eq!(node1_sid.sid_value, 101);
    assert!(node1_sid.is_node_sid());

    let node2_sid = srdb.find_node_sid(&sys_id_2).unwrap();
    assert_eq!(node2_sid.sid_value, 102);
}
