//! Integration tests for EVPN Selective Multicast (S-PMSI) Trees (RFC 9572 / RFC 6514)

use std::net::Ipv4Addr;
use toy_tcpip::evpn_spmsi_mcast::{
    EVPN_ROUTE_TYPE_LEAF_AD, EVPN_ROUTE_TYPE_SPMSI_AD, EvpnLeafAdRoute, EvpnSpmsiEngine,
    EvpnSpmsiRoute, MulticastDeliveryMode, PTA_TUNNEL_TYPE_INGRESS_REPL, PTunnelAttribute,
};

#[test]
fn test_spmsi_and_leaf_ad_full_lifecycle() {
    let mut engine = EvpnSpmsiEngine::new(Ipv4Addr::new(10, 0, 0, 100), 5_000_000); // 5 Mbps threshold

    let leaf1 = Ipv4Addr::new(10, 0, 0, 1);
    let leaf2 = Ipv4Addr::new(10, 0, 0, 2);
    let leaf3 = Ipv4Addr::new(10, 0, 0, 3);

    engine.register_vtep(leaf1);
    engine.register_vtep(leaf2);
    engine.register_vtep(leaf3);

    let src = Ipv4Addr::new(10, 100, 1, 50);
    let grp = Ipv4Addr::new(239, 10, 20, 30);
    let vni = 5000;

    // 1. Initial moderate traffic -> Inclusive mode (replicates to all 3 leaves)
    let (mode, spmsi_opt) = engine.record_traffic(vni, src, grp, 200_000, 1); // 1.6 Mbps
    assert_eq!(mode, MulticastDeliveryMode::Inclusive);
    assert!(spmsi_opt.is_none());

    let mut initial_targets = engine.get_replication_targets(vni, src, grp);
    initial_targets.sort();
    assert_eq!(initial_targets, vec![leaf1, leaf2, leaf3]);

    // 2. High burst -> 10 MB in 1s = 80 Mbps > 5 Mbps threshold -> S-PMSI trigger
    let (mode, spmsi_opt) = engine.record_traffic(vni, src, grp, 10_000_000, 1);
    assert_eq!(mode, MulticastDeliveryMode::Selective);
    let spmsi_route =
        spmsi_opt.expect("Expected S-PMSI A-D route generation upon threshold crossing");
    assert_eq!(spmsi_route.ethernet_tag_id, vni);
    assert_eq!(spmsi_route.source_ip, src);
    assert_eq!(spmsi_route.group_ip, grp);

    // Verify S-PMSI NLRI encoding
    let spmsi_wire = spmsi_route.serialize_nlri();
    assert_eq!(spmsi_wire[0], EVPN_ROUTE_TYPE_SPMSI_AD);
    let parsed_spmsi = EvpnSpmsiRoute::parse_nlri(&spmsi_wire).unwrap();
    assert_eq!(parsed_spmsi.source_ip, src);
    assert_eq!(parsed_spmsi.group_ip, grp);

    // Verify PTA attribute
    let pta = spmsi_route.pta.expect("PTA should be present");
    assert_eq!(pta.tunnel_type, PTA_TUNNEL_TYPE_INGRESS_REPL);
    assert!(pta.is_leaf_info_required());
    let pta_wire = pta.serialize();
    let parsed_pta = PTunnelAttribute::parse(&pta_wire).unwrap();
    assert_eq!(parsed_pta, pta);

    // Prior to leaf join: selective replication drops/zero targets
    let empty_targets = engine.get_replication_targets(vni, src, grp);
    assert!(empty_targets.is_empty());

    // 3. Leaf 1 and Leaf 3 send Leaf A-D join routes
    let leaf1_ad = EvpnLeafAdRoute::new(
        [0, 1, 0, 0, 0, 0, 0, 0],
        vni,
        src,
        grp,
        Ipv4Addr::new(10, 0, 0, 100),
        leaf1,
    );
    let leaf1_wire = leaf1_ad.serialize_nlri();
    assert_eq!(leaf1_wire[0], EVPN_ROUTE_TYPE_LEAF_AD);
    let parsed_leaf1 = EvpnLeafAdRoute::parse_nlri(&leaf1_wire).unwrap();
    assert_eq!(parsed_leaf1.leaf_ip, leaf1);

    let leaf3_ad = EvpnLeafAdRoute::new(
        [0, 1, 0, 0, 0, 0, 0, 0],
        vni,
        src,
        grp,
        Ipv4Addr::new(10, 0, 0, 100),
        leaf3,
    );

    assert!(engine.process_leaf_join(&leaf1_ad));
    assert!(engine.process_leaf_join(&leaf3_ad));

    let mut selective_targets = engine.get_replication_targets(vni, src, grp);
    selective_targets.sort();
    assert_eq!(selective_targets, vec![leaf1, leaf3]);

    // 4. Pruning Leaf 1 leaves only Leaf 3
    assert!(engine.process_leaf_prune(vni, src, grp, &leaf1));
    let targets_after_prune = engine.get_replication_targets(vni, src, grp);
    assert_eq!(targets_after_prune, vec![leaf3]);
}

#[test]
fn test_spmsi_demotion_and_teardown_back_to_inclusive() {
    let mut engine = EvpnSpmsiEngine::new(Ipv4Addr::new(10, 0, 0, 1), 2_000_000); // 2 Mbps promotion threshold

    let leaf2 = Ipv4Addr::new(10, 0, 0, 2);
    let leaf3 = Ipv4Addr::new(10, 0, 0, 3);
    engine.register_vtep(leaf2);
    engine.register_vtep(leaf3);

    let src = Ipv4Addr::new(192, 168, 5, 10);
    let grp = Ipv4Addr::new(239, 1, 2, 3);
    let vni = 1000;

    // 1. High burst triggers S-PMSI
    let (mode1, spmsi_opt1) = engine.record_traffic(vni, src, grp, 5_000_000, 1);
    assert_eq!(mode1, MulticastDeliveryMode::Selective);
    assert!(spmsi_opt1.is_some());
    assert_eq!(engine.active_spmsi_count(), 1);
    assert!(engine.is_selective(vni, src, grp));

    // Leaf 2 joins S-PMSI tree
    let leaf2_ad = EvpnLeafAdRoute::new([0; 8], vni, src, grp, Ipv4Addr::new(10, 0, 0, 1), leaf2);
    assert!(engine.process_leaf_join(&leaf2_ad));
    assert_eq!(engine.get_replication_targets(vni, src, grp), vec![leaf2]);

    // 2. Traffic rate drops significantly to 100 kbps (< 500 kbps low threshold)
    engine.record_traffic(vni, src, grp, 12_500, 1); // 100 kbps

    // Run periodic demotion check (threshold: 500 kbps)
    let withdrawals = engine.check_demotions(500_000);
    assert_eq!(withdrawals.len(), 1);
    assert_eq!(withdrawals[0].source_ip, src);
    assert_eq!(withdrawals[0].group_ip, grp);
    assert!(withdrawals[0].pta.is_none()); // PTA None indicates S-PMSI withdrawal

    // 3. Tree is now demoted back to Inclusive mode
    assert!(!engine.is_selective(vni, src, grp));
    assert_eq!(engine.active_spmsi_count(), 0);

    // Egress replication reverts to all fabric VTEPs (Leaf 2 & Leaf 3)
    let mut targets_inclusive = engine.get_replication_targets(vni, src, grp);
    targets_inclusive.sort();
    assert_eq!(targets_inclusive, vec![leaf2, leaf3]);
}
