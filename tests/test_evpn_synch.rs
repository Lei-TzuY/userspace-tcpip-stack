use toy_tcpip::evpn_synch::{
    EVPN_ROUTE_TYPE_JOIN_SYNCH, EVPN_ROUTE_TYPE_LEAVE_SYNCH, EthernetSegmentId, EvpnJoinSynchRoute,
    EvpnLeaveSynchRoute, EvpnMulticastSynchEngine,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_route_type7_join_synch_codec() {
    let esi = EthernetSegmentId::from_u32(0x55AA);
    let group = Ipv4Address::new(239, 1, 2, 3);
    let originator = Ipv4Address::new(192, 0, 2, 10);

    let route = EvpnJoinSynchRoute::new_any_source(esi, 200, group, originator);
    let wire = route.serialize_nlri();

    assert_eq!(wire[0], EVPN_ROUTE_TYPE_JOIN_SYNCH);
    assert_eq!(wire.len(), 32);

    let parsed = EvpnJoinSynchRoute::parse_nlri(&wire).expect("parse join synch");
    assert_eq!(parsed, route);
}

#[test]
fn test_evpn_route_type8_leave_synch_codec() {
    let esi = EthernetSegmentId::from_u32(0x55AA);
    let group = Ipv4Address::new(239, 1, 2, 3);
    let originator = Ipv4Address::new(192, 0, 2, 10);

    let route = EvpnLeaveSynchRoute::new(esi, 200, group, originator, 1500);
    let wire = route.serialize_nlri();

    assert_eq!(wire[0], EVPN_ROUTE_TYPE_LEAVE_SYNCH);
    assert_eq!(wire.len(), 34);

    let parsed = EvpnLeaveSynchRoute::parse_nlri(&wire).expect("parse leave synch");
    assert_eq!(parsed, route);
    assert_eq!(parsed.max_response_time_ms, 1500);
}

#[test]
fn test_evpn_multicast_synch_engine_lifecycle() {
    let mut engine = EvpnMulticastSynchEngine::new(Some(EthernetSegmentId::from_u32(1)));
    let esi = EthernetSegmentId::from_u32(1);
    let group = Ipv4Address::new(239, 255, 0, 10);
    let pe1 = Ipv4Address::new(10, 0, 0, 1);
    let pe2 = Ipv4Address::new(10, 0, 0, 2);

    // Initial state: not active
    assert!(!engine.is_group_active(esi, 100, group));

    // PE1 joins group
    engine.process_join_synch(EvpnJoinSynchRoute::new_any_source(esi, 100, group, pe1));
    assert!(engine.is_group_active(esi, 100, group));
    assert_eq!(engine.get_active_pes_for_group(esi, 100, group), vec![pe1]);

    // PE2 also joins group (multihomed redundancy)
    engine.process_join_synch(EvpnJoinSynchRoute::new_any_source(esi, 100, group, pe2));
    let active_pes = engine.get_active_pes_for_group(esi, 100, group);
    assert_eq!(active_pes.len(), 2);
    assert!(active_pes.contains(&pe1));
    assert!(active_pes.contains(&pe2));

    // PE1 leaves group
    engine.process_leave_synch(EvpnLeaveSynchRoute::new(esi, 100, group, pe1, 1000));
    // Group remains active because PE2 is still joined
    assert!(engine.is_group_active(esi, 100, group));
    assert_eq!(engine.get_active_pes_for_group(esi, 100, group), vec![pe2]);

    // PE2 leaves group -> now inactive
    engine.process_leave_synch(EvpnLeaveSynchRoute::new(esi, 100, group, pe2, 1000));
    assert!(!engine.is_group_active(esi, 100, group));
}

#[test]
fn test_evpn_route_type7_ssm_source_specific_codec() {
    let esi = EthernetSegmentId::from_u32(0x9999);
    let source = Ipv4Address::new(198, 51, 100, 1);
    let group = Ipv4Address::new(232, 1, 1, 1);
    let originator = Ipv4Address::new(10, 1, 1, 1);

    let route = EvpnJoinSynchRoute::new_source_specific(esi, 300, source, group, originator, false);
    assert!(route.is_include_mode());
    assert!(!route.is_exclude_mode());

    let wire = route.serialize_nlri();
    let parsed = EvpnJoinSynchRoute::parse_nlri(&wire).expect("parse SSM join synch");
    assert_eq!(parsed, route);
    assert_eq!(parsed.source_ip, source);
    assert_eq!(parsed.group_ip, group);
}

#[test]
fn test_evpn_v6_mld_synch_routes_codec() {
    use toy_tcpip::evpn_synch::{EvpnJoinSynchRouteV6, EvpnLeaveSynchRouteV6};
    use toy_tcpip::ipv6::Ipv6Address;

    let esi = EthernetSegmentId::from_u32(0x8888);
    let src_v6 = Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let grp_v6 = Ipv6Address([0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01]);
    let orig_v6 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
    ]);

    // Type 7 IPv6
    let join_v6 =
        EvpnJoinSynchRouteV6::new_source_specific(esi, 500, src_v6, grp_v6, orig_v6, false);
    let wire7 = join_v6.serialize_nlri();
    assert_eq!(wire7.len(), 68);
    let parsed7 = EvpnJoinSynchRouteV6::parse_nlri(&wire7).expect("parse join synch v6");
    assert_eq!(parsed7, join_v6);

    // Type 8 IPv6
    let leave_v6 = EvpnLeaveSynchRouteV6::new(esi, 500, grp_v6, orig_v6, 2500);
    let wire8 = leave_v6.serialize_nlri();
    assert_eq!(wire8.len(), 70);
    let parsed8 = EvpnLeaveSynchRouteV6::parse_nlri(&wire8).expect("parse leave synch v6");
    assert_eq!(parsed8, leave_v6);
    assert_eq!(parsed8.max_response_time_ms, 2500);
}

#[test]
fn test_evpn_multicast_ssm_and_leave_expiration() {
    let mut engine = EvpnMulticastSynchEngine::new(Some(EthernetSegmentId::from_u32(10)));
    let esi = EthernetSegmentId::from_u32(10);
    let group = Ipv4Address::new(232, 5, 5, 5);
    let src1 = Ipv4Address::new(10, 1, 1, 100);
    let src2 = Ipv4Address::new(10, 1, 1, 200);
    let pe = Ipv4Address::new(192, 0, 2, 1);

    // Join (src1, group) and (src2, group)
    engine.process_join_synch(EvpnJoinSynchRoute::new_source_specific(
        esi, 100, src1, group, pe, false,
    ));
    engine.process_join_synch(EvpnJoinSynchRoute::new_source_specific(
        esi, 100, src2, group, pe, false,
    ));

    assert!(engine.is_source_group_active(esi, 100, src1, group));
    assert!(engine.is_source_group_active(esi, 100, src2, group));

    let sources = engine.active_sources_for_group(esi, 100, group);
    assert_eq!(sources.len(), 2);
    assert!(sources.contains(&src1));
    assert!(sources.contains(&src2));

    // Peer PE sends Leave Synch with max_response_time_ms = 1000
    engine.process_leave_synch(EvpnLeaveSynchRoute::new_source_specific(
        esi, 100, src1, group, pe, 1000,
    ));
    // Join route for (src1, group) should be removed immediately from this PE
    assert!(!engine.is_source_group_active(esi, 100, src1, group));
    assert_eq!(engine.leave_routes.len(), 1);

    // Timer advances 400ms -> not expired
    let expired = engine.expire_leaves(400);
    assert_eq!(expired, 0);
    assert_eq!(engine.leave_routes.len(), 1);
    assert_eq!(engine.leave_routes[0].max_response_time_ms, 600);

    // Timer advances another 700ms -> expired
    let expired2 = engine.expire_leaves(700);
    assert_eq!(expired2, 1);
    assert!(engine.leave_routes.is_empty());
}
