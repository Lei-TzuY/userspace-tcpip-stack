use toy_tcpip::evpn_synch::{
    EthernetSegmentId, EvpnJoinSynchRoute, EvpnLeaveSynchRoute, EvpnMulticastSynchEngine,
    EVPN_ROUTE_TYPE_JOIN_SYNCH, EVPN_ROUTE_TYPE_LEAVE_SYNCH,
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
