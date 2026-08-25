use toy_tcpip::evpn_igmp_snooping::{
    EvpnIgmpSnoopingEngine, MulticastForwardingAction,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_igmp_snooping_and_multicast_pruning() {
    let mut snooping = EvpnIgmpSnoopingEngine::new();
    let vni = 200;
    let group = Ipv4Address::new(239, 255, 0, 1);

    // Initial state: no subscribers, forwarded packet must be pruned
    assert_eq!(
        snooping.evaluate_multicast_forwarding(vni, group),
        MulticastForwardingAction::PrunedNoReceivers
    );
    assert_eq!(snooping.pruned_packets_count, 1);

    // Port 1 joins
    snooping.process_igmp_join(vni, 1, group);
    // Port 4 joins
    snooping.process_igmp_join(vni, 4, group);

    // Multicast evaluation forwards to ports 1 and 4
    assert_eq!(
        snooping.evaluate_multicast_forwarding(vni, group),
        MulticastForwardingAction::ForwardToPorts(vec![1, 4])
    );
    assert_eq!(snooping.forwarded_packets_count, 1);

    // Port 1 leaves
    snooping.process_igmp_leave(vni, 1, group);
    assert_eq!(
        snooping.evaluate_multicast_forwarding(vni, group),
        MulticastForwardingAction::ForwardToPorts(vec![4])
    );

    // Port 4 leaves
    snooping.process_igmp_leave(vni, 4, group);
    assert_eq!(
        snooping.evaluate_multicast_forwarding(vni, group),
        MulticastForwardingAction::PrunedNoReceivers
    );
}
