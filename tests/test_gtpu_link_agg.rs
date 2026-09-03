use toy_tcpip::gtpu_link_agg::{
    AggregatedLink, FiveTuple, FlowDistributionResult, GtpuLinkAggEngine, LinkHealthState,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_gtpu_link_agg_lifecycle() {
    let mut agg = GtpuLinkAggEngine::new(10);

    let link_3gpp = AggregatedLink::new(
        1,
        "3GPP-Cellular",
        3,
        0x3001,
        Ipv4Address::new(10, 100, 1, 1),
    );
    let link_wifi = AggregatedLink::new(
        2,
        "Wi-Fi-Backhaul",
        1,
        0x3002,
        Ipv4Address::new(10, 200, 2, 2),
    );

    agg.add_link(link_3gpp);
    agg.add_link(link_wifi);

    let flow1 = FiveTuple {
        src_ip: Ipv4Address::new(192, 168, 1, 10),
        dst_ip: Ipv4Address::new(8, 8, 8, 8),
        src_port: 45000,
        dst_port: 53,
        proto: 17, // UDP
    };

    // 1. Consistent hash dispatching
    let d1 = agg.dispatch_packet(&flow1, 512);
    let d2 = agg.dispatch_packet(&flow1, 512);
    assert_eq!(d1, d2);

    // 2. Mark active link down -> failover to surviving link
    if let FlowDistributionResult::Forward { link_id, .. } = d1 {
        agg.set_link_status(link_id, LinkHealthState::Down);
        let d3 = agg.dispatch_packet(&flow1, 512);
        match d3 {
            FlowDistributionResult::Forward {
                link_id: new_link, ..
            } => {
                assert_ne!(link_id, new_link);
            }
            _ => panic!("Expected successful failover link"),
        }

        // 3. Mark remaining link down -> AllLinksDown
        let other_link = if link_id == 1 { 2 } else { 1 };
        agg.set_link_status(other_link, LinkHealthState::Down);
        assert_eq!(
            agg.dispatch_packet(&flow1, 512),
            FlowDistributionResult::AllLinksDown
        );
    }
}
