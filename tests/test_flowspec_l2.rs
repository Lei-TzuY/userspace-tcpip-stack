use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::flowspec_l2::{
    FLOWSPEC_L2_TYPE_DST_MAC, FLOWSPEC_L2_TYPE_ETHERTYPE, FLOWSPEC_L2_TYPE_PCP,
    FLOWSPEC_L2_TYPE_SRC_MAC, FLOWSPEC_L2_TYPE_VLAN_ID, FlowspecL2Action, FlowspecL2Decision,
    FlowspecL2Engine, FlowspecL2Match, FlowspecL2Rule,
};

#[test]
fn test_flowspec_l2_qinq_and_rate_limiting() {
    assert_eq!(FLOWSPEC_L2_TYPE_SRC_MAC, 0x10);
    assert_eq!(FLOWSPEC_L2_TYPE_DST_MAC, 0x11);
    assert_eq!(FLOWSPEC_L2_TYPE_ETHERTYPE, 0x12);
    assert_eq!(FLOWSPEC_L2_TYPE_VLAN_ID, 0x13);
    assert_eq!(FLOWSPEC_L2_TYPE_PCP, 0x14);

    let mut engine = FlowspecL2Engine::new();

    let client_mac = MacAddress::new([0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC]);
    let gw_mac = MacAddress::new([0x00, 0x00, 0x0C, 0x07, 0xAC, 0x01]);

    // Rule: Rate limit QinQ tenant frames (Outer VLAN 300, Inner VLAN 20) to 10Mbps
    engine.add_rule(FlowspecL2Rule {
        rule_id: 100,
        priority: 50,
        match_fields: FlowspecL2Match {
            src_mac: Some(client_mac),
            dst_mac: None,
            ethertype: Some(0x0800),
            vlan_id: Some(300),
            pcp: None,
            inner_vlan_id: Some(20),
        },
        action: FlowspecL2Action::RateLimitBps(10_000_000),
    });

    // Construct QinQ 802.1ad (0x88A8) + 802.1Q (0x8100) frame
    let mut qinq_frame = Vec::new();
    qinq_frame.extend_from_slice(&gw_mac.bytes());
    qinq_frame.extend_from_slice(&client_mac.bytes());
    // Outer S-TAG
    qinq_frame.extend_from_slice(&[0x88, 0xA8]);
    qinq_frame.extend_from_slice(&300u16.to_be_bytes()); // VLAN 300
    // Inner C-TAG
    qinq_frame.extend_from_slice(&[0x81, 0x00]);
    qinq_frame.extend_from_slice(&20u16.to_be_bytes()); // VLAN 20
    // EtherType IPv4
    qinq_frame.extend_from_slice(&[0x08, 0x00]);
    qinq_frame.extend_from_slice(b"PAYLOAD_DATA");

    let decision = engine.evaluate_frame(&qinq_frame);
    assert_eq!(
        decision,
        FlowspecL2Decision::RateLimit {
            rule_id: 100,
            bps: 10_000_000
        }
    );

    // Remove rule
    assert!(engine.remove_rule(100));
    assert_eq!(engine.evaluate_frame(&qinq_frame), FlowspecL2Decision::Pass);
}
