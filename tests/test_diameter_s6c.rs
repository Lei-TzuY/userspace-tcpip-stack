use toy_tcpip::diameter_s6c::{
    DIAMETER_APPLICATION_S6C, DIAMETER_CMD_SEND_ROUTING_INFO_FOR_SM, S6cAvp, S6cHssEngine,
    S6cMessage, S6cServingNodeInfo, S6cServingNodeType,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_diameter_s6c_sms_routing_lookup() {
    let mut hss = S6cHssEngine::new("hss.node.operator.com");
    let info = S6cServingNodeInfo {
        node_type: S6cServingNodeType::Smsf,
        node_fqdn: "smsf01.5gcore.org".into(),
        node_ip: Ipv4Address::new(172, 16, 0, 10),
    };
    hss.register_subscriber_location("460029991112223", info.clone());

    let srr = S6cMessage::new_srr("s6c-test-sess", "460029991112223");
    assert_eq!(srr.application_id, DIAMETER_APPLICATION_S6C);
    assert_eq!(srr.command_code, DIAMETER_CMD_SEND_ROUTING_INFO_FOR_SM);

    let sra = hss.handle_srr(&srr);
    let rc = sra.avps.iter().find_map(|a| {
        if let S6cAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(2001));

    let node = sra.avps.iter().find_map(|a| {
        if let S6cAvp::ServingNode(n) = a {
            Some(n.clone())
        } else {
            None
        }
    });
    assert_eq!(node, Some(info));
    assert_eq!(hss.total_srr_requests, 1);
}
