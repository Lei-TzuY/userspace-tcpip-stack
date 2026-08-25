use toy_tcpip::ifa_telemetry::{
    IfaHeader, IfaHopRecord, IfaPacket, IfaTelemetryEngine, IFA_REQ_LATENCY, IFA_REQ_NODE_ID,
    IFA_REQ_PORTS, IFA_REQ_QUEUE_DEPTH, IFA_VERSION_2,
};

#[test]
fn test_ifa_packet_framing_and_record_codec() {
    let req_vector = IFA_REQ_NODE_ID | IFA_REQ_PORTS | IFA_REQ_LATENCY | IFA_REQ_QUEUE_DEPTH;
    let header = IfaHeader::new(10, req_vector);
    let payload = b"InBand-Telemetry-Payload";

    let mut pkt = IfaPacket::new(header, payload.to_vec());
    let rec1 = IfaHopRecord::new(0x0A010101, 1, 2, 500, 16384);
    let rec2 = IfaHopRecord::new(0x0A010102, 3, 4, 350, 4096);
    pkt.records.push(rec1.clone());
    pkt.records.push(rec2.clone());
    pkt.header.current_hop_count = 2;

    let wire = pkt.serialize();
    let parsed = IfaPacket::parse(&wire).expect("parse IFA packet");

    assert_eq!(parsed.header.version, IFA_VERSION_2);
    assert_eq!(parsed.header.hop_limit, 10);
    assert_eq!(parsed.header.current_hop_count, 2);
    assert_eq!(parsed.records.len(), 2);
    assert_eq!(parsed.records[0], rec1);
    assert_eq!(parsed.records[1], rec2);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn test_ifa_telemetry_engine_ingress_transit_egress_flow() {
    let mut ingress_node = IfaTelemetryEngine::new(0x10000001);
    let mut transit_node = IfaTelemetryEngine::new(0x10000002);
    let mut egress_node = IfaTelemetryEngine::new(0x10000003);

    let mut probe = ingress_node.ingress_encapsulate(b"telemetry-test", 4, 0x0F);
    assert_eq!(probe.header.current_hop_count, 0);

    // Ingress node inserts hop
    assert!(ingress_node.transit_insert_hop(&mut probe, 1, 2, 200, 1024));
    assert_eq!(probe.header.current_hop_count, 1);

    // Transit node inserts hop
    assert!(transit_node.transit_insert_hop(&mut probe, 2, 3, 450, 8192));
    assert_eq!(probe.header.current_hop_count, 2);

    // Egress node collects metadata
    let collected = egress_node.egress_collect(&probe);
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].node_id, 0x10000001);
    assert_eq!(collected[1].node_id, 0x10000002);
    assert_eq!(collected[1].queue_depth_bytes, 8192);
}
