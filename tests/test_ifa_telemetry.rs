use toy_tcpip::ifa_telemetry::{
    IFA_REQ_LATENCY, IFA_REQ_NODE_ID, IFA_REQ_PORTS, IFA_REQ_QUEUE_DEPTH, IFA_VERSION_2, IfaHeader,
    IfaHopRecord, IfaPacket, IfaTelemetryEngine,
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

#[test]
fn test_ifa_extended_hop_record_codec_and_packet() {
    use toy_tcpip::ifa_telemetry::{
        IFA_REQ_BUFFER_OCCUPANCY, IFA_REQ_DROP_REASON, IFA_REQ_LATENCY, IFA_REQ_NODE_ID,
        IFA_REQ_PORTS, IFA_REQ_TIMESTAMPS, IfaDropReason, IfaExtendedHopRecord, IfaExtendedPacket,
        IfaHeader,
    };

    let rec1 = IfaExtendedHopRecord::new(
        0x0B010203,
        10,
        20,
        1_000_000_000,
        1_000_000_350, // 350 ns residence latency
        16384,
        45,
        IfaDropReason::None,
    );

    assert_eq!(rec1.transit_latency_ns(), 350);

    let wire_rec = rec1.serialize();
    assert_eq!(wire_rec.len(), 32);

    let parsed_rec = IfaExtendedHopRecord::parse(&wire_rec).expect("parse extended record");
    assert_eq!(parsed_rec, rec1);

    // Test extended packet framing
    let req_vec = IFA_REQ_NODE_ID
        | IFA_REQ_PORTS
        | IFA_REQ_LATENCY
        | IFA_REQ_TIMESTAMPS
        | IFA_REQ_DROP_REASON
        | IFA_REQ_BUFFER_OCCUPANCY;
    let mut ext_pkt = IfaExtendedPacket::new(IfaHeader::new(8, req_vec), b"payload-ext".to_vec());
    ext_pkt.records.push(rec1.clone());
    ext_pkt.header.current_hop_count = 1;

    let pkt_wire = ext_pkt.serialize();
    let parsed_pkt = IfaExtendedPacket::parse(&pkt_wire).expect("parse extended packet");
    assert_eq!(parsed_pkt.header.current_hop_count, 1);
    assert_eq!(parsed_pkt.records.len(), 1);
    assert_eq!(parsed_pkt.records[0], rec1);
    assert_eq!(parsed_pkt.payload, b"payload-ext");
}

#[test]
fn test_ifa_anomaly_detector_sla_and_drop_alerts() {
    use toy_tcpip::ifa_telemetry::{
        IfaAlertType, IfaAnomalyDetector, IfaDropReason, IfaExtendedHopRecord,
    };

    // Thresholds: latency > 500 ns, queue > 32KB, buffer > 80%
    let mut detector = IfaAnomalyDetector::new(500, 32768, 80);

    // Normal hop
    let rec_ok = IfaExtendedHopRecord::new(0x01, 1, 2, 1000, 1200, 4096, 20, IfaDropReason::None);
    let alerts = detector.inspect_record(&rec_ok);
    assert!(alerts.is_empty());

    // Latency spike hop (700 ns latency > 500 ns threshold)
    let rec_latency =
        IfaExtendedHopRecord::new(0x02, 2, 3, 1000, 1700, 8192, 40, IfaDropReason::None);
    let alerts = detector.inspect_record(&rec_latency);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, IfaAlertType::LatencySlaViolation);
    assert_eq!(alerts[0].observed_value, 700);

    // Buffer spike + packet drop hop
    let rec_drop = IfaExtendedHopRecord::new(
        0x03,
        3,
        4,
        1000,
        1300,
        65536,
        95,
        IfaDropReason::BufferOverflow,
    );
    let alerts = detector.inspect_record(&rec_drop);
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].alert_type, IfaAlertType::QueueBufferSpike);
    assert_eq!(alerts[1].alert_type, IfaAlertType::PacketDropDetected);

    assert_eq!(detector.alerts_generated.len(), 3);
}

#[test]
fn test_ifa_ipfix_export_formatting() {
    use toy_tcpip::ifa_telemetry::{IfaDropReason, IfaExtendedHopRecord, IfaIpfixExporter};

    let mut exporter = IfaIpfixExporter::new(256, 300);
    let rec = IfaExtendedHopRecord::new(
        0x10000001,
        1,
        2,
        2_000_000,
        2_000_450,
        8192,
        30,
        IfaDropReason::None,
    );

    let ipfix_msg = exporter.export_record(&rec, 1725345600);
    // Header (16 bytes) + Set Header (4 bytes) + Record (20 bytes) = 40 bytes
    assert_eq!(ipfix_msg.len(), 40);

    // Verify IPFIX Version = 10 (0x000A)
    assert_eq!(u16::from_be_bytes([ipfix_msg[0], ipfix_msg[1]]), 10);
    // Verify Length = 40
    assert_eq!(u16::from_be_bytes([ipfix_msg[2], ipfix_msg[3]]), 40);
    // Verify Set ID = 300 (Template ID)
    assert_eq!(u16::from_be_bytes([ipfix_msg[16], ipfix_msg[17]]), 300);
    // Verify Node ID = 0x10000001
    assert_eq!(
        u32::from_be_bytes([ipfix_msg[20], ipfix_msg[21], ipfix_msg[22], ipfix_msg[23]]),
        0x10000001
    );
    // Sequence number increments
    assert_eq!(exporter.sequence_number, 2);
}

#[test]
fn test_ifa_packet_anomaly_inspection_and_excessive_hops() {
    use toy_tcpip::ifa_telemetry::{
        IfaAlertType, IfaAnomalyDetector, IfaDropReason, IfaExtendedHopRecord, IfaExtendedPacket,
        IfaHeader,
    };

    let mut detector = IfaAnomalyDetector::new(500, 32768, 80).with_max_hop_count(2);

    let rec1 = IfaExtendedHopRecord::new(0x01, 1, 2, 1000, 1200, 4096, 20, IfaDropReason::None);
    let rec2 = IfaExtendedHopRecord::new(
        0x02,
        2,
        3,
        1000,
        1800,
        8192,
        40,
        IfaDropReason::None, // Latency 800 > 500
    );
    let rec3 = IfaExtendedHopRecord::new(0x03, 3, 4, 1000, 1200, 4096, 20, IfaDropReason::None);

    let mut pkt = IfaExtendedPacket::new(IfaHeader::new(8, 0x3F), b"test-payload".to_vec());
    pkt.records.push(rec1);
    pkt.records.push(rec2);
    pkt.records.push(rec3);
    pkt.header.current_hop_count = 3; // Hop count 3 > max 2

    let alerts = detector.inspect_packet(&pkt);
    assert_eq!(alerts.len(), 2);
    // 1. Excessive hop count alert
    assert_eq!(alerts[0].alert_type, IfaAlertType::ExcessiveHopCount);
    assert_eq!(alerts[0].observed_value, 3);
    // 2. Latency SLA violation from rec2
    assert_eq!(alerts[1].alert_type, IfaAlertType::LatencySlaViolation);
    assert_eq!(alerts[1].observed_value, 800);
}

#[test]
fn test_ifa_ipfix_batch_packet_export() {
    use toy_tcpip::ifa_telemetry::{
        IfaDropReason, IfaExtendedHopRecord, IfaExtendedPacket, IfaHeader, IfaIpfixExporter,
    };

    let mut exporter = IfaIpfixExporter::new(500, 301);

    let rec1 = IfaExtendedHopRecord::new(0x10, 1, 2, 1000, 1300, 4096, 20, IfaDropReason::None);
    let rec2 = IfaExtendedHopRecord::new(0x20, 2, 3, 2000, 2450, 8192, 30, IfaDropReason::None);

    let mut pkt = IfaExtendedPacket::new(IfaHeader::new(5, 0x1F), b"batch".to_vec());
    pkt.records.push(rec1);
    pkt.records.push(rec2);

    let ipfix_msg = exporter.export_packet_records(&pkt, 1725350000);
    // 16 (Header) + 4 (Set Header) + 20 * 2 (Records) = 60 bytes
    assert_eq!(ipfix_msg.len(), 60);
    assert_eq!(u16::from_be_bytes([ipfix_msg[2], ipfix_msg[3]]), 60); // Total length
    assert_eq!(u16::from_be_bytes([ipfix_msg[16], ipfix_msg[17]]), 301); // Set ID
    assert_eq!(u16::from_be_bytes([ipfix_msg[18], ipfix_msg[19]]), 44); // Set length (4 + 40)
}
