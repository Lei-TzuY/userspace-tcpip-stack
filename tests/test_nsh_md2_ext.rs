//! Integration tests for NSH MD Type 2 Extended Context TLVs (IOAM Telemetry, ECN, Subscriber ID).

use toy_tcpip::nsh_md2::{NSH_NP_IPV4, NshMd2Header, NshMd2Packet};
use toy_tcpip::nsh_md2_ext::{
    EcnCongestionTlv, IoamHopTelemetry, NSH_TLV_CLASS_IOAM, NSH_TLV_TYPE_IOAM_HOP_TELEMETRY,
    NshMd2ExtendedTransitEngine, SfcTelemetryCollector, SubscriberIdTlv, SubscriberIdType,
};

#[test]
fn test_ioam_hop_telemetry_serialize_parse_roundtrip() {
    let hop = IoamHopTelemetry {
        node_id: 0xDEAD_BEEF,
        ingress_if_id: 1,
        egress_if_id: 3,
        transit_delay_us: 42,
        queue_depth_bytes: 8192,
        tx_packet_count: 1_000_000,
        rx_drop_count: 17,
    };

    let bytes = hop.serialize();
    assert_eq!(bytes.len(), 24);

    let parsed = IoamHopTelemetry::parse(&bytes).unwrap();
    assert_eq!(parsed, hop);

    // Test NshContextTlv wrapping
    let tlv = hop.to_nsh_tlv();
    assert_eq!(tlv.class, NSH_TLV_CLASS_IOAM);
    assert_eq!(tlv.tlv_type, NSH_TLV_TYPE_IOAM_HOP_TELEMETRY);
    assert!(!tlv.critical);
}

#[test]
fn test_ecn_congestion_tlv_and_subscriber_id() {
    // ECN Congestion TLV
    let ecn = EcnCongestionTlv::new(0x1234, 2, 3, 87);
    let ecn_bytes = ecn.serialize();
    assert_eq!(ecn_bytes.len(), 8);

    let parsed_ecn = EcnCongestionTlv::parse(&ecn_bytes).unwrap();
    assert_eq!(parsed_ecn.reporting_node_id, 0x1234);
    assert_eq!(parsed_ecn.congestion_level, 2); // moderate
    assert_eq!(parsed_ecn.ecn_codepoint, 3); // CE
    assert_eq!(parsed_ecn.queue_utilization_pct, 87);

    // Verify the ECN TLV is marked critical
    let ecn_tlv = ecn.to_nsh_tlv();
    assert!(ecn_tlv.critical);

    // Subscriber ID TLV (IMSI)
    let sub_imsi = SubscriberIdTlv::new_imsi("310010123456789");
    assert!(matches!(sub_imsi.id_type, SubscriberIdType::Imsi));

    let sub_bytes = sub_imsi.serialize();
    let parsed_sub = SubscriberIdTlv::parse(&sub_bytes).unwrap();
    assert_eq!(parsed_sub.subscriber_id, "310010123456789");

    // Subscriber ID TLV (MSISDN)
    let sub_msisdn = SubscriberIdTlv::new_msisdn("+14155551234");
    let msisdn_tlv = sub_msisdn.to_nsh_tlv();
    assert!(!msisdn_tlv.critical); // Subscriber ID is not critical
}

#[test]
fn test_extended_transit_engine_multi_hop_telemetry_insertion() {
    // Create an NSH MD2 packet on SPI 100, SI 5
    let header = NshMd2Header::new(100, 5, NSH_NP_IPV4);
    let mut pkt = NshMd2Packet::new(header, vec![0xAA; 20]);

    assert!(pkt.header.tlvs.is_empty());

    // Transit node 1 inserts IOAM telemetry
    let mut node1 = NshMd2ExtendedTransitEngine::new(0x0001);
    node1.insert_ioam_telemetry(&mut pkt, 1, 2, 150, 4096);
    assert_eq!(pkt.header.tlvs.len(), 1);
    assert_eq!(node1.hops_processed, 1);

    // Transit node 2 inserts IOAM + ECN (queue at 90%)
    let mut node2 = NshMd2ExtendedTransitEngine::new(0x0002);
    node2.insert_ioam_telemetry(&mut pkt, 3, 4, 320, 16384);
    let congested = node2.insert_ecn_if_congested(&mut pkt, 90, 75);
    assert!(congested);
    assert_eq!(pkt.header.tlvs.len(), 3); // 2 IOAM + 1 ECN
    assert_eq!(node2.congestion_notifications_inserted, 1);

    // Transit node 3 inserts IOAM but no ECN (queue at 40%)
    let mut node3 = NshMd2ExtendedTransitEngine::new(0x0003);
    node3.insert_ioam_telemetry(&mut pkt, 5, 6, 85, 2048);
    let not_congested = node3.insert_ecn_if_congested(&mut pkt, 40, 75);
    assert!(!not_congested);
    assert_eq!(pkt.header.tlvs.len(), 4); // 3 IOAM + 1 ECN

    // Attach subscriber identity
    let subscriber = SubscriberIdTlv::new_imsi("310010987654321");
    node3.attach_subscriber_id(&mut pkt, &subscriber);
    assert_eq!(pkt.header.tlvs.len(), 5);

    // Serialize and re-parse the full packet
    let wire = pkt.encode();
    let decoded = NshMd2Packet::decode(&wire).unwrap();
    assert_eq!(decoded.header.service_path_id, 100);
    assert_eq!(decoded.header.tlvs.len(), 5);
    assert_eq!(decoded.payload.len(), 20);
}

#[test]
fn test_sfc_telemetry_collector_aggregate_stats() {
    let mut collector = SfcTelemetryCollector::new();

    // Simulate 3 flows on SPI 200 with varying hop telemetry
    for flow in 0..3 {
        let header = NshMd2Header::new(200, 3, NSH_NP_IPV4);
        let mut pkt = NshMd2Packet::new(header, vec![]);

        // Insert 2 hops per flow
        let mut node1 = NshMd2ExtendedTransitEngine::new(0x0001);
        node1.insert_ioam_telemetry(&mut pkt, 1, 2, 100 + flow * 20, 4096);

        let mut node2 = NshMd2ExtendedTransitEngine::new(0x0002);
        node2.insert_ioam_telemetry(&mut pkt, 3, 4, 200 + flow * 30, 8192 + flow * 1000);

        // Add ECN on last flow only
        if flow == 2 {
            node2.insert_ecn_if_congested(&mut pkt, 92, 75);
        }

        collector.collect_from_packet(&pkt);
    }

    assert_eq!(collector.total_flows_collected, 3);

    let stats = collector.path_stats.get(&200).unwrap();
    assert_eq!(stats.total_flows_observed, 3);
    assert_eq!(stats.total_hop_records, 6); // 2 hops × 3 flows
    assert_eq!(stats.congestion_events, 1); // Only last flow had ECN

    // Max single hop delay: 200 + 2*30 = 260 µs
    assert_eq!(stats.max_single_hop_delay_us, 260);

    // Average hop delay should be the mean of all 6 hop delays
    let avg = collector.average_hop_delay_us(200).unwrap();
    // Delays: 100, 200, 120, 230, 140, 260 → sum=1050, avg=175.0
    assert!((avg - 175.0).abs() < 0.01);

    // Non-existent SPI returns None
    assert!(collector.average_hop_delay_us(999).is_none());
}
