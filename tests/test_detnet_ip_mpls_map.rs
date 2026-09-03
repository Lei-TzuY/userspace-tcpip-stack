use toy_tcpip::detnet_ip_mpls_map::{
    DetNetFLabelPath, DetNetIpFlowKey, DetNetIpMplsEgressResult, DetNetIpMplsEngine,
    DetNetIpMplsFlowProfile, DetNetIpMplsIngressResult,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_detnet_ip_to_mpls_mapping_full_pipeline() {
    let mut engine = DetNetIpMplsEngine::new();

    let key = DetNetIpFlowKey {
        src_ip: Ipv4Address::new(10, 1, 1, 100),
        dst_ip: Ipv4Address::new(10, 2, 2, 200),
        protocol: 17, // UDP
        src_port: 9001,
        dst_port: 9002,
    };

    let profile = DetNetIpMplsFlowProfile {
        flow_id: 1001,
        flow_key: key,
        s_label: 8888,
        s_tc: 6, // High priority Traffic Class
        f_paths: vec![
            DetNetFLabelPath {
                f_label: 10001,
                traffic_class: 6,
                ttl: 128,
                out_if: "spine1-eth0".to_string(),
            },
            DetNetFLabelPath {
                f_label: 10002,
                traffic_class: 6,
                ttl: 128,
                out_if: "spine2-eth0".to_string(),
            },
        ],
    };

    engine.register_profile(profile);

    // Construct valid IPv4 UDP Packet
    let mut ip_pkt = vec![
        0x45, 0x00, 0x00, 0x22, // Version/IHL, DSCP/ECN, Length
        0x00, 0x01, 0x00, 0x00, // ID, Flags/FragOffset
        0x40, 0x11, 0x00, 0x00, // TTL=64, Protocol=UDP (17), Checksum
        10, 1, 1, 100, // Src IP
        10, 2, 2, 200, // Dst IP
    ];
    ip_pkt.extend_from_slice(&9001u16.to_be_bytes()); // Src Port
    ip_pkt.extend_from_slice(&9002u16.to_be_bytes()); // Dst Port
    ip_pkt.extend_from_slice(&14u16.to_be_bytes()); // UDP Len (8 + 6 payload)
    ip_pkt.extend_from_slice(&[0x00, 0x00]); // UDP Checksum
    ip_pkt.extend_from_slice(b"DETNET");

    // Packet 1 Ingress
    let res1 = engine.ingress_encap(&ip_pkt);
    let frames1 = match res1 {
        DetNetIpMplsIngressResult::Replicated {
            flow_id,
            seq,
            mpls_packets,
        } => {
            assert_eq!(flow_id, 1001);
            assert_eq!(seq, 0);
            assert_eq!(mpls_packets.len(), 2);
            mpls_packets
        }
        other => panic!("Unexpected ingress result: {:?}", other),
    };

    // Egress delivery: Path 1 arrives first
    let egress1_path1 = engine.egress_decap(&frames1[0].1);
    match egress1_path1 {
        DetNetIpMplsEgressResult::AcceptedUnique {
            s_label,
            seq,
            ip_packet,
        } => {
            assert_eq!(s_label, 8888);
            assert_eq!(seq, 0);
            assert_eq!(ip_packet, ip_pkt);
        }
        other => panic!("Expected unique acceptance, got {:?}", other),
    }

    // Egress delivery: Path 2 arrives second (eliminated)
    let egress1_path2 = engine.egress_decap(&frames1[1].1);
    match egress1_path2 {
        DetNetIpMplsEgressResult::DuplicateDropped { s_label, seq } => {
            assert_eq!(s_label, 8888);
            assert_eq!(seq, 0);
        }
        other => panic!("Expected duplicate drop, got {:?}", other),
    }

    // Packet 2 Ingress (Sequence increments)
    let res2 = engine.ingress_encap(&ip_pkt);
    let frames2 = match res2 {
        DetNetIpMplsIngressResult::Replicated {
            flow_id,
            seq,
            mpls_packets,
        } => {
            assert_eq!(flow_id, 1001);
            assert_eq!(seq, 1);
            mpls_packets
        }
        other => panic!("Unexpected ingress result: {:?}", other),
    };

    // Packet 2 Egress delivery
    let egress2_path1 = engine.egress_decap(&frames2[0].1);
    match egress2_path1 {
        DetNetIpMplsEgressResult::AcceptedUnique {
            s_label,
            seq,
            ip_packet,
        } => {
            assert_eq!(s_label, 8888);
            assert_eq!(seq, 1);
            assert_eq!(ip_packet, ip_pkt);
        }
        other => panic!("Expected unique acceptance for seq 1, got {:?}", other),
    }
}
