//! Integration tests for Deterministic IP DetNet-to-TSN Sub-Network Mapping (RFC 9024 / RFC 9025).

use toy_tcpip::detnet_tsn::{
    DetNetIpFlowKey, DetNetRTagHeader, DetNetTsnForwardResult, DetNetTsnGateway,
    ETHERTYPE_DETNET_8021Q, ETHERTYPE_DETNET_RTAG, TsnStreamId, TsnStreamProfile,
};
use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_detnet_tsn_constants_and_rtag_framing() {
    assert_eq!(ETHERTYPE_DETNET_RTAG, 0xF1C1);
    assert_eq!(ETHERTYPE_DETNET_8021Q, 0x8100);

    let rtag = DetNetRTagHeader::new(0xABCD);
    let ser = rtag.serialize();
    assert_eq!(ser[0..2], [0xF1, 0xC1]);
    assert_eq!(ser[2..4], [0x00, 0x00]);
    assert_eq!(ser[4..6], [0xAB, 0xCD]);

    let parsed = DetNetRTagHeader::parse(&ser).unwrap();
    assert_eq!(parsed.sequence_number, 0xABCD);
}

#[test]
fn test_detnet_tsn_end_to_end_gateway_pipeline() {
    let mut gw = DetNetTsnGateway::new();

    let flow_industrial = DetNetIpFlowKey {
        src_ip: Ipv4Address::new(192, 168, 100, 10),
        dst_ip: Ipv4Address::new(192, 168, 200, 20),
        src_port: 4840, // OPC UA
        dst_port: 4840,
        protocol: 6, // TCP
        dscp: 46,    // EF
    };

    let stream_id = TsnStreamId::new(MacAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]), 42);
    let profile = TsnStreamProfile {
        stream_id,
        src_mac: MacAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
        dst_mac: MacAddress([0x00, 0x50, 0x56, 0x11, 0x22, 0x33]),
        vlan_id: 300,
        pcp: 7,
        queue_id: 7, // Highest priority TAS scheduled queue
    };

    gw.register_flow_mapping(flow_industrial, profile);

    // Build DetNet IPv4 Packet
    let mut ip_pkt = vec![0x45, (46 << 2), 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
    ip_pkt.extend_from_slice(&[192, 168, 100, 10]);
    ip_pkt.extend_from_slice(&[192, 168, 200, 20]);
    ip_pkt.extend_from_slice(&4840u16.to_be_bytes());
    ip_pkt.extend_from_slice(&4840u16.to_be_bytes());
    ip_pkt.extend_from_slice(&[0; 16]); // TCP header remainder
    ip_pkt.extend_from_slice(b"DeterministicPayload");

    // 1. Ingress DetNet IP -> TSN Ethernet Frame
    let encap = gw.encapsulate_ip_to_tsn(&ip_pkt);
    let tsn_frame = match encap {
        DetNetTsnForwardResult::EncapsulatedTsnFrame {
            vlan_id,
            pcp,
            queue_id,
            frame,
            ..
        } => {
            assert_eq!(vlan_id, 300);
            assert_eq!(pcp, 7);
            assert_eq!(queue_id, 7);
            frame
        }
        other => panic!("Expected EncapsulatedTsnFrame, got {:?}", other),
    };

    // 2. Egress TSN Frame -> DetNet IP Packet
    let decap1 = gw.decapsulate_tsn_to_ip(stream_id, &tsn_frame);
    match decap1 {
        DetNetTsnForwardResult::DecapsulatedIpPacket { packet, .. } => {
            assert_eq!(packet, ip_pkt);
        }
        other => panic!("Expected DecapsulatedIpPacket, got {:?}", other),
    }

    // 3. Egress Duplicate Elimination (FRER duplicate rejection)
    let decap2 = gw.decapsulate_tsn_to_ip(stream_id, &tsn_frame);
    match decap2 {
        DetNetTsnForwardResult::DuplicateDropped { seq, .. } => {
            assert_eq!(seq, 0);
        }
        other => panic!("Expected DuplicateDropped, got {:?}", other),
    }
}
