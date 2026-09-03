use toy_tcpip::nsh_md2::{
    NSH_NP_IPV4, NSH_TLV_CLASS_IETF, NSH_TLV_TYPE_FLOW_HASH, NSH_TLV_TYPE_SECURITY_GROUP_TAG,
    NSH_TLV_TYPE_TENANT_ID, NshContextTlv, NshMd2Header, NshMd2Packet, NshMd2SffEngine,
    SffForwardingAction,
};

#[test]
fn test_nsh_md2_context_tlv_and_header_codec() {
    let mut hdr = NshMd2Header::new(0x001234, 10, NSH_NP_IPV4);
    let tlv1 = NshContextTlv::new_tenant_id(0x55AA_1234);
    assert_eq!(tlv1.class, NSH_TLV_CLASS_IETF);
    let tlv2 = NshContextTlv::new_flow_hash(0xCAFE_BABE);
    let tlv3 = NshContextTlv::new_security_group_tag(42);

    hdr = hdr.with_tlv(tlv1);
    hdr = hdr.with_tlv(tlv2);
    hdr = hdr.with_tlv(tlv3);

    assert_eq!(hdr.service_path_id, 0x001234);
    assert_eq!(hdr.service_index, 10);
    assert_eq!(hdr.tlvs.len(), 3);

    let wire = hdr.serialize();
    let parsed_hdr = NshMd2Header::parse(&wire).expect("parse NSH MD2 header");
    assert_eq!(parsed_hdr.service_path_id, 0x001234);
    assert_eq!(parsed_hdr.service_index, 10);
    assert_eq!(parsed_hdr.tlvs.len(), 3);
    assert_eq!(parsed_hdr.tlvs[0].tlv_type, NSH_TLV_TYPE_TENANT_ID);
    assert_eq!(parsed_hdr.tlvs[1].tlv_type, NSH_TLV_TYPE_FLOW_HASH);
    assert_eq!(parsed_hdr.tlvs[2].tlv_type, NSH_TLV_TYPE_SECURITY_GROUP_TAG);

    let pkt = NshMd2Packet::new(parsed_hdr, b"Sample Encapsulated IP Payload".to_vec());
    let pkt_wire = pkt.encode();
    let parsed_pkt = NshMd2Packet::decode(&pkt_wire).expect("decode NSH MD2 packet");
    assert_eq!(parsed_pkt.payload, b"Sample Encapsulated IP Payload");
}

#[test]
fn test_nsh_md2_sfc_forwarding_and_chain_termination() {
    let mut engine = NshMd2SffEngine::new();
    let spi = 0x002001;

    engine.add_path_hop(spi, 5, 101); // Firewall SFF
    engine.add_path_hop(spi, 4, 102); // DPI SFF
    engine.add_path_hop(spi, 3, 103); // WAF SFF

    let hdr = NshMd2Header::new(spi, 5, NSH_NP_IPV4);
    let mut pkt = NshMd2Packet::new(hdr, b"HTTP GET /sensitive".to_vec());

    // Hop 1: SI 5 -> 4
    let action1 = engine.process_packet(&mut pkt);
    assert_eq!(
        action1,
        SffForwardingAction::ForwardNextHop {
            spi,
            new_si: 4,
            next_hop_node_id: 101
        }
    );
    assert_eq!(pkt.header.service_index, 4);

    // Hop 2: SI 4 -> 3
    let action2 = engine.process_packet(&mut pkt);
    assert_eq!(
        action2,
        SffForwardingAction::ForwardNextHop {
            spi,
            new_si: 3,
            next_hop_node_id: 102
        }
    );
    assert_eq!(pkt.header.service_index, 3);

    // Set SI = 1 (End of chain)
    pkt.header.service_index = 1;
    let end_action = engine.process_packet(&mut pkt);
    assert_eq!(
        end_action,
        SffForwardingAction::EndChain {
            inner_protocol: NSH_NP_IPV4
        }
    );
}

#[test]
fn test_nsh_md2_critical_tlv_enforcement() {
    let engine = NshMd2SffEngine::new();
    let spi = 0x003001;

    // Build packet with an unknown vendor critical TLV (Class 0xF000, Type 0x99, Critical = true)
    let unknown_critical_tlv = NshContextTlv::new(0xF000, 0x99, true, vec![1, 2, 3, 4]);
    let hdr = NshMd2Header::new(spi, 5, NSH_NP_IPV4).with_tlv(unknown_critical_tlv);
    let mut pkt = NshMd2Packet::new(hdr, b"Encapsulated Data".to_vec());

    // SFF must drop packet because critical TLV is unsupported (RFC 8300 Section 3.5.2)
    let action = engine.process_packet(&mut pkt);
    assert_eq!(
        action,
        SffForwardingAction::DropUnsupportedCriticalTlv {
            class: 0xF000,
            tlv_type: 0x99
        }
    );

    // If an unknown TLV has critical = false, SFF ignores it and forwards
    let non_critical_unknown = NshContextTlv::new(0xF000, 0x99, false, vec![1, 2, 3, 4]);
    let hdr2 = NshMd2Header::new(spi, 5, NSH_NP_IPV4).with_tlv(non_critical_unknown);
    let mut pkt2 = NshMd2Packet::new(hdr2, b"Encapsulated Data".to_vec());

    let action2 = engine.process_packet(&mut pkt2);
    assert!(matches!(
        action2,
        SffForwardingAction::ForwardNextHop { .. }
    ));
}

#[test]
fn test_nsh_md2_security_group_acl_and_metadata_extraction() {
    use toy_tcpip::nsh_md2::NshMetadataExtractor;

    let mut engine = NshMd2SffEngine::new();
    let spi = 0x004001;

    // Deny tenant 1000 with security group 99
    engine.set_security_group_allowed(1000, 99, false);
    // Allow tenant 1000 with security group 10
    engine.set_security_group_allowed(1000, 10, true);

    let tlv_tenant = NshContextTlv::new_tenant_id(1000);
    let tlv_secgroup_denied = NshContextTlv::new_security_group_tag(99);
    let tlv_flow = NshContextTlv::new_flow_hash(0x1234_5678);

    let hdr = NshMd2Header::new(spi, 5, NSH_NP_IPV4)
        .with_tlv(tlv_tenant)
        .with_tlv(tlv_secgroup_denied)
        .with_tlv(tlv_flow);

    assert_eq!(NshMetadataExtractor::extract_tenant_id(&hdr), Some(1000));
    assert_eq!(
        NshMetadataExtractor::extract_security_group_tag(&hdr),
        Some(99)
    );
    assert_eq!(
        NshMetadataExtractor::extract_flow_hash(&hdr),
        Some(0x1234_5678)
    );

    let mut pkt = NshMd2Packet::new(hdr, b"Payload".to_vec());

    // Should drop due to security group violation
    let action = engine.process_packet(&mut pkt);
    assert_eq!(
        action,
        SffForwardingAction::DropSecurityViolation {
            tenant_id: 1000,
            security_group: 99
        }
    );

    // Decapsulation test
    let (inner_proto, payload) = NshMetadataExtractor::decapsulate(pkt);
    assert_eq!(inner_proto, NSH_NP_IPV4);
    assert_eq!(payload, b"Payload");
}

#[test]
fn test_nsh_md2_inband_path_trace_telemetry() {
    use toy_tcpip::nsh_md2::{
        NshContextTlv, NshMd2Header, NshMd2Packet, NshMd2SffEngine, NshMetadataExtractor,
    };

    let spi = 0x005001;
    let mut sff1 = NshMd2SffEngine::new().with_local_node_id(101);
    let mut sff2 = NshMd2SffEngine::new().with_local_node_id(102);
    let mut sff3 = NshMd2SffEngine::new().with_local_node_id(103);

    sff1.add_path_hop(spi, 5, 102);
    sff2.add_path_hop(spi, 4, 103);
    sff3.add_path_hop(spi, 3, 104);

    let hdr = NshMd2Header::new(spi, 5, 0x01).with_tlv(NshContextTlv::new_inband_path_trace(&[]));
    let mut pkt = NshMd2Packet::new(hdr, b"Payload Data".to_vec());

    // Packet traverses SFF1 -> SFF2 -> SFF3
    sff1.process_packet(&mut pkt);
    assert_eq!(pkt.header.service_index, 4);

    sff2.process_packet(&mut pkt);
    assert_eq!(pkt.header.service_index, 3);

    sff3.process_packet(&mut pkt);
    assert_eq!(pkt.header.service_index, 2);

    let trace = NshMetadataExtractor::extract_inband_path_trace(&pkt.header)
        .expect("extract in-band trace");
    assert_eq!(trace, vec![101, 102, 103]);
}

#[test]
fn test_nsh_md2_classifier_engine_encapsulation() {
    use toy_tcpip::nsh_md2::{
        NSH_NP_IPV4, NshClassificationRule, NshClassifierEngine, NshMetadataExtractor,
    };

    let mut classifier = NshClassifierEngine::new();

    // Rule: Match TCP (proto 6) dst_port 80 -> SPI 0x006001, SI 10, Tenant 400, SecGroup 15
    classifier.add_rule(NshClassificationRule {
        src_ip: None,
        dst_ip: None,
        ip_proto: Some(6),
        dst_port: Some(80),
        spi: 0x006001,
        initial_si: 10,
        tenant_id: Some(400),
        security_group: Some(15),
        enable_path_trace: true,
    });

    // Mock IPv4 TCP packet to port 80
    // Header len = 20 bytes (IHL = 5), total len = 40 bytes
    let mut raw_ip = vec![0u8; 40];
    raw_ip[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
    raw_ip[9] = 6; // TCP
    raw_ip[12..16].copy_from_slice(&[10, 0, 0, 1]); // src IP
    raw_ip[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst IP
    raw_ip[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port 12345
    raw_ip[22..24].copy_from_slice(&80u16.to_be_bytes()); // dst port 80

    let nsh_pkt = classifier
        .classify_and_encapsulate(&raw_ip)
        .expect("classify HTTP packet");

    assert_eq!(nsh_pkt.header.service_path_id, 0x006001);
    assert_eq!(nsh_pkt.header.service_index, 10);
    assert_eq!(nsh_pkt.header.next_protocol, NSH_NP_IPV4);
    assert_eq!(
        NshMetadataExtractor::extract_tenant_id(&nsh_pkt.header),
        Some(400)
    );
    assert_eq!(
        NshMetadataExtractor::extract_security_group_tag(&nsh_pkt.header),
        Some(15)
    );
    assert_eq!(
        NshMetadataExtractor::extract_inband_path_trace(&nsh_pkt.header),
        Some(vec![])
    );
    assert_eq!(nsh_pkt.payload, raw_ip);

    // Mock non-matching packet (UDP port 53)
    let mut raw_udp = vec![0u8; 40];
    raw_udp[0] = 0x45;
    raw_udp[9] = 17; // UDP
    raw_udp[22..24].copy_from_slice(&53u16.to_be_bytes());
    assert!(classifier.classify_and_encapsulate(&raw_udp).is_none());
}
