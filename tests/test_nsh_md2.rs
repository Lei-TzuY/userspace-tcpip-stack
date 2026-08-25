use toy_tcpip::nsh_md2::{
    NshContextTlv, NshMd2Header, NshMd2Packet, NshMd2SffEngine, SffForwardingAction, NSH_NP_IPV4,
    NSH_TLV_CLASS_IETF, NSH_TLV_TYPE_FLOW_HASH, NSH_TLV_TYPE_SECURITY_GROUP_TAG,
    NSH_TLV_TYPE_TENANT_ID,
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
