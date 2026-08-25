use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::sr_mpls_oam::{
    RETURN_CODE_LABEL_SWITCHED_AT_STACK_DEPTH, RETURN_CODE_REPLYING_ROUTER_IS_EGRESS,
    RETURN_CODE_REPLYING_ROUTER_NO_MAPPING, SrLspEchoRequest, SrMplsOamEngine, SrTargetFecSubTlv,
};

#[test]
fn test_sr_mpls_target_fec_sub_tlvs_codec() {
    let pfx = Ipv4Address::new(10, 1, 1, 100);
    let tlv = SrTargetFecSubTlv::Ipv4PrefixSid {
        prefix: pfx,
        prefix_len: 32,
        sid_label: 16100,
        protocol: 1, // IS-IS
    };

    let wire = tlv.serialize();
    let (parsed, consumed) = SrTargetFecSubTlv::parse(&wire).expect("parse Prefix-SID Sub-TLV");
    assert_eq!(consumed, wire.len());
    assert_eq!(parsed, tlv);

    let adj_tlv = SrTargetFecSubTlv::Ipv4AdjSid {
        local_ip: Ipv4Address::new(10, 0, 0, 1),
        remote_ip: Ipv4Address::new(10, 0, 0, 2),
        sid_label: 24001,
    };
    let adj_wire = adj_tlv.serialize();
    let (parsed_adj, consumed_adj) =
        SrTargetFecSubTlv::parse(&adj_wire).expect("parse Adj-SID Sub-TLV");
    assert_eq!(consumed_adj, adj_wire.len());
    assert_eq!(parsed_adj, adj_tlv);
}

#[test]
fn test_sr_mpls_oam_lsp_ping_validation() {
    let local_router_ip = Ipv4Address::new(10, 1, 1, 1);
    let mut engine = SrMplsOamEngine::new(local_router_ip);

    // Register local Prefix SID & Remote Prefix SID
    engine.register_prefix_sid(local_router_ip, 16001);
    engine.register_prefix_sid(Ipv4Address::new(10, 1, 1, 2), 16002);
    engine.register_adj_sid(24001, local_router_ip, Ipv4Address::new(10, 1, 1, 2));

    // 1. Ping targeting local router (Egress)
    let req_egress = SrLspEchoRequest {
        sender_handle: 0x1122_3344,
        seq_number: 1,
        target_fec: SrTargetFecSubTlv::Ipv4PrefixSid {
            prefix: local_router_ip,
            prefix_len: 32,
            sid_label: 16001,
            protocol: 1,
        },
    };
    let reply_egress = engine.process_echo_request(&req_egress);
    assert_eq!(
        reply_egress.return_code,
        RETURN_CODE_REPLYING_ROUTER_IS_EGRESS
    );

    // 2. Ping targeting transit router (Label Switched)
    let req_transit = SrLspEchoRequest {
        sender_handle: 0x1122_3344,
        seq_number: 2,
        target_fec: SrTargetFecSubTlv::Ipv4PrefixSid {
            prefix: Ipv4Address::new(10, 1, 1, 2),
            prefix_len: 32,
            sid_label: 16002,
            protocol: 1,
        },
    };
    let reply_transit = engine.process_echo_request(&req_transit);
    assert_eq!(
        reply_transit.return_code,
        RETURN_CODE_LABEL_SWITCHED_AT_STACK_DEPTH
    );

    // 3. Ping with wrong SID label mapping (No Mapping)
    let req_invalid = SrLspEchoRequest {
        sender_handle: 0x1122_3344,
        seq_number: 3,
        target_fec: SrTargetFecSubTlv::Ipv4PrefixSid {
            prefix: local_router_ip,
            prefix_len: 32,
            sid_label: 99999, // Mismatched label
            protocol: 1,
        },
    };
    let reply_invalid = engine.process_echo_request(&req_invalid);
    assert_eq!(
        reply_invalid.return_code,
        RETURN_CODE_REPLYING_ROUTER_NO_MAPPING
    );
}
