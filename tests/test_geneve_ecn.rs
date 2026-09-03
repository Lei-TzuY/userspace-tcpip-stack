//! Integration tests for Geneve ECN & DiffServ Tunneling (RFC 8926 / RFC 6040).

use toy_tcpip::geneve_ecn::{
    DiffServTunnelMode, EcnCodepoint, EcnDecapResult, GeneveEcnMode, GeneveEcnPipeline,
};

#[test]
fn test_geneve_ecn_codepoints() {
    assert_eq!(EcnCodepoint::NotEct.to_bits(), 0b00);
    assert_eq!(EcnCodepoint::Ect1.to_bits(), 0b01);
    assert_eq!(EcnCodepoint::Ect0.to_bits(), 0b10);
    assert_eq!(EcnCodepoint::Ce.to_bits(), 0b11);

    assert_eq!(EcnCodepoint::from_bits(0b00), EcnCodepoint::NotEct);
    assert_eq!(EcnCodepoint::from_bits(0b01), EcnCodepoint::Ect1);
    assert_eq!(EcnCodepoint::from_bits(0b10), EcnCodepoint::Ect0);
    assert_eq!(EcnCodepoint::from_bits(0b11), EcnCodepoint::Ce);
}

#[test]
fn test_geneve_ecn_tunnel_modes_and_marking() {
    let pipeline_uniform =
        GeneveEcnPipeline::new(GeneveEcnMode::Normal, DiffServTunnelMode::Uniform);

    // IPv6 Packet with DSCP CS5 (40 -> 0x28) and ECN ECT(1) (1) -> TC = (40 << 2) | 1 = 161 (0xA1)
    let mut ipv6_pkt = vec![0x60 | (0xA1 >> 4), (0xA1 << 4), 0, 0, 0, 10, 59, 64];
    ipv6_pkt.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ipv6_pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    ipv6_pkt.extend_from_slice(b"ECNTesting");

    let outer_tos = pipeline_uniform.calculate_outer_tos(&ipv6_pkt).unwrap();
    assert_eq!(outer_tos, 0xA1);

    // Decapsulation with Outer CE (0b11) -> Egress should remark IPv6 inner packet to CE
    let outer_ce_tos = (outer_tos & !0b11) | 0b11;
    let res = pipeline_uniform.decapsulate_and_combine_ecn(outer_ce_tos, ipv6_pkt);
    match res {
        EcnDecapResult::Admitted {
            final_ecn,
            final_dscp,
            inner_packet,
        } => {
            assert_eq!(final_ecn, EcnCodepoint::Ce);
            assert_eq!(final_dscp, 40);
            let tc = ((inner_packet[0] & 0x0F) << 4) | (inner_packet[1] >> 4);
            assert_eq!(tc & 0b11, 0b11);
        }
        other => panic!("Expected Admitted with CE, got {:?}", other),
    }
}
