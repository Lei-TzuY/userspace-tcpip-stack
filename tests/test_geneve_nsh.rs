//! Integration tests for Geneve Network Service Header (NSH) SFC Option Co-existence (RFC 8926 / RFC 8300).

use toy_tcpip::geneve_nsh::{
    GENEVE_OPT_CLASS_NSH, GENEVE_OPT_TYPE_NSH_MD1, NshMd1Header, NshMdType1Context, NshNextProto,
    SffEngine, SffForwardAction, SffHopTarget,
};

#[test]
fn test_geneve_nsh_option_constants_and_encap() {
    assert_eq!(GENEVE_OPT_CLASS_NSH, 0x0104);
    assert_eq!(GENEVE_OPT_TYPE_NSH_MD1, 0x01);

    let ctx = NshMdType1Context::new(0x11112222, 0x33334444, 0x55556666, 0x77778888);
    let nsh = NshMd1Header::new(8888, 10, NshNextProto::Ipv6, ctx);

    let opt = nsh.to_geneve_option();
    assert_eq!(opt.class, 0x0104);
    assert_eq!(opt.opt_type, 0x01);

    let parsed = NshMd1Header::from_geneve_option(&opt).unwrap();
    assert_eq!(parsed.spi, 8888);
    assert_eq!(parsed.si, 10);
    assert_eq!(parsed.next_proto, NshNextProto::Ipv6);
    assert_eq!(parsed.context.c1_platform_context, 0x11112222);
    assert_eq!(parsed.context.c4_service_id_context, 0x77778888);
}

#[test]
fn test_geneve_nsh_multi_sff_service_chain_steering() {
    let mut sff1 = SffEngine::new();
    let mut sff2 = SffEngine::new();

    let spi = 777;

    // SFF 1 (Ingress Forwarder):
    // Hop 10 -> Local Firewall
    sff1.add_hop(
        spi,
        10,
        SffHopTarget::LocalSf {
            sf_name: "Firewall_VNF".to_string(),
        },
    );
    // Hop 9 -> Next SFF across Geneve VNI 9000
    sff1.add_hop(spi, 9, SffHopTarget::NextSff { next_vni: 9000 });

    // SFF 2 (Egress Forwarder):
    // Hop 8 -> Local Load Balancer
    sff2.add_hop(
        spi,
        8,
        SffHopTarget::LocalSf {
            sf_name: "LB_VNF".to_string(),
        },
    );
    // Hop 7 -> Egress to destination
    sff2.add_hop(spi, 7, SffHopTarget::Egress);

    let ctx = NshMdType1Context::new(100, 200, 300, 400);
    let mut nsh = NshMd1Header::new(spi, 10, NshNextProto::Ethernet, ctx);

    // 1. SFF 1 receives packet with SI=10
    let act1 = sff1.process_nsh(nsh.clone());
    match act1 {
        SffForwardAction::ForwardToSf {
            sf_instance,
            updated_nsh,
            ..
        } => {
            assert_eq!(sf_instance, "Firewall_VNF");
            assert_eq!(updated_nsh.si, 9);
            nsh = updated_nsh;
        }
        other => panic!("Expected ForwardToSf at Hop 10, got {:?}", other),
    }

    // 2. Firewall returns packet with SI=9 to SFF 1 -> tunnels to SFF 2
    let act2 = sff1.process_nsh(nsh.clone());
    match act2 {
        SffForwardAction::ForwardNextSff {
            next_sff_tunnel,
            updated_nsh,
            ..
        } => {
            assert_eq!(next_sff_tunnel, 9000);
            assert_eq!(updated_nsh.si, 8);
            nsh = updated_nsh;
        }
        other => panic!("Expected ForwardNextSff at Hop 9, got {:?}", other),
    }

    // 3. SFF 2 receives tunnel packet with SI=8 -> local LB
    let act3 = sff2.process_nsh(nsh.clone());
    match act3 {
        SffForwardAction::ForwardToSf {
            sf_instance,
            updated_nsh,
            ..
        } => {
            assert_eq!(sf_instance, "LB_VNF");
            assert_eq!(updated_nsh.si, 7);
            nsh = updated_nsh;
        }
        other => panic!("Expected ForwardToSf at Hop 8, got {:?}", other),
    }

    // 4. LB returns packet with SI=7 to SFF 2 -> Egress decapsulation
    let act4 = sff2.process_nsh(nsh);
    match act4 {
        SffForwardAction::ChainEgress { next_proto, c1, c2 } => {
            assert_eq!(next_proto, NshNextProto::Ethernet);
            assert_eq!(c1, 100);
            assert_eq!(c2, 200);
        }
        other => panic!("Expected ChainEgress at Hop 7, got {:?}", other),
    }
}
