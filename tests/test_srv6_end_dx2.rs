use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::srv6::Srv6Header;
use toy_tcpip::srv6_end_dx2::{
    Srv6EndDx2Binding, Srv6EndDx2Engine, Srv6EndDx2ForwardResult, Srv6VlanRewriteAction,
};

#[test]
fn test_srv6_end_dx2_pop_push_normalize_pipeline() {
    let mut engine = Srv6EndDx2Engine::new();

    let sid_pop = Ipv6Address::from_bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let sid_push = Ipv6Address::from_bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let sid_qinq = Ipv6Address::from_bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

    engine.register_binding(Srv6EndDx2Binding {
        sid: sid_pop,
        out_if: "port-access".to_string(),
        rewrite_action: Srv6VlanRewriteAction::PopOuterVlan,
        allowed_vlans: None,
    });

    engine.register_binding(Srv6EndDx2Binding {
        sid: sid_push,
        out_if: "port-trunk".to_string(),
        rewrite_action: Srv6VlanRewriteAction::PushVlan {
            vlan_id: 500,
            pcp: 4,
        },
        allowed_vlans: Some(vec![500]),
    });

    engine.register_binding(Srv6EndDx2Binding {
        sid: sid_qinq,
        out_if: "port-carrier".to_string(),
        rewrite_action: Srv6VlanRewriteAction::NormalizeQinQ {
            s_vlan: 1000,
            c_vlan: 200,
        },
        allowed_vlans: None,
    });

    // 1. Tagged frame in -> Popped untagged frame out
    let tagged_frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, // Src
        0x81, 0x00, // 802.1Q
        0x00, 0x64, // VLAN 100
        0x08, 0x00, // EtherType IPv4
        0x45, 0x00, 0x00, 0x20, // IPv4 payload
    ];

    let srh_complete = Srv6Header::build(41, &[sid_pop]); // Segments Left = 0

    let res_pop = engine.process_srv6_l2_decap(&sid_pop, Some(&srh_complete), &tagged_frame);
    match res_pop {
        Srv6EndDx2ForwardResult::ForwardL2 { out_if, frame } => {
            assert_eq!(out_if, "port-access");
            assert_eq!(frame.len(), tagged_frame.len() - 4);
            // EtherType should now be at offset 12
            assert_eq!(&frame[12..14], &[0x08, 0x00]);
        }
        other => panic!("Expected ForwardL2, got {:?}", other),
    }

    // 2. Untagged frame in -> Pushed VLAN 500 PCP 4 out
    let untagged_frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x20,
    ];

    let res_push = engine.process_srv6_l2_decap(&sid_push, None, &untagged_frame);
    match res_push {
        Srv6EndDx2ForwardResult::ForwardL2 { out_if, frame } => {
            assert_eq!(out_if, "port-trunk");
            assert_eq!(frame.len(), untagged_frame.len() + 4);
            assert_eq!(&frame[12..14], &[0x81, 0x00]);
            let tci = u16::from_be_bytes([frame[14], frame[15]]);
            assert_eq!(tci & 0x0FFF, 500);
            assert_eq!((tci >> 13) & 0x07, 4);
        }
        other => panic!("Expected ForwardL2, got {:?}", other),
    }

    // 3. Raw frame in -> Standardized QinQ (0x88A8 1000 + 0x8100 200) out
    let res_qinq = engine.process_srv6_l2_decap(&sid_qinq, None, &untagged_frame);
    match res_qinq {
        Srv6EndDx2ForwardResult::ForwardL2 { out_if, frame } => {
            assert_eq!(out_if, "port-carrier");
            assert_eq!(&frame[12..14], &[0x88, 0xA8]);
            assert_eq!(u16::from_be_bytes([frame[14], frame[15]]) & 0x0FFF, 1000);
            assert_eq!(&frame[16..18], &[0x81, 0x00]);
            assert_eq!(u16::from_be_bytes([frame[18], frame[19]]) & 0x0FFF, 200);
            assert_eq!(&frame[20..22], &[0x08, 0x00]);
        }
        other => panic!("Expected ForwardL2, got {:?}", other),
    }
}
