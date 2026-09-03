use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::srv6_mup_handover::{
    MupHandoverCommand, MupHandoverEngine, MupHandoverEvent, MupSessionState,
};

#[test]
fn test_srv6_mup_handover_end_to_end_orchestration() {
    let mut engine = MupHandoverEngine::new(100);

    let ue_ip = Ipv4Address::new(10, 100, 5, 20);
    let src_gnb = Ipv4Address::new(172, 16, 1, 10);
    let tgt_gnb = Ipv4Address::new(172, 16, 2, 20);
    let src_mup_sid =
        Ipv6Address::from_bytes([0xfd, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11]);
    let tgt_mup_sid =
        Ipv6Address::from_bytes([0xfd, 0x00, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22]);

    // Initialize session
    assert!(
        engine
            .create_session(500, ue_ip, src_gnb, 1050, src_mup_sid, 5)
            .is_ok()
    );

    let sess = engine.sessions.get(&500).unwrap();
    assert_eq!(sess.state, MupSessionState::Active);

    // Prepare
    let prep_ev = engine.prepare_handover(500);
    assert_eq!(prep_ev, MupHandoverEvent::Prepared { session_id: 500 });

    // Execute
    let cmd = MupHandoverCommand {
        session_id: 500,
        target_gnb_ip: tgt_gnb,
        target_teid: 2050,
        target_mup_sid: tgt_mup_sid,
    };
    let exec_ev = engine.execute_handover(cmd.clone());
    assert_eq!(
        exec_ev,
        MupHandoverEvent::Executing {
            session_id: 500,
            target_sid: tgt_mup_sid,
        }
    );

    // Packets queued during transition
    for i in 0..5 {
        let payload = format!("GTP_U_PACKET_{}", i).into_bytes();
        let res = engine.handle_packet(500, true, payload).unwrap();
        assert_eq!(res, None);
    }

    // Complete transition
    let (comp_ev, buffered) = engine.complete_handover(cmd);
    match comp_ev {
        MupHandoverEvent::Completed {
            session_id,
            flushed_packets,
        } => {
            assert_eq!(session_id, 500);
            assert_eq!(flushed_packets, 5);
        }
        other => panic!("Unexpected handover completion event: {:?}", other),
    }

    assert_eq!(buffered.len(), 5);
    for (i, pkt) in buffered.iter().enumerate() {
        assert_eq!(pkt.payload, format!("GTP_U_PACKET_{}", i).into_bytes());
    }

    // Release session
    let rel_ev = engine.release_session(500);
    assert_eq!(rel_ev, MupHandoverEvent::Released { session_id: 500 });
    assert!(engine.sessions.get(&500).is_none());
}
