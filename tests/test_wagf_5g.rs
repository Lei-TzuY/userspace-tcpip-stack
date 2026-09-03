//! Integration tests for 3GPP TS 23.316 / BBF TR-456 5G W-AGF (Wireline Access Gateway Function).

use toy_tcpip::wagf_5g::*;

// ---------------------------------------------------------------------------
// 1. Session Establishment and N3 GTP-U Encapsulation Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_wagf_session_establishment_and_n3_encapsulation_happy_path() {
    let mut wagf = WagfEngine::new("wagf-tokyo-bng-01");

    let line = GlobalLineId {
        operator_id: [0x46, 0x69, 0x01], // BBF Operator ID
        circuit_id: "ont-slot1-pon2-chiyoda".to_string(),
        s_vlan: 100,
        c_vlan: 200,
    };

    let supi = "fixed-sub-001@operator.com";

    // Step 1: Line Discovery (GPON optical carrier detected)
    let sess_id = wagf.register_line_discovery(RgType::Rg5G, line, supi);
    let sess = wagf.sessions.get(&sess_id).unwrap();
    assert_eq!(sess.state, WirelineSessionState::LineDiscovered);
    assert_eq!(sess.supi, supi);

    // Step 2: AMF confirms N2 Registration
    wagf.confirm_amf_registration(&sess_id, 8888).unwrap();
    assert_eq!(
        wagf.sessions.get(&sess_id).unwrap().state,
        WirelineSessionState::NasRegistered
    );

    // Step 3: PDU Session established for Fixed VoIP (CoS = 6 -> 5QI = 1)
    let upf_teid = 0xABCDEF01;
    wagf.complete_pdu_session_setup(&sess_id, upf_teid, 6)
        .unwrap();
    let pdu_sess = wagf.sessions.get(&sess_id).unwrap();
    assert_eq!(pdu_sess.state, WirelineSessionState::PduActive);
    assert_eq!(pdu_sess.active_5qi, 1);
    assert_eq!(pdu_sess.active_qfi, 3);

    // Step 4: Encapsulate Fixed Voice Frame into N3 GTP-U
    let voice_packet = b"RTP Voice Data Payload";
    let gtp_frame = wagf
        .encapsulate_fixed_to_n3(&sess_id, voice_packet)
        .unwrap();

    assert_eq!(gtp_frame[0], 0x30); // GTP-U v1
    assert_eq!(gtp_frame[1], 0xFF); // G-PDU
    let teid = u32::from_be_bytes([gtp_frame[4], gtp_frame[5], gtp_frame[6], gtp_frame[7]]);
    assert_eq!(teid, upf_teid);
    assert_eq!(&gtp_frame[8..], voice_packet);
}

// ---------------------------------------------------------------------------
// 2. QoS Mapping for IPTV and Best-Effort Internet
// ---------------------------------------------------------------------------

#[test]
fn test_wagf_qos_mapping_iptv_and_best_effort() {
    let mut wagf = WagfEngine::new("wagf-osaka-02");

    let line1 = GlobalLineId {
        operator_id: [0x01, 0x02, 0x03],
        circuit_id: "ont-iptv-line".to_string(),
        s_vlan: 300,
        c_vlan: 400,
    };
    let s1 = wagf.register_line_discovery(RgType::FnRg, line1, "iptv-user");
    wagf.confirm_amf_registration(&s1, 101).unwrap();
    wagf.complete_pdu_session_setup(&s1, 0x1111, 4).unwrap(); // CoS 4 -> 5QI 75 (Managed Video)
    assert_eq!(wagf.sessions.get(&s1).unwrap().active_5qi, 75);

    let line2 = GlobalLineId {
        operator_id: [0x01, 0x02, 0x03],
        circuit_id: "ont-internet-line".to_string(),
        s_vlan: 500,
        c_vlan: 600,
    };
    let s2 = wagf.register_line_discovery(RgType::FnRg, line2, "internet-user");
    wagf.confirm_amf_registration(&s2, 102).unwrap();
    wagf.complete_pdu_session_setup(&s2, 0x2222, 0).unwrap(); // CoS 0 -> 5QI 9 (Best Effort Internet)
    assert_eq!(wagf.sessions.get(&s2).unwrap().active_5qi, 9);
}

// ---------------------------------------------------------------------------
// 3. Invalid Session State Transitions
// ---------------------------------------------------------------------------

#[test]
fn test_wagf_invalid_session_state_transitions() {
    let mut wagf = WagfEngine::new("wagf-core-03");

    let line = GlobalLineId {
        operator_id: [0x00, 0x00, 0x01],
        circuit_id: "ont-err".to_string(),
        s_vlan: 10,
        c_vlan: 20,
    };
    let s = wagf.register_line_discovery(RgType::Rg5G, line, "user-err");

    // Attempting PDU setup before AMF confirmation must fail
    let err1 = wagf.complete_pdu_session_setup(&s, 0x9999, 0);
    assert_eq!(
        err1,
        Err(WagfError::InvalidSessionState(
            "Session must be NasRegistered before establishing PDU session"
        ))
    );

    // Attempting N3 encapsulation before PDU active must fail
    let err2 = wagf.encapsulate_fixed_to_n3(&s, b"test");
    assert_eq!(
        err2,
        Err(WagfError::InvalidSessionState("PDU session is not active"))
    );
}

// ---------------------------------------------------------------------------
// 4. Unknown QoS Mapping Handling
// ---------------------------------------------------------------------------

#[test]
fn test_wagf_unknown_qos_mapping() {
    let mut wagf = WagfEngine::new("wagf-core-04");

    let line = GlobalLineId {
        operator_id: [0x00, 0x00, 0x02],
        circuit_id: "ont-qos-err".to_string(),
        s_vlan: 10,
        c_vlan: 20,
    };
    let s = wagf.register_line_discovery(RgType::Rg5G, line, "user-qos");
    wagf.confirm_amf_registration(&s, 555).unwrap();

    // CoS 7 has no mapped QoS rule
    let err = wagf.complete_pdu_session_setup(&s, 0x8888, 7);
    assert_eq!(err, Err(WagfError::QosMappingNotFound));
}

// ---------------------------------------------------------------------------
// 5. Session Termination Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_wagf_session_termination() {
    let mut wagf = WagfEngine::new("wagf-core-05");

    let line = GlobalLineId {
        operator_id: [0x00, 0x00, 0x05],
        circuit_id: "ont-disconnect".to_string(),
        s_vlan: 100,
        c_vlan: 200,
    };
    let s = wagf.register_line_discovery(RgType::Rg5G, line.clone(), "user-bye");
    assert!(wagf.sessions.contains_key(&s));
    assert!(wagf.line_to_session.contains_key(&line));

    wagf.terminate_line_session(&s).expect("Termination failed");
    assert!(!wagf.sessions.contains_key(&s));
    assert!(!wagf.line_to_session.contains_key(&line));

    // Terminating again should fail
    let err = wagf.terminate_line_session(&s);
    assert_eq!(err, Err(WagfError::SessionNotFound));
}
