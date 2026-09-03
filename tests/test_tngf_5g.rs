//! Integration tests for 3GPP TS 23.501 / TS 23.502 / TS 24.502 5G TNGF (Trusted Non-3GPP Gateway Function).

use toy_tcpip::tngf_5g::*;

// ---------------------------------------------------------------------------
// 1. Trusted Wi-Fi 6 Attachment and GRE-to-GTP-U Forwarding Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_tngf_trusted_wifi_attachment_and_gre_forwarding_happy_path() {
    let mut tngf = TngfEngine::new("tngf-tokyo-hotspot-01");

    let tnap = TnapInfo {
        tnap_id: "ap-haneda-gate12".to_string(),
        ssid: "Operator-5G-Passpoint".to_string(),
        bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        access_type: TrustedAccessType::CarrierWifiPasspoint,
    };

    let supi = "imsi-208950000000001";
    let mock_nas_reg_req = b"EAP-5G Initial NAS Registration";

    // Step 1: UE attaches to Wi-Fi 6 AP & sends EAP-5G message
    let sess_id = tngf.initiate_eap5g_access(supi, tnap, mock_nas_reg_req);
    let s1 = tngf.sessions.get(&sess_id).unwrap();
    assert_eq!(s1.state, TngfSessionState::AuthenticatingEap5g);
    assert_eq!(s1.supi, supi);

    // Step 2: AMF confirms N2 Registration
    tngf.confirm_amf_registration(&sess_id, 7777).unwrap();
    assert_eq!(
        tngf.sessions.get(&sess_id).unwrap().state,
        TngfSessionState::AuthenticatedNasRegistered
    );

    // Step 3: Establish PDU Session (QFI = 5)
    let upf_teid = 0x55AA1122;
    let gre_key = tngf.establish_pdu_session(&sess_id, upf_teid, 5).unwrap();
    assert_eq!(
        tngf.sessions.get(&sess_id).unwrap().state,
        TngfSessionState::GreSessionActive
    );
    assert_eq!(
        tngf.sessions.get(&sess_id).unwrap().upf_teid,
        Some(upf_teid)
    );

    // Step 4: UE encapsulates user payload into lightweight RFC 2890 GRE packet
    let user_payload = b"High-Speed Wi-Fi 6 Video Stream";
    let gre_frame = tngf
        .encapsulate_user_packet_to_gre(&sess_id, user_payload)
        .unwrap();

    // Verify GRE header: Key present (0x20), Protocol IPv4 (0x0800), 32-bit GRE key
    assert_eq!(gre_frame[0], 0x20);
    assert_eq!(gre_frame[1], 0x00);
    assert_eq!(gre_frame[2], 0x08);
    assert_eq!(gre_frame[3], 0x00);
    let parsed_key = u32::from_be_bytes([gre_frame[4], gre_frame[5], gre_frame[6], gre_frame[7]]);
    assert_eq!(parsed_key, gre_key);
    assert_eq!(&gre_frame[8..], user_payload);

    // Step 5: TNGF translates inbound GRE frame into N3 GTP-U packet towards UPF
    let gtpu_frame = tngf.forward_gre_to_n3_gtpu(&gre_frame).unwrap();

    // Verify GTP-U: v1 G-PDU (0x30, 0xFF), UPF TEID, payload intact
    assert_eq!(gtpu_frame[0], 0x30);
    assert_eq!(gtpu_frame[1], 0xFF);
    let teid = u32::from_be_bytes([gtpu_frame[4], gtpu_frame[5], gtpu_frame[6], gtpu_frame[7]]);
    assert_eq!(teid, upf_teid);
    assert_eq!(&gtpu_frame[8..], user_payload);
}

// ---------------------------------------------------------------------------
// 2. Invalid Session State Transitions
// ---------------------------------------------------------------------------

#[test]
fn test_tngf_invalid_session_state_transitions() {
    let mut tngf = TngfEngine::new("tngf-core-02");

    let tnap = TnapInfo {
        tnap_id: "ap-campus-01".to_string(),
        ssid: "Enterprise-5G".to_string(),
        bssid: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        access_type: TrustedAccessType::EnterpriseWpa3,
    };

    let sess_id = tngf.initiate_eap5g_access("user-test", tnap, b"nas");

    // Attempting PDU establishment before AMF confirmation must fail
    let err1 = tngf.establish_pdu_session(&sess_id, 0x1111, 1);
    assert_eq!(
        err1,
        Err(TngfError::InvalidSessionState(
            "Session must be AuthenticatedNasRegistered before PDU session setup"
        ))
    );

    // Attempting GRE encapsulation before PDU session active must fail
    let err2 = tngf.encapsulate_user_packet_to_gre(&sess_id, b"data");
    assert_eq!(
        err2,
        Err(TngfError::InvalidSessionState("GRE session is not active"))
    );
}

// ---------------------------------------------------------------------------
// 3. Corrupt GRE Packet Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_tngf_corrupt_gre_packet_rejection() {
    let tngf = TngfEngine::new("tngf-core-03");

    // Short packet (< 8 bytes)
    let err1 = tngf.forward_gre_to_n3_gtpu(&[0x20, 0x00, 0x08]);
    assert_eq!(
        err1,
        Err(TngfError::InvalidGrePacket("GRE frame is too short"))
    );

    // Missing Key flag (bit 2 is 0)
    let bad_flags_pkt = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF];
    let err2 = tngf.forward_gre_to_n3_gtpu(&bad_flags_pkt);
    assert_eq!(
        err2,
        Err(TngfError::InvalidGrePacket("GRE Key flag missing"))
    );
}

// ---------------------------------------------------------------------------
// 4. Unknown GRE Key Handling
// ---------------------------------------------------------------------------

#[test]
fn test_tngf_unknown_gre_key_handling() {
    let tngf = TngfEngine::new("tngf-core-04");

    // GRE key 0x99999999 has no matching session
    let pkt = [0x20, 0x00, 0x08, 0x00, 0x99, 0x99, 0x99, 0x99, 0xDE, 0xAD];
    let err = tngf.forward_gre_to_n3_gtpu(&pkt);
    assert_eq!(err, Err(TngfError::SessionNotFound));
}

// ---------------------------------------------------------------------------
// 5. Session Termination Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_tngf_session_termination_lifecycle() {
    let mut tngf = TngfEngine::new("tngf-core-05");

    let tnap = TnapInfo {
        tnap_id: "ap-term".to_string(),
        ssid: "Wifi-5G".to_string(),
        bssid: [0x11; 6],
        access_type: TrustedAccessType::CarrierWifiPasspoint,
    };

    let sess_id = tngf.initiate_eap5g_access("user-term", tnap, b"nas");
    let gre_key = tngf.sessions.get(&sess_id).unwrap().gre_key;
    assert!(tngf.gre_key_to_session.contains_key(&gre_key));

    // Terminate session
    tngf.terminate_session(&sess_id)
        .expect("Termination failed");
    assert!(!tngf.sessions.contains_key(&sess_id));
    assert!(!tngf.gre_key_to_session.contains_key(&gre_key));

    // Second termination returns error
    let err = tngf.terminate_session(&sess_id);
    assert_eq!(err, Err(TngfError::SessionNotFound));
}
