//! Integration tests for 3GPP Rel-17 5G ProSe Direct Communication & UE-to-Network (U2N) Relay Protocol Engine.

use std::net::Ipv4Addr;
use toy_tcpip::prose_relay_5g::{
    DEFAULT_HEARTBEAT_TIMEOUT_S, DEFAULT_RLF_RSRP_THRESHOLD_DBM, Pc5Layer2Id, Pc5LinkState,
    Pc5QoSProfile, Pc5SecurityAlgorithm, Pc5SignalingMessage, ProSeRelayEngine, ProseRelayError,
    RSC_COMMERCIAL_INTERNET, RSC_EMERGENCY_SERVICES, RSC_PUBLIC_SAFETY_VOICE, RSC_SMART_GRID_IOT,
    RelayAnnouncement, RelayServiceCode, SrapHeader, derive_k_nrp_sess,
};

#[test]
fn test_prose_model_a_and_model_b_relay_discovery() {
    let relay_l2_id = Pc5Layer2Id::new(0x11, 0x22, 0x33);
    let remote_l2_id = Pc5Layer2Id::new(0x44, 0x55, 0x66);

    let authorized_rscs = vec![
        RelayServiceCode::new(RSC_EMERGENCY_SERVICES),
        RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE),
    ];

    let relay_engine = ProSeRelayEngine::new_relay(
        "relay-ue-01",
        relay_l2_id,
        authorized_rscs,
        Ipv4Addr::new(10, 0, 0, 1),
        0x1001,
    );
    let remote_engine = ProSeRelayEngine::new_remote("remote-ue-01", remote_l2_id);

    // --- Model A Discovery: Announcement ---
    let announcement = relay_engine
        .create_model_a_announcement(
            RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE),
            -78, // good RSRP
            1000,
        )
        .expect("Model A announcement creation should succeed");

    assert_eq!(announcement.relay_l2_id, relay_l2_id);
    assert_eq!(
        announcement.rsc,
        RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE)
    );
    assert_eq!(announcement.rsrp_dbm, -78);

    // Remote UE evaluates announcement
    let acceptable = remote_engine.evaluate_model_a_announcement(&announcement);
    assert!(acceptable, "RSRP of -78 dBm should be acceptable");

    // Announcement with weak signal below threshold (-115 dBm < -110 dBm)
    let weak_announcement = RelayAnnouncement {
        relay_l2_id,
        rsc: RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE),
        rsrp_dbm: -118,
        relay_ue_id: "relay-ue-01".to_string(),
        supported_slices: vec![],
        timestamp_s: 1000,
    };
    assert!(
        !remote_engine.evaluate_model_a_announcement(&weak_announcement),
        "RSRP of -118 dBm must be rejected"
    );

    // Relay tries to announce unauthorized RSC
    let unauthorized_err = relay_engine.create_model_a_announcement(
        RelayServiceCode::new(RSC_COMMERCIAL_INTERNET),
        -70,
        1000,
    );
    assert!(matches!(
        unauthorized_err,
        Err(ProseRelayError::UnauthorizedRsc(RSC_COMMERCIAL_INTERNET))
    ));

    // --- Model B Discovery: Solicitation & Response ---
    let solicitation =
        remote_engine.create_model_b_solicitation(RelayServiceCode::new(RSC_EMERGENCY_SERVICES));
    assert_eq!(solicitation.remote_l2_id, remote_l2_id);
    assert_eq!(
        solicitation.requested_rsc,
        RelayServiceCode::new(RSC_EMERGENCY_SERVICES)
    );

    let response = relay_engine.handle_model_b_solicitation(&solicitation, -82);
    assert!(
        response.is_some(),
        "Authorized solicitation must receive response"
    );
    let resp = response.unwrap();
    assert_eq!(resp.relay_l2_id, relay_l2_id);
    assert_eq!(
        resp.accepted_rsc,
        RelayServiceCode::new(RSC_EMERGENCY_SERVICES)
    );
    assert_eq!(resp.rsrp_dbm, -82);

    // Solicit unsupported RSC (Smart Grid)
    let unsupported_solicitation =
        remote_engine.create_model_b_solicitation(RelayServiceCode::new(RSC_SMART_GRID_IOT));
    let unsupp_resp = relay_engine.handle_model_b_solicitation(&unsupported_solicitation, -82);
    assert!(
        unsupp_resp.is_none(),
        "Unsupported RSC should yield no response"
    );
}

#[test]
fn test_pc5_signaling_link_establishment_and_security() {
    let relay_l2_id = Pc5Layer2Id::new(0x01, 0x02, 0x03);
    let remote_l2_id = Pc5Layer2Id::new(0x0A, 0x0B, 0x0C);

    let mut relay_engine = ProSeRelayEngine::new_relay(
        "relay-ue",
        relay_l2_id,
        vec![RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE)],
        Ipv4Addr::new(192, 168, 50, 1),
        0x2001,
    );
    let mut remote_engine = ProSeRelayEngine::new_remote("remote-ue", remote_l2_id);

    let root_key = [0x77u8; 32];
    relay_engine.register_peer_root_key(remote_l2_id, root_key);
    let start_time_s = 500;

    // Step 1: Remote initiates PC5 link with PQI 23 (Public Safety Voice)
    let (remote_session_id, dcr) =
        remote_engine.initiate_pc5_link(relay_l2_id, root_key, 23, start_time_s);

    assert_eq!(
        remote_engine.pc5_sessions[&remote_session_id].state,
        Pc5LinkState::Connecting
    );

    // Step 2: Relay processes DCR -> generates SecurityModeCommand
    let sm_cmd_opt = relay_engine
        .handle_pc5_signaling(&dcr, start_time_s)
        .expect("DCR processing should succeed");
    assert!(sm_cmd_opt.is_some());
    let sm_cmd = sm_cmd_opt.unwrap();

    let relay_session_id = match &sm_cmd {
        Pc5SignalingMessage::DirectSecurityModeCommand { session_id, .. } => *session_id,
        _ => panic!("Expected DirectSecurityModeCommand"),
    };
    assert_eq!(
        relay_engine.pc5_sessions[&relay_session_id].state,
        Pc5LinkState::Securing
    );

    // Step 3: Remote processes SecurityModeCommand -> generates SecurityModeComplete
    let sm_complete_opt = remote_engine
        .handle_pc5_signaling(&sm_cmd, start_time_s)
        .expect("SecurityModeCommand processing should succeed");
    assert!(sm_complete_opt.is_some());
    let sm_complete = sm_complete_opt.unwrap();

    assert_eq!(
        remote_engine.pc5_sessions[&remote_session_id].state,
        Pc5LinkState::Securing
    );

    // Step 4: Relay processes SecurityModeComplete -> accepts and sends DirectCommunicationAccept
    let dca_opt = relay_engine
        .handle_pc5_signaling(&sm_complete, start_time_s)
        .expect("SecurityModeComplete processing should succeed");
    assert!(dca_opt.is_some());
    let dca = dca_opt.unwrap();

    assert_eq!(
        relay_engine.pc5_sessions[&relay_session_id].state,
        Pc5LinkState::Established
    );

    // Step 5: Remote receives DirectCommunicationAccept -> Link Established!
    let finish_opt = remote_engine
        .handle_pc5_signaling(&dca, start_time_s)
        .expect("DirectCommunicationAccept should succeed");
    assert!(finish_opt.is_none());

    assert_eq!(
        remote_engine.pc5_sessions[&remote_session_id].state,
        Pc5LinkState::Established
    );
    assert!(
        remote_engine.pc5_sessions[&remote_session_id]
            .ip_address
            .is_some(),
        "Remote UE must be assigned an IP address"
    );

    // Verify key derivation agreement: K_NRP-sess matches on both peers
    let remote_k_sess = remote_engine.pc5_sessions[&remote_session_id].k_nrp_sess;
    let relay_k_sess = relay_engine.pc5_sessions[&relay_session_id].k_nrp_sess;
    assert_ne!(remote_k_sess, [0u8; 32]);
    assert_eq!(
        remote_k_sess, relay_k_sess,
        "Derived session keys must match between Remote and Relay"
    );

    // Verify direct KDF calculation and profile parameters
    let expected_k = derive_k_nrp_sess(&root_key, &[0xAA; 16], &[0x55; 16], relay_session_id);
    assert_eq!(relay_k_sess, expected_k);
    assert_eq!(
        remote_engine.pc5_sessions[&remote_session_id].cipher_algo,
        Pc5SecurityAlgorithm::Nea2AesCtr
    );
    assert_eq!(
        remote_engine.pc5_sessions[&remote_session_id].qos_profile,
        Pc5QoSProfile::from_pqi(23)
    );
}

#[test]
fn test_l2_u2n_relay_srap_multiplexing_and_demux() {
    let relay_l2_id = Pc5Layer2Id::new(0xAA, 0xBB, 0xCC);
    let remote_l2_id = Pc5Layer2Id::new(0xDD, 0xEE, 0xFF);

    let mut relay_engine = ProSeRelayEngine::new_relay(
        "relay-l2",
        relay_l2_id,
        vec![RelayServiceCode::new(RSC_COMMERCIAL_INTERNET)],
        Ipv4Addr::new(10, 1, 1, 1),
        0x3001,
    );

    // Register Remote UE in L2 SRAP Routing table
    let uu_bearer_id = 4;
    let pc5_rlc_channel_id = 2;
    let remote_local_id =
        relay_engine.register_l2_remote_ue(remote_l2_id, uu_bearer_id, pc5_rlc_channel_id);
    assert_eq!(remote_local_id, 1);

    // Uplink test: Remote sends packet payload over PC5 -> Relay wraps in SRAP header for Uu
    let original_payload = b"Uplink payload from Remote UE to 5G Core";
    let srap_uplink_pkt = relay_engine
        .forward_l2_uplink(remote_local_id, uu_bearer_id, original_payload)
        .expect("L2 SRAP uplink forwarding should succeed");

    // Verify SRAP header format: 3 bytes
    assert_eq!(srap_uplink_pkt.len(), 3 + original_payload.len());
    let (decoded_header, extracted_payload) =
        SrapHeader::decode(&srap_uplink_pkt).expect("SRAP decoding should succeed");
    assert_eq!(decoded_header.remote_ue_local_id, remote_local_id);
    assert_eq!(decoded_header.bearer_id, uu_bearer_id);
    assert_eq!(extracted_payload, original_payload);

    // Downlink test: gNodeB sends downlink packet over Uu with SRAP header -> Relay demultiplexes
    let dl_original_payload = b"Downlink payload from UPF to Remote UE";
    let mut dl_srap_packet = Vec::new();
    dl_srap_packet.extend_from_slice(&SrapHeader::new(remote_local_id, uu_bearer_id).encode());
    dl_srap_packet.extend_from_slice(dl_original_payload);

    let (target_l2_id, target_rlc_ch, dl_payload) = relay_engine
        .forward_l2_downlink(&dl_srap_packet)
        .expect("L2 SRAP downlink forwarding should succeed");

    assert_eq!(target_l2_id, remote_l2_id);
    assert_eq!(target_rlc_ch, pc5_rlc_channel_id);
    assert_eq!(dl_payload, dl_original_payload);

    // Unknown local ID error
    let invalid_srap = SrapHeader::new(999, 1).encode();
    let err = relay_engine.forward_l2_downlink(&invalid_srap);
    assert!(matches!(
        err,
        Err(ProseRelayError::RemoteLocalIdNotFound(999))
    ));
}

#[test]
fn test_l3_u2n_relay_ip_forwarding_and_nat() {
    let relay_l2_id = Pc5Layer2Id::new(0x21, 0x22, 0x23);
    let relay_external_ip = Ipv4Addr::new(10, 45, 0, 10);
    let pdu_teid = 0x5500_1234;

    let mut relay_engine = ProSeRelayEngine::new_relay(
        "relay-l3",
        relay_l2_id,
        vec![RelayServiceCode::new(RSC_COMMERCIAL_INTERNET)],
        relay_external_ip,
        pdu_teid,
    );

    let remote_ip = Ipv4Addr::new(192, 168, 50, 25);
    let remote_port = 45123;
    let dest_ip = Ipv4Addr::new(8, 8, 8, 8);
    let dest_port = 53;
    let protocol = 17; // UDP
    let dns_query_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00";

    let current_time_s = 1000;

    // Uplink: Remote sends DNS query -> Relay translates with NAT
    let (teid, nat_uplink_pkt) = relay_engine
        .forward_l3_uplink(
            remote_ip,
            remote_port,
            dest_ip,
            dest_port,
            protocol,
            dns_query_payload,
            current_time_s,
        )
        .expect("L3 NAT uplink translation must succeed");

    assert_eq!(teid, pdu_teid);
    assert_eq!(nat_uplink_pkt.len(), 13 + dns_query_payload.len());

    // Extract assigned relay port from NAT packet (bytes 9..11)
    let assigned_port = u16::from_be_bytes([nat_uplink_pkt[9], nat_uplink_pkt[10]]);
    assert_eq!(assigned_port, 30000);

    // Downlink: DNS response arrives from 8.8.8.8:53 destined to Relay_External_IP:assigned_port
    let dns_resp_payload = b"\x12\x34\x81\x80\x00\x01\x00\x01";
    let (ret_remote_ip, ret_remote_port, nat_downlink_pkt) = relay_engine
        .forward_l3_downlink(
            assigned_port,
            dest_ip,
            dest_port,
            dns_resp_payload,
            current_time_s + 1,
        )
        .expect("L3 NAT downlink reverse translation must succeed");

    assert_eq!(ret_remote_ip, remote_ip);
    assert_eq!(ret_remote_port, remote_port);
    assert_eq!(&nat_downlink_pkt[12..], dns_resp_payload);

    // Unmapped port should fail
    let unmapped_err = relay_engine.forward_l3_downlink(
        39999,
        dest_ip,
        dest_port,
        dns_resp_payload,
        current_time_s + 2,
    );
    assert_eq!(unmapped_err, Err(ProseRelayError::NatMappingNotFound));
}

#[test]
fn test_pc5_link_monitoring_keepalive_and_rlf_reselection() {
    let relay_l2_id = Pc5Layer2Id::new(0x31, 0x32, 0x33);
    let remote_l2_id = Pc5Layer2Id::new(0x61, 0x62, 0x63);

    let mut remote_engine = ProSeRelayEngine::new_remote("remote-ue", remote_l2_id);
    assert_eq!(
        remote_engine.rlf_rsrp_threshold_dbm,
        DEFAULT_RLF_RSRP_THRESHOLD_DBM
    );

    let (session_id, _) = remote_engine.initiate_pc5_link(relay_l2_id, [0x99; 32], 21, 100);

    // Mark as established
    if let Some(session) = remote_engine.pc5_sessions.get_mut(&session_id) {
        session.state = Pc5LinkState::Established;
    }

    // Normal heartbeat update
    let hb_res = remote_engine.record_heartbeat(session_id, -85, 102);
    assert_eq!(hb_res, Ok(true));

    // Radio Link Failure via severe RSRP degradation below -110 dBm threshold
    let rlf_res = remote_engine.record_heartbeat(session_id, -118, 104);
    assert!(matches!(
        rlf_res,
        Err(ProseRelayError::RadioLinkFailure {
            session_id: 1,
            rsrp_dbm: -118
        })
    ));
    assert_eq!(
        remote_engine.pc5_sessions[&session_id].state,
        Pc5LinkState::Disconnected
    );

    // Test keepalive timeout and missed heartbeat counter
    if let Some(session) = remote_engine.pc5_sessions.get_mut(&session_id) {
        session.state = Pc5LinkState::Established;
        session.last_heartbeat_s = 200;
        session.missed_keepalives = 0;
    }

    // Tick at 206s (delta = 6s > 5s timeout)
    let timed_out_sessions = remote_engine.tick_liveness_check(206, DEFAULT_HEARTBEAT_TIMEOUT_S);
    assert!(
        timed_out_sessions.is_empty(),
        "1 missed keepalive should not trigger RLF yet"
    );

    // Advance more ticks until max missed keepalives (3) is exceeded
    remote_engine.tick_liveness_check(212, DEFAULT_HEARTBEAT_TIMEOUT_S);
    let rlf_sessions = remote_engine.tick_liveness_check(218, DEFAULT_HEARTBEAT_TIMEOUT_S);
    assert_eq!(rlf_sessions, vec![session_id]);
    assert_eq!(
        remote_engine.pc5_sessions[&session_id].state,
        Pc5LinkState::Disconnected
    );

    // Trigger relay reselection among candidates
    let alternate_relays = vec![
        RelayAnnouncement {
            relay_l2_id: Pc5Layer2Id::new(0xA1, 0xA2, 0xA3),
            rsc: RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE),
            rsrp_dbm: -115, // too weak (< -110 dBm)
            relay_ue_id: "weak-relay".to_string(),
            supported_slices: vec![],
            timestamp_s: 220,
        },
        RelayAnnouncement {
            relay_l2_id: Pc5Layer2Id::new(0xB1, 0xB2, 0xB3),
            rsc: RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE),
            rsrp_dbm: -75, // strongest!
            relay_ue_id: "strong-relay-b".to_string(),
            supported_slices: vec![],
            timestamp_s: 220,
        },
        RelayAnnouncement {
            relay_l2_id: Pc5Layer2Id::new(0xC1, 0xC2, 0xC3),
            rsc: RelayServiceCode::new(RSC_PUBLIC_SAFETY_VOICE),
            rsrp_dbm: -88, // moderate
            relay_ue_id: "relay-c".to_string(),
            supported_slices: vec![],
            timestamp_s: 220,
        },
    ];

    let reselected = remote_engine
        .trigger_reselection(session_id, &alternate_relays)
        .expect("Relay reselection should find a viable candidate");

    assert_eq!(reselected.relay_ue_id, "strong-relay-b");
    assert_eq!(reselected.rsrp_dbm, -75);
    assert_eq!(reselected.relay_l2_id, Pc5Layer2Id::new(0xB1, 0xB2, 0xB3));
}
