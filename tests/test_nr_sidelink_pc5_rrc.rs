//! Comprehensive integration tests for 3GPP Rel-18/19 5G NR Sidelink PC5-RRC
//! Connection, Capability & Measurement Engine.

use toy_tcpip::nr_sidelink_pc5_rrc::{
    Pc5RrcEngine, Pc5RrcError, Pc5RrcMessage, Pc5RrcState, SlMeasurementReport, SlRlcMode,
    SlUeCapabilities, SlrbConfig,
};

// ---------------------------------------------------------------------------
// Test 1: PC5-RRC Wire Codec & CRC-16 Integrity
// ---------------------------------------------------------------------------
#[test]
fn test_pc5_rrc_wire_codec_and_crc() {
    // 1. Test RrcReconfiguration message serialization & deserialization
    let slrb1 = SlrbConfig::new_am(1, 10, 1);
    let slrb2 = SlrbConfig::new_um(2, 20, 2);
    let msg = Pc5RrcMessage::RrcReconfiguration {
        transaction_id: 2,
        slrbs_to_add: vec![slrb1, slrb2],
        slrbs_to_release: vec![5],
    };

    let wire_bytes = msg.encode_wire();
    assert!(wire_bytes.len() > 20);

    let decoded = Pc5RrcMessage::decode_wire(&wire_bytes).expect("Decode RrcReconfiguration");
    match decoded {
        Pc5RrcMessage::RrcReconfiguration { transaction_id, slrbs_to_add, slrbs_to_release } => {
            assert_eq!(transaction_id, 2);
            assert_eq!(slrbs_to_add.len(), 2);
            assert_eq!(slrbs_to_add[0].slrb_id, 1);
            assert_eq!(slrbs_to_add[0].pqfi, 10);
            assert_eq!(slrbs_to_add[1].slrb_id, 2);
            assert_eq!(slrbs_to_release, vec![5]);
        }
        _ => panic!("Expected RrcReconfiguration message"),
    }

    // 2. Corrupt 1 byte in CRC and verify failure
    let mut corrupted = wire_bytes.clone();
    let idx = corrupted.len() - 1;
    corrupted[idx] ^= 0xFF;
    let err = Pc5RrcMessage::decode_wire(&corrupted);
    assert!(matches!(err, Err(Pc5RrcError::ChecksumMismatch { .. })));

    // 3. Test MasterInformationBlockSidelink codec
    let mib = Pc5RrcMessage::MasterInformationBlockSidelink {
        direct_frame_number: 512,
        direct_subframe_number: 7,
        in_coverage: true,
    };
    let mib_wire = mib.encode_wire();
    let mib_decoded = Pc5RrcMessage::decode_wire(&mib_wire).expect("Decode MIB-SL");
    match mib_decoded {
        Pc5RrcMessage::MasterInformationBlockSidelink { direct_frame_number, direct_subframe_number, in_coverage } => {
            assert_eq!(direct_frame_number, 512);
            assert_eq!(direct_subframe_number, 7);
            assert_eq!(in_coverage, true);
        }
        _ => panic!("Expected MIB-SL"),
    }
}

// ---------------------------------------------------------------------------
// Test 2: PC5-RRC Connection Lifecycle Management
// ---------------------------------------------------------------------------
#[test]
fn test_pc5_rrc_connection_lifecycle() {
    let mut engine = Pc5RrcEngine::new(0x111111);
    let peer_id = 0x222222;

    assert!(engine.get_peer(peer_id).is_none());

    // 1. Initiate connection
    engine.initiate_connection(peer_id).expect("Initiate PC5-RRC connection");
    let peer = engine.get_peer(peer_id).expect("Peer context created");
    assert_eq!(peer.state, Pc5RrcState::Connected);
    assert_eq!(engine.telemetry().connections_established, 1);

    // 2. Release connection
    engine.release_connection(peer_id);
    let peer_after = engine.get_peer(peer_id).expect("Peer context retained");
    assert_eq!(peer_after.state, Pc5RrcState::Disconnected);
    assert!(peer_after.active_slrbs.is_empty());
}

// ---------------------------------------------------------------------------
// Test 3: Sidelink Radio Bearer (SLRB) Reconfiguration Handshake
// ---------------------------------------------------------------------------
#[test]
fn test_slrb_configuration_handshake() {
    let mut ue_a = Pc5RrcEngine::new(0xAAAAAA);
    let mut ue_b = Pc5RrcEngine::new(0xBBBBBB);

    ue_a.initiate_connection(ue_b.local_l2_id()).unwrap();
    ue_b.initiate_connection(ue_a.local_l2_id()).unwrap();

    // 1. UE A initiates reconfiguration to add 2 SLRBs (SLRB 1 AM, SLRB 2 UM)
    let slrb1 = SlrbConfig::new_am(1, 10, 1);
    let slrb2 = SlrbConfig::new_um(2, 20, 2);
    let reconfig_msg = ue_a
        .prepare_reconfiguration(ue_b.local_l2_id(), vec![slrb1.clone(), slrb2.clone()], vec![])
        .expect("UE A prepare reconfig");

    let tx_id = match &reconfig_msg {
        Pc5RrcMessage::RrcReconfiguration { transaction_id, .. } => *transaction_id,
        _ => panic!("Expected RrcReconfiguration"),
    };

    assert_eq!(ue_a.get_peer(ue_b.local_l2_id()).unwrap().state, Pc5RrcState::Reconfiguring);

    // 2. UE B processes incoming reconfiguration and replies with Complete
    let complete_msg = ue_b
        .process_reconfiguration(ue_a.local_l2_id(), tx_id, vec![slrb1.clone(), slrb2.clone()], vec![])
        .expect("UE B process reconfig");

    assert_eq!(ue_b.get_peer(ue_a.local_l2_id()).unwrap().active_slrbs.len(), 2);

    // 3. UE A receives ReconfigurationComplete and finalizes its local state
    match complete_msg {
        Pc5RrcMessage::RrcReconfigurationComplete { transaction_id } => {
            ue_a.process_reconfiguration_complete(ue_b.local_l2_id(), transaction_id, vec![slrb1, slrb2], vec![])
                .expect("UE A finalize reconfig");
        }
        _ => panic!("Expected RrcReconfigurationComplete"),
    }

    assert_eq!(ue_a.get_peer(ue_b.local_l2_id()).unwrap().state, Pc5RrcState::Connected);
    assert_eq!(ue_a.get_peer(ue_b.local_l2_id()).unwrap().active_slrbs.len(), 2);
    assert_eq!(ue_a.telemetry().reconfigurations_completed, 1);
    assert_eq!(ue_b.telemetry().reconfigurations_completed, 1);
}

// ---------------------------------------------------------------------------
// Test 4: Sidelink UE Capability Transfer Handshake
// ---------------------------------------------------------------------------
#[test]
fn test_ue_capability_transfer_handshake() {
    let mut ue_a = Pc5RrcEngine::new(0x101010);
    let mut ue_b = Pc5RrcEngine::new(0x202020);

    ue_a.initiate_connection(ue_b.local_l2_id()).unwrap();
    ue_b.initiate_connection(ue_a.local_l2_id()).unwrap();

    // 1. UE A sends capability enquiry for bands 47 and 48
    let _enquiry = ue_a
        .prepare_capability_enquiry(ue_b.local_l2_id(), vec![47, 48])
        .expect("Prepare capability enquiry");

    // 2. UE B constructs capability response
    let b_caps = SlUeCapabilities {
        supports_mode1: true,
        supports_mode2: true,
        max_modulation_order: 8, // 256QAM
        supports_psfch_harq: true,
        max_concurrent_slrbs: 32,
        supported_bands: vec![47, 48, 102],
    };

    // 3. UE A processes UE B's capability information
    ue_a.process_capability_information(ue_b.local_l2_id(), b_caps.clone()).expect("Process caps");

    let peer = ue_a.get_peer(ue_b.local_l2_id()).unwrap();
    assert_eq!(peer.peer_capabilities, Some(b_caps));
    assert_eq!(ue_a.telemetry().capability_exchanges_completed, 1);
}

// ---------------------------------------------------------------------------
// Test 5: Sidelink Measurement Reporting & Layer-3 Exponential Filtering
// ---------------------------------------------------------------------------
#[test]
fn test_sidelink_measurement_reporting_and_l3_filter() {
    let mut engine = Pc5RrcEngine::new(0x123456);
    let peer_id = 0x654321;
    engine.initiate_connection(peer_id).unwrap();

    let alpha = 0.5f32; // Filter coefficient

    // Report 1: -80.0 dBm -> initial filtered value = -80.0 dBm
    let report1 = SlMeasurementReport { peer_rsrp_dbm: -80.0, cbr: 0.25, sl_cqi: 12, sl_ri: 1 };
    engine.process_measurement_report(peer_id, report1, alpha).unwrap();
    assert_eq!(engine.get_peer(peer_id).unwrap().filtered_rsrp_dbm, Some(-80.0));

    // Report 2: -70.0 dBm -> 0.5 * (-80) + 0.5 * (-70) = -75.0 dBm
    let report2 = SlMeasurementReport { peer_rsrp_dbm: -70.0, cbr: 0.30, sl_cqi: 14, sl_ri: 2 };
    engine.process_measurement_report(peer_id, report2, alpha).unwrap();
    assert_eq!(engine.get_peer(peer_id).unwrap().filtered_rsrp_dbm, Some(-75.0));

    // Report 3: -90.0 dBm -> 0.5 * (-75) + 0.5 * (-90) = -82.5 dBm
    let report3 = SlMeasurementReport { peer_rsrp_dbm: -90.0, cbr: 0.40, sl_cqi: 10, sl_ri: 1 };
    engine.process_measurement_report(peer_id, report3, alpha).unwrap();
    assert_eq!(engine.get_peer(peer_id).unwrap().filtered_rsrp_dbm, Some(-82.5));
    assert_eq!(engine.telemetry().measurement_reports_processed, 3);
}

// ---------------------------------------------------------------------------
// Test 6: Sidelink Radio Link Failure (SL-RLF) via RLC Max Retransmissions
// ---------------------------------------------------------------------------
#[test]
fn test_sidelink_radio_link_failure_rlc_max_retx() {
    let mut engine = Pc5RrcEngine::new(0x112233);
    let peer_id = 0x445566;
    engine.initiate_connection(peer_id).unwrap();

    // Configure SLRB 1 with max_retx_threshold = 4
    let mut slrb = SlrbConfig::new_am(1, 10, 1);
    slrb.rlc_mode = SlRlcMode::Acknowledged { max_retx_threshold: 4 };

    engine.process_reconfiguration(peer_id, 0, vec![slrb], vec![]).unwrap();

    // 1st, 2nd, 3rd failures -> below threshold
    assert_eq!(engine.notify_rlc_transmission_failure(peer_id, 1).unwrap(), false);
    assert_eq!(engine.notify_rlc_transmission_failure(peer_id, 1).unwrap(), false);
    assert_eq!(engine.notify_rlc_transmission_failure(peer_id, 1).unwrap(), false);
    assert_eq!(engine.get_peer(peer_id).unwrap().state, Pc5RrcState::Connected);

    // 4th failure -> triggers SL-RLF!
    assert_eq!(engine.notify_rlc_transmission_failure(peer_id, 1).unwrap(), true);
    assert_eq!(engine.get_peer(peer_id).unwrap().state, Pc5RrcState::RlfDetected);
    assert_eq!(engine.telemetry().sl_rlf_events, 1);

    // Resetting on success clears counter
    engine.notify_rlc_transmission_success(peer_id);
    assert_eq!(engine.get_peer(peer_id).unwrap().consecutive_rlc_failures, 0);
}

// ---------------------------------------------------------------------------
// Test 7: T400 Response Timer Expiration Declaring SL-RLF
// ---------------------------------------------------------------------------
#[test]
fn test_t400_response_timer_timeout_sl_rlf() {
    let mut engine = Pc5RrcEngine::new(0x999999);
    let peer_id = 0x888888;
    engine.initiate_connection(peer_id).unwrap();

    // Prepare capability enquiry which starts T400 = 1000 ms
    engine.prepare_capability_enquiry(peer_id, vec![47]).unwrap();

    // Advance 500 ms -> no timeout
    let timeouts = engine.advance_time_ms(500);
    assert!(timeouts.is_empty());

    // Advance 600 ms (total 1100 ms > 1000 ms) -> T400 expires and declares RLF!
    let timeouts2 = engine.advance_time_ms(600);
    assert_eq!(timeouts2.len(), 1);
    assert_eq!(timeouts2[0].0, peer_id);
    assert_eq!(engine.get_peer(peer_id).unwrap().state, Pc5RrcState::RlfDetected);
    assert_eq!(engine.telemetry().sl_rlf_events, 1);
}

// ---------------------------------------------------------------------------
// Test 8: Edge Cases and Limit Handling
// ---------------------------------------------------------------------------
#[test]
fn test_edge_cases_and_limits() {
    let mut engine = Pc5RrcEngine::new(0x100000);
    let peer_id = 0x200000;
    engine.initiate_connection(peer_id).unwrap();

    // Attempting to exceed MAX_SLRBS_PER_PEER (32)
    let mut excess_slrbs = Vec::new();
    for i in 1..=33 {
        excess_slrbs.push(SlrbConfig::new_um(i, i, 1));
    }

    let err = engine.prepare_reconfiguration(peer_id, excess_slrbs, vec![]);
    assert!(matches!(err, Err(Pc5RrcError::SlrbLimitExceeded { .. })));

    // Operating on disconnected peer
    let err_peer = engine.prepare_capability_enquiry(0x999999, vec![]);
    assert!(matches!(err_peer, Err(Pc5RrcError::PeerNotConnected(_))));
}
