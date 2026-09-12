//! Integration tests for 3GPP Rel-18 Sidelink Relay Discovery & Reselection Engine.

use toy_tcpip::nr_sidelink_relay_discovery::{
    Pc5DiscoveryMessage, Pc5DiscoveryMessageType, RelayConnectionState, RelayDiscoveryError,
    RelayReselectionDecision, SidelinkRelayConfig, SidelinkRelayDiscoveryEngine, SidelinkRelayRole,
};

#[test]
fn test_pc5_discovery_message_binary_codecs() {
    // 1. Model A Announcement
    let ann = Pc5DiscoveryMessage {
        msg_type: Pc5DiscoveryMessageType::Announcement,
        relay_service_code: 0x00A1_B2C3,
        sender_l2_id: [0x11, 0x22, 0x33],
        target_l2_id: None,
        uu_rsrp_dbm: Some(-88.0),
        hop_count: 1,
    };
    let bytes_ann = ann.to_bytes();
    let decoded_ann = Pc5DiscoveryMessage::from_bytes(&bytes_ann).expect("Decodes announcement");
    assert_eq!(ann.msg_type, decoded_ann.msg_type);
    assert_eq!(ann.relay_service_code, decoded_ann.relay_service_code);
    assert_eq!(ann.sender_l2_id, decoded_ann.sender_l2_id);
    assert_eq!(decoded_ann.target_l2_id, None);
    assert!((ann.uu_rsrp_dbm.unwrap() - decoded_ann.uu_rsrp_dbm.unwrap()).abs() < 1.0);

    // 2. Model B Response with Target L2 ID
    let resp = Pc5DiscoveryMessage {
        msg_type: Pc5DiscoveryMessageType::Response,
        relay_service_code: 0x00A1_B2C3,
        sender_l2_id: [0x44, 0x55, 0x66],
        target_l2_id: Some([0x11, 0x22, 0x33]),
        uu_rsrp_dbm: Some(-75.0),
        hop_count: 2,
    };
    let bytes_resp = resp.to_bytes();
    let decoded_resp = Pc5DiscoveryMessage::from_bytes(&bytes_resp).expect("Decodes response");
    assert_eq!(resp.target_l2_id, decoded_resp.target_l2_id);
    assert_eq!(decoded_resp.hop_count, 2);

    // 3. Truncated buffer check
    assert!(matches!(
        Pc5DiscoveryMessage::from_bytes(&[1, 2, 3]),
        Err(RelayDiscoveryError::BufferTooShort { .. })
    ));
}

#[test]
fn test_model_a_announcement_and_candidate_ingestion() {
    let rsc = 0x0001_0001;
    let relay_id = [0xAA, 0x01, 0x02];
    let remote_id = [0xBB, 0x03, 0x04];

    let relay_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RelayUe,
        relay_id,
        rsc,
        SidelinkRelayConfig::default_config(),
    );
    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        remote_id,
        rsc,
        SidelinkRelayConfig::default_config(),
    );

    // Relay UE broadcasts Model A announcement
    let ann_msg = relay_engine
        .generate_announcement(-82.0)
        .expect("Generates announcement");

    // Remote UE receives announcement at PC5-RSRP = -88.0 dBm
    let reply = remote_engine.process_discovery_message(&ann_msg, -88.0, 1000);
    assert_eq!(reply, None); // Model A requires no reply

    assert_eq!(remote_engine.candidate_relays.len(), 1);
    let candidate = remote_engine.candidate_relays.get(&relay_id).unwrap();
    assert_eq!(candidate.relay_l2_id, relay_id);
    assert_eq!(candidate.pc5_rsrp_dbm, -88.0);
    assert_eq!(candidate.uu_rsrp_dbm, -82.0);
    assert_eq!(candidate.hop_count, 1);
}

#[test]
fn test_model_b_solicitation_and_response_handshake() {
    let rsc = 0x0002_0002;
    let relay_id = [0x10, 0x20, 0x30];
    let remote_id = [0x70, 0x80, 0x90];

    let mut relay_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RelayUe,
        relay_id,
        rsc,
        SidelinkRelayConfig::default_config(),
    );
    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        remote_id,
        rsc,
        SidelinkRelayConfig::default_config(),
    );

    // Remote UE emits Model B solicitation
    let sol_msg = remote_engine.generate_solicitation(rsc);

    // Relay UE receives solicitation and replies with Response
    let resp_msg = relay_engine
        .process_discovery_message(&sol_msg, -85.0, 500)
        .expect("Relay UE replies to matching solicitation");
    assert_eq!(resp_msg.msg_type, Pc5DiscoveryMessageType::Response);
    assert_eq!(resp_msg.target_l2_id, Some(remote_id));

    // Remote UE ingests response
    remote_engine.process_discovery_message(&resp_msg, -86.0, 510);
    assert_eq!(remote_engine.candidate_relays.len(), 1);
}

#[test]
fn test_relay_selection_out_of_coverage_with_ttt() {
    let rsc = 0x0003_0003;
    let remote_id = [0xAA, 0xBB, 0xCC];
    let relay_id = [0x11, 0x22, 0x33];

    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        remote_id,
        rsc,
        SidelinkRelayConfig::default_config(), // TTT = 100 ms
    );

    // Ingest candidate relay
    let ann = Pc5DiscoveryMessage {
        msg_type: Pc5DiscoveryMessageType::Announcement,
        relay_service_code: rsc,
        sender_l2_id: relay_id,
        target_l2_id: None,
        uu_rsrp_dbm: Some(-80.0),
        hop_count: 1,
    };
    remote_engine.process_discovery_message(&ann, -85.0, 100);

    // Evaluate reselection at t = 100 ms: condition met, TTT armed
    let d1 = remote_engine.evaluate_reselection(None, 100);
    assert_eq!(d1, RelayReselectionDecision::StayConnected);
    assert!(remote_engine.pending_reselection.is_some());

    // Evaluate at t = 150 ms (TTT = 50 ms < 100 ms): still pending
    let d2 = remote_engine.evaluate_reselection(None, 150);
    assert_eq!(d2, RelayReselectionDecision::StayConnected);

    // Evaluate at t = 200 ms (TTT = 100 ms reached): commit SwitchToRelay
    let d3 = remote_engine.evaluate_reselection(None, 200);
    match d3 {
        RelayReselectionDecision::SwitchToRelay {
            target_relay_l2_id, ..
        } => {
            assert_eq!(target_relay_l2_id, relay_id);
        }
        other => panic!("Expected SwitchToRelay, got: {:?}", other),
    }

    assert!(matches!(
        remote_engine.connection_state,
        RelayConnectionState::ConnectedViaRelay { .. }
    ));
    assert_eq!(remote_engine.stats_reselections_executed, 1);
}

#[test]
fn test_reselection_hysteresis_ping_pong_mitigation() {
    let rsc = 0x0004_0004;
    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        [0x01, 0x02, 0x03],
        rsc,
        SidelinkRelayConfig::default_config(), // Hysteresis = 3.0 dB
    );

    let relay_a = [0x0A, 0x00, 0x01];
    let relay_b = [0x0B, 0x00, 0x02];

    // Connect to Relay A (metric min(-90, -80) = -90 dBm)
    remote_engine.connection_state = RelayConnectionState::ConnectedViaRelay {
        relay_l2_id: relay_a,
        pc5_rsrp_dbm: -90.0,
        hop_count: 1,
    };
    remote_engine.candidate_relays.insert(
        relay_a,
        toy_tcpip::nr_sidelink_relay_discovery::CandidateRelay {
            relay_l2_id: relay_a,
            relay_service_code: rsc,
            pc5_rsrp_dbm: -90.0,
            uu_rsrp_dbm: -80.0,
            hop_count: 1,
            last_seen_ms: 1000,
        },
    );

    // Relay B appears with metric -88 dBm (+2 dB better, but < 3 dB hysteresis)
    remote_engine.candidate_relays.insert(
        relay_b,
        toy_tcpip::nr_sidelink_relay_discovery::CandidateRelay {
            relay_l2_id: relay_b,
            relay_service_code: rsc,
            pc5_rsrp_dbm: -88.0,
            uu_rsrp_dbm: -80.0,
            hop_count: 1,
            last_seen_ms: 1000,
        },
    );

    let dec_stay = remote_engine.evaluate_reselection(None, 1100);
    assert_eq!(dec_stay, RelayReselectionDecision::StayConnected);

    // Relay B improves to -85 dBm (+5 dB better, exceeds 3 dB hysteresis)
    remote_engine
        .candidate_relays
        .get_mut(&relay_b)
        .unwrap()
        .pc5_rsrp_dbm = -85.0;

    // TTT arming at 1200
    remote_engine.evaluate_reselection(None, 1200);
    // TTT firing at 1300
    let dec_switch = remote_engine.evaluate_reselection(None, 1300);
    match dec_switch {
        RelayReselectionDecision::SwitchToRelay {
            target_relay_l2_id, ..
        } => {
            assert_eq!(target_relay_l2_id, relay_b);
        }
        other => panic!("Expected SwitchToRelay to B, got {:?}", other),
    }
}

#[test]
fn test_switch_back_to_direct_uu_when_coverage_restored() {
    let rsc = 0x0005_0005;
    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        [0x01, 0x02, 0x03],
        rsc,
        SidelinkRelayConfig::default_config(),
    );

    remote_engine.connection_state = RelayConnectionState::ConnectedViaRelay {
        relay_l2_id: [0xAA, 0xBB, 0xCC],
        pc5_rsrp_dbm: -90.0,
        hop_count: 1,
    };

    // Direct Uu RSRP recovers to -98 dBm (above Thresh_High -105 + Hyst 3 = -102 dBm)
    remote_engine.evaluate_reselection(Some(-98.0), 100);
    let dec = remote_engine.evaluate_reselection(Some(-98.0), 200);

    match dec {
        RelayReselectionDecision::SwitchToDirectUu {
            direct_uu_rsrp_dbm, ..
        } => {
            assert_eq!(direct_uu_rsrp_dbm, -98.0);
        }
        other => panic!("Expected SwitchToDirectUu, got {:?}", other),
    }
}

#[test]
fn test_multi_hop_relay_limit_and_penalty() {
    let rsc = 0x0006_0006;
    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        [0x01, 0x02, 0x03],
        rsc,
        SidelinkRelayConfig::default_config(), // Max hops = 2, Penalty = 3 dB/hop
    );

    // 1. Ingest announcement with 3 hops -> rejected because max_hops = 2
    let msg_3hops = Pc5DiscoveryMessage {
        msg_type: Pc5DiscoveryMessageType::Announcement,
        relay_service_code: rsc,
        sender_l2_id: [0x33, 0x33, 0x33],
        target_l2_id: None,
        uu_rsrp_dbm: Some(-80.0),
        hop_count: 3,
    };
    remote_engine.process_discovery_message(&msg_3hops, -80.0, 100);
    assert_eq!(remote_engine.candidate_relays.len(), 0);

    // 2. Ingest 2-hop announcement -> accepted with 3 dB hop penalty
    let msg_2hops = Pc5DiscoveryMessage {
        msg_type: Pc5DiscoveryMessageType::Announcement,
        relay_service_code: rsc,
        sender_l2_id: [0x22, 0x22, 0x22],
        target_l2_id: None,
        uu_rsrp_dbm: Some(-80.0),
        hop_count: 2,
    };
    remote_engine.process_discovery_message(&msg_2hops, -80.0, 100);
    assert_eq!(remote_engine.candidate_relays.len(), 1);

    let candidate = remote_engine
        .candidate_relays
        .get(&[0x22, 0x22, 0x22])
        .unwrap();
    // Bottleneck min(-80, -80) = -80. Hop penalty = (2 - 1) * 3 = 3 dB -> Metric = -83 dBm
    assert_eq!(candidate.calculate_metric(3.0), -83.0);
}

#[test]
fn test_prune_stale_relays() {
    let mut remote_engine = SidelinkRelayDiscoveryEngine::new(
        SidelinkRelayRole::RemoteUe,
        [1, 2, 3],
        100,
        SidelinkRelayConfig::default_config(), // Expiry = 3000 ms
    );

    remote_engine.candidate_relays.insert(
        [10, 20, 30],
        toy_tcpip::nr_sidelink_relay_discovery::CandidateRelay {
            relay_l2_id: [10, 20, 30],
            relay_service_code: 100,
            pc5_rsrp_dbm: -90.0,
            uu_rsrp_dbm: -80.0,
            hop_count: 1,
            last_seen_ms: 1000,
        },
    );

    // At 3500 ms (age = 2500 <= 3000): retained
    remote_engine.prune_stale_relays(3500);
    assert_eq!(remote_engine.candidate_relays.len(), 1);

    // At 4500 ms (age = 3500 > 3000): pruned
    remote_engine.prune_stale_relays(4500);
    assert_eq!(remote_engine.candidate_relays.len(), 0);
}
