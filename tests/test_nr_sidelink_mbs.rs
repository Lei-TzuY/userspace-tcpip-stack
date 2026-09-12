//! Integration tests for 3GPP Rel-18/19 Sidelink Multicast & Broadcast Services (SL-MBS) Engine.

use toy_tcpip::nr_sidelink_mbs::*;

#[test]
fn test_group_lifecycle_and_member_management() {
    let mut engine = NrSlMbsEngine::new(1001, Location3D::new(0.0, 0.0, 0.0));

    let tmgi = SlMbsTmgi::new([0x01, 0x02, 0x03], "v2x.platoon.domain");
    let group_cfg = SlMbsGroupConfig::new(
        0x123456,
        tmgi.clone(),
        SlMbsServiceType::V2xPlatooning,
        150.0,
    );

    // Create group
    assert!(engine.create_group(group_cfg.clone()).is_ok());

    // Duplicate group creation should fail
    assert_eq!(
        engine.create_group(group_cfg),
        Err(SlMbsError::DuplicateGroupId(0x123456))
    );

    // Join members
    let loc1 = Location3D::new(10.0, 0.0, 0.0);
    let loc2 = Location3D::new(20.0, 0.0, 0.0);
    assert!(engine.join_group(0x123456, 2001, loc1, 1000).is_ok());
    assert!(engine.join_group(0x123456, 2002, loc2, 1000).is_ok());

    let members = engine.get_group_members(0x123456).unwrap();
    assert_eq!(members.len(), 2);

    // Update existing member location and heartbeat
    let loc1_new = Location3D::new(12.0, 1.0, 0.0);
    assert!(engine.join_group(0x123456, 2001, loc1_new, 2000).is_ok());
    let members = engine.get_group_members(0x123456).unwrap();
    assert_eq!(members.len(), 2); // Still 2 members
    assert_eq!(members[0].location.x_m, 12.0);
    assert_eq!(members[0].last_heard_ms, 2000);

    // Evict timed out members (member 2002 last heard at 1000, now 4000, timeout 2500)
    let evicted = engine.evict_timed_out_members(0x123456, 4000, 2500);
    assert_eq!(evicted, 1);
    let members = engine.get_group_members(0x123456).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].member_l2_id, 2001);

    // Member leaves group
    assert!(engine.leave_group(0x123456, 2001).is_ok());
    assert_eq!(engine.get_group_members(0x123456).unwrap().len(), 0);

    // Leaving non-existent member fails
    assert_eq!(
        engine.leave_group(0x123456, 9999),
        Err(SlMbsError::MemberNotFound(9999))
    );
}

#[test]
fn test_option1_distance_based_nack_feedback_within_mcr() {
    // Local receiver UE at (0, 0, 0)
    let mut rx_engine = NrSlMbsEngine::new(2001, Location3D::new(0.0, 0.0, 0.0));

    let tmgi = SlMbsTmgi::new([0x0A, 0x0B, 0x0C], "public.safety");
    let mut group_cfg = SlMbsGroupConfig::new(
        0x555555,
        tmgi,
        SlMbsServiceType::PublicSafetyGroupCall,
        100.0, // MCR = 100 meters
    );
    group_cfg.feedback_scheme = HarqFeedbackScheme::Option1NackOnlyMcr;
    rx_engine.create_group(group_cfg).unwrap();

    // Transmitter is at (30.0, 40.0, 0.0) -> Distance = sqrt(30^2 + 40^2) = 50 meters <= MCR (100m)
    let tx_loc = Location3D::new(30.0, 40.0, 0.0);

    // Case 1: Decoding failure within MCR -> Must send NACK on PSFCH
    let decision_fail = rx_engine
        .evaluate_rx_feedback(0x555555, &tx_loc, false)
        .unwrap();
    assert_eq!(decision_fail, SlMbsPsfchDecision::SendNack);
    assert_eq!(rx_engine.telemetry().psfch_nacks_received, 1);

    // Case 2: Decoding success within MCR -> SendAck (no PSFCH congestion)
    let decision_ok = rx_engine
        .evaluate_rx_feedback(0x555555, &tx_loc, true)
        .unwrap();
    assert_eq!(decision_ok, SlMbsPsfchDecision::SendAck);
}

#[test]
fn test_option1_distance_based_feedback_suppression_outside_mcr() {
    // Local receiver UE at (0, 0, 0)
    let mut rx_engine = NrSlMbsEngine::new(2002, Location3D::new(0.0, 0.0, 0.0));

    let tmgi = SlMbsTmgi::new([0x01, 0x01, 0x01], "v2x.warning");
    let mut group_cfg = SlMbsGroupConfig::new(
        0x777777,
        tmgi,
        SlMbsServiceType::V2xPlatooning,
        80.0, // MCR = 80 meters
    );
    group_cfg.feedback_scheme = HarqFeedbackScheme::Option1NackOnlyMcr;
    rx_engine.create_group(group_cfg).unwrap();

    // Transmitter is at (100.0, 0.0, 0.0) -> Distance = 100 meters > MCR (80m)
    let tx_loc = Location3D::new(100.0, 0.0, 0.0);

    // Even on decoding failure, feedback MUST be suppressed outside MCR!
    let decision = rx_engine
        .evaluate_rx_feedback(0x777777, &tx_loc, false)
        .unwrap();
    assert_eq!(decision, SlMbsPsfchDecision::SuppressedOutsideMcr);

    // Verify suppression telemetry
    assert_eq!(rx_engine.telemetry().mcr_suppressions, 1);
    assert_eq!(rx_engine.telemetry().psfch_nacks_received, 0);
    assert_eq!(rx_engine.telemetry().suppression_ratio_percent(), 100.0);
}

#[test]
fn test_option2_individual_ack_nack_and_blind_retx() {
    let mut engine = NrSlMbsEngine::new(3001, Location3D::new(0.0, 0.0, 0.0));

    // Group with Option 2 (dedicated ACK/NACK)
    let mut cfg2 = SlMbsGroupConfig::new(
        0x222222,
        SlMbsTmgi::new([1, 2, 3], "fleet.group"),
        SlMbsServiceType::IndustrialFleetCoordination,
        50.0,
    );
    cfg2.feedback_scheme = HarqFeedbackScheme::Option2AckNackIndividual;
    engine.create_group(cfg2).unwrap();

    let tx_far = Location3D::new(500.0, 0.0, 0.0); // Far away
    let d_ok = engine
        .evaluate_rx_feedback(0x222222, &tx_far, true)
        .unwrap();
    assert_eq!(d_ok, SlMbsPsfchDecision::SendAck);

    let d_fail = engine
        .evaluate_rx_feedback(0x222222, &tx_far, false)
        .unwrap();
    assert_eq!(d_fail, SlMbsPsfchDecision::SendNack);

    // Group with Blind Retransmission
    let mut cfg_blind = SlMbsGroupConfig::new(
        0x333333,
        SlMbsTmgi::new([4, 5, 6], "media.broadcast"),
        SlMbsServiceType::LocalMediaBroadcast,
        200.0,
    );
    cfg_blind.feedback_scheme = HarqFeedbackScheme::BlindRetransmissions;
    engine.create_group(cfg_blind).unwrap();

    let d_blind = engine
        .evaluate_rx_feedback(0x333333, &tx_far, false)
        .unwrap();
    assert_eq!(d_blind, SlMbsPsfchDecision::SuppressedBlindRetx);
}

#[test]
fn test_transmitter_multicast_tx_and_psfch_handling() {
    let mut tx_engine = NrSlMbsEngine::new(1001, Location3D::new(15.0, 25.0, 2.0));

    let group_cfg = SlMbsGroupConfig::new(
        0xABCDEF,
        SlMbsTmgi::new([9, 9, 9], "test.tx"),
        SlMbsServiceType::V2xPlatooning,
        120.0,
    );
    tx_engine.create_group(group_cfg).unwrap();

    // Prepare PDU
    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let pdu = tx_engine
        .prepare_multicast_tx(0xABCDEF, 42, payload.clone())
        .unwrap();

    assert_eq!(pdu.group_l2_id, 0xABCDEF);
    assert_eq!(pdu.sequence_number, 42);
    assert_eq!(pdu.tx_ue_id, 1001);
    assert_eq!(pdu.tx_x_m, 15.0);
    assert_eq!(pdu.tx_y_m, 25.0);
    assert_eq!(pdu.mcr_m, 120.0);
    assert_eq!(pdu.payload, payload);

    // Transmitter handles feedback: 2 NACKs received -> Must retransmit
    let need_retx = tx_engine.handle_psfch_feedback(0xABCDEF, 2, 5, 0).unwrap();
    assert!(need_retx);
    assert_eq!(tx_engine.telemetry().retransmissions_sent, 1);

    // Retransmit again, now 0 NACKs received -> Success, no further retransmissions
    let need_retx2 = tx_engine.handle_psfch_feedback(0xABCDEF, 0, 7, 1).unwrap();
    assert!(!need_retx2);
    assert_eq!(tx_engine.telemetry().successful_deliveries, 1);

    // If max retransmission limit reached (max = 3)
    let need_retx3 = tx_engine.handle_psfch_feedback(0xABCDEF, 3, 0, 3).unwrap();
    assert!(!need_retx3); // Reached max, stops retransmitting
}

#[test]
fn test_group_drx_synchronization() {
    let mut engine = NrSlMbsEngine::new(1001, Location3D::default());

    let mut cfg = SlMbsGroupConfig::new(
        0x111111,
        SlMbsTmgi::new([1, 1, 1], "drx.test"),
        SlMbsServiceType::PublicSafetyGroupCall,
        100.0,
    );
    cfg.drx_cycle_ms = 100;
    cfg.drx_on_duration_ms = 20; // Active during [0..20) ms of each 100 ms cycle
    engine.create_group(cfg).unwrap();

    // In cycle 0
    assert_eq!(engine.is_group_drx_active(0x111111, 0).unwrap(), true);
    assert_eq!(engine.is_group_drx_active(0x111111, 15).unwrap(), true);
    assert_eq!(engine.is_group_drx_active(0x111111, 20).unwrap(), false); // Muted
    assert_eq!(engine.is_group_drx_active(0x111111, 85).unwrap(), false); // Muted

    // In cycle 1 (100 - 200 ms)
    assert_eq!(engine.is_group_drx_active(0x111111, 100).unwrap(), true);
    assert_eq!(engine.is_group_drx_active(0x111111, 110).unwrap(), true);
    assert_eq!(engine.is_group_drx_active(0x111111, 130).unwrap(), false);
}

#[test]
fn test_binary_wire_codec_and_crc16() {
    let pdu = SlMbsPdu {
        group_l2_id: 0x123456,
        sequence_number: 9999,
        tx_ue_id: 8888,
        tx_x_m: 100.5,
        tx_y_m: -50.25,
        tx_z_m: 12.0,
        mcr_m: 150.0,
        feedback_scheme: HarqFeedbackScheme::Option1NackOnlyMcr,
        payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };

    let wire = pdu.encode_wire();
    assert!(wire.len() >= 35);

    let decoded = SlMbsPdu::decode_wire(&wire).expect("decoding failed");
    assert_eq!(decoded.group_l2_id, pdu.group_l2_id);
    assert_eq!(decoded.sequence_number, pdu.sequence_number);
    assert_eq!(decoded.tx_ue_id, pdu.tx_ue_id);
    assert_eq!(decoded.tx_x_m, pdu.tx_x_m);
    assert_eq!(decoded.tx_y_m, pdu.tx_y_m);
    assert_eq!(decoded.tx_z_m, pdu.tx_z_m);
    assert_eq!(decoded.mcr_m, pdu.mcr_m);
    assert_eq!(decoded.feedback_scheme, pdu.feedback_scheme);
    assert_eq!(decoded.payload, pdu.payload);

    // Corrupted CRC test
    let mut corrupted = wire.clone();
    let idx = corrupted.len() - 1;
    corrupted[idx] ^= 0xFF;
    assert!(matches!(
        SlMbsPdu::decode_wire(&corrupted),
        Err(SlMbsError::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_error_display() {
    let e1 = SlMbsError::GroupNotFound(0x123456);
    assert!(format!("{}", e1).contains("Group L2 ID 0x123456 not found"));

    let e2 = SlMbsError::GroupCapacityExceeded {
        max: 16,
        attempted: 17,
    };
    assert!(format!("{}", e2).contains("Group capacity exceeded"));

    let e3 = SlMbsError::MemberNotFound(0x654321);
    assert!(format!("{}", e3).contains("Group member 0x654321 not found"));

    let e4 = SlMbsError::ChecksumMismatch {
        expected: 0xABCD,
        calculated: 0x1234,
    };
    assert!(format!("{}", e4).contains("0xABCD"));
}
