//! Integration tests for 3GPP Rel-18 5G-Advanced Multi-SIM (MUSIM) & Dual-Stack Coordination Engine.

use toy_tcpip::nr_musim_engine::{
    DEFAULT_PCMAX_MW, MusimAssistanceInfo, MusimDeviceCapability, MusimEngine, MusimError,
    MusimGapConfig, MusimLeaveAction, MusimLeaveCause, MusimPowerSharingServo, MusimRrcState,
    MusimServicePriority, SimId, SimProfile, TemporaryLeaveState,
};

#[test]
fn test_musim_device_capabilities_and_profile_setup() {
    let sim_a = SimProfile::new(SimId::SimA, [4, 6, 0], 12345, 64);
    let sim_b = SimProfile::new(SimId::SimB, [4, 6, 1], 67890, 128);

    assert_eq!(sim_a.sim_id.peer(), SimId::SimB);
    assert_eq!(sim_b.sim_id.peer(), SimId::SimA);

    let engine_dsda = MusimEngine::new(MusimDeviceCapability::DualRxDualTx, sim_a, sim_b);
    assert_eq!(engine_dsda.capability, MusimDeviceCapability::DualRxDualTx);
    assert_eq!(engine_dsda.sim_a.rrc_state, MusimRrcState::RrcIdle);
    assert_eq!(engine_dsda.sim_b.rrc_state, MusimRrcState::RrcIdle);
}

#[test]
fn test_paging_frame_and_occasion_subframe_mapping() {
    // 1. DRX cycle T = 64 frames, N = 64, UE_ID = 200
    let mut sim1 = SimProfile::new(SimId::SimA, [4, 6, 0], 200, 64);
    // PF = 200 % 64 = 8
    assert_eq!(sim1.calculate_paging_frame(), 8);
    // Ns = 1 -> PO subframe is always 9
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 9);

    // 2. Ns = 2, test both occasion indices
    sim1.paging_occasions_ns = 2;
    // (UE_ID / N) % Ns = (200 / 64) % 2 = 3 % 2 = 1 -> subframe 9
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 9);

    sim1.ue_id = 64 * 4; // 256 -> (256 / 64) % 2 = 4 % 2 = 0 -> subframe 4
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 4);

    // 3. Ns = 4 -> subframes 0, 4, 5, 9
    sim1.paging_occasions_ns = 4;
    sim1.ue_id = 0; // i_s = 0 -> subframe 0
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 0);
    sim1.ue_id = 64 * 1; // i_s = 1 -> subframe 4
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 4);
    sim1.ue_id = 64 * 2; // i_s = 2 -> subframe 5
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 5);
    sim1.ue_id = 64 * 3; // i_s = 3 -> subframe 9
    assert_eq!(sim1.calculate_paging_occasion_subframe(), 9);
}

#[test]
fn test_paging_collision_detection_and_assistance_info() {
    let mut sim_a = SimProfile::new(SimId::SimA, [4, 6, 0], 100, 64);
    let sim_b = SimProfile::new(SimId::SimB, [4, 6, 1], 200, 64);

    sim_a.rrc_state = MusimRrcState::RrcConnected;
    sim_a.active_service = MusimServicePriority::BestEffortData;

    let mut engine = MusimEngine::new(MusimDeviceCapability::DualRxSingleTx, sim_a, sim_b);

    let sim_b_pf = engine.sim_b.calculate_paging_frame(); // 200 % 64 = 8
    assert_eq!(sim_b_pf, 8);

    // Lookahead across 128 frames (2 full DRX cycles)
    let collisions = engine.detect_paging_collisions(0, 128);
    // Should detect collisions at SFN 8 and SFN 72 (8 + 64)
    assert_eq!(collisions.len(), 2);
    assert_eq!(collisions[0].sfn, 8);
    assert_eq!(collisions[0].busy_sim, SimId::SimA);
    assert_eq!(collisions[0].paged_sim, SimId::SimB);
    assert_eq!(collisions[1].sfn, 72);

    // Verify statistics counter
    assert_eq!(engine.stats_paging_collisions, 2);

    // Generate MUSIM-AssistanceInformation for SIM B
    let assist = engine.generate_assistance_info(SimId::SimB);
    assert_eq!(assist.preferred_drx_offset_frames, 4);
    assert!(assist.paging_subgrouping_requested);

    // Binary serialization roundtrip
    let wire_bytes = assist.to_bytes();
    assert_eq!(wire_bytes.len(), 4);
    let decoded = MusimAssistanceInfo::from_bytes(&wire_bytes).expect("Decodes cleanly");
    assert_eq!(assist, decoded);
}

#[test]
fn test_musim_gap_config_scheduling() {
    // Gap: length = 10 ms, periodicity = 640 ms, offset = 50 ms
    let gap = MusimGapConfig::new(1, 10, 640, 50);

    // Active during [50..60 ms)
    assert!(!gap.is_gap_active(49));
    assert!(gap.is_gap_active(50));
    assert!(gap.is_gap_active(55));
    assert!(gap.is_gap_active(59));
    assert!(!gap.is_gap_active(60));

    // Next period at 640 + 50 = 690 ms
    assert!(!gap.is_gap_active(689));
    assert!(gap.is_gap_active(690));
    assert!(gap.is_gap_active(695));
    assert!(!gap.is_gap_active(700));
}

#[test]
fn test_temporary_leave_and_resume_state_machine() {
    let mut sim_a = SimProfile::new(SimId::SimA, [4, 6, 0], 100, 64);
    let sim_b = SimProfile::new(SimId::SimB, [4, 6, 1], 200, 64);

    sim_a.rrc_state = MusimRrcState::RrcConnected;
    sim_a.active_service = MusimServicePriority::BestEffortData;

    let mut engine = MusimEngine::new(MusimDeviceCapability::SingleRxSingleTx, sim_a, sim_b);

    // 1. Voice call on SIM B triggers fast MAC CE Temporary Leave on SIM A
    let action = engine
        .request_temporary_leave(SimId::SimA, MusimLeaveCause::VoiceCall, 10_000, 1000)
        .expect("Leave succeeds");

    match action {
        MusimLeaveAction::SendMacCeTemporaryLeave {
            cause,
            expected_duration_ms,
        } => {
            assert_eq!(cause, MusimLeaveCause::VoiceCall);
            assert_eq!(expected_duration_ms, 10_000);
        }
        other => panic!("Expected SendMacCeTemporaryLeave, got: {:?}", other),
    }

    assert_eq!(
        engine.leave_state_a,
        TemporaryLeaveState::LeaveInProgress {
            cause: MusimLeaveCause::VoiceCall,
            leave_start_ms: 1000,
            duration_ms: 10_000,
        }
    );

    // 2. Return from leave
    engine
        .resume_from_leave(SimId::SimA)
        .expect("Resume succeeds");
    assert_eq!(engine.leave_state_a, TemporaryLeaveState::Active);

    // 3. If SIM A is active in Emergency call, leave request for normal voice on SIM B is rejected
    engine.sim_a.active_service = MusimServicePriority::Emergency;
    let conflict = engine
        .request_temporary_leave(SimId::SimA, MusimLeaveCause::VoiceCall, 5000, 2000)
        .expect("Conflict handled");

    match conflict {
        MusimLeaveAction::RejectLeaveConflict {
            active_priority,
            requested_priority,
        } => {
            assert_eq!(active_priority, MusimServicePriority::Emergency);
            assert_eq!(requested_priority, MusimServicePriority::PagingMonitoring);
        }
        other => panic!("Expected RejectLeaveConflict, got: {:?}", other),
    }
}

#[test]
fn test_dsda_dynamic_power_sharing_servo() {
    let servo = MusimPowerSharingServo::default_ue(); // ~199.53 mW (23 dBm)

    // 1. Under budget: SIM A = 70 mW, SIM B = 50 mW -> Total 120 mW <= 199.53 mW
    let alloc_ok = servo.allocate_power(
        70.0,
        MusimServicePriority::BestEffortData,
        50.0,
        MusimServicePriority::BestEffortData,
    );
    assert!(!alloc_ok.was_throttled);
    assert_eq!(alloc_ok.sim_a_power_mw, 70.0);
    assert_eq!(alloc_ok.sim_b_power_mw, 50.0);
    assert_eq!(alloc_ok.total_power_mw, 120.0);

    // 2. Over budget with equal priorities: 150 mW + 150 mW = 300 mW -> Scaled 50/50
    let alloc_equal = servo.allocate_power(
        150.0,
        MusimServicePriority::UrllcData,
        150.0,
        MusimServicePriority::UrllcData,
    );
    assert!(alloc_equal.was_throttled);
    let half_pcmax = DEFAULT_PCMAX_MW / 2.0;
    assert!((alloc_equal.sim_a_power_mw - half_pcmax).abs() < 1e-4);
    assert!((alloc_equal.sim_b_power_mw - half_pcmax).abs() < 1e-4);
    assert!((alloc_equal.total_power_mw - DEFAULT_PCMAX_MW).abs() < 1e-4);

    // 3. Over budget with priority differentiation: VoNR (Prio 1) vs Best-Effort (Prio 4)
    // SIM A (VoNR) requests 120 mW; SIM B (Data) requests 120 mW.
    let alloc_prio = servo.allocate_power(
        120.0,
        MusimServicePriority::VoiceOverNr,
        120.0,
        MusimServicePriority::BestEffortData,
    );
    assert!(alloc_prio.was_throttled);
    // VoNR gets full 120 mW requested
    assert_eq!(alloc_prio.sim_a_power_mw, 120.0);
    // Data gets remainder: 199.53 - 120 = 79.53 mW
    assert!((alloc_prio.sim_b_power_mw - (DEFAULT_PCMAX_MW - 120.0)).abs() < 1e-4);
    assert!((alloc_prio.total_power_mw - DEFAULT_PCMAX_MW).abs() < 1e-4);

    // 4. Test dBm and mW unit conversions
    assert!((MusimPowerSharingServo::mw_to_dbm(100.0) - 20.0).abs() < 1e-4);
    assert!((MusimPowerSharingServo::mw_to_dbm(10.0) - 10.0).abs() < 1e-4);
    assert!((MusimPowerSharingServo::mw_to_dbm(1.0) - 0.0).abs() < 1e-4);
    assert!((MusimPowerSharingServo::dbm_to_mw(20.0) - 100.0).abs() < 1e-4);
}

#[test]
fn test_error_handling_and_buffer_limits() {
    // Truncated buffer decoding
    let short_buf = [0x70, 0x01];
    let err = MusimAssistanceInfo::from_bytes(&short_buf);
    assert!(matches!(
        err,
        Err(MusimError::BufferTooShort {
            expected: 4,
            actual: 2
        })
    ));

    // Invalid negative PCMAX
    let servo_err = MusimPowerSharingServo::new(-10.0);
    assert!(matches!(
        servo_err,
        Err(MusimError::InvalidConfiguration(_))
    ));

    // Error display
    let err_str = format!("{}", MusimError::SimNotFound(SimId::SimA));
    assert!(err_str.contains("SIM slot SimA not configured"));
}
