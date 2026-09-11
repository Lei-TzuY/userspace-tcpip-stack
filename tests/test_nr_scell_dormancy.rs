//! Comprehensive integration tests for 3GPP Release 18/19 Fast SCell Activation,
//! Dormancy & Multi-Carrier Power Saving Engine.
//!
//! Conforms to 3GPP TS 38.321 Rel-18 §5.9, TS 38.213 §11.1, and TS 38.331.

use std::collections::HashMap;
use toy_tcpip::nr_scell_dormancy::{
    DciDormancyFormat, FastSCellDormancyEngine, SCellConfig, SCellError, SCellState,
    TransitionCause, COLD_ACTIVATION_LATENCY_MS, L1_DCI_ACTIVATION_LATENCY_MS,
    LCID_SCELL_ACT_DEACT_1_OCTET, LCID_SCELL_ACT_DEACT_4_OCTET,
    LCID_SCELL_DORMANCY_1_OCTET, LCID_SCELL_DORMANCY_4_OCTET,
};

// ---------------------------------------------------------------------------
// Test 1: SCell Registration, Configuration & Validation
// ---------------------------------------------------------------------------
#[test]
fn test_scell_registration_and_validation() {
    let mut engine = FastSCellDormancyEngine::new();
    assert_eq!(engine.scell_count(), 0);

    // Valid SCell 1 with active BWP 1 and dormant BWP 2
    let cfg1 = SCellConfig::new(1, 1, Some(2))
        .expect("Valid SCellConfig")
        .with_group(0)
        .expect("Valid group")
        .with_timers(160, Some(40));

    assert!(engine.add_scell(cfg1).is_ok());
    assert_eq!(engine.scell_count(), 1);

    // Initial state must be Deactivated
    let state = engine.get_state(1).expect("State exists");
    assert_eq!(state.current_state, SCellState::Deactivated);
    assert_eq!(state.current_bwp_id, 1);

    // Invalid SCell ID 0 (valid is 1..31)
    assert!(SCellConfig::new(0, 1, None).is_err());
    // Invalid SCell ID 32
    assert!(SCellConfig::new(32, 1, None).is_err());

    // Duplicate registration rejected
    let duplicate_cfg = SCellConfig::new(1, 1, None).unwrap();
    assert_eq!(engine.add_scell(duplicate_cfg), Err(SCellError::SCellAlreadyExists(1)));

    // Invalid group ID (valid is 0..3)
    let cfg_bad_group = SCellConfig::new(2, 1, None).unwrap().with_group(4);
    assert!(cfg_bad_group.is_err());
}

// ---------------------------------------------------------------------------
// Test 2: MAC CE 1-Octet and 4-Octet Activation / Deactivation Codec
// ---------------------------------------------------------------------------
#[test]
fn test_mac_ce_activation_deactivation_codec() {
    let mut engine = FastSCellDormancyEngine::new();
    for id in 1..=5 {
        let cfg = SCellConfig::new(id, 1, Some(2)).unwrap();
        engine.add_scell(cfg).unwrap();
    }

    // 1. Test 1-Octet MAC CE (LCID 62): Activate SCell 1 and 3, Deactivate others
    let mut target_states = HashMap::new();
    target_states.insert(1, SCellState::Activated);
    target_states.insert(3, SCellState::Activated);
    target_states.insert(2, SCellState::Deactivated);

    let payload = engine
        .encode_mac_ce(LCID_SCELL_ACT_DEACT_1_OCTET, &target_states)
        .expect("Encode 1-octet MAC CE");
    assert_eq!(payload.len(), 1);
    // Bit 1 and Bit 3 must be set: (1 << 1) | (1 << 3) = 0b00001010 = 0x0A
    assert_eq!(payload[0], 0x0A);

    // Decode and apply
    let transitions = engine
        .decode_and_apply_mac_ce(LCID_SCELL_ACT_DEACT_1_OCTET, &payload)
        .expect("Decode 1-octet MAC CE");

    assert_eq!(transitions.len(), 2);
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine.get_state(3).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine.get_state(2).unwrap().current_state, SCellState::Deactivated);

    // 2. Test 4-Octet MAC CE (LCID 61): Activate SCell 12 and 20
    let mut engine_wide = FastSCellDormancyEngine::new();
    for id in 1..=20 {
        let cfg = SCellConfig::new(id, 1, Some(2)).unwrap();
        engine_wide.add_scell(cfg).unwrap();
    }

    let mut target_wide = HashMap::new();
    target_wide.insert(12, SCellState::Activated);
    target_wide.insert(20, SCellState::Activated);

    let payload4 = engine_wide
        .encode_mac_ce(LCID_SCELL_ACT_DEACT_4_OCTET, &target_wide)
        .expect("Encode 4-octet MAC CE");
    assert_eq!(payload4.len(), 4);

    let transitions4 = engine_wide
        .decode_and_apply_mac_ce(LCID_SCELL_ACT_DEACT_4_OCTET, &payload4)
        .expect("Decode 4-octet MAC CE");

    assert_eq!(transitions4.len(), 2);
    assert_eq!(engine_wide.get_state(12).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine_wide.get_state(20).unwrap().current_state, SCellState::Activated);
}

// ---------------------------------------------------------------------------
// Test 3: MAC CE 1-Octet and 4-Octet Dormancy Codec (LCID 51 & 52)
// ---------------------------------------------------------------------------
#[test]
fn test_mac_ce_dormancy_codec() {
    let mut engine = FastSCellDormancyEngine::new();
    for id in 1..=4 {
        let cfg = SCellConfig::new(id, 1, Some(2)).unwrap();
        engine.add_scell(cfg).unwrap();
    }

    // Set target states for 1-octet Dormancy MAC CE:
    // SCell 1: Activated (10), SCell 2: Dormant (01), SCell 3: Deactivated (00), SCell 4: Dormant (01)
    let mut target = HashMap::new();
    target.insert(1, SCellState::Activated);
    target.insert(2, SCellState::Dormant);
    target.insert(3, SCellState::Deactivated);
    target.insert(4, SCellState::Dormant);

    let payload = engine
        .encode_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &target)
        .expect("Encode 1-octet Dormancy MAC CE");
    assert_eq!(payload.len(), 1);

    // Bit layout: SCell 4 (bits 7-6: 01), SCell 3 (bits 5-4: 00), SCell 2 (bits 3-2: 01), SCell 1 (bits 1-0: 10)
    // 0b01_00_01_10 = 0x46
    assert_eq!(payload[0], 0x46);

    // Apply
    let transitions = engine
        .decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &payload)
        .expect("Decode 1-octet Dormancy MAC CE");

    assert_eq!(transitions.len(), 3); // SCell 3 was already Deactivated
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine.get_state(2).unwrap().current_state, SCellState::Dormant);
    assert_eq!(engine.get_state(2).unwrap().current_bwp_id, 2); // switched to dormant BWP
    assert_eq!(engine.get_state(4).unwrap().current_state, SCellState::Dormant);

    // 4-Octet Dormancy MAC CE test (LCID 51)
    let mut engine16 = FastSCellDormancyEngine::new();
    for id in 1..=16 {
        let cfg = SCellConfig::new(id, 1, Some(3)).unwrap();
        engine16.add_scell(cfg).unwrap();
    }
    let mut target16 = HashMap::new();
    target16.insert(5, SCellState::Dormant);
    target16.insert(10, SCellState::Activated);

    let payload4 = engine16
        .encode_mac_ce(LCID_SCELL_DORMANCY_4_OCTET, &target16)
        .expect("Encode 4-octet Dormancy MAC CE");
    assert_eq!(payload4.len(), 4);

    let trans16 = engine16
        .decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_4_OCTET, &payload4)
        .expect("Decode 4-octet Dormancy MAC CE");

    assert_eq!(trans16.len(), 2);
    assert_eq!(engine16.get_state(5).unwrap().current_state, SCellState::Dormant);
    assert_eq!(engine16.get_state(10).unwrap().current_state, SCellState::Activated);
}

// ---------------------------------------------------------------------------
// Test 4: Fast L1 DCI SCell Dormancy Switching & Latency Prediction
// ---------------------------------------------------------------------------
#[test]
fn test_fast_l1_dci_dormancy_switching_and_latency() {
    let mut engine = FastSCellDormancyEngine::new();
    let cfg1 = SCellConfig::new(1, 10, Some(20)).unwrap();
    let cfg2 = SCellConfig::new(2, 10, Some(20)).unwrap();
    engine.add_scell(cfg1).unwrap();
    engine.add_scell(cfg2).unwrap();

    // 1. Check activation latency when Deactivated (cold start)
    assert_eq!(engine.predict_activation_latency_ms(1).unwrap(), COLD_ACTIVATION_LATENCY_MS);

    // 2. Transition SCell 1 and 2 to Dormant via MAC CE
    let mut target = HashMap::new();
    target.insert(1, SCellState::Dormant);
    target.insert(2, SCellState::Dormant);
    let payload = engine.encode_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &target).unwrap();
    engine.decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &payload).unwrap();

    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Dormant);
    assert_eq!(engine.predict_activation_latency_ms(1).unwrap(), L1_DCI_ACTIVATION_LATENCY_MS);

    // 3. Send L1 DCI 1_1: Bit 0 = 1 (Activate SCell 1), Bit 1 = 0 (Keep SCell 2 Dormant)
    let bitmap = 0b01; // Bit 0 is 1, Bit 1 is 0
    let scell_ids = [1, 2];
    let transitions = engine
        .process_l1_dci_dormancy(DciDormancyFormat::Dci1_1, bitmap, Some(&scell_ids), false)
        .expect("Process L1 DCI");

    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].scell_id, 1);
    assert_eq!(transitions[0].new_state, SCellState::Activated);
    assert_eq!(transitions[0].active_bwp_id, 10);
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine.predict_activation_latency_ms(1).unwrap(), 0); // Already active

    // 4. Send L1 DCI 0_1: Bit 0 = 0 (Switch SCell 1 to Dormant)
    let bitmap2 = 0b00;
    let transitions2 = engine
        .process_l1_dci_dormancy(DciDormancyFormat::Dci0_1, bitmap2, Some(&scell_ids), false)
        .expect("Process L1 DCI 0_1");

    assert_eq!(transitions2.len(), 1);
    assert_eq!(transitions2[0].scell_id, 1);
    assert_eq!(transitions2[0].new_state, SCellState::Dormant);
    assert_eq!(transitions2[0].active_bwp_id, 20); // switched back to dormant BWP
}

// ---------------------------------------------------------------------------
// Test 5: Synchronized SCell Group Dormancy Control
// ---------------------------------------------------------------------------
#[test]
fn test_synchronized_scell_group_dormancy() {
    let mut engine = FastSCellDormancyEngine::new();

    // Group 0: SCell 1 & SCell 2 (e.g. FR1 Component Carriers)
    let cfg1 = SCellConfig::new(1, 1, Some(2)).unwrap().with_group(0).unwrap();
    let cfg2 = SCellConfig::new(2, 1, Some(2)).unwrap().with_group(0).unwrap();
    // Group 1: SCell 3 & SCell 4 (e.g. FR2 mmWave Component Carriers)
    let cfg3 = SCellConfig::new(3, 1, Some(2)).unwrap().with_group(1).unwrap();
    let cfg4 = SCellConfig::new(4, 1, Some(2)).unwrap().with_group(1).unwrap();

    engine.add_scell(cfg1).unwrap();
    engine.add_scell(cfg2).unwrap();
    engine.add_scell(cfg3).unwrap();
    engine.add_scell(cfg4).unwrap();

    // Set all to Dormant first
    let mut target = HashMap::new();
    for id in 1..=4 {
        target.insert(id, SCellState::Dormant);
    }
    let payload = engine.encode_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &target).unwrap();
    engine.decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &payload).unwrap();

    // Send DCI 2_6 targeting SCell Groups:
    // Bit 0 (Group 0) = 1 (Activate SCell 1 & 2)
    // Bit 1 (Group 1) = 0 (Keep SCell 3 & 4 Dormant)
    let group_bitmap = 0b01;
    let group_ids = [0, 1];
    let trans = engine
        .process_l1_dci_dormancy(DciDormancyFormat::Dci2_6, group_bitmap, Some(&group_ids), true)
        .expect("Process group DCI");

    assert_eq!(trans.len(), 2);
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine.get_state(2).unwrap().current_state, SCellState::Activated);
    assert_eq!(engine.get_state(3).unwrap().current_state, SCellState::Dormant);
    assert_eq!(engine.get_state(4).unwrap().current_state, SCellState::Dormant);
}

// ---------------------------------------------------------------------------
// Test 6: Dual Timers: sCellDormancyTimer & sCellDeactivationTimer Expiry
// ---------------------------------------------------------------------------
#[test]
fn test_dual_timers_expiry() {
    let mut engine = FastSCellDormancyEngine::new();
    // Configure SCell with 40 ms dormancy timer and 160 ms deactivation timer
    let cfg = SCellConfig::new(1, 1, Some(2))
        .unwrap()
        .with_timers(160, Some(40));
    engine.add_scell(cfg).unwrap();

    // Activate SCell 1 via traffic demand
    engine.request_traffic_activation(1).unwrap();
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Activated);

    // Advance 20 ms -> both timers running, no expiry
    let t1 = engine.advance_time_ms(20);
    assert!(t1.is_empty());
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Activated);

    // Advance another 20 ms (total 40 ms) -> dormancy timer expires!
    let t2 = engine.advance_time_ms(20);
    assert_eq!(t2.len(), 1);
    assert_eq!(t2[0].cause, TransitionCause::DormancyTimerExpiry);
    assert_eq!(t2[0].new_state, SCellState::Dormant);
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Dormant);

    // Advance 160 ms -> deactivation timer (restarted upon entering dormancy) expires!
    let t3 = engine.advance_time_ms(160);
    assert_eq!(t3.len(), 1);
    assert_eq!(t3[0].cause, TransitionCause::DeactivationTimerExpiry);
    assert_eq!(t3[0].new_state, SCellState::Deactivated);
    assert_eq!(engine.get_state(1).unwrap().current_state, SCellState::Deactivated);

    // Check telemetry
    let telem = engine.telemetry();
    assert_eq!(telem.dormancy_timer_expiries, 1);
    assert_eq!(telem.deactivation_timer_expiries, 1);
}

// ---------------------------------------------------------------------------
// Test 7: CQI & Beam Reporting on Dormant BWP
// ---------------------------------------------------------------------------
#[test]
fn test_cqi_reporting_in_dormancy() {
    let mut engine = FastSCellDormancyEngine::new();
    let cfg = SCellConfig::new(1, 1, Some(2)).unwrap();
    engine.add_scell(cfg).unwrap();

    // Put cell in Dormant state
    let mut target = HashMap::new();
    target.insert(1, SCellState::Dormant);
    let payload = engine.encode_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &target).unwrap();
    engine.decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &payload).unwrap();

    // Record periodic CQI reports while dormant
    for cqi in 10..=15 {
        engine.record_cqi(1, cqi, -85.0).unwrap();
    }

    let state = engine.get_state(1).unwrap();
    assert_eq!(state.last_reported_cqi, Some(15));
    assert_eq!(state.last_rsrp_dbm, Some(-85.0));
    assert_eq!(engine.telemetry().total_cqi_reports_in_dormancy, 6);
}

// ---------------------------------------------------------------------------
// Test 8: Energy Consumption & Power Saving Model
// ---------------------------------------------------------------------------
#[test]
fn test_energy_savings_and_power_model() {
    let mut engine = FastSCellDormancyEngine::new();
    // Configure with standard power: 850 mW active, 160 mW dormant, 15 mW deactivated
    // Disable auto-deactivation timer to test deterministic multi-second intervals
    let cfg = SCellConfig::new(1, 1, Some(2)).unwrap().with_timers(0, None);
    engine.add_scell(cfg).unwrap();

    // 1. Initial deactivated: 15 mW
    assert_eq!(engine.current_power_draw_mw(), 15.0);
    engine.advance_time_ms(1000); // 1 sec in deactivated

    // 2. Transition to Dormant: 160 mW
    let mut target = HashMap::new();
    target.insert(1, SCellState::Dormant);
    let payload = engine.encode_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &target).unwrap();
    engine.decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &payload).unwrap();
    assert_eq!(engine.current_power_draw_mw(), 160.0);
    engine.advance_time_ms(3000); // 3 sec in dormant

    // 3. Fast L1 DCI activation: 850 mW
    let bitmap = 0b01;
    let ids = [1];
    engine.process_l1_dci_dormancy(DciDormancyFormat::Dci1_1, bitmap, Some(&ids), false).unwrap();
    assert_eq!(engine.current_power_draw_mw(), 850.0);
    engine.advance_time_ms(1000); // 1 sec in active

    // Evaluate energy metrics
    let telem = engine.telemetry();
    assert_eq!(telem.total_active_time_ms, 1000);
    assert_eq!(telem.total_dormant_time_ms, 3000);
    assert_eq!(telem.total_deactivated_time_ms, 1000);

    // Energy savings should be substantial (> 65%) compared to baseline of 850 mW continuous
    let savings = telem.energy_savings_percentage();
    assert!(savings > 65.0, "Energy savings should exceed 65%, got {:.2}%", savings);

    let duty_cycle = telem.power_save_duty_cycle();
    assert_eq!(duty_cycle, 0.80); // 4000 ms power save / 5000 ms total = 80%
}

// ---------------------------------------------------------------------------
// Test 9: Edge Cases and Error Handling
// ---------------------------------------------------------------------------
#[test]
fn test_edge_cases_and_error_handling() {
    let mut engine = FastSCellDormancyEngine::new();

    // Attempting Dormancy on an SCell without dormantBWP-Id configured must fail
    let cfg_no_dormant = SCellConfig::new(2, 1, None).unwrap();
    engine.add_scell(cfg_no_dormant).unwrap();

    let mut target = HashMap::new();
    target.insert(2, SCellState::Dormant);
    let payload = engine.encode_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &target).unwrap();
    let err = engine.decode_and_apply_mac_ce(LCID_SCELL_DORMANCY_1_OCTET, &payload);
    assert!(matches!(err, Err(SCellError::InvalidBwpConfiguration(_))));

    // MAC CE buffer too short
    let short_buf: [u8; 2] = [0, 0];
    let err_short = engine.decode_and_apply_mac_ce(LCID_SCELL_ACT_DEACT_4_OCTET, &short_buf);
    assert!(matches!(err_short, Err(SCellError::MacCeBufferTooShort { .. })));

    // Unsupported LCID
    let err_lcid = engine.decode_and_apply_mac_ce(99, &[0]);
    assert_eq!(err_lcid, Err(SCellError::InvalidLcid(99)));

    // Unknown SCell query
    assert!(engine.get_state(99).is_none());
    assert_eq!(engine.predict_activation_latency_ms(99), Err(SCellError::SCellNotFound(99)));
}
