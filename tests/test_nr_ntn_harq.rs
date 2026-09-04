//! Integration tests for 3GPP Rel-17 5G NR NTN HARQ & Autonomous TA Tracking Engine.

use toy_tcpip::nr_ntn_harq::{
    DEFAULT_TA_STEP_THRESHOLD_US, NtnHarqEngine, NtnHarqError, NtnHarqProcessState, NtnSib19Config,
    SatelliteOrbitType,
};

fn create_mock_leo_sib19() -> NtnSib19Config {
    NtnSib19Config {
        orbit_type: SatelliteOrbitType::Leo,
        k_offset_slots: 50, // 50 slots = 50 ms at 15 kHz SCS
        k_mac_slots: 4,
        feeder_link_delay_ms: 5.0,
        // Satellite at ~600 km altitude above earth surface
        satellite_pos_ecef_m: [0.0, 0.0, 6_971_000.0],
        // Orbital velocity ~7500 m/s along Y-axis
        satellite_vel_ecef_mps: [0.0, 7500.0, 0.0],
        epoch_time_s: 1_700_000_000,
        carrier_frequency_hz: 2.0e9, // 2 GHz S-band NTN
        subcarrier_spacing_khz: 15,
    }
}

#[test]
fn test_ntn_sib19_config_and_k_offset_calculation() {
    let sib19 = create_mock_leo_sib19();
    assert_eq!(sib19.slot_duration_ms(), 1.0);

    // Ground UE directly underneath satellite (600 km distance)
    // One-way service delay = 600,000 / 299,792,458 = ~2.001 ms
    let service_delay_ms = 2.001;
    let min_k_offset = sib19.calculate_min_k_offset(service_delay_ms);

    // Total RTT = 2 * (5.0 + 2.001) = 14.002 ms -> ceil to 15 slots
    assert_eq!(min_k_offset, 15);
    assert!(sib19.k_offset_slots >= min_k_offset);
}

#[test]
fn test_extended_32_harq_processes_allocation() {
    let sib19 = create_mock_leo_sib19();
    let ue_pos = [0.0, 0.0, 6_371_000.0]; // Earth surface
    let mut engine = NtnHarqEngine::new(0x0001, sib19, ue_pos, 32).expect("Engine creation failed");

    assert_eq!(engine.processes.len(), 32);

    // Schedule 32 consecutive uplink grants (exhausting all 32 processes)
    for i in 0..32 {
        let res = engine.schedule_uplink_grant(4, 256);
        assert!(res.is_ok());
        let (proc_id, scheduled_slot) = res.unwrap();
        assert_eq!(proc_id, i as u8);
        assert_eq!(scheduled_slot, 4 + 50); // current_slot(0) + k2(4) + k_offset(50)
    }

    assert!(engine.is_stalled());

    // 33rd grant must fail with HarqBufferStalled error
    let fail_res = engine.schedule_uplink_grant(4, 256);
    match fail_res {
        Err(NtnHarqError::HarqBufferStalled { active_processes }) => {
            assert_eq!(active_processes, 32);
        }
        _ => panic!("Expected HarqBufferStalled error"),
    }
    assert_eq!(engine.telemetry().stall_slots_count, 1);

    // Receive ACK for process 0
    assert!(engine.notify_harq_feedback(0, true).is_ok());
    assert!(!engine.is_stalled());

    // Now scheduling succeeds allocating process 0
    let retry_res = engine.schedule_uplink_grant(4, 256);
    assert!(retry_res.is_ok());
    assert_eq!(retry_res.unwrap().0, 0);
}

#[test]
fn test_harq_feedback_disabling_and_blind_retransmission() {
    let sib19 = create_mock_leo_sib19();
    let ue_pos = [0.0, 0.0, 6_371_000.0];
    let mut engine = NtnHarqEngine::new(0x0002, sib19, ue_pos, 16).unwrap();

    // Disable HARQ feedback on process 0, configure 3 blind repetitions
    engine.configure_harq_feedback(0, false, 3).unwrap();

    // Schedule grant at current_slot = 0, k2 = 4 -> target_slot = 54
    let (proc_id, target_slot) = engine.schedule_uplink_grant(4, 128).unwrap();
    assert_eq!(proc_id, 0);
    assert_eq!(target_slot, 54);

    // Advance to slot 53 (just before target)
    engine.advance_slots(54);

    // At slot 54, process 0 executes repetition 0
    engine.advance_slot();
    match engine.processes[0].state {
        NtnHarqProcessState::Transmitting { repetition_idx } => {
            assert_eq!(repetition_idx, 1);
        }
        ref st => panic!("Expected Transmitting repetition 1, got {:?}", st),
    }

    // Advance slot 55: repetition 2
    engine.advance_slot();
    // Advance slot 56: repetition 3
    engine.advance_slot();
    // Advance slot 57: completed!
    engine.advance_slot();

    assert_eq!(engine.processes[0].state, NtnHarqProcessState::Completed);
    assert_eq!(engine.processes[0].blind_repetitions_done, 3);
    assert!(engine.telemetry().stall_slots_avoided_count >= 1);
}

#[test]
fn test_buffer_stalling_prevention_over_leo_geo_delay() {
    // GEO satellite: 540 ms RTT -> k_offset = 540 slots
    let mut geo_sib19 = create_mock_leo_sib19();
    geo_sib19.orbit_type = SatelliteOrbitType::Geo;
    geo_sib19.k_offset_slots = 540;

    let ue_pos = [0.0, 0.0, 6_371_000.0];

    // Case A: Conventional 16 processes with feedback enabled
    let mut engine_16 = NtnHarqEngine::new(0x0003, geo_sib19.clone(), ue_pos, 16).unwrap();
    for _ in 0..16 {
        assert!(engine_16.schedule_uplink_grant(4, 512).is_ok());
    }
    // Stalled immediately on the 17th grant!
    assert!(engine_16.is_stalled());
    assert!(engine_16.schedule_uplink_grant(4, 512).is_err());

    // Case B: Extended 32 processes with feedback disabled (Blind Retransmissions)
    let mut engine_32_blind = NtnHarqEngine::new(0x0004, geo_sib19, ue_pos, 32).unwrap();
    for id in 0..32 {
        engine_32_blind
            .configure_harq_feedback(id, false, 1)
            .unwrap();
    }

    // Transmit across multiple slots without stalling
    for _ in 0..32 {
        assert!(engine_32_blind.schedule_uplink_grant(4, 512).is_ok());
    }
    assert_eq!(engine_32_blind.telemetry().total_scheduled_grants, 32);
    assert!(engine_32_blind.telemetry().stall_slots_avoided_count >= 32);
}

#[test]
fn test_autonomous_timing_advance_and_doppler_drift() {
    let sib19 = create_mock_leo_sib19();
    let ue_pos = [0.0, 0.0, 6_371_000.0];
    let mut engine = NtnHarqEngine::new(0x0005, sib19, ue_pos, 16).unwrap();

    let tracker = &engine.ta_tracker;
    // Direct overhead distance: 6,971,000 - 6,371,000 = 600,000 m = 600 km
    assert!((tracker.current_slant_range_km - 600.0).abs() < 1e-3);
    assert_eq!(tracker.step_threshold_us, DEFAULT_TA_STEP_THRESHOLD_US);

    // Initial Doppler at broadside (velocity orthogonal to line of sight) is near 0
    assert!(tracker.current_doppler_shift_hz.abs() < 1.0);

    // Simulate 5 seconds of orbital motion along Y-axis
    let adj = engine.update_satellite_orbit(5.0);
    // As satellite moves away, slant range increases and radial velocity becomes non-zero
    assert!(engine.ta_tracker.current_slant_range_km > 600.0);
    assert!(engine.ta_tracker.current_radial_velocity_mps > 0.0);
    assert!(engine.ta_tracker.current_doppler_shift_hz != 0.0);

    // TA drift occurred
    if adj.is_some() {
        assert!(engine.telemetry().autonomous_ta_updates_count >= 1);
    }
}

#[test]
fn test_k_offset_uplink_grant_timing() {
    let sib19 = create_mock_leo_sib19();
    let ue_pos = [0.0, 0.0, 6_371_000.0];
    let mut engine = NtnHarqEngine::new(0x0006, sib19, ue_pos, 16).unwrap();

    engine.advance_slots(100);
    assert_eq!(engine.current_slot, 100);

    // Grant scheduled at current_slot(100) + k2(4) + k_offset(50) = 154
    let (proc_id, target_slot) = engine.schedule_uplink_grant(4, 1000).unwrap();
    assert_eq!(proc_id, 0);
    assert_eq!(target_slot, 154);

    let proc = &engine.processes[0];
    assert!(proc.ndi); // Toggled NDI
    assert_eq!(proc.payload_size_bytes, 1000);
}
