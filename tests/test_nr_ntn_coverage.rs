//! Integration tests for 3GPP Release 18 NTN Uplink Coverage Enhancement & Adaptive Repetition Engine.

use toy_tcpip::nr_ntn_coverage::{
    DmrsBundlingAuditor, NtnCoverageEngine, NtnDmrsBundleConfig, NtnFreqHopConfig,
    NtnFreqHoppingPatternGenerator, NtnModulationOrder, NtnSatelliteGeometry,
    NtnSlantRangeAdaptiveServo, PucchMultiSlotRepetitionManager, TBoMsCodingEngine,
};

#[test]
fn test_ntn_orbital_slant_range_and_fspl() {
    let leo = NtnSatelliteGeometry::new_leo_600km(2.0e9); // 2 GHz S-band

    // At zenith (90 degrees), slant range must equal orbital altitude (600 km)
    let slant_zenith = leo
        .slant_range_km(90.0)
        .expect("Zenith calculation should succeed");
    assert!(
        (slant_zenith - 600.0).abs() < 0.1,
        "Zenith slant range should be 600 km, got {slant_zenith}"
    );

    // At 10 degrees elevation, slant range is significantly longer (~1930 km)
    let slant_horizon = leo
        .slant_range_km(10.0)
        .expect("10 deg calculation should succeed");
    assert!(
        slant_horizon > 1800.0 && slant_horizon < 2100.0,
        "10 deg slant range unexpected: {slant_horizon} km"
    );

    // Pathloss at 10 deg must be higher than at zenith
    let pl_zenith = leo.total_pathloss_db(90.0).unwrap();
    let pl_horizon = leo.total_pathloss_db(10.0).unwrap();
    let pl_diff = pl_horizon - pl_zenith;
    assert!(
        pl_diff > 9.0 && pl_diff < 12.0,
        "Pathloss increase at 10 deg should be ~10 dB, got {pl_diff:.2} dB"
    );

    // GEO satellite test
    let geo = NtnSatelliteGeometry::new_geo_35786km(2.0e9);
    let geo_zenith = geo.slant_range_km(90.0).unwrap();
    assert!((geo_zenith - 35786.0).abs() < 1.0);
}

#[test]
fn test_dmrs_bundling_cross_slot_phase_continuity() {
    let bundle_cfg = NtnDmrsBundleConfig {
        nominal_bundle_size: 4,
        max_phase_drift_rad: 0.785, // pi/4
        max_power_step_db: 0.5,
    };
    let mut auditor = DmrsBundlingAuditor::new(bundle_cfg);

    // Slot 0: first slot starts bundle
    let s0 = auditor.audit_slot(0, 23.0, 10, 0.0);
    assert!(!s0.is_bundled_with_prev);
    assert_eq!(s0.current_bundle_length, 1);

    // Slot 1: continuous transmission
    let s1 = auditor.audit_slot(1, 23.1, 10, 0.1);
    assert!(s1.is_bundled_with_prev);
    assert_eq!(s1.current_bundle_length, 2);
    assert!((s1.accumulated_snr_gain_db - 3.01).abs() < 0.1); // 10*log10(2) = 3.01 dB

    // Slot 2: continuous transmission
    let s2 = auditor.audit_slot(2, 23.2, 10, 0.1);
    assert!(s2.is_bundled_with_prev);
    assert_eq!(s2.current_bundle_length, 3);

    // Slot 3: reaches 4-slot bundle
    let s3 = auditor.audit_slot(3, 23.0, 10, -0.05);
    assert!(s3.is_bundled_with_prev);
    assert_eq!(s3.current_bundle_length, 4);
    assert!((s3.accumulated_snr_gain_db - 6.02).abs() < 0.1); // 10*log10(4) = 6.02 dB

    // Slot 4: exceeds nominal bundle size -> bundle resets
    let s4 = auditor.audit_slot(4, 23.0, 10, 0.0);
    assert!(!s4.is_bundled_with_prev);
    assert_eq!(s4.current_bundle_length, 1);
    assert!(
        s4.phase_break_reason
            .unwrap()
            .contains("Nominal bundle size boundary")
    );

    // Slot 5: power step too large (23.0 -> 24.0 dBm, step = 1.0 dB > 0.5 dB)
    let s5 = auditor.audit_slot(5, 24.0, 10, 0.0);
    assert!(!s5.is_bundled_with_prev);
    assert!(s5.phase_break_reason.unwrap().contains("Power step"));
}

#[test]
fn test_tboms_joint_rate_matching_gain() {
    let engine = TBoMsCodingEngine::new();

    let tbs_bits = 2400;
    let re_per_slot = 1200; // e.g. 100 PRBs
    let qm = NtnModulationOrder::Qpsk; // 2 bits/RE -> 2400 bits/slot

    // With 1 slot: effective rate = 2400 / 2400 = 1.0, gain = 0 dB
    let (rate1, gain1) = engine.evaluate_tboms(tbs_bits, re_per_slot, qm, 1);
    assert!((rate1 - 1.0).abs() <= 0.01);
    assert_eq!(gain1, 0.0);

    // With TBoMS over K = 8 slots:
    // Total coded bits = 8 * 2400 = 19200
    // Effective code rate = 2400 / 19200 = 0.125
    let (rate8, gain8) = engine.evaluate_tboms(tbs_bits, re_per_slot, qm, 8);
    assert!((rate8 - 0.125).abs() < 1e-4);
    assert!(
        gain8 > 2.0 && gain8 <= 3.0,
        "Coding gain should be between 2.0 and 3.0 dB, got {gain8:.2} dB"
    );
}

#[test]
fn test_inter_slot_frequency_hopping_with_bundled_boundaries() {
    let config = NtnFreqHopConfig {
        enabled: true,
        hop0_prb: 15,
        hop1_prb: 65,
        slots_per_hop: 4, // 4-slot hop period matching 4-slot DMRS bundle
    };
    let generator = NtnFreqHoppingPatternGenerator::new(config);

    // First bundle (slots 0..3) -> hop 0
    for slot in 0..4 {
        assert_eq!(generator.get_prb_offset(slot), 15);
    }

    // Second bundle (slots 4..7) -> hop 1
    for slot in 4..8 {
        assert_eq!(generator.get_prb_offset(slot), 65);
    }

    // Third bundle (slots 8..11) -> hop 0
    for slot in 8..12 {
        assert_eq!(generator.get_prb_offset(slot), 15);
    }
}

#[test]
fn test_pucch_multi_slot_repetition_and_cyclic_shift_hopping() {
    let pucch_mgr =
        PucchMultiSlotRepetitionManager::new(4, 2).expect("PUCCH creation should succeed");

    // Cyclic shift hops across repetitions: (2 + k * 3) % 12
    let cs0 = pucch_mgr.get_cyclic_shift(0);
    let cs1 = pucch_mgr.get_cyclic_shift(1);
    let cs2 = pucch_mgr.get_cyclic_shift(2);
    let cs3 = pucch_mgr.get_cyclic_shift(3);

    assert_eq!(cs0, 2);
    assert_eq!(cs1, 5);
    assert_eq!(cs2, 8);
    assert_eq!(cs3, 11);
}

#[test]
fn test_slant_range_adaptive_repetition_servo() {
    let geo = NtnSatelliteGeometry::new_leo_600km(2.0e9);
    let servo = NtnSlantRangeAdaptiveServo::new(
        geo, 23.0,  // 23 dBm PCMAX
        4.0,   // Sat G/T = 4.0 dB/K
        12.0,  // Target SINR = 12 dB (high throughput)
        180e3, // 1 PRB (180 kHz)
    );

    // High elevation (80 degrees near zenith): short slant range -> low repetition factor (1 or 2)
    let (k_zenith, _b_zenith, _p_zenith, margin_zenith) = servo.adapt_for_elevation(80.0).unwrap();
    assert!(
        k_zenith <= 2,
        "Zenith repetition should be low, got {k_zenith}"
    );
    assert!(
        margin_zenith > 0.0,
        "Margin at zenith should be positive: {margin_zenith:.2} dB"
    );

    // Low elevation (10 degrees near horizon): high slant range -> high repetition factor (8 or 16)
    let (k_horizon, _b_horizon, p_horizon, margin_horizon) =
        servo.adapt_for_elevation(10.0).unwrap();
    assert!(
        k_horizon >= 8,
        "Near horizon repetition should be high (>=8), got {k_horizon}"
    );
    assert_eq!(p_horizon, 23.0, "Power at horizon must be maximum (23 dBm)");
    assert!(
        margin_horizon > -1.0,
        "Repetition should restore link margin, got {margin_horizon:.2} dB"
    );
}

#[test]
fn test_end_to_end_ntn_coverage_engine_coordinator() {
    let geo = NtnSatelliteGeometry::new_leo_600km(2.0e9);
    let dmrs_cfg = NtnDmrsBundleConfig {
        nominal_bundle_size: 4,
        max_phase_drift_rad: 0.785,
        max_power_step_db: 0.5,
    };
    let hop_cfg = NtnFreqHopConfig {
        enabled: true,
        hop0_prb: 20,
        hop1_prb: 80,
        slots_per_hop: 4,
    };

    let mut engine = NtnCoverageEngine::new(geo, dmrs_cfg, hop_cfg, 23.0, 4.0, -3.0, 180e3);

    // Transmit 8 slots with frequency hopping at slot 4
    for slot in 0..8 {
        let (prb, status) = engine.transmit_uplink_slot(slot, 23.0, 0.05);
        if slot < 4 {
            assert_eq!(prb, 20);
        } else {
            assert_eq!(prb, 80);
        }

        if slot == 0 || slot == 4 {
            assert!(!status.is_bundled_with_prev);
        } else {
            assert!(status.is_bundled_with_prev);
        }
    }

    assert_eq!(engine.metrics.total_transmitted_slots, 8);
    assert_eq!(engine.metrics.dmrs_bundled_slots, 6); // 3 bundled in first half + 3 in second half
}
