//! Comprehensive Integration Tests for 3GPP Rel-18 P-PUT (Pre-configured Positioning Uplink Transmission).
//! Standards Reference: 3GPP TS 38.305, TS 38.331, TS 38.211, TS 38.213, TS 38.214 Rel-18.

use toy_tcpip::nr_pput_positioning::{
    HybridTdoaAoaSolver, PPUT_SPEED_OF_LIGHT_M_S, PputBenchmarkEngine, PputCombSize, PputError,
    PputPositioningEngine, PputPowerConfig, PputPowerController, PputResource,
    PputValidityCriteria, TaValidationState, TaValidityTracker, TrpMeasurement,
};

#[test]
fn test_pput_resource_configuration_and_validation() {
    // 1. Valid Comb-4 resource
    let res = PputResource::new(
        1,
        PputCombSize::Comb4,
        2, // cyclic shift < 4
        0,
        48,
        2,
        1,
        1001,
    )
    .expect("Valid Comb-4 resource configuration should succeed");

    assert_eq!(res.resource_id, 1);
    assert_eq!(res.comb_size, PputCombSize::Comb4);
    assert_eq!(res.cyclic_shift, 2);
    assert_eq!(res.num_prbs, 48);

    // 2. Cyclic shift exceeding comb size
    let cs_err = PputResource::new(2, PputCombSize::Comb2, 2, 0, 48, 2, 1, 1002);
    assert!(matches!(cs_err, Err(PputError::ConfigurationError(_))));

    // 3. Invalid PRBs: 0 or > 273
    let prb_zero = PputResource::new(3, PputCombSize::Comb4, 0, 0, 0, 2, 1, 1003);
    assert!(matches!(prb_zero, Err(PputError::InvalidBandwidth(0))));

    let prb_overflow = PputResource::new(4, PputCombSize::Comb4, 0, 0, 300, 2, 1, 1004);
    assert!(matches!(
        prb_overflow,
        Err(PputError::InvalidBandwidth(300))
    ));

    // 4. Invalid symbol count (valid: 1, 2, 4)
    let sym_err = PputResource::new(5, PputCombSize::Comb4, 0, 0, 48, 3, 1, 1005);
    assert!(matches!(sym_err, Err(PputError::ConfigurationError(_))));

    // 5. Invalid antenna ports (valid: 1, 2, 4)
    let port_err = PputResource::new(6, PputCombSize::Comb4, 0, 0, 48, 2, 3, 1006);
    assert!(matches!(port_err, Err(PputError::ConfigurationError(_))));
}

#[test]
fn test_autonomous_ta_validity_tracker() {
    let criteria = PputValidityCriteria {
        ta_validity_timer_ms: 5000,
        rsrp_change_threshold_db: 5.0,
        max_consecutive_transmissions: 4,
    };

    let mut tracker = TaValidityTracker::new(criteria, -85.0);

    // State 1: Freshly initialized
    assert_eq!(tracker.evaluate_validity(), TaValidationState::Valid);

    // State 2: Progress time within boundary (2000 ms), small RSRP drift (2.0 dB)
    tracker.update_radio_conditions(2000, -87.0);
    tracker.record_transmission();
    assert_eq!(tracker.evaluate_validity(), TaValidationState::Valid);

    // State 3: Excessive RSRP drift (> 5.0 dB from baseline -85.0)
    tracker.update_radio_conditions(500, -91.5); // drift = 6.5 dB
    assert!(matches!(
        tracker.evaluate_validity(),
        TaValidationState::ExcessiveRsrpDrift { .. }
    ));

    // Refresh TA resets baseline and drift
    tracker.refresh_ta(-90.0);
    assert_eq!(tracker.evaluate_validity(), TaValidationState::Valid);

    // State 4: Timer expiry (> 5000 ms)
    tracker.update_radio_conditions(5500, -90.5);
    assert!(matches!(
        tracker.evaluate_validity(),
        TaValidationState::ExpiredTimer { .. }
    ));

    // Refresh TA resets timer
    tracker.refresh_ta(-90.0);
    assert_eq!(tracker.evaluate_validity(), TaValidationState::Valid);

    // State 5: Max consecutive transmissions exceeded
    for _ in 0..4 {
        tracker.record_transmission();
    }
    assert!(matches!(
        tracker.evaluate_validity(),
        TaValidationState::MaxTransmissionsExceeded { .. }
    ));

    // Refresh TA clears transmission count
    tracker.refresh_ta(-90.0);
    assert_eq!(tracker.evaluate_validity(), TaValidationState::Valid);
}

#[test]
fn test_pput_open_loop_power_control() {
    let power_cfg = PputPowerConfig {
        p0_srs_dbm: -80.0,
        alpha_srs: 0.8,
        pcmax_dbm: 23.0,
    };
    let controller = PputPowerController::new(power_cfg);

    // Test case 1: Pathloss = 90 dB, 48 PRBs, 1 port
    // P_SRS = -80 + 0.8 * 90 + 10 * log10(48) + 10 * log10(1)
    // = -80 + 72 + 16.8124 + 0 = 8.8124 dBm (< 23 dBm)
    let p_tx1 = controller.calculate_power(90.0, 48, 1);
    let expected1 = -80.0 + 0.8 * 90.0 + 10.0 * (48.0_f64.log10());
    assert!((p_tx1 - expected1).abs() < 1e-3);

    // Test case 2: Deep pathloss = 130 dB, 96 PRBs, 2 ports (Hits Pcmax limit)
    // P_open = -80 + 0.8 * 130 + 10*log10(96) + 10*log10(2)
    // = -80 + 104 + 19.8227 + 3.0103 = 46.833 dBm -> clamped to 23.0 dBm
    let p_tx2 = controller.calculate_power(130.0, 96, 2);
    assert_eq!(p_tx2, 23.0);
}

#[test]
fn test_hybrid_tdoa_aoa_3d_multilateration_solver() {
    // 4 TRPs distributed in 3D space around a cell
    let trps: [(u32, f64, f64, f64); 4] = [
        (0, 0.0, 0.0, 25.0),
        (1, 100.0, 0.0, 30.0),
        (2, 0.0, 100.0, 20.0),
        (3, 100.0, 100.0, 28.0),
    ];

    // Ground truth UE position
    let true_x: f64 = 42.0;
    let true_y: f64 = 58.0;
    let true_z: f64 = 1.5;

    let c = PPUT_SPEED_OF_LIGHT_M_S;
    let mut measurements = Vec::new();

    for &(id, tx, ty, tz) in &trps {
        let dx = true_x - tx;
        let dy = true_y - ty;
        let dz = true_z - tz;
        let dist = (dx * dx + dy * dy + dz * dz).sqrt();
        let rtoa = dist / c;
        let az = dy.atan2(dx);
        let el = dz.atan2((dx * dx + dy * dy).sqrt());

        measurements.push(TrpMeasurement {
            trp_id: id,
            pos_x: tx,
            pos_y: ty,
            pos_z: tz,
            rtoa_seconds: rtoa,
            azimuth_rad: az,
            elevation_rad: el,
            srs_rsrp_dbm: -85.0,
        });
    }

    let solver = HybridTdoaAoaSolver::default();
    let estimate = solver
        .solve(&measurements)
        .expect("Hybrid TDOA/AoA solver should converge");

    let err_x = (estimate.x - true_x).abs();
    let err_y = (estimate.y - true_y).abs();
    let err_z = (estimate.z - true_z).abs();
    let total_pos_err = (err_x * err_x + err_y * err_y + err_z * err_z).sqrt();

    assert!(
        total_pos_err < 0.1,
        "Position error {total_pos_err:.4} m exceeds 10 cm target"
    );
    assert!(estimate.iterations < 25);
    assert!(estimate.residual_rms_m < 1e-4);

    // Test minimum 2 TRPs: still solvable with hybrid TDOA + AoA
    let estimate_2trp = solver
        .solve(&measurements[0..2])
        .expect("2-TRP hybrid solver should converge");
    let err_2trp = ((estimate_2trp.x - true_x).powi(2)
        + (estimate_2trp.y - true_y).powi(2)
        + (estimate_2trp.z - true_z).powi(2))
    .sqrt();
    assert!(
        err_2trp < 0.2,
        "2-TRP hybrid error {err_2trp:.4} m exceeds 20 cm target"
    );

    // Insufficient TRPs (< 2) returns error
    let single_trp = &measurements[0..1];
    let err = solver.solve(single_trp);
    assert!(matches!(
        err,
        Err(PputError::InsufficientMeasurements {
            required: 2,
            provided: 1
        })
    ));
}

#[test]
fn test_energy_and_latency_benchmarking() {
    let bench = PputBenchmarkEngine::new();
    let comparison = bench.evaluate_savings();

    assert_eq!(comparison.legacy_latency_ms, 200.0);
    assert_eq!(comparison.pput_latency_ms, 3.0);
    assert!(
        comparison.latency_reduction_ratio > 60.0,
        "Latency reduction should exceed 60x"
    );

    assert_eq!(comparison.legacy_energy_mj, 110.0);
    assert_eq!(comparison.pput_energy_mj, 1.2);
    assert!(
        comparison.energy_savings_percentage > 98.0,
        "Energy savings percentage should exceed 98%"
    );
}

#[test]
fn test_end_to_end_pput_positioning_engine_coordinator() {
    let res = PputResource::new(1, PputCombSize::Comb4, 0, 0, 48, 2, 1, 2024)
        .expect("Valid P-PUT resource");

    let criteria = PputValidityCriteria {
        ta_validity_timer_ms: 6000,
        rsrp_change_threshold_db: 4.0,
        max_consecutive_transmissions: 5,
    };

    let power_cfg = PputPowerConfig {
        p0_srs_dbm: -82.0,
        alpha_srs: 0.8,
        pcmax_dbm: 23.0,
    };

    let mut engine = PputPositioningEngine::new(res, criteria, -80.0, power_cfg);

    // 1. Initial autonomous transmission succeeds
    let tx_power = engine
        .attempt_pput_transmission(85.0)
        .expect("Autonomous transmission should succeed");
    assert!(tx_power > 0.0);
    assert_eq!(engine.metrics.total_positioning_requests, 1);
    assert_eq!(engine.metrics.autonomous_pput_transmissions, 1);
    assert_eq!(engine.metrics.fallback_to_rach_events, 0);
    assert!(engine.metrics.total_energy_saved_joules > 0.1);

    // 2. Simulate excessive RSRP drift causing RACH fallback
    engine.ta_tracker.update_radio_conditions(100, -88.0); // 8 dB drift > 4 dB threshold
    let fail_res = engine.attempt_pput_transmission(85.0);
    assert!(matches!(fail_res, Err(PputError::TaValidationFailed(_))));
    assert_eq!(engine.metrics.fallback_to_rach_events, 1);

    // 3. Refresh TA restores validity
    engine.ta_tracker.refresh_ta(-88.0);
    let ok_res = engine.attempt_pput_transmission(85.0);
    assert!(ok_res.is_ok());
    assert_eq!(engine.metrics.autonomous_pput_transmissions, 2);

    // 4. Multi-TRP positioning estimation via engine
    let trps: [(u32, f64, f64, f64); 3] = [
        (10, 0.0, 0.0, 20.0),
        (11, 80.0, 0.0, 25.0),
        (12, 0.0, 80.0, 22.0),
    ];
    let ue_true: (f64, f64, f64) = (30.0, 30.0, 1.5);
    let c = PPUT_SPEED_OF_LIGHT_M_S;

    let measurements: Vec<TrpMeasurement> = trps
        .iter()
        .map(|&(id, tx, ty, tz)| {
            let dx = ue_true.0 - tx;
            let dy = ue_true.1 - ty;
            let dz = ue_true.2 - tz;
            let dist = (dx * dx + dy * dy + dz * dz).sqrt();
            TrpMeasurement {
                trp_id: id,
                pos_x: tx,
                pos_y: ty,
                pos_z: tz,
                rtoa_seconds: dist / c,
                azimuth_rad: dy.atan2(dx),
                elevation_rad: dz.atan2((dx * dx + dy * dy).sqrt()),
                srs_rsrp_dbm: -80.0,
            }
        })
        .collect();

    let pos = engine
        .compute_position(&measurements)
        .expect("Position computation should succeed");
    assert!((pos.x - ue_true.0).abs() < 0.1);
    assert!((pos.y - ue_true.1).abs() < 0.1);
    assert!((pos.z - ue_true.2).abs() < 0.1);
    assert_eq!(engine.metrics.successful_position_fixes, 1);
}
