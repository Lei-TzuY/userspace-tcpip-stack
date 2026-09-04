//! Integration tests for 3GPP Rel-18 5G NR Carrier Phase Positioning & RTK Engine.

use toy_tcpip::nr_carrier_phase_rtk::{
    CarrierPhaseError, CarrierPhaseObservation, CarrierPhaseRtkSolver, Cartesian3D,
    CycleSlipDetector, LambdaAmbiguitySolver, RTK_CYCLE_SLIP_THRESHOLD_CYCLES,
    RTK_DEFAULT_AMBIGUITY_RATIO_THRESHOLD, RTK_DEFAULT_CARRIER_FREQ_HZ, RTK_SPEED_OF_LIGHT_M_S,
    RtkFixStatus, TrpCarrierPhaseConfig,
};

#[test]
fn test_carrier_phase_observation_and_wavelength() {
    // 1. Frequency to wavelength conversions
    // 3.5 GHz (Band n78): lambda = 299,792,458 / 3.5e9 = 0.085654988 m (~8.57 cm)
    let trp_n78 = TrpCarrierPhaseConfig::new(
        1,
        Cartesian3D::new(0.0, 0.0, 10.0),
        RTK_DEFAULT_CARRIER_FREQ_HZ,
    )
    .expect("Valid TRP configuration");

    assert_eq!(trp_n78.trp_id, 1);
    assert!((trp_n78.wavelength_m - 0.085654988).abs() < 1e-6);

    // 28 GHz mmWave (Band n257): lambda = 299,792,458 / 28e9 = 0.01070687 m (~1.07 cm)
    let trp_mmwave =
        TrpCarrierPhaseConfig::new(2, Cartesian3D::new(10.0, 20.0, 15.0), 28_000_000_000.0)
            .expect("Valid mmWave TRP");
    assert!((trp_mmwave.wavelength_m - 0.01070687).abs() < 1e-6);

    // Invalid zero or negative frequency rejection
    let err_zero = TrpCarrierPhaseConfig::new(3, Cartesian3D::ZERO, 0.0).unwrap_err();
    assert_eq!(err_zero, CarrierPhaseError::InvalidFrequency(0.0));

    // 2. Carrier phase observation creation
    let obs = CarrierPhaseObservation::new(1, 12543.82, 32.5, 1_000_000, false);
    assert_eq!(obs.trp_id, 1);
    assert_eq!(obs.carrier_phase_cycles, 12543.82);
    assert_eq!(obs.snr_db, 32.5);
    assert!(!obs.half_cycle_ambiguity);
}

#[test]
fn test_single_and_double_differencing_clock_bias_elimination() {
    let lambda = 0.085654988; // 3.5 GHz wavelength

    // Coordinates:
    let trp0_loc = Cartesian3D::new(0.0, 0.0, 20.0);
    let trp1_loc = Cartesian3D::new(100.0, 0.0, 25.0);

    let target_pos = Cartesian3D::new(45.0, 60.0, 1.5);
    let ref_pos = Cartesian3D::new(10.0, 10.0, 0.0);

    // Geometric ranges
    let rho_tgt_0 = target_pos.distance_to(&trp0_loc);
    let rho_tgt_1 = target_pos.distance_to(&trp1_loc);
    let rho_ref_0 = ref_pos.distance_to(&trp0_loc);
    let rho_ref_1 = ref_pos.distance_to(&trp1_loc);

    // Realistic oscillator clock offsets (in seconds)
    let ue_tgt_clock_bias = 0.000012345; // Target UE local clock bias
    let ue_ref_clock_bias = -0.000004567; // Reference Station clock bias
    let trp0_clock_bias = 0.000000100;
    let trp1_clock_bias = 0.000000250;

    let c = RTK_SPEED_OF_LIGHT_M_S;

    // Integer ambiguities
    let n_tgt_0 = 1000;
    let n_tgt_1 = 1500;
    let n_ref_0 = 800;
    let n_ref_1 = 1200;

    // Raw Carrier Phase Observations: phi = (rho + c*(dt_rx - dt_tx)) / lambda + N
    let phi_tgt_0 =
        (rho_tgt_0 + c * (ue_tgt_clock_bias - trp0_clock_bias)) / lambda + (n_tgt_0 as f64);
    let phi_tgt_1 =
        (rho_tgt_1 + c * (ue_tgt_clock_bias - trp1_clock_bias)) / lambda + (n_tgt_1 as f64);

    let phi_ref_0 =
        (rho_ref_0 + c * (ue_ref_clock_bias - trp0_clock_bias)) / lambda + (n_ref_0 as f64);
    let phi_ref_1 =
        (rho_ref_1 + c * (ue_ref_clock_bias - trp1_clock_bias)) / lambda + (n_ref_1 as f64);

    // 1. Single Difference (Target): phi_tgt_1 - phi_tgt_0
    let sd_tgt = phi_tgt_1 - phi_tgt_0;
    // Theoretical SD: ((rho1 - rho0) - c*(dt1 - dt0)) / lambda + (N1 - N0)
    let expected_sd_tgt = ((rho_tgt_1 - rho_tgt_0) - c * (trp1_clock_bias - trp0_clock_bias))
        / lambda
        + ((n_tgt_1 - n_tgt_0) as f64);
    assert!(
        (sd_tgt - expected_sd_tgt).abs() < 1e-9,
        "Single differencing must completely eliminate Target UE receiver clock bias!"
    );

    // 2. Double Difference: (phi_tgt_1 - phi_tgt_0) - (phi_ref_1 - phi_ref_0)
    let sd_ref = phi_ref_1 - phi_ref_0;
    let dd_actual = sd_tgt - sd_ref;

    // Theoretical DD: [ (rho_tgt_1 - rho_tgt_0) - (rho_ref_1 - rho_ref_0) ] / lambda + DD_N
    let dd_n = (n_tgt_1 - n_tgt_0) - (n_ref_1 - n_ref_0);
    let expected_dd = ((rho_tgt_1 - rho_tgt_0) - (rho_ref_1 - rho_ref_0)) / lambda + (dd_n as f64);

    assert!(
        (dd_actual - expected_dd).abs() < 1e-9,
        "Double differencing must completely cancel BOTH receiver and transmitter clock biases!"
    );
}

#[test]
fn test_cycle_slip_detection_and_repair() {
    let mut detector = CycleSlipDetector::new();
    let trp_id = 42;
    let lambda = 0.085654988;

    // Epoch 1: Initial lock at t = 0 ms, distance = 100.0 m, phase = 100.0 / lambda = 1167.47
    let initial_dist = 100.0;
    let initial_phase = initial_dist / lambda;
    let obs1 = CarrierPhaseObservation::new(trp_id, initial_phase, 30.0, 0, false);
    let res1 = detector.check_and_update(&obs1, initial_dist, lambda);
    assert!(res1.is_ok());

    // Epoch 2: Smooth motion at t = 20 ms, displaced by 0.04 m (phase +0.467 cycles)
    let dist2 = 100.04;
    let phase2 = dist2 / lambda;
    let obs2 = CarrierPhaseObservation::new(trp_id, phase2, 30.0, 20_000_000, false);
    let res2 = detector.check_and_update(&obs2, dist2, lambda);
    assert!(res2.is_ok());

    // Epoch 3: Cycle slip injected (sudden jump of +1.0 full cycle)
    let dist3 = 100.08;
    let phase3 = (dist3 / lambda) + 1.0; // Injected 1-cycle slip
    let obs3 = CarrierPhaseObservation::new(trp_id, phase3, 30.0, 40_000_000, false);
    let res3 = detector.check_and_update(&obs3, dist3, lambda);

    // Should detect the cycle slip
    assert!(res3.is_err());
    match res3.unwrap_err() {
        CarrierPhaseError::CycleSlipDetected {
            trp_id: tid,
            residual_cycles,
        } => {
            assert_eq!(tid, trp_id);
            assert!(residual_cycles > 0.4);
        }
        other => panic!("Expected CycleSlipDetected error, got: {:?}", other),
    }

    // Reset TRP after slip handling
    detector.reset_trp(trp_id);
    let obs4 = CarrierPhaseObservation::new(trp_id, phase3, 30.0, 60_000_000, false);
    assert!(detector.check_and_update(&obs4, dist3, lambda).is_ok());
}

#[test]
fn test_lambda_integer_ambiguity_resolution() {
    let solver = LambdaAmbiguitySolver::new(RTK_DEFAULT_AMBIGUITY_RATIO_THRESHOLD);

    // 1. Float ambiguities that are close to true integers [5, -12, 42]
    let float_ambiguities = vec![5.02, -11.97, 42.01];
    let (int_cand, ratio, is_fixed) = solver
        .resolve_ambiguities(&float_ambiguities)
        .expect("Resolution should succeed");

    assert_eq!(int_cand, vec![5, -12, 42]);
    assert!(
        ratio > 10.0,
        "High ratio indicates distinct integer solution"
    );
    assert!(is_fixed);

    // 2. Ambiguous float values near half-cycles [3.49, 7.50]
    let float_ambiguous = vec![3.49, 7.50];
    let (int_cand_amb, ratio_amb, is_fixed_amb) = solver
        .resolve_ambiguities(&float_ambiguous)
        .expect("Resolution runs");

    assert_eq!(int_cand_amb, vec![3, 8]);
    assert!(
        ratio_amb < RTK_DEFAULT_AMBIGUITY_RATIO_THRESHOLD,
        "Ambiguous candidates must produce low ratio below threshold"
    );
    assert!(!is_fixed_amb);
}

#[test]
fn test_centimeter_accuracy_rtk_position_solver() {
    let lambda = 0.085654988; // 3.5 GHz
    let freq = RTK_DEFAULT_CARRIER_FREQ_HZ;

    // 4 TRPs distributed in 3D space around the area
    let trp0 = TrpCarrierPhaseConfig::new(10, Cartesian3D::new(0.0, 0.0, 20.0), freq).unwrap();
    let trp1 = TrpCarrierPhaseConfig::new(11, Cartesian3D::new(120.0, 0.0, 18.0), freq).unwrap();
    let trp2 = TrpCarrierPhaseConfig::new(12, Cartesian3D::new(0.0, 150.0, 22.0), freq).unwrap();
    let trp3 = TrpCarrierPhaseConfig::new(13, Cartesian3D::new(140.0, 160.0, 25.0), freq).unwrap();

    let mut solver =
        CarrierPhaseRtkSolver::new(vec![trp0.clone(), trp1.clone(), trp2.clone(), trp3.clone()]);

    // Ground-truth coordinates:
    let reference_pos = Cartesian3D::new(20.0, 20.0, 0.0);
    let true_target_pos = Cartesian3D::new(65.432, 48.765, 1.500);

    // Known integer ambiguities for double difference pairs
    let n_pairs = [120, -85, 340]; // for TRP1, TRP2, TRP3 relative to TRP0

    // Generate synthetic observations
    let trps = [&trp0, &trp1, &trp2, &trp3];
    let mut ref_obs = Vec::new();
    let mut tgt_obs = Vec::new();

    let ref_d0 = reference_pos.distance_to(&trp0.location);
    let tgt_d0 = true_target_pos.distance_to(&trp0.location);

    // Reference TRP0 observations
    ref_obs.push(CarrierPhaseObservation::new(
        trp0.trp_id,
        ref_d0 / lambda,
        35.0,
        1_000_000,
        false,
    ));
    tgt_obs.push(CarrierPhaseObservation::new(
        trp0.trp_id,
        tgt_d0 / lambda,
        34.0,
        1_000_000,
        false,
    ));

    // Remaining TRP observations with double-difference integer ambiguities added
    for (i, trp) in trps[1..].iter().enumerate() {
        let ref_di = reference_pos.distance_to(&trp.location);
        let tgt_di = true_target_pos.distance_to(&trp.location);

        let ref_phase = ref_di / lambda;
        // DD = (tgt_phase - tgt_0) - (ref_phase - ref_0) = (tgt_di - tgt_d0 - ref_di + ref_d0)/lambda + N
        let tgt_phase = (tgt_di - tgt_d0 - ref_di + ref_d0) / lambda
            + (n_pairs[i] as f64)
            + (ref_phase - (ref_d0 / lambda))
            + (tgt_d0 / lambda);

        ref_obs.push(CarrierPhaseObservation::new(
            trp.trp_id, ref_phase, 33.0, 1_000_000, false,
        ));
        tgt_obs.push(CarrierPhaseObservation::new(
            trp.trp_id, tgt_phase, 32.0, 1_000_000, false,
        ));
    }

    // Initial rough guess within ~2 meters of true position
    let initial_guess = Cartesian3D::new(64.0, 50.0, 0.5);

    // Solve RTK position
    let solution = solver
        .solve_double_difference(
            &tgt_obs,
            &ref_obs,
            &reference_pos,
            &initial_guess,
            Some(&n_pairs),
        )
        .expect("RTK position solving must succeed");

    assert_eq!(solution.status, RtkFixStatus::Fixed);
    assert_eq!(solution.num_trps, 4);
    assert!(solution.gdop > 0.0);

    // Verify centimeter accuracy (< 0.02 m = 2 cm deviation from true target)
    let position_error = solution.position.distance_to(&true_target_pos);
    assert!(
        position_error < 0.020,
        "Carrier Phase RTK solution error must be < 2 cm! Got: {:.4} m",
        position_error
    );

    // Check individual coordinate accuracy
    assert!((solution.position.x - true_target_pos.x).abs() < 0.015);
    assert!((solution.position.y - true_target_pos.y).abs() < 0.015);
    assert!((solution.position.z - true_target_pos.z).abs() < 0.020);

    // Check telemetry counters
    assert_eq!(solver.metrics.total_epochs_processed, 1);
    assert_eq!(solver.metrics.fixed_epochs_count, 1);
}

#[test]
fn test_insufficient_trps_and_error_handling() {
    let mut solver = CarrierPhaseRtkSolver::new(Vec::new());
    let ref_pos = Cartesian3D::ZERO;
    let init_guess = Cartesian3D::ZERO;

    // Only 2 observations (need at least 4)
    let obs = vec![
        CarrierPhaseObservation::new(1, 100.0, 20.0, 0, false),
        CarrierPhaseObservation::new(2, 200.0, 20.0, 0, false),
    ];

    let err = solver
        .solve_double_difference(&obs, &obs, &ref_pos, &init_guess, None)
        .unwrap_err();

    match err {
        CarrierPhaseError::InsufficientTrps { needed, available } => {
            assert_eq!(needed, 4);
            assert_eq!(available, 0); // 0 common TRPs in network
        }
        other => panic!("Expected InsufficientTrps, got: {:?}", other),
    }

    // Error formatting display tests
    let err_dilution =
        CarrierPhaseError::GeometricDilutionDeficiency("collinear points".to_string());
    assert!(format!("{}", err_dilution).contains("collinear points"));

    let err_conv = CarrierPhaseError::ConvergenceFailure {
        iterations: 30,
        residual_norm: 0.15,
    };
    assert!(format!("{}", err_conv).contains("failed to converge after 30"));

    let err_ratio = CarrierPhaseError::AmbiguityResolutionFailed {
        best_norm: 0.1,
        second_best_norm: 0.2,
        ratio: 2.0,
        threshold: 3.0,
    };
    assert!(format!("{}", err_ratio).contains("ratio 2.00 < threshold 3.00"));

    // Verify constants
    assert_eq!(RTK_SPEED_OF_LIGHT_M_S, 299_792_458.0);
    assert_eq!(RTK_CYCLE_SLIP_THRESHOLD_CYCLES, 0.50);
}
