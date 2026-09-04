//! Integration tests for 3GPP Rel-17/18 5G NR Sidelink Positioning & Direct Ranging Engine.

use toy_tcpip::nr_sidelink_positioning::{
    GoldSequenceGenerator, SPEED_OF_LIGHT_M_S, SlAnchorUe, SlAoAMeasurement, SlCombSize,
    SlKinematicTracker, SlMultilaterationSolver, SlPositioningError, SlPrsConfig, SlRangingSession,
    SlRttMeasurement, SlSessionState,
};

#[test]
fn test_sl_prs_gold_sequence_generation() {
    // 1. Verify 31-bit Gold sequence generator properties
    let mut gold = GoldSequenceGenerator::new(0x1234_5678);
    let bits = gold.generate_bits(64);
    assert_eq!(bits.len(), 64);
    for &b in &bits {
        assert!(b == 0 || b == 1);
    }

    // Two generators with same seed produce identical sequences
    let mut gold1 = GoldSequenceGenerator::new(0x42);
    let mut gold2 = GoldSequenceGenerator::new(0x42);
    assert_eq!(gold1.generate_bits(100), gold2.generate_bits(100));

    // Different seeds produce different sequences
    let mut gold3 = GoldSequenceGenerator::new(0x99);
    assert_ne!(gold1.generate_bits(50), gold3.generate_bits(50));

    // 2. SL-PRS Configuration validation
    let valid_cfg = SlPrsConfig::new(100, SlCombSize::Comb4, 2, 2, 8, 20, 5);
    assert!(valid_cfg.is_ok());

    // Invalid comb offset (>= comb_size)
    let invalid_offset = SlPrsConfig::new(100, SlCombSize::Comb4, 4, 2, 8, 20, 5);
    assert_eq!(
        invalid_offset,
        Err(SlPositioningError::InvalidCombOffset {
            offset: 4,
            comb_size: 4
        })
    );

    // Invalid symbol range (exceeds slot boundary)
    let invalid_sym = SlPrsConfig::new(100, SlCombSize::Comb2, 0, 10, 6, 20, 5);
    assert_eq!(
        invalid_sym,
        Err(SlPositioningError::InvalidSymbolRange {
            start: 10,
            duration: 6
        })
    );

    // 3. Generate symbol RE pattern
    let cfg = valid_cfg.unwrap();
    let re_pattern = cfg.generate_symbol_re_pattern(2);
    // For 20 PRBs, total subcarriers = 20 * 12 = 240.
    // Comb-4 produces 240 / 4 = 60 subcarrier allocations
    assert_eq!(re_pattern.len(), 60);

    // Check first subcarrier index = comb_offset = 2
    assert_eq!(re_pattern[0].0, 2);
    // Check second subcarrier index = 2 + 4 = 6
    assert_eq!(re_pattern[1].0, 6);

    // Verify QPSK symbol power |r|^2 = i^2 + q^2 = 0.5 + 0.5 = 1.0
    for &(_, (i, q)) in &re_pattern {
        let power = i * i + q * q;
        assert!((power - 1.0).abs() < 1e-6);
    }
}

#[test]
fn test_sl_rtt_distance_calculation_and_calibration() {
    // Round trip scenario:
    // t1 (init tx) = 1_000_000.0 ns
    // t2 (resp rx) = 1_000_050.0 ns (50 ns one-way propagation)
    // t3 (resp tx) = 1_005_000.0 ns (4950 ns turnaround time)
    // t4 (init rx) = 1_005_050.0 ns
    // Hardware internal delays: 5.0 ns on initiator, 5.0 ns on responder (total 10.0 ns cal)
    // Net two-way: (5050) - (4950) - 10 = 90.0 ns
    // Net one-way ToF: 45.0 ns
    let rtt = SlRttMeasurement::new(1_000_000.0, 1_000_050.0, 1_005_000.0, 1_005_050.0, 5.0, 5.0);

    let tof_ns = rtt.calculate_tof_ns().unwrap();
    assert_eq!(tof_ns, 45.0);

    let dist_m = rtt.calculate_distance_m().unwrap();
    // 45.0e-9 s * 299792458.0 m/s = 13.49066061 m
    let expected_dist = 45.0e-9 * SPEED_OF_LIGHT_M_S;
    assert!((dist_m - expected_dist).abs() < 1e-5);

    // Negative RTT test (unphysical large calibration overhead)
    let bad_rtt = SlRttMeasurement::new(
        1_000_000.0,
        1_000_050.0,
        1_005_000.0,
        1_005_050.0,
        100.0, // Cal delay exceeds 100 ns net
        100.0,
    );
    assert_eq!(
        bad_rtt.calculate_tof_ns(),
        Err(SlPositioningError::NegativeRttDistance { rtt_ns: -100.0 })
    );
}

#[test]
fn test_sl_aoa_phase_interferometry() {
    let fc = 5.9e9; // 5.9 GHz V2X
    let d = SlAoAMeasurement::half_wavelength(fc);

    // 1. Azimuth = +30.0 degrees
    // delta_phi = 2 * pi * (d / lambda) * sin(30 deg) = pi * 0.5 = pi / 2
    let phase_diff_30deg = std::f64::consts::PI * 0.5;
    let aoa = SlAoAMeasurement::new(phase_diff_30deg, 0.0, fc, d);

    let az_deg = aoa.calculate_azimuth_deg().unwrap();
    assert!((az_deg - 30.0).abs() < 1e-4);

    // Elevation = 0.0
    let el_deg = aoa.calculate_elevation_deg().unwrap();
    assert!((el_deg - 0.0).abs() < 1e-4);

    // 2. Elevation = -15.0 degrees
    let target_el = -15.0f64;
    let phase_diff_neg15 = std::f64::consts::PI * target_el.to_radians().sin();
    let aoa2 = SlAoAMeasurement::new(0.0, phase_diff_neg15, fc, d);

    let el_deg2 = aoa2.calculate_elevation_deg().unwrap();
    assert!((el_deg2 - target_el).abs() < 1e-4);

    // 3. Out of range phase diff (> pi)
    let bad_aoa = SlAoAMeasurement::new(4.5, 0.0, fc, d);
    match bad_aoa.calculate_azimuth_deg() {
        Err(SlPositioningError::AngleOutOfRange(_)) => {}
        _ => panic!("Expected AngleOutOfRange"),
    }
}

#[test]
fn test_multi_anchor_cooperative_multilateration() {
    // 4 Sidelink Anchors with 3D spatial diversity
    let a1 = SlAnchorUe {
        anchor_id: 1,
        x_m: 0.0,
        y_m: 0.0,
        z_m: 0.0,
    };
    let a2 = SlAnchorUe {
        anchor_id: 2,
        x_m: 100.0,
        y_m: 0.0,
        z_m: 50.0,
    };
    let a3 = SlAnchorUe {
        anchor_id: 3,
        x_m: 0.0,
        y_m: 100.0,
        z_m: 50.0,
    };
    let a4 = SlAnchorUe {
        anchor_id: 4,
        x_m: 100.0,
        y_m: 100.0,
        z_m: 0.0,
    };

    // True target location
    let true_x = 30.0;
    let true_y = 40.0;
    let true_z = 20.0;

    let dist = |a: &SlAnchorUe| {
        ((true_x - a.x_m).powi(2) + (true_y - a.y_m).powi(2) + (true_z - a.z_m).powi(2)).sqrt()
    };

    let anchors = vec![
        (a1, dist(&a1)),
        (a2, dist(&a2)),
        (a3, dist(&a3)),
        (a4, dist(&a4)),
    ];

    let solver = SlMultilaterationSolver::default();
    let estimate = solver.solve_position(&anchors, None).unwrap();

    // Verify millimeter position accuracy
    assert!((estimate.x_m - true_x).abs() < 1e-3);
    assert!((estimate.y_m - true_y).abs() < 1e-3);
    assert!((estimate.z_m - true_z).abs() < 1e-3);

    assert!(estimate.residual_rms_m < 1e-4);
    assert!(estimate.gdop > 0.0 && estimate.gdop < 5.0);
    assert!(estimate.iterations_used < 20);

    // Insufficient anchors error (< 3)
    let too_few = vec![(a1, 10.0), (a2, 20.0)];
    assert_eq!(
        solver.solve_position(&too_few, None),
        Err(SlPositioningError::InsufficientAnchors {
            required: 3,
            provided: 2
        })
    );
}

#[test]
fn test_kinematic_tracking_and_uncertainty() {
    // Initial position (10, 5)
    let mut tracker = SlKinematicTracker::new(10.0, 5.0, 5.0, 0.2);

    let dt = 0.5; // 500 ms measurement interval
    let vx_true = 2.0; // 2 m/s
    let vy_true = 1.0; // 1 m/s

    // Simulate 10 time steps
    let mut t = 0.0;
    for _ in 0..10 {
        tracker.predict(dt);
        t += dt;

        let true_x = 10.0 + vx_true * t;
        let true_y = 5.0 + vy_true * t;

        tracker.update_measurement(true_x, true_y, 0.5, dt);
    }

    // Velocity should converge near sqrt(2^2 + 1^2) = 2.236 m/s
    let speed = tracker.speed_mps();
    let true_speed = (vx_true * vx_true + vy_true * vy_true).sqrt();
    assert!((speed - true_speed).abs() < 0.5);

    // Variance should reduce as measurements arrive
    assert!(tracker.pos_variance < 5.0);
}

#[test]
fn test_ranging_session_state_machine() {
    let prs_cfg = SlPrsConfig::new(1, SlCombSize::Comb4, 0, 0, 12, 10, 0).unwrap();
    let mut session = SlRangingSession::new(101, 10, 20, prs_cfg);

    assert_eq!(session.state, SlSessionState::Idle);

    // Cannot measure in Idle
    let rtt_dummy = SlRttMeasurement::new(0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
    let bad_meas = session.record_rtt_measurement(rtt_dummy);
    assert_eq!(
        bad_meas,
        Err(SlPositioningError::SessionStateConflict {
            current: SlSessionState::Idle,
            action: "record_rtt_measurement",
        })
    );

    // Start negotiation
    session.start_negotiation().unwrap();
    assert_eq!(session.state, SlSessionState::Negotiating);

    // Confirm negotiation
    session.confirm_negotiation().unwrap();
    assert_eq!(session.state, SlSessionState::Measuring);

    // Record measurements
    for i in 0..5 {
        let rtt = SlRttMeasurement::new(
            0.0,
            100.0,
            200.0,
            300.0 + (i as f64) * 0.1, // ~100 ns one-way = ~30 m
            0.0,
            0.0,
        );
        session.record_rtt_measurement(rtt).unwrap();
    }

    // After 5 measurements, session enters Tracking state
    assert_eq!(session.state, SlSessionState::Tracking);
    assert_eq!(session.total_measurements, 5);
    assert!(session.running_avg_distance_m > 25.0 && session.running_avg_distance_m < 35.0);

    // Terminate
    session.terminate();
    assert_eq!(session.state, SlSessionState::Terminated);
}

#[test]
fn test_error_formatting_and_display() {
    let err_comb = SlPositioningError::InvalidCombOffset {
        offset: 5,
        comb_size: 4,
    };
    let s = format!("{}", err_comb);
    assert!(s.contains("Invalid comb offset"));

    let err_sym = SlPositioningError::InvalidSymbolRange {
        start: 12,
        duration: 4,
    };
    let s2 = format!("{}", err_sym);
    assert!(s2.contains("Invalid symbol range"));

    let err_rtt = SlPositioningError::NegativeRttDistance { rtt_ns: -5.0 };
    let s3 = format!("{}", err_rtt);
    assert!(s3.contains("Calculated negative RTT"));

    let err_anchors = SlPositioningError::InsufficientAnchors {
        required: 3,
        provided: 1,
    };
    let s4 = format!("{}", err_anchors);
    assert!(s4.contains("Insufficient anchor UEs"));

    let err_matrix = SlPositioningError::SingularMatrix;
    let s5 = format!("{}", err_matrix);
    assert!(s5.contains("Singular normal matrix"));

    let err_ang = SlPositioningError::AngleOutOfRange(1.5);
    let s6 = format!("{}", err_ang);
    assert!(s6.contains("out-of-range angle"));

    let err_state = SlPositioningError::SessionStateConflict {
        current: SlSessionState::Terminated,
        action: "test_action",
    };
    let s7 = format!("{}", err_state);
    assert!(s7.contains("Cannot execute action 'test_action'"));
}
