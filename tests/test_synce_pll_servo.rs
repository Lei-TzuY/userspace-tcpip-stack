//! Integration tests for ITU-T G.8262 / G.8262.1 SyncE EEC & eEEC Phase-Locked Loop (PLL) Servo & Wander Filter Engine.

use toy_tcpip::synce_pll_servo::{
    EecProfile, MAX_WANDER_HISTORY_SAMPLES, OscillatorGrade, SyncEClockState, SyncEError,
    SyncEPllConfig, SyncEPllServo, WanderAuditor,
};

#[test]
fn test_eec_profiles_and_parameter_initialization() {
    // 1. Check G.8262 Option 1 (European hierarchy)
    let opt1 = EecProfile::G8262Option1;
    assert_eq!(opt1.default_loop_bandwidth_hz(), 3.0);
    assert_eq!(opt1.max_phase_transient_ns(), 120.0);
    assert_eq!(opt1.free_run_accuracy_ppb(), 4600.0);

    // 2. Check G.8262 Option 2 (North American Stratum 3)
    let opt2 = EecProfile::G8262Option2;
    assert_eq!(opt2.default_loop_bandwidth_hz(), 1.5);
    assert_eq!(opt2.max_phase_transient_ns(), 120.0);
    assert_eq!(opt2.free_run_accuracy_ppb(), 4600.0);

    // 3. Check G.8262.1 Enhanced EEC (eEEC for 5G / O-RAN)
    let eeec = EecProfile::G82621EnhancedEec;
    assert_eq!(eeec.default_loop_bandwidth_hz(), 0.08);
    assert_eq!(eeec.max_phase_transient_ns(), 5.0); // Strict 5 ns transient limit
    assert_eq!(eeec.free_run_accuracy_ppb(), 100.0);

    // 4. Config initialization
    let cfg = SyncEPllConfig::new(eeec, OscillatorGrade::OcxoHighStability).unwrap();
    assert_eq!(cfg.loop_bandwidth_hz, 0.08);
    assert_eq!(cfg.damping_factor, 2.0); // Overdamped for < 0.2 dB peaking
    assert_eq!(cfg.lock_phase_threshold_ns, 2.0);
    assert_eq!(cfg.sampling_period_sec, 0.01);

    // 5. Oscillator grades
    let ocxo_std = OscillatorGrade::OcxoStandard;
    assert_eq!(ocxo_std.temp_coefficient_ppb_per_deg(), 0.5);
    assert_eq!(ocxo_std.aging_rate_ppb_per_day(), 1.0);

    let ocxo_hi = OscillatorGrade::OcxoHighStability;
    assert_eq!(ocxo_hi.temp_coefficient_ppb_per_deg(), 0.05);
    assert_eq!(ocxo_hi.aging_rate_ppb_per_day(), 0.1);

    let rb = OscillatorGrade::RubidiumAtomic;
    assert_eq!(rb.temp_coefficient_ppb_per_deg(), 0.005);
    assert_eq!(rb.aging_rate_ppb_per_day(), 0.002);
}

#[test]
fn test_dpll_phase_locking_and_convergence() {
    let cfg = SyncEPllConfig::new(
        EecProfile::G82621EnhancedEec,
        OscillatorGrade::OcxoHighStability,
    )
    .unwrap();

    let mut servo = SyncEPllServo::new(cfg);
    assert_eq!(servo.state, SyncEClockState::FreeRun);

    // Initial frequency offset
    assert!(servo.current_steered_frequency_ppb().abs() > 0.0);

    // Feed reference phase measurements (reference is ideal at 0.0 ns)
    let mut timestamp = 0.0;
    let dt = 0.01;

    for _ in 0..150 {
        servo.process_sample(timestamp, 0.0, 25.0);
        timestamp += dt;
    }

    // After 150 samples (1.5 seconds), the PLL should pull in and lock
    assert_eq!(servo.state, SyncEClockState::Locked);
    assert!(servo.current_phase_error_ns().abs() <= 2.0);
}

#[test]
fn test_reference_switchover_and_phase_transient_dampening() {
    let cfg = SyncEPllConfig::new(
        EecProfile::G82621EnhancedEec,
        OscillatorGrade::OcxoHighStability,
    )
    .unwrap();

    let mut servo = SyncEPllServo::new(cfg);

    // Run to lock
    let mut timestamp = 0.0;
    for _ in 0..150 {
        servo.process_sample(timestamp, 0.0, 25.0);
        timestamp += 0.01;
    }

    // Reference switchover: New reference has a 4.0 ns phase jump (within 5.0 ns eEEC limit)
    let transient = servo.handle_reference_switchover(4.0).unwrap();
    assert!((transient - 4.0).abs() < 1e-3);

    // Verify transient absorption: immediate phase error seen by loop filter does NOT jump by 4.0 ns
    let err_after_switch = servo.process_sample(timestamp, 4.0, 25.0);
    assert!(err_after_switch.abs() < 2.0); // Absorbed into filter offset

    // If an extreme phase jump occurs (> 5.0 ns for eEEC), handle_reference_switchover reports violation
    let violation = servo.handle_reference_switchover(12.0);
    match violation {
        Err(SyncEError::PhaseTransientViolation {
            transient_ns,
            max_allowed_ns,
        }) => {
            assert!((transient_ns - 12.0).abs() < 1e-3);
            assert_eq!(max_allowed_ns, 5.0);
        }
        _ => panic!("Expected PhaseTransientViolation"),
    }
}

#[test]
fn test_holdover_learned_offset_and_temperature_aging() {
    let cfg = SyncEPllConfig::new(
        EecProfile::G82621EnhancedEec,
        OscillatorGrade::OcxoHighStability,
    )
    .unwrap();

    let mut servo = SyncEPllServo::new(cfg);

    // 1. Run until locked and frequency is learned
    let mut timestamp = 0.0;
    for _ in 0..150 {
        servo.process_sample(timestamp, 0.0, 25.0);
        timestamp += 0.01;
    }
    assert_eq!(servo.state, SyncEClockState::Locked);

    // 2. Enter holdover upon reference loss
    servo.enter_holdover();
    assert_eq!(servo.state, SyncEClockState::Holdover);

    // 3. Advance time in holdover with a 10 deg C temperature shift
    let phase_at_entry = servo.process_sample(timestamp, 0.0, 25.0);
    timestamp += 10.0; // 10 seconds later
    let phase_after_temp = servo.process_sample(timestamp, 0.0, 35.0);

    // Drift occurs predictably without abrupt phase steps
    let drift = phase_after_temp - phase_at_entry;
    assert!(drift.abs() < 100.0); // Within reasonable holdover bounds
}

#[test]
fn test_realtime_mtie_and_tdev_mask_auditing() {
    let mut auditor = WanderAuditor::new();

    // Generate low-wander time series: small sinusoidal jitter around 0.1 ns
    let dt = 0.01;
    for i in 0..500 {
        let t = (i as f64) * dt;
        let jitter = 0.08 * (2.0 * std::f64::consts::PI * t).sin();
        auditor.add_sample(t, jitter);
    }

    // Evaluate MTIE at tau = 0.1s and 1.0s
    let mtie_01 = auditor.compute_mtie(0.1).unwrap();
    let mtie_10 = auditor.compute_mtie(1.0).unwrap();
    assert!(mtie_01 > 0.0);
    assert!(mtie_10 >= mtie_01);
    assert!(mtie_10 <= 0.20); // Low wander well within limit

    // Evaluate TDEV at tau = 1.0s
    let tdev_10 = auditor.compute_tdev(1.0).unwrap();
    assert!(tdev_10 > 0.0);
    assert!(tdev_10 < 0.10);

    // Compliance check
    assert!(auditor.verify_eeec_mtie_compliance());

    // Buffer capacity
    assert_eq!(MAX_WANDER_HISTORY_SAMPLES, 2000);
}

#[test]
fn test_error_formatting_and_display() {
    let err_bw = SyncEError::InvalidLoopBandwidth {
        bandwidth_hz: 15.0,
        min_hz: 1.0,
        max_hz: 10.0,
    };
    let s = format!("{}", err_bw);
    assert!(s.contains("Invalid loop bandwidth"));

    let err_p = SyncEError::InvalidSamplingPeriod { period_sec: -0.01 };
    let s2 = format!("{}", err_p);
    assert!(s2.contains("Invalid PLL sampling period"));

    let err_trans = SyncEError::PhaseTransientViolation {
        transient_ns: 8.5,
        max_allowed_ns: 5.0,
    };
    let s3 = format!("{}", err_trans);
    assert!(s3.contains("Phase transient 8.50 ns exceeded maximum allowed 5.00 ns"));

    let err_hist = SyncEError::InsufficientWanderHistory {
        samples: 1,
        required: 3,
    };
    let s4 = format!("{}", err_hist);
    assert!(s4.contains("Wander calculation requires at least 3 samples, have 1"));
}
