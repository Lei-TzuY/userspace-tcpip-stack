//! Integration test suite for ITU-T G.8273.2 Class D Enhanced Telecom Boundary Clock Engine.

use toy_tcpip::ptp_telecom_class_d::{
    CLASS_D_MAX_CTE_PS, CLASS_D_MAX_DTE_PS, CLASS_D_MAX_TE_PS, ClassDPhaseServo,
    ClassDTimeErrorFilter, FiberAsymmetryModel, HoldoverPredictor, PtpClockClassTier,
    PtpTelecomClassDManager, SubNanoPtpSample,
};

#[test]
fn test_sub_nanosecond_timestamp_and_phase_error() {
    // 1.0 s base timestamp
    let t1 = 1_000_000_000_000i64; // Master Tx: 1.000000000000 s
    let t2 = 1_000_010_000_250i64; // Slave Rx:  +10.000250 us
    let t3 = 1_000_020_000_000i64; // Slave Tx:  +20.000000 us
    let t4 = 1_000_029_999_750i64; // Master Rx: +29.999750 us
    let corr = 0i64;

    let sample = SubNanoPtpSample::new(1, t1, t2, t3, t4, corr);

    // Forward delay = t2 - t1 = 10,000,250 ps (10.000250 us)
    // Reverse delay = t4 - t3 = 9,999,750 ps  (9.999750 us)
    // Mean path delay = (10,000,250 + 9,999,750) / 2 = 10,000,000 ps = 10.0 us
    assert_eq!(sample.raw_mean_path_delay_ps(), 10_000_000);

    // Phase offset = (10,000,250 - 9,999,750) / 2 = 500 / 2 = 250 ps = 0.25 ns
    assert_eq!(sample.raw_phase_offset_ps(), 250);
}

#[test]
fn test_fiber_thermal_and_chromatic_asymmetry_correction() {
    // 20 km optical fiber link, 1310 nm forward, 1490 nm reverse
    let mut asym_model = FiberAsymmetryModel::new(20.0, 1310.0, 1490.0);
    asym_model.reference_temp_deg = 25.0;
    asym_model.current_temp_deg = 25.0;

    // At reference temperature (25°C): Chromatic dispersion only
    // Delta_tau_chrom = D * (1490 - 1310) * 20 = 3.5 * 180 * 20 = 12600 ps = 12.6 ns
    assert_eq!(asym_model.compute_asymmetry_ps(), 12_600);

    // Temperature shifts to 40°C (+15°C excursion)
    // Delta_tau_thermal = 40 ps/km/°C * 15°C * 20 km = 12,000 ps = 12.0 ns
    asym_model.current_temp_deg = 40.0;
    // Total asymmetry = 12,600 + 12,000 = 24,600 ps = 24.6 ns
    assert_eq!(asym_model.compute_asymmetry_ps(), 24_600);

    // End-to-end compensation in manager:
    let mut manager = PtpTelecomClassDManager::new(asym_model);
    manager.set_optical_temperature(40.0);

    // Raw sample has +24,600 ps offset purely due to fiber asymmetry
    let sample = SubNanoPtpSample::new(10, 0, 100_024_600, 200_000_000, 300_000_000, 0);
    let te = manager.process_ptp_sample(&sample, 1.0);

    // Once asymmetry is subtracted (24,600 - 24,600 = 0), true phase error is near 0
    assert!(te.instantaneous_te_ps.abs() < 1000); // Well under Class D 5000 ps limit
}

#[test]
fn test_class_d_cte_and_dte_decomposition() {
    let mut filter = ClassDTimeErrorFilter::new(50);

    // Constant bias cTE = 1500 ps (1.5 ns), with alternating dynamic jitter +-800 ps (0.8 ns)
    let mut last_components = None;
    for i in 0..100 {
        let jitter = if i % 2 == 0 { 800 } else { -800 };
        let te_sample = 1500 + jitter;
        last_components = Some(filter.feed(te_sample));
    }

    let comp = last_components.unwrap();
    // Constant time error cTE should be ~1500 ps (within +/- 50 ps)
    assert!(
        (comp.constant_te_ps - 1500).abs() <= 50,
        "cTE was {}, expected ~1500 ps",
        comp.constant_te_ps
    );
    // Dynamic time error dTE should be ~800 ps
    assert!(
        (comp.dynamic_te_ps.abs() - 800).abs() <= 50,
        "dTE was {}, expected ~800 ps",
        comp.dynamic_te_ps
    );
    // Verified Class D compliance:
    // max|TE| <= 5000 ps, |cTE| <= 3000 ps, |dTE| <= 2000 ps
    assert!(comp.instantaneous_te_ps.abs() <= CLASS_D_MAX_TE_PS);
    assert!(comp.constant_te_ps.abs() <= CLASS_D_MAX_CTE_PS);
    assert!(comp.dynamic_te_ps.abs() <= CLASS_D_MAX_DTE_PS);
    assert_eq!(comp.class_tier, PtpClockClassTier::ClassD);
    assert!(comp.is_class_d_compliant);
}

#[test]
fn test_class_d_servo_closed_loop_convergence() {
    let mut servo = ClassDPhaseServo::default_class_d();

    // Initial phase offset of 45,000 ps (45 ns)
    let mut residual_error = 45_000i64;

    for _ in 0..60 {
        residual_error = servo.update(residual_error, 1.0);
    }

    // After 60 iterations, closed-loop servo must steer error to within Class D limit (< 5000 ps = 5.0 ns)
    assert!(
        residual_error.abs() < CLASS_D_MAX_TE_PS,
        "Servo did not converge to Class D: residual was {} ps",
        residual_error
    );
}

#[test]
fn test_class_tier_compliance_grading() {
    // 1. Class D: 2,500 ps (2.5 ns: max|TE| <= 5 ns, |cTE| <= 3 ns, |dTE| <= 2 ns)
    let mut filter_d = ClassDTimeErrorFilter::new(20);
    let d = filter_d.feed(2_500);
    assert_eq!(d.class_tier, PtpClockClassTier::ClassD);
    assert!(d.is_class_d_compliant);

    // 2. Class C: 8,000 ps (8.0 ns: max|TE| <= 30 ns, |cTE| <= 10 ns, |dTE| <= 10 ns)
    let mut filter_c = ClassDTimeErrorFilter::new(20);
    let c = filter_c.feed(8_000);
    assert_eq!(c.class_tier, PtpClockClassTier::ClassC);
    assert!(!c.is_class_d_compliant);

    // 3. Class B: 60,000 ps (60.0 ns: max|TE| <= 70 ns)
    let mut filter_b = ClassDTimeErrorFilter::new(20);
    let b = filter_b.feed(60_000);
    assert_eq!(b.class_tier, PtpClockClassTier::ClassB);

    // 4. Class A: 90,000 ps (90.0 ns: max|TE| <= 100 ns)
    let mut filter_a = ClassDTimeErrorFilter::new(20);
    let a = filter_a.feed(90_000);
    assert_eq!(a.class_tier, PtpClockClassTier::ClassA);

    // 5. Out of Spec: 120,000 ps (120.0 ns: > 100 ns)
    let mut filter_oos = ClassDTimeErrorFilter::new(20);
    let oos = filter_oos.feed(120_000);
    assert_eq!(oos.class_tier, PtpClockClassTier::OutOfSpec);
}

#[test]
fn test_holdover_drift_prediction() {
    let ocxo = HoldoverPredictor::new_ocxo();

    // 4 hours (14,400 seconds) of holdover with 2.0°C temperature gradient
    let predicted_drift = ocxo.predict_drift_ps(14_400.0, 2.0);

    // Expected drift: aging + thermal offset
    // Should be finite, positive, and within reasonable picosecond/nanosecond range
    assert!(predicted_drift > 0);
    // Over 4 hours on high-stability OCXO, drift should be under 2,000,000 ps (2 us)
    assert!(predicted_drift < 2_000_000);
}
