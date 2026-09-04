//! Integration tests for 3GPP Rel-16/17 Remote Interference Management (RIM) & Cross-Link Interference (CLI) Engine.

use toy_tcpip::nr_rim_cli_engine::*;

#[test]
fn test_rim_rs_gold_sequence_generation_and_orthogonality() {
    let len = 128;
    // RIM-RS-1 for Cell 100
    let seq1_c100 = RimGoldSequenceGenerator::generate_sequence(100, RimRsType::RimRs1, len)
        .expect("Sequence generation should succeed");
    assert_eq!(seq1_c100.len(), len);

    // RIM-RS-2 for Cell 100
    let seq2_c100 = RimGoldSequenceGenerator::generate_sequence(100, RimRsType::RimRs2, len)
        .expect("Sequence generation should succeed");

    // RIM-RS-1 for Cell 101
    let seq1_c101 = RimGoldSequenceGenerator::generate_sequence(101, RimRsType::RimRs1, len)
        .expect("Sequence generation should succeed");

    // Check unit power for all generated samples
    for s in &seq1_c100 {
        assert!((s.power() - 1.0).abs() < 1e-6);
    }

    // Autocorrelation at zero lag must be exactly 1.0
    let mut auto_corr = ComplexSample::default();
    for s in &seq1_c100 {
        let prod = s.multiply(&s.conjugate());
        auto_corr.i += prod.i;
        auto_corr.q += prod.q;
    }
    let norm_auto = (auto_corr.power() / ((len as f64) * (len as f64))).sqrt();
    assert!((norm_auto - 1.0).abs() < 1e-4);

    // Cross-correlation between RS1 and RS2 (orthogonal m-sequences) should be low
    let mut cross_corr = ComplexSample::default();
    for i in 0..len {
        let prod = seq1_c100[i].multiply(&seq2_c100[i].conjugate());
        cross_corr.i += prod.i;
        cross_corr.q += prod.q;
    }
    let norm_cross = (cross_corr.power() / ((len as f64) * (len as f64))).sqrt();
    assert!(
        norm_cross < 0.35,
        "Cross-correlation {} should be < 0.35",
        norm_cross
    );

    // Cross-correlation between different cell IDs should also be low
    let mut cross_cell = ComplexSample::default();
    for i in 0..len {
        let prod = seq1_c100[i].multiply(&seq1_c101[i].conjugate());
        cross_cell.i += prod.i;
        cross_cell.q += prod.q;
    }
    let norm_cross_cell = (cross_cell.power() / ((len as f64) * (len as f64))).sqrt();
    assert!(
        norm_cross_cell < 0.35,
        "Cross-cell correlation {} should be < 0.35",
        norm_cross_cell
    );
}

#[test]
fn test_atmospheric_ducting_delay_and_distance_resolution() {
    let sampling_rate = 30.72e6; // 30.72 MHz sampling rate
    let profile = AtmosphericDuctingProfile::new(
        sampling_rate,
        0.7, // 70% correlation threshold
        DEFAULT_THERMAL_NOISE_DBM,
    )
    .unwrap();

    let mut engine = RimCliMitigationEngine::new(profile);

    let ref_seq = RimGoldSequenceGenerator::generate_sequence(42, RimRsType::RimRs1, 64).unwrap();

    // Create a received buffer of 2000 samples with noise
    let mut rx_samples = vec![ComplexSample::new(0.01, -0.01); 1000];

    // Inject reference sequence at sample offset 450
    let injected_delay = 450usize;
    for (i, s) in ref_seq.iter().enumerate() {
        rx_samples[injected_delay + i] = *s;
    }

    let det = engine
        .detect_atmospheric_ducting(&rx_samples, &ref_seq)
        .expect("Ducting detection should succeed");

    assert!(det.is_detected);
    assert_eq!(det.delay_samples, injected_delay);
    assert!(det.peak_correlation > 0.85);

    // Delay in µs: 450 / 30.72e6 ≈ 14.648 µs
    assert!((det.propagation_delay_us - 14.6484).abs() < 0.05);

    // Distance in km: c * 14.6484 µs ≈ 4.391 km
    assert!((det.ducting_distance_km - 4.3915).abs() < 0.05);
    assert_eq!(engine.metrics.total_duct_detections, 1);
}

#[test]
fn test_cli_rssi_and_inr_calculation() {
    let profile = AtmosphericDuctingProfile::new(30.72e6, 0.7, -94.0).unwrap();
    let mut engine = RimCliMitigationEngine::new(profile);

    // 1. Weak signal (below thermal noise) -> INR = 0, None severity
    // P = 1e-13 -> RSSI = 10 * log10(1e-13) + 30 = -130 + 30 = -100 dBm
    let weak_samples = vec![ComplexSample::new(1e-7, 1e-7); 100];
    let (rssi_weak, inr_weak, sev_weak) = engine.evaluate_cli_rssi(&weak_samples);
    assert!(rssi_weak < -94.0);
    assert_eq!(inr_weak, 0.0);
    assert_eq!(sev_weak, InterferenceSeverity::None);

    // 2. Moderate interference: P = 1e-11 -> RSSI = -80 dBm -> INR = -80 - (-94) = 14 dB
    let mod_samples = vec![ComplexSample::new(2.236e-6, 2.236e-6); 100]; // power ≈ 1e-11
    let (rssi_mod, inr_mod, sev_mod) = engine.evaluate_cli_rssi(&mod_samples);
    assert!((rssi_mod - (-80.0)).abs() < 1.0);
    assert!((inr_mod - 14.0).abs() < 1.0);
    assert_eq!(sev_mod, InterferenceSeverity::Moderate);

    // 3. Severe interference: P = 1e-9 -> RSSI = -60 dBm -> INR = 34 dB >= 20 dB
    let sev_samples = vec![ComplexSample::new(2.236e-5, 2.236e-5); 100]; // power ≈ 1e-9
    let (rssi_sev, inr_sev, sev_sev) = engine.evaluate_cli_rssi(&sev_samples);
    assert!((rssi_sev - (-60.0)).abs() < 1.0);
    assert!(inr_sev > 20.0);
    assert_eq!(sev_sev, InterferenceSeverity::Severe);
}

#[test]
fn test_adaptive_mitigation_actions() {
    let profile = AtmosphericDuctingProfile::new(30.72e6, 0.7, -94.0).unwrap();
    let mut engine = RimCliMitigationEngine::new(profile);

    let det_short = DuctingDetectionResult {
        is_detected: true,
        peak_correlation: 0.9,
        delay_samples: 500,
        propagation_delay_us: 16.0,
        ducting_distance_km: 50.0, // < 100 km
    };

    let det_long = DuctingDetectionResult {
        is_detected: true,
        peak_correlation: 0.9,
        delay_samples: 2000,
        propagation_delay_us: 65.0,
        ducting_distance_km: 180.0, // > 100 km
    };

    // Minor severity -> 1 guard symbol expansion
    let act_minor = engine.determine_mitigation(&det_short, InterferenceSeverity::Minor);
    assert_eq!(
        act_minor,
        MitigationAction::ExpandGuardPeriod { added_symbols: 1 }
    );
    assert_eq!(engine.metrics.active_guard_expansion_symbols, 1);

    // Moderate severity at short distance -> 2 guard symbols
    let act_mod_short = engine.determine_mitigation(&det_short, InterferenceSeverity::Moderate);
    assert_eq!(
        act_mod_short,
        MitigationAction::ExpandGuardPeriod { added_symbols: 2 }
    );
    assert_eq!(engine.metrics.active_guard_expansion_symbols, 2);

    // Moderate severity at long distance (> 100 km) -> 3 dB DL power backoff
    let act_mod_long = engine.determine_mitigation(&det_long, InterferenceSeverity::Moderate);
    assert_eq!(
        act_mod_long,
        MitigationAction::DlPowerBackoff { backoff_db: 3.0 }
    );
    assert_eq!(engine.metrics.active_power_backoff_db, 3.0);

    // Severe severity -> 9 dB DL power backoff and 3 guard symbols
    let act_sev = engine.determine_mitigation(&det_long, InterferenceSeverity::Severe);
    assert_eq!(
        act_sev,
        MitigationAction::DlPowerBackoff { backoff_db: 9.0 }
    );
    assert_eq!(engine.metrics.active_power_backoff_db, 9.0);
    assert_eq!(engine.metrics.active_guard_expansion_symbols, 3);
}

#[test]
fn test_error_formatting_and_display() {
    let err_cell = RimCliError::InvalidCellId(1050);
    assert!(err_cell.to_string().contains("Invalid cell ID 1050"));

    let err_seq = RimCliError::InvalidSequenceLength(0);
    assert!(err_seq.to_string().contains("Invalid sequence length 0"));

    let err_samp = RimCliError::InsufficientSamples {
        available: 50,
        required: 100,
    };
    assert!(
        err_samp
            .to_string()
            .contains("Insufficient samples for correlation")
    );

    let err_rate = RimCliError::InvalidSamplingRate(-1.0);
    assert!(err_rate.to_string().contains("Invalid sampling rate"));

    let err_th = RimCliError::CorrelationThresholdOutOfRange(1.5);
    assert!(
        err_th
            .to_string()
            .contains("Correlation threshold 1.500 out of range")
    );
}
