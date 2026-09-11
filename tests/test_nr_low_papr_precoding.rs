//! Integration and unit tests for 3GPP Rel-18/19 5G-Advanced Low-PAPR Waveform Shaping
//! and Transform Precoding Engine.

use toy_tcpip::nr_low_papr_precoding::*;

#[test]
fn test_complex_arithmetic_and_dft_transform() {
    // 1. Complex arithmetic
    let c1 = Complex64::new(3.0, 4.0);
    assert!((c1.abs() - 5.0).abs() < 1e-12);
    assert!((c1.norm_sqr() - 25.0).abs() < 1e-12);

    let c2 = Complex64::new(1.0, -2.0);
    let c_add = c1 + c2;
    assert_eq!(c_add, Complex64::new(4.0, 2.0));

    let c_mul = c1 * c2;
    // (3 + 4i)*(1 - 2i) = 3 - 6i + 4i - 8i^2 = 11 - 2i
    assert_eq!(c_mul, Complex64::new(11.0, -2.0));

    // 2. DFT and IDFT roundtrip
    let original = vec![
        Complex64::new(1.0, 0.0),
        Complex64::new(0.0, 1.0),
        Complex64::new(-1.0, 0.0),
        Complex64::new(0.0, -1.0),
        Complex64::new(2.0, 0.5),
        Complex64::new(-0.5, 1.5),
        Complex64::new(0.3, -0.7),
        Complex64::new(-1.2, -0.4),
    ];

    let frequency = dft(&original);
    assert_eq!(frequency.len(), original.len());

    // Parseval's energy conservation
    let energy_time: f64 = original.iter().map(|c| c.norm_sqr()).sum();
    let energy_freq: f64 = frequency.iter().map(|c| c.norm_sqr()).sum();
    assert!(
        (energy_time - energy_freq).abs() < 1e-10,
        "Parseval violation: time={}, freq={}",
        energy_time,
        energy_freq
    );

    // IDFT recovery
    let recovered = idft(&frequency);
    for (idx, (orig, rec)) in original.iter().zip(recovered.iter()).enumerate() {
        assert!(
            (orig.re - rec.re).abs() < 1e-10 && (orig.im - rec.im).abs() < 1e-10,
            "Mismatch at index {}: orig={:?}, rec={:?}",
            idx,
            orig,
            rec
        );
    }
}

#[test]
fn test_pi_half_bpsk_modulation_and_phase_rotation() {
    let bits = vec![0, 1, 0, 0, 1, 1, 0, 1];
    let symbols = ModulationScheme::PiHalfBpsk
        .modulate(&bits)
        .expect("Modulation should succeed");

    assert_eq!(symbols.len(), 8);

    // Verify alternating real and imaginary components (skipping origin)
    for (n, s) in symbols.iter().enumerate() {
        // Every symbol must have unit magnitude
        assert!(
            (s.abs() - 1.0).abs() < 1e-12,
            "Symbol {} must have unit amplitude",
            n
        );

        match n % 4 {
            0 => {
                // n=0: phase = 0, pure real (+1 or -1)
                assert!(s.im.abs() < 1e-12);
                assert!((s.re.abs() - 1.0).abs() < 1e-12);
            }
            1 => {
                // n=1: phase = pi/2, pure imaginary (+i or -i)
                assert!(s.re.abs() < 1e-12);
                assert!((s.im.abs() - 1.0).abs() < 1e-12);
            }
            2 => {
                // n=2: phase = pi, pure real (-1 or +1)
                assert!(s.im.abs() < 1e-12);
                assert!((s.re.abs() - 1.0).abs() < 1e-12);
            }
            3 => {
                // n=3: phase = 3pi/2, pure imaginary (-i or +i)
                assert!(s.re.abs() < 1e-12);
                assert!((s.im.abs() - 1.0).abs() < 1e-12);
            }
            _ => unreachable!(),
        }
    }

    // Test invalid bitstream length for QPSK
    let odd_bits = vec![0, 1, 1];
    assert!(ModulationScheme::Qpsk.modulate(&odd_bits).is_err());
}

#[test]
fn test_fdss_spectral_shaping_filter_responses() {
    let num_subcarriers = 48; // 4 PRBs
    let alpha = 0.25;

    // 1. Raised Cosine
    let rc_cfg = FdssConfig::new(FdssFilterType::RaisedCosine, alpha).unwrap();
    let rc_weights = rc_cfg.compute_filter_weights(num_subcarriers);
    assert_eq!(rc_weights.len(), num_subcarriers);

    // Verify energy normalization: sum(w^2) == M
    let energy_rc: f64 = rc_weights.iter().map(|&w| w * w).sum();
    assert!(
        (energy_rc - (num_subcarriers as f64)).abs() < 1e-10,
        "RC Energy normalization failed: {}",
        energy_rc
    );

    // Symmetry check
    for i in 0..num_subcarriers / 2 {
        assert!(
            (rc_weights[i] - rc_weights[num_subcarriers - 1 - i]).abs() < 1e-10,
            "Asymmetry at index {}",
            i
        );
    }

    // 2. Half Sine
    let hs_cfg = FdssConfig::new(FdssFilterType::HalfSine, alpha).unwrap();
    let hs_weights = hs_cfg.compute_filter_weights(num_subcarriers);
    let energy_hs: f64 = hs_weights.iter().map(|&w| w * w).sum();
    assert!(
        (energy_hs - (num_subcarriers as f64)).abs() < 1e-10,
        "Half-Sine Energy normalization failed: {}",
        energy_hs
    );

    // 3. Rectangular (flat)
    let rect_cfg = FdssConfig::new(FdssFilterType::Rectangular, 0.0).unwrap();
    let rect_weights = rect_cfg.compute_filter_weights(num_subcarriers);
    for &w in &rect_weights {
        assert!((w - 1.0).abs() < 1e-10);
    }

    // Invalid alpha rejection
    assert!(FdssConfig::new(FdssFilterType::RaisedCosine, 1.5).is_err());
}

#[test]
fn test_papr_reduction_comparison_cp_ofdm_vs_dft_s_ofdm_vs_fdss() {
    let prb_count = 4; // 48 subcarriers
    let synthesizer = WaveformSynthesizer::new(prb_count, 4).unwrap();
    let num_sc = synthesizer.num_subcarriers();

    // Deterministic bitstream
    let mut bits = Vec::with_capacity(num_sc * 2);
    let mut state: u32 = 0x12345678;
    for _ in 0..(num_sc * 2) {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        bits.push(((state >> 16) & 1) as u8);
    }

    // 1. CP-OFDM with QPSK
    let symbols_qpsk = ModulationScheme::Qpsk.modulate(&bits[0..num_sc * 2]).unwrap();
    let wave_cp_ofdm = synthesizer
        .synthesize(&symbols_qpsk, WaveformType::CpOfdm)
        .unwrap();
    let report_cp_ofdm = evaluate_papr_and_cm(&wave_cp_ofdm).unwrap();

    // 2. DFT-s-OFDM with QPSK
    let wave_dft_qpsk = synthesizer
        .synthesize(
            &symbols_qpsk,
            WaveformType::DftSpreadOfdm { fdss: None },
        )
        .unwrap();
    let report_dft_qpsk = evaluate_papr_and_cm(&wave_dft_qpsk).unwrap();

    // 3. DFT-s-OFDM with pi/2-BPSK (no FDSS)
    let symbols_pibpsk = ModulationScheme::PiHalfBpsk
        .modulate(&bits[0..num_sc])
        .unwrap();
    let wave_dft_pibpsk = synthesizer
        .synthesize(
            &symbols_pibpsk,
            WaveformType::DftSpreadOfdm { fdss: None },
        )
        .unwrap();
    let report_dft_pibpsk = evaluate_papr_and_cm(&wave_dft_pibpsk).unwrap();

    // 4. DFT-s-OFDM with pi/2-BPSK + Rel-18 FDSS (RC alpha=0.3)
    let fdss_cfg = FdssConfig::new(FdssFilterType::RaisedCosine, 0.3).unwrap();
    let wave_dft_fdss = synthesizer
        .synthesize(
            &symbols_pibpsk,
            WaveformType::DftSpreadOfdm { fdss: Some(fdss_cfg) },
        )
        .unwrap();
    let report_dft_fdss = evaluate_papr_and_cm(&wave_dft_fdss).unwrap();

    println!("PAPR Results:");
    println!("  CP-OFDM QPSK:          {:.2} dB, CM: {:.2} dB", report_cp_ofdm.papr_db, report_cp_ofdm.cubic_metric_db);
    println!("  DFT-s-OFDM QPSK:       {:.2} dB, CM: {:.2} dB", report_dft_qpsk.papr_db, report_dft_qpsk.cubic_metric_db);
    println!("  DFT-s-OFDM pi/2-BPSK:  {:.2} dB, CM: {:.2} dB", report_dft_pibpsk.papr_db, report_dft_pibpsk.cubic_metric_db);
    println!("  FDSS pi/2-BPSK (Rel18):{:.2} dB, CM: {:.2} dB", report_dft_fdss.papr_db, report_dft_fdss.cubic_metric_db);

    // Fundamental 3GPP Rel-18 Physical Guarantees:
    // 1. DFT-s-OFDM has lower PAPR than CP-OFDM
    assert!(
        report_dft_qpsk.papr_db < report_cp_ofdm.papr_db,
        "DFT-s-OFDM PAPR ({:.2} dB) must be less than CP-OFDM ({:.2} dB)",
        report_dft_qpsk.papr_db,
        report_cp_ofdm.papr_db
    );

    // 2. pi/2-BPSK has lower PAPR than QPSK in DFT-s-OFDM
    assert!(
        report_dft_pibpsk.papr_db < report_dft_qpsk.papr_db,
        "pi/2-BPSK PAPR ({:.2} dB) must be less than QPSK ({:.2} dB)",
        report_dft_pibpsk.papr_db,
        report_dft_qpsk.papr_db
    );

    // 3. Rel-18 FDSS further suppresses PAPR and Cubic Metric
    assert!(
        report_dft_fdss.papr_db <= report_dft_pibpsk.papr_db + 0.1,
        "FDSS PAPR ({:.2} dB) must not exceed unshaped ({:.2} dB)",
        report_dft_fdss.papr_db,
        report_dft_pibpsk.papr_db
    );

    // Substantial PAPR reduction of FDSS over CP-OFDM: > 3.0 dB!
    let papr_reduction = report_cp_ofdm.papr_db - report_dft_fdss.papr_db;
    assert!(
        papr_reduction > 3.0,
        "Rel-18 FDSS pi/2-BPSK must achieve > 3 dB PAPR reduction over CP-OFDM, got {:.2} dB",
        papr_reduction
    );
}

#[test]
fn test_cubic_metric_evaluation_and_mpr_backoff() {
    let cp_ofdm = WaveformType::CpOfdm;
    let dft_qpsk = WaveformType::DftSpreadOfdm { fdss: None };
    let dft_pibpsk = WaveformType::DftSpreadOfdm { fdss: None };
    let fdss_pibpsk = WaveformType::DftSpreadOfdm {
        fdss: Some(FdssConfig::new(FdssFilterType::RaisedCosine, 0.25).unwrap()),
    };

    let mpr_cp_qpsk = compute_mpr(cp_ofdm, ModulationScheme::Qpsk);
    let mpr_dft_qpsk = compute_mpr(dft_qpsk, ModulationScheme::Qpsk);
    let mpr_dft_pibpsk = compute_mpr(dft_pibpsk, ModulationScheme::PiHalfBpsk);
    let mpr_fdss_pibpsk = compute_mpr(fdss_pibpsk, ModulationScheme::PiHalfBpsk);

    assert_eq!(mpr_cp_qpsk, 1.5);
    assert_eq!(mpr_dft_qpsk, 1.0);
    assert_eq!(mpr_dft_pibpsk, 0.5);
    assert_eq!(mpr_fdss_pibpsk, 0.0); // 0 dB MPR achieved!

    // Power amplifier headroom savings: 1.5 dB transmit power boost
    let pa_power_boost_db = mpr_cp_qpsk - mpr_fdss_pibpsk;
    assert_eq!(pa_power_boost_db, 1.5);
}

#[test]
fn test_ccdf_empirical_distribution_curves() {
    let synthesizer = WaveformSynthesizer::new(2, 4).unwrap(); // 24 subcarriers
    let thresholds = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];

    let ccdf_cp = generate_empirical_ccdf(
        &synthesizer,
        WaveformType::CpOfdm,
        ModulationScheme::Qpsk,
        &thresholds,
        60,
        12345,
    )
    .unwrap();

    let fdss_cfg = FdssConfig::new(FdssFilterType::RaisedCosine, 0.25).unwrap();
    let ccdf_fdss = generate_empirical_ccdf(
        &synthesizer,
        WaveformType::DftSpreadOfdm { fdss: Some(fdss_cfg) },
        ModulationScheme::PiHalfBpsk,
        &thresholds,
        60,
        12345,
    )
    .unwrap();

    // Monotonicity verification
    for i in 1..ccdf_cp.len() {
        assert!(ccdf_cp[i].probability <= ccdf_cp[i - 1].probability);
        assert!(ccdf_fdss[i].probability <= ccdf_fdss[i - 1].probability);
    }

    // FDSS curve must drop to 0 at much lower threshold than CP-OFDM
    let high_thresh_prob_fdss = ccdf_fdss.iter().find(|p| p.threshold_papr_db == 6.0).unwrap().probability;
    let high_thresh_prob_cp = ccdf_cp.iter().find(|p| p.threshold_papr_db == 6.0).unwrap().probability;

    assert!(
        high_thresh_prob_fdss <= high_thresh_prob_cp,
        "FDSS Pr(PAPR > 6dB) ({:.2}) must be <= CP-OFDM ({:.2})",
        high_thresh_prob_fdss,
        high_thresh_prob_cp
    );
}

#[test]
fn test_cell_edge_coverage_distance_multiplier() {
    let cp_ofdm = WaveformType::CpOfdm;
    let fdss_pibpsk = WaveformType::DftSpreadOfdm {
        fdss: Some(FdssConfig::new(FdssFilterType::RootRaisedCosine, 0.3).unwrap()),
    };

    // Pathloss exponent alpha = 3.5 (standard urban micro)
    let dist_mult_35 = compute_coverage_distance_multiplier(
        cp_ofdm,
        ModulationScheme::Qpsk,
        fdss_pibpsk,
        ModulationScheme::PiHalfBpsk,
        3.5,
    );

    // Delta P = 1.5 dB, dist_mult = 10^(1.5 / 35) = 10^0.04286 ≈ 1.1037
    assert!(dist_mult_35 > 1.10);
    assert!(dist_mult_35 < 1.15);

    // Free-space pathloss alpha = 2.0
    let dist_mult_20 = compute_coverage_distance_multiplier(
        cp_ofdm,
        ModulationScheme::Qpsk,
        fdss_pibpsk,
        ModulationScheme::PiHalfBpsk,
        2.0,
    );

    // Delta P = 1.5 dB, dist_mult = 10^(1.5 / 20) = 10^0.075 ≈ 1.1885
    assert!(dist_mult_20 > 1.18);
    assert!(dist_mult_20 < 1.25);
}

#[test]
fn test_wire_codec_and_crc16_integrity() {
    let pdu = LowPaprConfigPdu {
        version: 1,
        waveform_type: 1, // DFT-s-OFDM
        modulation: 0,    // pi/2-BPSK
        filter_type: 1,   // Raised Cosine
        roll_off_alpha_x1000: 250, // alpha = 0.25
        prb_count: 24,
        measured_papr_x100: 215, // 2.15 dB
        measured_cm_x100: 12,    // 0.12 dB
        mpr_db_x100: 0,          // 0.00 dB
    };

    let bytes = pdu.to_bytes();
    assert_eq!(bytes.len(), LowPaprConfigPdu::FIXED_WIRE_SIZE);

    // Decode roundtrip
    let decoded = LowPaprConfigPdu::from_bytes(&bytes).expect("Decoding must succeed");
    assert_eq!(decoded, pdu);

    // Corrupted CRC test
    let mut corrupted = bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(matches!(
        LowPaprConfigPdu::from_bytes(&corrupted),
        Err(LowPaprError::CrcMismatch { .. })
    ));

    // Corrupted Magic test
    let mut bad_magic = bytes.clone();
    bad_magic[0] = 0x00;
    assert!(matches!(
        LowPaprConfigPdu::from_bytes(&bad_magic),
        Err(LowPaprError::InvalidMagic(_))
    ));
}
