//! Integration tests for 3GPP Rel-18 Uplink 8-Tx Antenna MIMO & Precoding Engine.

use toy_tcpip::nr_ul_8tx_mimo::{
    AntennaPanel8Tx, CodebookCoherenceSubset, CodebookGenerator8Tx, Complex64, MpeThermalServo,
    Ul8TxMimoEngine, UlTxPortMode,
};

#[test]
fn test_8tx_antenna_panel_geometry_and_modes() {
    let linear = AntennaPanel8Tx::Linear4x1x2;
    assert_eq!(linear.dimensions(), (4, 1, 2));
    assert_eq!(linear.total_ports(), 8);

    let planar = AntennaPanel8Tx::Planar2x2x2;
    assert_eq!(planar.dimensions(), (2, 2, 2));
    assert_eq!(planar.total_ports(), 8);

    let engine_8tx = Ul8TxMimoEngine::new(linear, CodebookCoherenceSubset::FullCoherent, 85.0);
    // Theoretical array gain: 10 * log10(8) = ~9.03 dB
    let gain_8tx = engine_8tx.theoretical_array_gain_db();
    assert!((gain_8tx - 9.0309).abs() < 0.01);
}

#[test]
fn test_8tx_precoding_codebook_generation_and_power_normalization() {
    // 1-Layer Full-Coherent Codebook
    let cb_1l = CodebookGenerator8Tx::generate_1layer_full_coherent();
    assert_eq!(cb_1l.len(), 16); // 4 DFT beams x 4 co-phasing angles
    for matrix in &cb_1l {
        assert_eq!(matrix.num_layers, 1);
        let power = matrix.total_power();
        assert!(
            (power - 1.0).abs() < 1e-6,
            "1-Layer Matrix TPMI {} power was {}",
            matrix.tpmi,
            power
        );
    }

    // 2-Layer Full-Coherent Codebook
    let cb_2l = CodebookGenerator8Tx::generate_2layer_full_coherent();
    assert_eq!(cb_2l.len(), 8); // 4 DFT beams x 2 co-phasing angles
    for matrix in &cb_2l {
        assert_eq!(matrix.num_layers, 2);
        let power = matrix.total_power();
        assert!(
            (power - 1.0).abs() < 1e-6,
            "2-Layer Matrix TPMI {} power was {}",
            matrix.tpmi,
            power
        );
    }

    // Partial-Coherent Codebook
    let cb_partial = CodebookGenerator8Tx::generate_1layer_partial_coherent();
    assert_eq!(cb_partial.len(), 16); // 4 pairs x 4 co-phasing angles
    for matrix in &cb_partial {
        assert!((matrix.total_power() - 1.0).abs() < 1e-6);
    }

    // Non-Coherent Codebook
    let cb_non = CodebookGenerator8Tx::generate_1layer_non_coherent();
    assert_eq!(cb_non.len(), 8); // 8 ports
    for matrix in &cb_non {
        assert!((matrix.total_power() - 1.0).abs() < 1e-6);
    }
}

#[test]
fn test_precoding_matrix_vector_multiplication() {
    let cb = CodebookGenerator8Tx::generate_1layer_full_coherent();
    let mat = &cb[0];

    let layer_sym = [Complex64::new(1.0, 0.0)];
    let ports = mat.precod(&layer_sym);
    assert_eq!(ports.len(), 8);

    // Total power across 8 output ports should match input power (1.0)
    let total_out_power: f64 = ports.iter().map(|c| c.norm_sqr()).sum();
    assert!((total_out_power - 1.0).abs() < 1e-6);

    // 2-Layer precoding
    let cb_2l = CodebookGenerator8Tx::generate_2layer_full_coherent();
    let mat_2l = &cb_2l[0];
    let layer_syms_2 = [Complex64::new(1.0, 0.0), Complex64::new(0.0, 1.0)];
    let ports_2l = mat_2l.precod(&layer_syms_2);
    assert_eq!(ports_2l.len(), 8);
    let total_out_power_2l: f64 = ports_2l.iter().map(|c| c.norm_sqr()).sum();
    // Input power is 1^2 + 1^2 = 2.0. With normalized matrix, output power is 2.0 / 2 = 1.0
    assert!((total_out_power_2l - 1.0).abs() < 1e-6);
}

#[test]
fn test_tpmi_selection_matching_channel_reciprocity() {
    let engine = Ul8TxMimoEngine::new(
        AntennaPanel8Tx::Linear4x1x2,
        CodebookCoherenceSubset::FullCoherent,
        85.0,
    );

    // Target precoding matrix 5 in the 1-layer codebook
    let target_matrix = &engine.codebook_1layer[5];
    let target_tpmi = target_matrix.tpmi;

    // Construct reciprocal channel vector H matching target precoding matrix conjugate
    let mut h_channel = [Complex64::ZERO; 8];
    for p in 0..8 {
        h_channel[p] = target_matrix.get(p, 0).conj();
    }

    let (best_tpmi, max_power) = engine.select_best_tpmi_1layer(&h_channel);
    assert_eq!(best_tpmi, target_tpmi);
    // Ideal matched filter gain: (sum |w|^2)^2 = 1.0^2 = 1.0
    assert!((max_power - 1.0).abs() < 1e-6);

    // Non-matched TPMI comparison: orthogonal beam should have near-zero power
    let other_matrix = &engine.codebook_1layer[1]; // Different beam
    let mut other_sum = Complex64::ZERO;
    for p in 0..8 {
        other_sum = other_sum.add(&h_channel[p].mul(&other_matrix.get(p, 0)));
    }
    let other_power = other_sum.norm_sqr();
    assert!(max_power > other_power * 5.0); // Matched power is vastly superior
}

#[test]
fn test_mpe_and_thermal_servo_dynamic_backoff() {
    let mut servo = MpeThermalServo::new(85.0);
    assert_eq!(servo.current_mode, UlTxPortMode::Mode8Tx);

    // Step 1: Moderate proximity detection (P-MPR = 1.5 dB)
    let mode1 = servo.update(true, 1.5, 50.0);
    assert_eq!(mode1, UlTxPortMode::Mode4Tx);
    assert_eq!(servo.mode_switch_count, 1);

    // Step 2: High proximity detection (P-MPR = 3.5 dB)
    let mode2 = servo.update(true, 3.5, 55.0);
    assert_eq!(mode2, UlTxPortMode::Mode2Tx);
    assert_eq!(servo.mode_switch_count, 2);

    // Step 3: Critical regulatory threshold (P-MPR = 6.5 dB)
    let mode3 = servo.update(true, 6.5, 60.0);
    assert_eq!(mode3, UlTxPortMode::Mode1Tx);
    assert_eq!(servo.mode_switch_count, 3);

    // Step 4: Temperature runaway with no proximity (Temp = 96 C > 85 + 10)
    let mode4 = servo.update(false, 0.0, 96.0);
    assert_eq!(mode4, UlTxPortMode::Mode1Tx);

    // Step 5: System cooled down (Temp = 40 C, P-MPR = 0 dB)
    let mode5 = servo.update(false, 0.0, 40.0);
    assert_eq!(mode5, UlTxPortMode::Mode8Tx);
    assert_eq!(servo.mode_switch_count, 4);
}

#[test]
fn test_transmit_pusch_with_port_masking_and_telemetry() {
    let mut engine = Ul8TxMimoEngine::new(
        AntennaPanel8Tx::Linear4x1x2,
        CodebookCoherenceSubset::FullCoherent,
        85.0,
    );
    let mat = engine.codebook_1layer[0].clone();
    let symbol = [Complex64::new(1.0, 0.0)];

    // Transmit in normal 8-Tx mode
    let tx_8 = engine.transmit_pusch(&mat, &symbol);
    assert_eq!(engine.stats_transmissions_8tx, 1);
    assert_eq!(engine.stats_transmissions_fallback, 0);
    for port in 0..8 {
        assert_ne!(tx_8[port], Complex64::ZERO);
    }

    // Trigger servo into 4-Tx mode
    engine.servo.update(true, 1.5, 50.0);
    assert_eq!(engine.servo.current_mode, UlTxPortMode::Mode4Tx);

    let tx_4 = engine.transmit_pusch(&mat, &symbol);
    assert_eq!(engine.stats_transmissions_8tx, 1);
    assert_eq!(engine.stats_transmissions_fallback, 1);
    // First 4 ports active
    for port in 0..4 {
        assert_ne!(tx_4[port], Complex64::ZERO);
    }
    // Ports 4..7 must be masked to zero
    for port in 4..8 {
        assert_eq!(tx_4[port], Complex64::ZERO);
    }
}
