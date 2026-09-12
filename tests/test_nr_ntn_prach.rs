//! Integration tests for 3GPP Rel-18 5G-Advanced Satellite NTN PRACH Engine.

use toy_tcpip::nr_ntn_prach::{
    DEFAULT_DETECTION_PAR_THRESH_DB, DEFAULT_TA_OFFSET_MS, NtnPrachEngine, NtnPrachFormatConfig,
    PrachSequenceLength, SPEED_OF_LIGHT_M_S, Sib19NtnConfig, UeNtnPrachPrecompensation,
    generate_zadoff_chu_sequence,
};

fn setup_leo_sib19() -> Sib19NtnConfig {
    Sib19NtnConfig {
        epoch_time_ms: 1_000_000,
        ta_common_epoch_ms: 20.0, // 20 ms common delay to reference ground point
        ta_common_drift_ms_s: 0.05, // 50 us/s drift due to LEO motion
        ta_common_drift_variant_ms_s2: 0.001,
        k_offset_slots: 80,
        scs_khz: 15,
        carrier_freq_hz: 2.0e9,  // 2 GHz S-band
        cell_diff_delay_ms: 3.0, // 3 ms delay variation across satellite beam
    }
}

#[test]
fn test_zadoff_chu_sequence_generation_and_properties() {
    let zc_839 = generate_zadoff_chu_sequence(1, 0, PrachSequenceLength::L839);
    assert_eq!(zc_839.len(), 839);
    for sample in &zc_839 {
        let mag = sample.norm();
        assert!((mag - 1.0).abs() < 1e-6); // Constant envelope (PAPR = 0 dB)
    }

    let zc_139 = generate_zadoff_chu_sequence(5, 10, PrachSequenceLength::L139);
    assert_eq!(zc_139.len(), 139);
    for sample in &zc_139 {
        assert!((sample.norm() - 1.0).abs() < 1e-6);
    }

    // Cyclic shift property: shifted sequence should match base sequence shifted cyclically
    let zc_base = generate_zadoff_chu_sequence(3, 0, PrachSequenceLength::L139);
    let zc_shifted = generate_zadoff_chu_sequence(3, 15, PrachSequenceLength::L139);
    for i in 0..139 {
        let expected = zc_base[(i + 15) % 139];
        let actual = zc_shifted[i];
        assert!((actual.re - expected.re).abs() < 1e-6);
        assert!((actual.im - expected.im).abs() < 1e-6);
    }
}

#[test]
fn test_sib19_time_varying_common_timing_advance_tracking() {
    let sib19 = setup_leo_sib19();

    // At epoch:
    let ta_0 = sib19.evaluate_ta_common_ms(1_000_000);
    assert_eq!(ta_0, 20.0);

    // After 10 seconds (10,000 ms):
    // ta = 20.0 + 0.05 * 10 + 0.5 * 0.001 * 100 = 20.0 + 0.5 + 0.05 = 20.55 ms
    let ta_10s = sib19.evaluate_ta_common_ms(1_010_000);
    assert!((ta_10s - 20.55).abs() < 1e-6);

    // Drift rate at 10s: drift + variant * 10 = 0.05 + 0.01 = 0.06 ms/s
    let drift_10s = sib19.evaluate_ta_drift_rate_ms_s(1_010_000);
    assert!((drift_10s - 0.06).abs() < 1e-6);
}

#[test]
fn test_ue_autonomous_service_link_precompensation() {
    let ue_precomp = UeNtnPrachPrecompensation {
        service_link_distance_m: 800_000.0, // 800 km slant range
        radial_velocity_m_s: -3_000.0,      // Satellite approaching at 3 km/s
        radial_acceleration_m_s2: 50.0,
    };

    // Service link RTT: 2 * 800,000 / 299,792,458 * 1000 = ~5.337025 ms
    let rtt = ue_precomp.rtt_service_link_ms();
    let expected_rtt = (2.0 * 800_000.0 / SPEED_OF_LIGHT_M_S) * 1000.0;
    assert!((rtt - expected_rtt).abs() < 1e-5);
    assert_eq!(ue_precomp.ue_timing_advance_ms(), rtt);

    // Doppler shift at 2 GHz: -2e9 * (-3000 / 299792458) = +20,013.84 Hz
    let doppler_hz = ue_precomp.doppler_shift_hz(2.0e9);
    assert!((doppler_hz - 20_013.84).abs() < 1.0);

    // Total TA computation:
    let sib19 = setup_leo_sib19();
    let format = NtnPrachFormatConfig::default_leo_format();
    let engine = NtnPrachEngine::new(sib19, format, 4.0, DEFAULT_DETECTION_PAR_THRESH_DB);

    let total_ta = engine.compute_total_ta_ms(&ue_precomp, 1_000_000);
    // TA_total = 20.0 (ta_common) + 5.337025 (ta_ue) + 0.5 (ta_offset) = 25.837025 ms
    assert!((total_ta - (20.0 + expected_rtt + DEFAULT_TA_OFFSET_MS)).abs() < 1e-5);
}

#[test]
fn test_preamble_repetition_and_frequency_hopping_waveform() {
    let sib19 = setup_leo_sib19();
    let format = NtnPrachFormatConfig::default_leo_format(); // 4 repetitions, L839
    let mut engine = NtnPrachEngine::new(sib19, format, 4.0, DEFAULT_DETECTION_PAR_THRESH_DB);

    let ue_precomp = UeNtnPrachPrecompensation {
        service_link_distance_m: 600_000.0,
        radial_velocity_m_s: 1_500.0,
        radial_acceleration_m_s2: 10.0,
    };

    let tx = engine.prepare_ue_transmission(
        12, // preamble index
        1,  // root_u
        0,  // n_cs
        &ue_precomp,
        1_000_000,
        5, // slot_id
        1, // freq_id
    );

    assert_eq!(tx.preamble_index, 12);
    assert_eq!(tx.num_repetitions, 4);
    // Total symbols generated: 4 * 839 = 3356
    assert_eq!(tx.symbols.len(), 4 * 839);

    // Check RA-RNTI derivation for slot 5, freq 1:
    // 1 + 0 + 14 * 5 + 14 * 80 * 1 = 1 + 70 + 1120 = 1191
    assert_eq!(tx.ra_rnti, 1191);
    assert_eq!(engine.stats_preambles_transmitted, 1);
}

#[test]
fn test_satellite_payload_detection_window_alignment() {
    let sib19 = setup_leo_sib19();
    let format = NtnPrachFormatConfig::default_leo_format();
    let mut engine = NtnPrachEngine::new(
        sib19,
        format,
        4.0, // 4 ms PRACH detection window
        DEFAULT_DETECTION_PAR_THRESH_DB,
    );

    let ue_precomp = UeNtnPrachPrecompensation {
        service_link_distance_m: 750_000.0,
        radial_velocity_m_s: -2_500.0,
        radial_acceleration_m_s2: 30.0,
    };

    let tx = engine.prepare_ue_transmission(7, 1, 0, &ue_precomp, 1_000_000, 2, 0);

    // Simulate true physical channel matching pre-compensation with minor residual timing jitter (0.2 ms)
    let actual_delay_ms = tx.total_ta_ms - DEFAULT_TA_OFFSET_MS + 0.2;
    // Doppler pre-compensation left 15 Hz residual Doppler
    let actual_channel_doppler_hz = -tx.tx_freq_offset_hz + 15.0;

    let result = engine.evaluate_satellite_reception(
        &tx,
        actual_delay_ms,
        actual_channel_doppler_hz,
        10.0, // 10 dB SNR
    );

    assert!(result.within_window);
    assert!(result.detected);
    assert_eq!(result.preamble_index, 7);
    assert!((result.residual_delay_us - 200.0).abs() < 1.0); // 0.2 ms = 200 us
    assert!((result.residual_frequency_hz - 15.0).abs() < 0.1);
    assert!(result.par_db >= DEFAULT_DETECTION_PAR_THRESH_DB);
    assert_eq!(engine.stats_preambles_detected, 1);
}

#[test]
fn test_satellite_payload_detection_window_miss_and_excess_doppler() {
    let sib19 = setup_leo_sib19();
    let format = NtnPrachFormatConfig::default_leo_format();
    let mut engine = NtnPrachEngine::new(
        sib19,
        format,
        2.0, // Strict 2 ms detection window
        DEFAULT_DETECTION_PAR_THRESH_DB,
    );

    let ue_precomp = UeNtnPrachPrecompensation {
        service_link_distance_m: 750_000.0,
        radial_velocity_m_s: 0.0,
        radial_acceleration_m_s2: 0.0,
    };

    let tx = engine.prepare_ue_transmission(3, 1, 0, &ue_precomp, 1_000_000, 0, 0);

    // Case 1: Huge uncompensated timing error of 3.5 ms (outside 2 ms window [-1.0 .. +1.0] ms)
    let actual_delay_err_ms = tx.total_ta_ms - DEFAULT_TA_OFFSET_MS + 3.5;
    let res_miss = engine.evaluate_satellite_reception(&tx, actual_delay_err_ms, 0.0, 10.0);
    assert!(!res_miss.within_window);
    assert!(!res_miss.detected);
    assert_eq!(engine.stats_window_misses, 1);

    // Case 2: Arrival inside window, but catastrophic uncompensated Doppler (1250 Hz = 1 SCS subcarrier shift)
    // Sinc loss causes severe correlation degradation
    let actual_delay_in_win = tx.total_ta_ms - DEFAULT_TA_OFFSET_MS;
    let res_doppler_loss =
        engine.evaluate_satellite_reception(&tx, actual_delay_in_win, 1250.0, 5.0);
    assert!(res_doppler_loss.within_window);
    assert!(!res_doppler_loss.detected); // Sinc loss drove PAR below threshold
}

#[test]
fn test_ra_rnti_derivation_ntn_multi_slot() {
    let sib19 = setup_leo_sib19();
    let format = NtnPrachFormatConfig::default_short_format();
    let engine = NtnPrachEngine::new(sib19, format, 1.0, DEFAULT_DETECTION_PAR_THRESH_DB);

    // symbol_id = 0, slot_id = 0, freq_id = 0, ul_carrier_id = 0 -> RA-RNTI = 1
    assert_eq!(engine.compute_ra_rnti(0, 0, 0, 0), 1);

    // symbol_id = 4, slot_id = 10, freq_id = 2, ul_carrier_id = 1:
    // 1 + 4 + 14 * 10 + 14 * 80 * 2 + 14 * 80 * 8 * 1
    // = 1 + 4 + 140 + 2240 + 8960 = 11345
    assert_eq!(engine.compute_ra_rnti(4, 10, 2, 1), 11345);
}
