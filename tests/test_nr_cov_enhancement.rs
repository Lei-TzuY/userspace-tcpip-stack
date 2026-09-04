//! Integration tests for 3GPP Rel-17 5G NR Coverage Enhancement (CovEnh) Engine.

use toy_tcpip::nr_cov_enhancement::*;

#[test]
fn test_pusch_repetition_type_a_scheduling_and_rv_cycling() {
    let tdd_fmt = TddSlotFormat::all_uplink_fdd();
    let segmenter = PuschTypeBSegmenter::new(tdd_fmt, RvPattern::Pattern0231);

    // Repetition Type A: slot-level allocation over 8 slots, 14 symbols per slot
    let reps = segmenter
        .segment_nominal_repetitions(0, 0, 14, 8)
        .expect("Type A allocation should succeed");

    assert_eq!(reps.len(), 8);

    let expected_rvs = [0, 2, 3, 1, 0, 2, 3, 1];
    for (i, rep) in reps.iter().enumerate() {
        assert_eq!(rep.actual_idx, i as u32);
        assert_eq!(rep.nominal_idx, i as u32);
        assert_eq!(rep.slot_idx, i as u32);
        assert_eq!(rep.start_symbol, 0);
        assert_eq!(rep.num_symbols, 14);
        assert_eq!(rep.rv, expected_rvs[i]);
    }
}

#[test]
fn test_pusch_repetition_type_b_nominal_to_actual_segmentation() {
    let tdd_fmt = TddSlotFormat::all_uplink_fdd();
    let segmenter = PuschTypeBSegmenter::new(tdd_fmt, RvPattern::Pattern0231);

    // Nominal allocation starting at symbol 10 with duration 8 symbols.
    // Crosses slot boundary: symbols 10..13 in slot 0 (4 symbols), symbols 0..3 in slot 1 (4 symbols).
    let reps = segmenter
        .segment_nominal_repetitions(0, 10, 8, 1)
        .expect("Sub-slot nominal repetition segmentation should succeed");

    assert_eq!(
        reps.len(),
        2,
        "Must segment into 2 actual repetitions across slot boundary"
    );

    // First segment in slot 0
    assert_eq!(reps[0].actual_idx, 0);
    assert_eq!(reps[0].nominal_idx, 0);
    assert_eq!(reps[0].slot_idx, 0);
    assert_eq!(reps[0].start_symbol, 10);
    assert_eq!(reps[0].num_symbols, 4);
    assert_eq!(reps[0].rv, 0);

    // Second segment in slot 1
    assert_eq!(reps[1].actual_idx, 1);
    assert_eq!(reps[1].nominal_idx, 0);
    assert_eq!(reps[1].slot_idx, 1);
    assert_eq!(reps[1].start_symbol, 0);
    assert_eq!(reps[1].num_symbols, 4);
    assert_eq!(reps[1].rv, 2);
}

#[test]
fn test_pusch_repetition_type_b_tdd_invalid_and_dl_symbol_filtering() {
    // 5G TDD 4:1 pattern:
    // Slot 0, 1, 2: 14 DL
    // Slot 3: 10 DL, 2 Invalid (Guard), 2 UL (symbols 12..13)
    // Slot 4: 14 UL (symbols 0..13)
    let tdd_fmt = TddSlotFormat::standard_5g_tdd_4to1();
    let segmenter = PuschTypeBSegmenter::new(tdd_fmt, RvPattern::Pattern0303);

    // Schedule 1 nominal repetition starting at slot 3, symbol 8, duration 6 symbols
    // Symbols 8, 9 are DL (invalid for UL)
    // Symbols 10, 11 are Guard/Invalid
    // Symbols 12, 13 are UL -> should create 1 actual repetition of length 2
    let reps = segmenter
        .segment_nominal_repetitions(3, 8, 6, 1)
        .expect("TDD filtered segmentation should succeed");

    assert_eq!(reps.len(), 1);
    assert_eq!(reps[0].actual_idx, 0);
    assert_eq!(reps[0].nominal_idx, 0);
    assert_eq!(reps[0].slot_idx, 3);
    assert_eq!(reps[0].start_symbol, 12);
    assert_eq!(reps[0].num_symbols, 2);
    assert_eq!(reps[0].rv, 0);
}

#[test]
fn test_pusch_repetition_type_b_zero_ul_symbols_error() {
    let tdd_fmt = TddSlotFormat::standard_5g_tdd_4to1();
    let segmenter = PuschTypeBSegmenter::new(tdd_fmt, RvPattern::Pattern0231);

    // Attempt to schedule PUSCH inside slot 0 which is 100% Downlink
    let result = segmenter.segment_nominal_repetitions(0, 0, 14, 1);
    assert_eq!(result, Err(CovEnhError::ZeroAvailableUlSymbols));
}

#[test]
fn test_tboms_effective_code_rate_and_coding_gain() {
    // Transport Block over 4 slots
    // TB size: 1000 bits (CRC = 16 bits)
    // 10 PRBs, 12 UL symbols, 2 DMRS symbols (10 data symbols per slot)
    // Data REs per slot = 10 PRB * 12 subcarriers * 10 data syms = 1200 REs
    // QPSK (modulation order 2): 1200 * 2 = 2400 coded bits per slot
    // 4 slots: 2400 * 4 = 9600 coded bits
    let tboms = TbomsConfig::new(1000, 4, 10, 12, 2, 2)
        .expect("Valid TBoMS configuration should construct");

    assert_eq!(tboms.data_res_per_slot(), 1200);
    assert_eq!(tboms.total_available_coded_bits(), 9600);

    let effective_rate = tboms.effective_code_rate();
    let expected_rate = 1016.0 / 9600.0;
    assert!((effective_rate - expected_rate).abs() < 1e-6);

    // Estimated coding gain: 10 * log10(4) - 0.5 = 6.0206 - 0.5 = 5.5206 dB
    let gain = tboms.estimated_coding_gain_db();
    assert!((gain - 5.5206).abs() < 0.01);

    // Invalid slot counts (3 is not allowed by 3GPP Rel-17; only {2, 4, 8, 16})
    let invalid_slots = TbomsConfig::new(1000, 3, 10, 12, 2, 2);
    assert_eq!(invalid_slots, Err(CovEnhError::TbomsInvalidSlotCount(3)));

    // Invalid symbol count
    let invalid_sym = TbomsConfig::new(1000, 4, 10, 2, 2, 2);
    assert_eq!(
        invalid_sym,
        Err(CovEnhError::InvalidSymbolRange {
            start: 2,
            duration: 2
        })
    );
}

#[test]
fn test_cross_slot_dmrs_bundling_phase_coherence() {
    let mut bundling = DmrsBundlingController::new(4, 1.0);

    // Slot 0: Initial slot in bundle
    let res0 = bundling.evaluate_slot(0, 23.0, false);
    assert_eq!(res0, PhaseDiscontinuityReason::None);

    // Slot 1: Consecutive slot, power delta 0.5 dB <= 1.0 dB threshold
    let res1 = bundling.evaluate_slot(1, 23.5, false);
    assert_eq!(res1, PhaseDiscontinuityReason::None);

    // Slot 2: Consecutive slot, power delta 0.3 dB <= 1.0 dB threshold
    let res2 = bundling.evaluate_slot(2, 23.8, false);
    assert_eq!(res2, PhaseDiscontinuityReason::None);

    // Slot 3: 4th slot -> Bundle boundary reached
    let res3 = bundling.evaluate_slot(3, 23.9, false);
    assert_eq!(res3, PhaseDiscontinuityReason::BundleBoundaryReached);

    // Slot 4: Power step 2.0 dB > 1.0 dB threshold -> Phase discontinuity
    let res4 = bundling.evaluate_slot(4, 25.9, false);
    match res4 {
        PhaseDiscontinuityReason::TransmitPowerStepExceeded { step_db, max_db } => {
            assert!((step_db - 2.0).abs() < 1e-4);
            assert!((max_db - 1.0).abs() < 1e-4);
        }
        _ => panic!("Expected TransmitPowerStepExceeded, got {:?}", res4),
    }

    // Slot 5: Frequency hopping break
    let res5 = bundling.evaluate_slot(5, 25.9, true);
    assert_eq!(res5, PhaseDiscontinuityReason::FrequencyHoppingBreak);

    // Slot 7: Gap of 2 slots (5 -> 7)
    let res7 = bundling.evaluate_slot(7, 25.9, false);
    assert_eq!(
        res7,
        PhaseDiscontinuityReason::NonConsecutiveSlotGap { gap_slots: 2 }
    );

    // Joint channel estimation gain for bundle size 4
    let joint_gain = bundling.joint_channel_est_gain_db();
    assert!((joint_gain - 5.5206).abs() < 0.01);
}

#[test]
fn test_coverage_range_extension_metrics() {
    // 6 dB link gain, standard terrestrial pathloss exponent 3.5
    // d_new / d_old = 10^(6 / (10 * 3.5)) = 10^(6 / 35) = 10^0.17142857 ≈ 1.48398
    let mult = CovEnhMetrics::compute_range_extension(6.0, DEFAULT_PATHLOSS_EXPONENT);
    assert!((mult - 1.48398).abs() < 1e-4);

    // Free space pathloss exponent 2.0
    // d_new / d_old = 10^(6 / (10 * 2.0)) = 10^(0.3) ≈ 1.99526
    let mult_fs = CovEnhMetrics::compute_range_extension(6.0, 2.0);
    assert!((mult_fs - 1.99526).abs() < 1e-4);
}

#[test]
fn test_error_formatting_and_display() {
    let err_sym = CovEnhError::InvalidSymbolRange {
        start: 10,
        duration: 8,
    };
    assert!(err_sym.to_string().contains("Invalid symbol range"));

    let err_rep = CovEnhError::InvalidRepetitionCount(0);
    assert!(err_rep.to_string().contains("Invalid repetition count"));

    let err_ul = CovEnhError::ZeroAvailableUlSymbols;
    assert!(err_ul.to_string().contains("No valid uplink symbols"));

    let err_tboms = CovEnhError::TbomsInvalidSlotCount(7);
    assert!(
        err_tboms
            .to_string()
            .contains("TBoMS requires 2, 4, 8, or 16 slots")
    );

    let err_tdd = CovEnhError::EmptyTddPattern;
    assert!(
        err_tdd
            .to_string()
            .contains("TDD slot configuration pattern cannot be empty")
    );
}
