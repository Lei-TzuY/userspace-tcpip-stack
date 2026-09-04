//! Integration tests for 3GPP Release 18 Dynamic Spectrum Sharing (DSS) Phase 2
//! and Mixed Numerology Cross-Carrier Scheduling Engine.

use toy_tcpip::nr_dss_mixed_numerology::{
    CarrierNumerology, CrossCarrierSchedulingConfig, CrossCarrierSlotMapper, DssMixedEngine,
    DssMixedError, LteCrsAntennaPorts, LteCrsRateMatchingPattern, LteMbsfnConfig,
};

// ---------------------------------------------------------------------------
// Test 1: LTE CRS Rate Matching Pattern & Frequency Shifting (v_shift)
// ---------------------------------------------------------------------------
#[test]
fn test_lte_crs_pattern_and_frequency_shift() {
    // Standard TS 36.211 §6.10.1.2: v_shift = Cell_ID mod 6
    let p0 = LteCrsRateMatchingPattern::new(0, 0, LteCrsAntennaPorts::Port1, 100, None)
        .expect("Valid pattern");
    assert_eq!(p0.v_shift, 0);

    let p1 = LteCrsRateMatchingPattern::new(0, 1, LteCrsAntennaPorts::Port2, 100, None)
        .expect("Valid pattern");
    assert_eq!(p1.v_shift, 1);

    let p500 = LteCrsRateMatchingPattern::new(0, 500, LteCrsAntennaPorts::Port4, 100, None)
        .expect("Valid pattern");
    assert_eq!(p500.v_shift, (500u16 % 6) as u8); // 2

    let p1007 = LteCrsRateMatchingPattern::new(0, 1007, LteCrsAntennaPorts::Port4, 100, None)
        .expect("Valid pattern");
    assert_eq!(p1007.v_shift, (1007u16 % 6) as u8); // 5

    // Invalid Cell ID (> 1007)
    let err = LteCrsRateMatchingPattern::new(0, 1008, LteCrsAntennaPorts::Port1, 100, None);
    assert_eq!(err, Err(DssMixedError::InvalidCellId(1008)));

    // Antenna Port conversion checks
    assert_eq!(
        LteCrsAntennaPorts::from_u8(1).unwrap(),
        LteCrsAntennaPorts::Port1
    );
    assert_eq!(
        LteCrsAntennaPorts::from_u8(2).unwrap(),
        LteCrsAntennaPorts::Port2
    );
    assert_eq!(
        LteCrsAntennaPorts::from_u8(4).unwrap(),
        LteCrsAntennaPorts::Port4
    );
    assert_eq!(
        LteCrsAntennaPorts::from_u8(3),
        Err(DssMixedError::InvalidAntennaPortCount(3))
    );
}

// ---------------------------------------------------------------------------
// Test 2: CRS RE Puncturing Masks and Net PDSCH Capacity
// ---------------------------------------------------------------------------
#[test]
fn test_crs_re_puncturing_masks_and_pdsch_capacity() {
    let total_re_per_prb = 14 * 12; // 168 REs

    // Case 1: 1-port CRS
    // CRS on symbols 0, 4, 7, 11 (2 REs per symbol = 8 REs punctured)
    let p_port1 = LteCrsRateMatchingPattern::new(0, 0, LteCrsAntennaPorts::Port1, 50, None)
        .expect("Valid pattern");
    let mask_p1 = p_port1.compute_puncturing_mask(0, 0);
    assert_eq!(mask_p1.punctured_re_count, 8);
    assert_eq!(mask_p1.usable_re_count, total_re_per_prb - 8); // 160
    assert!(mask_p1.is_re_usable(2, 0)); // Symbol 2 has no CRS
    assert!(!mask_p1.is_re_usable(0, 0)); // Symbol 0, subcarrier 0 has CRS for cell_id=0
    assert!(!mask_p1.is_re_usable(0, 6)); // Symbol 0, subcarrier 6 has CRS

    // Case 2: 2-port CRS
    // CRS on symbols 0, 4, 7, 11 (4 REs per symbol = 16 REs punctured)
    let p_port2 = LteCrsRateMatchingPattern::new(0, 0, LteCrsAntennaPorts::Port2, 50, None)
        .expect("Valid pattern");
    let mask_p2 = p_port2.compute_puncturing_mask(0, 0);
    assert_eq!(mask_p2.punctured_re_count, 16);
    assert_eq!(mask_p2.usable_re_count, total_re_per_prb - 16); // 152

    // Case 3: 4-port CRS
    // CRS on symbols 0, 4, 7, 11 (4 REs per symbol = 16 REs) + symbols 1, 8 (4 REs per symbol = 8 REs) = 24 REs
    let p_port4 = LteCrsRateMatchingPattern::new(0, 0, LteCrsAntennaPorts::Port4, 50, None)
        .expect("Valid pattern");
    let mask_p4 = p_port4.compute_puncturing_mask(0, 0);
    assert_eq!(mask_p4.punctured_re_count, 24);
    assert_eq!(mask_p4.usable_re_count, total_re_per_prb - 24); // 144
    assert!(!mask_p4.is_re_usable(1, 0)); // Symbol 1 port 2/3 CRS punctured
}

// ---------------------------------------------------------------------------
// Test 3: LTE MBSFN Subframe Reservation Eliminating CRS
// ---------------------------------------------------------------------------
#[test]
fn test_lte_mbsfn_subframe_reservation() {
    // Configure FDD MBSFN with subframe 1 active (bit 5 in 6-bit allocation bitmap = 0b100000 = 0x20)
    // Non-MBSFN control symbols = 1
    let mbsfn_cfg = LteMbsfnConfig::new_fdd(0x20, 1);
    assert!(mbsfn_cfg.is_mbsfn_subframe(1));
    assert!(!mbsfn_cfg.is_mbsfn_subframe(0)); // Subframe 0 is never MBSFN in FDD
    assert!(!mbsfn_cfg.is_mbsfn_subframe(2));

    let pattern =
        LteCrsRateMatchingPattern::new(0, 0, LteCrsAntennaPorts::Port4, 100, Some(mbsfn_cfg))
            .expect("Valid pattern");

    // Normal non-MBSFN subframe 0: 24 REs punctured by 4-port CRS
    let mask_sf0 = pattern.compute_puncturing_mask(0, 0);
    assert_eq!(mask_sf0.punctured_re_count, 24);

    // MBSFN subframe 1: CRS only present in first symbol (symbol 0), symbols 1..13 completely free of CRS
    let mask_sf1 = pattern.compute_puncturing_mask(0, 1);
    // Symbol 0 has 4 REs punctured (for cell_id=0, ports 0 and 1 CRS)
    assert_eq!(mask_sf1.punctured_re_count, 4);
    assert_eq!(mask_sf1.usable_re_count, 168 - 4); // 164 usable REs!
    // Symbols 4, 7, 8, 11 are now fully usable for 5G NR PDSCH
    assert!(mask_sf1.is_re_usable(4, 0));
    assert!(mask_sf1.is_re_usable(7, 0));
    assert!(mask_sf1.is_re_usable(11, 0));
}

// ---------------------------------------------------------------------------
// Test 4: Cross-Carrier Scheduling: 15 kHz (mu=0) Scheduling 30 kHz (mu=1) Carrier
// ---------------------------------------------------------------------------
#[test]
fn test_cross_carrier_scheduling_mu0_to_mu1_k0_scaling() {
    let mu0 = CarrierNumerology::Mu0_15Khz;
    let mu1 = CarrierNumerology::Mu1_30Khz;

    assert_eq!(mu0.slots_per_subframe(), 1);
    assert_eq!(mu1.slots_per_subframe(), 2);
    assert_eq!(mu0.slot_duration_us(), 1000.0);
    assert_eq!(mu1.slot_duration_us(), 500.0);

    // TS 38.214: target_slot = (sched_slot * 2^(1 - 0)) + K0
    let sched_slot = 3;
    let k0 = 1;
    let target_slot = CrossCarrierSlotMapper::calculate_dl_target_slot(sched_slot, mu0, mu1, k0);
    assert_eq!(target_slot, 3 * 2 + 1); // 7

    // Slot 10 with K0 = 0
    let target_slot_zero = CrossCarrierSlotMapper::calculate_dl_target_slot(10, mu0, mu1, 0);
    assert_eq!(target_slot_zero, 20);
}

// ---------------------------------------------------------------------------
// Test 5: Cross-Carrier Scheduling: 30 kHz (mu=1) Scheduling 15 kHz (mu=0) Carrier
// ---------------------------------------------------------------------------
#[test]
fn test_cross_carrier_scheduling_mu1_to_mu0_k2_scaling() {
    let mu1 = CarrierNumerology::Mu1_30Khz;
    let mu0 = CarrierNumerology::Mu0_15Khz;

    // TS 38.214: target_slot = floor(sched_slot * 2^(0 - 1)) + K2 = floor(sched_slot / 2) + K2
    let sched_slot = 5;
    let k2 = 2;
    let target_slot = CrossCarrierSlotMapper::calculate_ul_target_slot(sched_slot, mu1, mu0, k2);
    assert_eq!(target_slot, (5 / 2) + 2); // 4

    let sched_slot_even = 8;
    let target_slot_even =
        CrossCarrierSlotMapper::calculate_ul_target_slot(sched_slot_even, mu1, mu0, 1);
    assert_eq!(target_slot_even, (8 / 2) + 1); // 5
}

// ---------------------------------------------------------------------------
// Test 6: Cross-Carrier HARQ-ACK Timing (K1) Translation
// ---------------------------------------------------------------------------
#[test]
fn test_cross_carrier_harq_feedback_timing_k1() {
    let mu0 = CarrierNumerology::Mu0_15Khz;
    let mu1 = CarrierNumerology::Mu1_30Khz;

    // Case 1: Target carrier is mu1 (30 kHz), scheduling/PUCCH carrier is mu0 (15 kHz)
    // scheduled_slot = 7 on mu1. K1 = 3 (scheduled slot units).
    // Target ACK slot = 7 + 3 = 10 on mu1.
    // In mu0 grid: floor(10 / 2) = 5.
    let feedback_slot_mu0 = CrossCarrierSlotMapper::calculate_harq_feedback_slot(7, 3, mu1, mu0);
    assert_eq!(feedback_slot_mu0, 5);

    // Case 2: Target carrier is mu0 (15 kHz), scheduling/PUCCH carrier is mu1 (30 kHz)
    // scheduled_slot = 3 on mu0. K1 = 2 (scheduled slot units).
    // Target ACK slot = 3 + 2 = 5 on mu0.
    // In mu1 grid: 5 * 2 = 10.
    let feedback_slot_mu1 = CrossCarrierSlotMapper::calculate_harq_feedback_slot(3, 2, mu0, mu1);
    assert_eq!(feedback_slot_mu1, 10);
}

// ---------------------------------------------------------------------------
// Test 7: Multi-Carrier Scheduling Engine & Blind Decoding Budget
// ---------------------------------------------------------------------------
#[test]
fn test_dss_mixed_engine_multi_carrier_and_blind_decoding_budget() {
    let mut engine = DssMixedEngine::new();

    // Carrier 0: 15 kHz Primary Cell with 4-port LTE CRS DSS (50 PRBs)
    let crs_p0 = LteCrsRateMatchingPattern::new(0, 42, LteCrsAntennaPorts::Port4, 50, None)
        .expect("Valid CRS");
    engine
        .add_carrier(0, CarrierNumerology::Mu0_15Khz, 50, Some(crs_p0))
        .expect("Add carrier 0");

    // Carrier 1: 30 kHz Secondary Cell pure 5G NR (100 PRBs)
    engine
        .add_carrier(1, CarrierNumerology::Mu1_30Khz, 100, None)
        .expect("Add carrier 1");

    // Configure cross-carrier scheduling (Cell 0 schedules Cell 1, CIF = 1)
    let ccs_config = CrossCarrierSchedulingConfig::new(
        0, // scheduling
        1, // scheduled
        1, // CIF
        CarrierNumerology::Mu0_15Khz,
        CarrierNumerology::Mu1_30Khz,
        1, // default K0
        2, // default K2
        2, // default K1
    )
    .expect("Valid CCS config");
    engine.configure_cross_carrier(ccs_config);

    // Schedule DL cross-carrier transmission at scheduling slot 4
    let res = engine
        .schedule_cross_carrier_dl(0, 1, 4, None, None, 10)
        .expect("Schedule success");

    assert_eq!(res.scheduled_carrier_id, 1);
    assert_eq!(res.scheduling_slot, 4);
    assert_eq!(res.scheduled_slot, 4 * 2 + 1); // 9 (mu0 -> mu1 with K0=1)
    assert_eq!(res.k_offset_applied, 1);

    // Test Blind Decoding Budget Enforcement on Carrier 0 (mu=0 limit is 44 BDs)
    // We already used 10 BDs at slot 4. Adding 30 more should succeed (total 40 <= 44).
    let res2 = engine.schedule_cross_carrier_dl(0, 1, 4, None, None, 30);
    assert!(res2.is_ok());

    // Adding 10 more at slot 4 should fail (40 + 10 = 50 > 44)
    let res_overflow = engine.schedule_cross_carrier_dl(0, 1, 4, None, None, 10);
    match res_overflow {
        Err(DssMixedError::BlindDecodingBudgetExceeded {
            slot,
            limit,
            requested,
        }) => {
            assert_eq!(slot, 4);
            assert_eq!(limit, 44);
            assert_eq!(requested, 50);
        }
        other => panic!(
            "Expected BlindDecodingBudgetExceeded error, got: {:?}",
            other
        ),
    }

    // Verify Telemetry Metrics
    assert_eq!(engine.metrics.total_dci_scheduled, 2);
    assert_eq!(engine.metrics.total_cross_carrier_schedules, 2);

    // Evaluate PRB capacity
    let cap_c0 = engine
        .evaluate_prb_capacity(0, 0)
        .expect("Capacity carrier 0");
    assert_eq!(cap_c0.punctured_re_count, 24); // 4-port CRS
    assert_eq!(cap_c0.usable_re_count, 144);

    let cap_c1 = engine
        .evaluate_prb_capacity(1, 0)
        .expect("Capacity carrier 1");
    assert_eq!(cap_c1.punctured_re_count, 0); // Pure 5G NR
    assert_eq!(cap_c1.usable_re_count, 168);
}
