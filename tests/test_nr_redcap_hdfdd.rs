//! Integration tests for 3GPP Rel-17 RedCap HD-FDD & Relaxed RRM Engine.

use toy_tcpip::REDCAP_SYMBOLS_PER_SLOT;
use toy_tcpip::nr_redcap_hdfdd::{
    ChannelAllocation, HdChannelType, HdDirection, HdFddScheduler, HdFddType, NR_SYMBOLS_PER_SLOT,
    RedCapHdFddError, RelaxedRrmCriteria, RelaxedRrmState, ResolutionReason,
    RrmRelaxationEvaluator, SwitchingGuardConfig,
};

#[test]
fn test_switching_guard_validation_and_config() {
    // Valid FR1 default: 1 symbol Rx-Tx, 1 symbol Tx-Rx
    let fr1 = SwitchingGuardConfig::fr1_default();
    assert_eq!(fr1.n_rx_to_tx_symbols, 1);
    assert_eq!(fr1.n_tx_to_rx_symbols, 1);

    // Valid relaxed config: 2 symbols each
    let relaxed = SwitchingGuardConfig::relaxed();
    assert_eq!(relaxed.n_rx_to_tx_symbols, 2);
    assert_eq!(relaxed.n_tx_to_rx_symbols, 2);

    // Custom valid config
    let custom = SwitchingGuardConfig::new(3, 4);
    assert!(custom.is_ok());

    // Invalid configs (> 4 symbols)
    let invalid_rx = SwitchingGuardConfig::new(5, 1);
    assert_eq!(
        invalid_rx,
        Err(RedCapHdFddError::InvalidSwitchingGuard { rx_tx: 5, tx_rx: 1 })
    );

    let invalid_tx = SwitchingGuardConfig::new(1, 6);
    assert_eq!(
        invalid_tx,
        Err(RedCapHdFddError::InvalidSwitchingGuard { rx_tx: 1, tx_rx: 6 })
    );

    // Channel allocation bounds validation
    let valid_alloc = ChannelAllocation::new(1, HdChannelType::Pdsch, 0, 14, false);
    assert!(valid_alloc.is_ok());

    // Start symbol >= 14
    let invalid_start = ChannelAllocation::new(2, HdChannelType::Pdsch, 14, 1, false);
    assert_eq!(
        invalid_start,
        Err(RedCapHdFddError::InvalidSymbolRange {
            start: 14,
            duration: 1
        })
    );

    // Duration 0
    let invalid_dur = ChannelAllocation::new(3, HdChannelType::Pdsch, 2, 0, false);
    assert_eq!(
        invalid_dur,
        Err(RedCapHdFddError::InvalidSymbolRange {
            start: 2,
            duration: 0
        })
    );

    // Exceeds 14 symbols boundary
    let invalid_overflow = ChannelAllocation::new(4, HdChannelType::Pdsch, 10, 5, false);
    assert_eq!(
        invalid_overflow,
        Err(RedCapHdFddError::InvalidSymbolRange {
            start: 10,
            duration: 5
        })
    );
}

#[test]
fn test_direct_overlapping_collision_resolution() {
    let guard = SwitchingGuardConfig::fr1_default();
    let mut scheduler = HdFddScheduler::new(HdFddType::TypeB, guard);

    // Scenario 1: SSB (DL, priority 10) vs PUSCH (UL, priority 4) overlapping at symbols 2..6
    let ssb = ChannelAllocation::new(101, HdChannelType::Ssb, 2, 4, false).unwrap();
    let pusch = ChannelAllocation::new(102, HdChannelType::Pusch, 3, 5, false).unwrap();

    let res = scheduler.schedule_slot(0, vec![ssb, pusch]);
    assert_eq!(res.scheduled.len(), 1);
    assert_eq!(res.scheduled[0].allocation_id, 101);
    assert_eq!(res.scheduled[0].channel_type, HdChannelType::Ssb);

    assert_eq!(res.cancelled.len(), 1);
    assert_eq!(res.cancelled[0].allocation_id, 102);
    assert_eq!(res.cancelled[0].channel_type, HdChannelType::Pusch);
    assert_eq!(
        res.cancelled[0].reason,
        ResolutionReason::HigherPriorityPreemption {
            preempted_by: HdChannelType::Ssb
        }
    );

    // Scenario 2: PRACH (UL, priority 9) vs PDSCH (DL, priority 5) overlapping at symbols 0..6
    let prach = ChannelAllocation::new(201, HdChannelType::Prach, 0, 6, false).unwrap();
    let pdsch = ChannelAllocation::new(202, HdChannelType::Pdsch, 2, 8, false).unwrap();

    let res2 = scheduler.schedule_slot(1, vec![pdsch, prach]);
    assert_eq!(res2.scheduled.len(), 1);
    assert_eq!(res2.scheduled[0].allocation_id, 201);
    assert_eq!(res2.scheduled[0].channel_type, HdChannelType::Prach);

    assert_eq!(res2.cancelled.len(), 1);
    assert_eq!(res2.cancelled[0].allocation_id, 202);
    assert_eq!(res2.cancelled[0].channel_type, HdChannelType::Pdsch);
    assert_eq!(
        res2.cancelled[0].reason,
        ResolutionReason::HigherPriorityPreemption {
            preempted_by: HdChannelType::Prach
        }
    );

    // Scenario 3: PUCCH HARQ-ACK (UL, priority 8) vs Periodic CSI-RS (DL, priority 2)
    let pucch = ChannelAllocation::new(301, HdChannelType::PucchHarqAck, 8, 4, false).unwrap();
    let csi_rs = ChannelAllocation::new(302, HdChannelType::PeriodicCsiRs, 7, 3, false).unwrap();

    let res3 = scheduler.schedule_slot(2, vec![csi_rs, pucch]);
    assert_eq!(res3.scheduled.len(), 1);
    assert_eq!(res3.scheduled[0].allocation_id, 301);
    assert_eq!(res3.scheduled[0].channel_type, HdChannelType::PucchHarqAck);
}

#[test]
fn test_insufficient_switching_guard_and_guard_puncturing() {
    let guard = SwitchingGuardConfig::new(2, 2).unwrap(); // 2 symbols required for Rx-to-Tx & Tx-to-Rx
    let mut scheduler = HdFddScheduler::new(HdFddType::TypeB, guard);

    // Case 1: PUSCH (UL, rank 4, symbols 0..4) followed by PDSCH (DL, rank 5, symbols 5..10)
    // Gap between 4 and 5 is 1 symbol. Deficit is 2 - 1 = 1 symbol.
    // PUSCH (prev) has rank 4 <= PDSCH rank 5, and num_symbols = 4 > 1.
    // PUSCH allows puncturing by scheduler logic to satisfy Tx-to-Rx guard:
    // PUSCH shortened to 3 symbols (symbols 0..3). Guard inserted = 2.
    let pusch = ChannelAllocation::new(401, HdChannelType::Pusch, 0, 4, true).unwrap();
    let pdsch = ChannelAllocation::new(402, HdChannelType::Pdsch, 5, 5, false).unwrap();

    let res = scheduler.schedule_slot(0, vec![pusch, pdsch]);
    assert_eq!(res.scheduled.len(), 2);
    // Previous channel (PUSCH) punctured
    assert_eq!(res.scheduled[0].allocation_id, 401);
    assert_eq!(res.scheduled[0].num_symbols, 3);
    assert!(res.scheduled[0].is_punctured);

    // PDSCH scheduled normally
    assert_eq!(res.scheduled[1].allocation_id, 402);
    assert_eq!(res.scheduled[1].start_symbol, 5);
    assert_eq!(res.scheduled[1].num_symbols, 5);
    assert!(!res.scheduled[1].is_punctured);
    assert_eq!(res.guard_symbols_inserted, 2);

    // Case 2: PDSCH (DL, rank 5, symbols 0..6, no puncturing) followed by PUSCH (UL, rank 4, symbols 6..12, allows puncturing)
    // Rx-to-Tx guard = 2 symbols. Gap between 6 and 6 is 0. Deficit = 2.
    // PDSCH is higher rank than PUSCH, so PDSCH won't be punctured.
    // PUSCH allows puncturing: start shifted from 6 to 8, length from 6 to 4.
    let pdsch2 = ChannelAllocation::new(501, HdChannelType::Pdsch, 0, 6, false).unwrap();
    let pusch2 = ChannelAllocation::new(502, HdChannelType::Pusch, 6, 6, true).unwrap();

    let res2 = scheduler.schedule_slot(1, vec![pdsch2, pusch2]);
    assert_eq!(res2.scheduled.len(), 2);
    assert_eq!(res2.scheduled[0].allocation_id, 501);
    assert_eq!(res2.scheduled[0].num_symbols, 6);
    assert!(!res2.scheduled[0].is_punctured);

    assert_eq!(res2.scheduled[1].allocation_id, 502);
    assert_eq!(res2.scheduled[1].start_symbol, 8); // Shifted by 2
    assert_eq!(res2.scheduled[1].num_symbols, 4); // 6 - 2 = 4
    assert!(res2.scheduled[1].is_punctured);

    // Case 3: When puncturing is disallowed on both channels and deficit cannot be resolved,
    // lower priority channel is dropped.
    let pdsch3 = ChannelAllocation::new(601, HdChannelType::Pdsch, 0, 6, false).unwrap();
    let pusch3 = ChannelAllocation::new(602, HdChannelType::Pusch, 6, 6, false).unwrap();

    let res3 = scheduler.schedule_slot(2, vec![pdsch3, pusch3]);
    assert_eq!(res3.scheduled.len(), 1);
    assert_eq!(res3.scheduled[0].allocation_id, 601);
    assert_eq!(res3.cancelled.len(), 1);
    assert_eq!(res3.cancelled[0].allocation_id, 602);
    assert_eq!(
        res3.cancelled[0].reason,
        ResolutionReason::InsufficientSwitchingGuard { needed_symbols: 2 }
    );
}

#[test]
fn test_periodic_signal_cancellation() {
    let guard = SwitchingGuardConfig::fr1_default();
    let mut scheduler = HdFddScheduler::new(HdFddType::TypeB, guard);

    // Periodic SRS (UL, rank 1, symbol 13) after PDSCH (DL, rank 5, symbols 0..13)
    // Rx-to-Tx gap is 0 (end of PDSCH is 13, SRS is at 13).
    // SRS duration is 1 symbol, cannot be punctured (1 <= 1 deficit).
    // Lower priority SRS cancelled.
    let pdsch = ChannelAllocation::new(701, HdChannelType::Pdsch, 0, 13, false).unwrap();
    let srs = ChannelAllocation::new(702, HdChannelType::PeriodicSrs, 13, 1, true).unwrap();

    let res = scheduler.schedule_slot(0, vec![pdsch, srs]);
    assert_eq!(res.scheduled.len(), 1);
    assert_eq!(res.scheduled[0].allocation_id, 701);
    assert_eq!(res.cancelled.len(), 1);
    assert_eq!(res.cancelled[0].allocation_id, 702);
    assert_eq!(res.cancelled[0].channel_type, HdChannelType::PeriodicSrs);
}

#[test]
fn test_hdfdd_metrics_computation() {
    let guard = SwitchingGuardConfig::fr1_default();
    let mut scheduler = HdFddScheduler::new(HdFddType::TypeA, guard);

    // Slot 0: Downlink slot (PDCCH + PDSCH = 14 symbols)
    let pdcch = ChannelAllocation::new(1, HdChannelType::Pdcch, 0, 2, false).unwrap();
    let pdsch = ChannelAllocation::new(2, HdChannelType::Pdsch, 2, 12, false).unwrap();
    let res0 = scheduler.schedule_slot(0, vec![pdcch, pdsch]);
    assert_eq!(res0.dl_active_symbols, 14);
    assert_eq!(res0.ul_active_symbols, 0);

    // Slot 1: Uplink slot (PUSCH = 14 symbols)
    let pusch = ChannelAllocation::new(3, HdChannelType::Pusch, 0, 14, false).unwrap();
    let res1 = scheduler.schedule_slot(1, vec![pusch]);
    assert_eq!(res1.dl_active_symbols, 0);
    assert_eq!(res1.ul_active_symbols, 14);

    // Slot 2: Mixed slot with puncturing
    let pdsch_mix = ChannelAllocation::new(4, HdChannelType::Pdsch, 0, 8, false).unwrap();
    let pusch_mix = ChannelAllocation::new(5, HdChannelType::Pusch, 8, 6, true).unwrap();
    scheduler.schedule_slot(2, vec![pdsch_mix, pusch_mix]);

    let metrics = scheduler.compute_metrics();
    assert_eq!(metrics.total_slots_evaluated, 3);
    assert_eq!(metrics.total_allocations, 5);
    assert_eq!(metrics.scheduled_count, 5);
    assert_eq!(metrics.cancelled_count, 0);
    assert_eq!(metrics.punctured_count, 1);
    assert_eq!(metrics.throughput_retention_ratio, 1.0);

    // Total capacity = 3 slots * 14 symbols = 42 symbols
    // DL symbols = 14 (slot 0) + 0 (slot 1) + 8 (slot 2) = 22 symbols
    // UL symbols = 0 (slot 0) + 14 (slot 1) + 5 (slot 2 punctured from 6 to 5 because gap was 0, deficit 1) = 19 symbols
    assert!((metrics.dl_duty_cycle_percent - (22.0 / 42.0 * 100.0)).abs() < 1e-3);
    assert!((metrics.ul_duty_cycle_percent - (19.0 / 42.0 * 100.0)).abs() < 1e-3);
}

#[test]
fn test_stationary_rrm_relaxation_evaluation() {
    let criteria = RelaxedRrmCriteria::default_redcap();
    let mut evaluator = RrmRelaxationEvaluator::new(criteria);

    // Initial state: FullMeasurement
    assert_eq!(evaluator.current_state, RelaxedRrmState::FullMeasurement);
    assert_eq!(evaluator.power_saving_factor(), 1.0);

    // Not enough samples (< 3)
    evaluator.add_measurement(0.0, -80.0);
    evaluator.add_measurement(60.0, -80.5);
    let state = evaluator.evaluate_state().unwrap();
    assert_eq!(state, RelaxedRrmState::FullMeasurement);

    // 3 samples with stationary RSRP (-80.0 to -80.8 dBm, delta 0.8 dB < 3 dB) and good signal (> -95 dBm)
    evaluator.add_measurement(120.0, -80.8);
    let state2 = evaluator.evaluate_state().unwrap();
    assert_eq!(state2, RelaxedRrmState::NeighborMeasurementDisabled);
    assert_eq!(evaluator.power_saving_factor(), 0.35); // 65% power reduction

    // Scenario 2: High mobility (large RSRP variation: -80 to -87 dBm, delta 7 dB > 3 dB)
    evaluator.add_measurement(180.0, -87.0);
    let state3 = evaluator.evaluate_state().unwrap();
    assert_eq!(state3, RelaxedRrmState::FullMeasurement);
    assert_eq!(evaluator.power_saving_factor(), 1.0);

    // Scenario 3: Stationary UE at cell edge (low RSRP: -100 dBm < -95 dBm threshold, but steady)
    // Add measurements at t = 500, 560, 620 so previous samples outside 300s window are pruned
    evaluator.add_measurement(500.0, -101.0);
    evaluator.add_measurement(560.0, -101.2);
    evaluator.add_measurement(620.0, -100.9);
    let state4 = evaluator.evaluate_state().unwrap();
    assert_eq!(state4, RelaxedRrmState::RelaxedServingOnly);
    assert_eq!(evaluator.power_saving_factor(), 0.65); // 35% power reduction
}

#[test]
fn test_error_formatting_and_display() {
    let err_sym = RedCapHdFddError::InvalidSymbolRange {
        start: 12,
        duration: 4,
    };
    let s = format!("{}", err_sym);
    assert!(s.contains("Invalid symbol range"));

    let err_guard = RedCapHdFddError::InvalidSwitchingGuard { rx_tx: 5, tx_rx: 1 };
    let s2 = format!("{}", err_guard);
    assert!(s2.contains("Invalid switching guard"));

    let err_conflict = RedCapHdFddError::AllocationConflict("test conflict");
    let s3 = format!("{}", err_conflict);
    assert!(s3.contains("HD-FDD allocation conflict"));

    let err_win = RedCapHdFddError::EvaluationWindowTooShort {
        samples: 1,
        required: 3,
    };
    let s4 = format!("{}", err_win);
    assert!(s4.contains("RRM evaluation window has 1 samples"));

    // Check direction and symbols per slot
    assert_eq!(HdChannelType::Ssb.direction(), HdDirection::Downlink);
    assert_eq!(HdChannelType::Prach.direction(), HdDirection::Uplink);
    assert_eq!(REDCAP_SYMBOLS_PER_SLOT, 14);
    assert_eq!(NR_SYMBOLS_PER_SLOT, REDCAP_SYMBOLS_PER_SLOT);
}
