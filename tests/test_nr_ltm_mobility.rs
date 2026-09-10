//! Integration tests for 3GPP Rel-18 5G NR Layer-1 / Layer-2 Triggered Mobility (LTM).

use toy_tcpip::nr_ltm_mobility::{
    LtmCandidateCell, LtmCellSwitchCommandMacCe, LtmError, LtmMobilityEngine, LtmState,
    LtmSwitchMode, LTM_CFRA_SWITCH_LATENCY_MS, LTM_RACHLESS_SWITCH_LATENCY_MS, MAX_LTM_CANDIDATES,
};

#[test]
fn test_ltm_candidate_management_and_capacity_limits() {
    let mut engine = LtmMobilityEngine::new(100, 0x1000, 3_500_000);

    // Add up to MAX_LTM_CANDIDATES (8)
    for i in 0..MAX_LTM_CANDIDATES as u8 {
        let candidate = LtmCandidateCell::new(
            i,
            200 + i as u16,
            3_500_000,
            0x2000 + i as u16,
            vec![i, i + 1],
        );
        assert!(engine.add_candidate(candidate).is_ok());
    }

    assert_eq!(engine.candidates.len(), MAX_LTM_CANDIDATES);

    // Attempting to add 9th candidate should return MaxCandidatesExceeded
    let extra_candidate = LtmCandidateCell::new(8, 299, 3_500_000, 0x2999, vec![0]);
    let err = engine.add_candidate(extra_candidate).unwrap_err();
    assert_eq!(err, LtmError::MaxCandidatesExceeded(MAX_LTM_CANDIDATES));

    // Remove candidate 3
    assert!(engine.remove_candidate(3).is_ok());
    assert_eq!(engine.candidates.len(), MAX_LTM_CANDIDATES - 1);
    assert!(!engine.candidates.contains_key(&3));

    // Removing non-existent candidate returns CandidateNotFound
    assert_eq!(
        engine.remove_candidate(99).unwrap_err(),
        LtmError::CandidateNotFound(99)
    );
}

#[test]
fn test_ltm_l1_beam_measurements_and_best_candidate_tracking() {
    let mut engine = LtmMobilityEngine::new(100, 0x1000, 3_500_000);

    let cand0 = LtmCandidateCell::new(0, 101, 3_500_000, 0x2001, vec![0, 1]);
    let cand1 = LtmCandidateCell::new(1, 102, 3_500_000, 0x2002, vec![2, 3]);
    let cand2 = LtmCandidateCell::new(2, 103, 3_500_000, 0x2003, vec![4, 5]);

    engine.add_candidate(cand0).unwrap();
    engine.add_candidate(cand1).unwrap();
    engine.add_candidate(cand2).unwrap();

    // Update measurements:
    // Candidate 0: -95 dBm
    // Candidate 1: -82 dBm (best)
    // Candidate 2: -118 dBm (below min_switch_rsrp_dbm of -110 dBm)
    engine.update_l1_measurement(0, 1, -95.0, 12.0, 1000).unwrap();
    engine.update_l1_measurement(1, 3, -82.0, 20.5, 1005).unwrap();
    engine.update_l1_measurement(2, 4, -118.0, -5.0, 1010).unwrap();

    let best = engine.best_candidate().expect("Candidate 1 should be best");
    assert_eq!(best.candidate_id, 1);
    assert_eq!(best.physical_cell_id, 102);
    assert_eq!(best.best_beam_id, 3);
    assert_eq!(best.latest_l1_rsrp_dbm, -82.0);
}

#[test]
fn test_ltm_mac_ce_codec_and_bit_packing() {
    // 1. Verify standard fields
    let ce = LtmCellSwitchCommandMacCe::new(5, 12, true, 25);
    let bytes = ce.serialize();
    assert_eq!(bytes.len(), 2);

    let parsed = LtmCellSwitchCommandMacCe::parse(&bytes).unwrap();
    assert_eq!(parsed.target_candidate_id, 5);
    assert_eq!(parsed.target_tci_id, 12);
    assert!(parsed.rachless_switch);
    assert_eq!(parsed.timing_advance_command, 25);

    // 2. Truncated bytes error handling
    let short_bytes = [0x5Cu8];
    assert_eq!(
        LtmCellSwitchCommandMacCe::parse(&short_bytes).unwrap_err(),
        LtmError::InvalidMacCeLength(1)
    );
}

#[test]
fn test_ltm_rachless_cell_switch_under_10ms() {
    let mut engine = LtmMobilityEngine::new(50, 0x1111, 3_500_000);

    // Pre-configure candidate 0 with verified TA
    let cand = LtmCandidateCell::new(0, 60, 3_500_000, 0x2222, vec![3, 7])
        .with_verified_ta(96);
    engine.add_candidate(cand).unwrap();

    engine.update_l1_measurement(0, 7, -78.0, 24.0, 500).unwrap();

    // Command RACH-less switch to candidate 0, TCI 7
    let cmd = LtmCellSwitchCommandMacCe::new(0, 7, true, 0);
    let outcome = engine.process_switch_command(&cmd, 505).unwrap();

    assert!(outcome.success);
    assert_eq!(outcome.mode, LtmSwitchMode::Rachless);
    assert_eq!(outcome.interruption_latency_ms, LTM_RACHLESS_SWITCH_LATENCY_MS);
    assert!(outcome.interruption_latency_ms < 10, "LTM RACH-less interruption must be < 10ms");

    // Verify UE updated serving context
    assert_eq!(engine.serving_pci, 60);
    assert_eq!(engine.serving_c_rnti, 0x2222);
    assert_eq!(engine.serving_tci_id, 7);
    assert_eq!(engine.stats_switches_requested, 1);
    assert_eq!(engine.stats_rachless_switches, 1);
    assert_eq!(engine.state, LtmState::ConnectedTarget { active_candidate_id: 0 });
}

#[test]
fn test_ltm_cfra_fallback_when_ta_unaligned() {
    let mut engine = LtmMobilityEngine::new(50, 0x1111, 3_500_000);

    // Candidate without verified TA (requires CFRA)
    let cand = LtmCandidateCell::new(1, 70, 3_500_000, 0x3333, vec![1, 2])
        .with_cfra(18, 2);
    engine.add_candidate(cand).unwrap();
    engine.update_l1_measurement(1, 2, -84.0, 19.0, 600).unwrap();

    // Even if gNB signaled rachless_switch = true, engine safely falls back to CFRA
    let cmd = LtmCellSwitchCommandMacCe::new(1, 2, true, 0);
    let outcome = engine.process_switch_command(&cmd, 605).unwrap();

    assert!(outcome.success);
    assert_eq!(outcome.mode, LtmSwitchMode::ContentionFreeRach);
    assert_eq!(outcome.interruption_latency_ms, LTM_CFRA_SWITCH_LATENCY_MS);
    assert_eq!(engine.serving_pci, 70);
    assert_eq!(engine.stats_cfra_switches, 1);
}

#[test]
fn test_ltm_degraded_target_beam_triggers_fallback() {
    let mut engine = LtmMobilityEngine::new(50, 0x1111, 3_500_000);

    let cand = LtmCandidateCell::new(2, 80, 3_500_000, 0x4444, vec![5])
        .with_verified_ta(48);
    engine.add_candidate(cand).unwrap();

    // Target beam suffered sudden blockage (-122 dBm < -110 dBm minimum)
    engine.update_l1_measurement(2, 5, -122.0, -8.0, 700).unwrap();

    let cmd = LtmCellSwitchCommandMacCe::new(2, 5, true, 0);
    let outcome = engine.process_switch_command(&cmd, 705).unwrap();

    assert!(!outcome.success);
    assert!(outcome.fallback_triggered);
    // Serving cell context preserved
    assert_eq!(engine.serving_pci, 50);
    assert_eq!(engine.serving_c_rnti, 0x1111);
    assert_eq!(engine.stats_fallback_recoveries, 1);
    assert!(matches!(engine.state, LtmState::FallbackRecovery { .. }));
}

#[test]
fn test_ltm_post_switch_failure_and_source_recovery() {
    let mut engine = LtmMobilityEngine::new(50, 0x1111, 3_500_000);

    let cand = LtmCandidateCell::new(0, 90, 3_500_000, 0x5555, vec![1])
        .with_verified_ta(32);
    engine.add_candidate(cand).unwrap();
    engine.update_l1_measurement(0, 1, -80.0, 20.0, 800).unwrap();

    let cmd = LtmCellSwitchCommandMacCe::new(0, 1, true, 0);
    assert!(engine.process_switch_command(&cmd, 805).unwrap().success);

    // Post-switch: Radio link failure on target cell triggers fallback to source
    engine.trigger_fallback_to_source(50, 0x1111, 0, "Target cell RLF during LTM execution");

    assert_eq!(engine.serving_pci, 50);
    assert_eq!(engine.serving_c_rnti, 0x1111);
    assert_eq!(engine.stats_fallback_recoveries, 1);
    match &engine.state {
        LtmState::FallbackRecovery { reason, .. } => {
            assert!(reason.contains("Target cell RLF"));
        }
        _ => panic!("Expected FallbackRecovery state"),
    }
}
