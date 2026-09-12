//! Integration Tests for 3GPP Rel-18 Inter-Cell Multi-TRP (IC-mTRP) & URLLC Engine.
//!
//! Validates:
//! 1. Multi-TRP configuration with distinct PCIs (Inter-Cell mTRP).
//! 2. PDSCH repetition schemes (SDM, TDM Scheme 1a/1b, FDM Scheme 2a/2b).
//! 3. Maximal Ratio Combining (MRC) soft-combining SINR gain in repetition modes.
//! 4. Independent per-TRP Beam Failure Detection (BFD) and Rel-18 Multi-TRP BFR MAC CE.
//! 5. Automatic single-TRP fallback during one TRP's outage ensuring zero-loss URLLC continuity.
//! 6. MAC CE bitfield serialization/deserialization fidelity and boundary validations.

use toy_tcpip::nr_mtrp_engine::{
    CoresetPoolId, DEFAULT_MTRP_BFI_THRESHOLD, DEFAULT_MTRP_Q_OUT_DBM, MAC_LCID_MTRP_BFR,
    MAX_MTRP_TRPS, MtrpBfrMacCe, MtrpDciMode, MtrpEngine, MtrpError, MtrpHarqMode, MtrpScheme,
    TrpLinkState,
};

#[test]
fn test_inter_cell_mtrp_initialization_and_validation() {
    // Inter-Cell Multi-TRP: Serving Cell PCI 101, Neighbor Cell PCI 202
    let engine = MtrpEngine::new(101, 202).expect("Valid PCIs");

    assert_eq!(MAX_MTRP_TRPS, 2);
    assert_eq!(DEFAULT_MTRP_BFI_THRESHOLD, 4);
    assert_eq!(MAC_LCID_MTRP_BFR, 0x34);

    let trp0 = engine.get_trp(CoresetPoolId::Pool0);
    assert_eq!(trp0.physical_cell_id, 101);
    assert!(trp0.is_serving_cell);
    assert_eq!(trp0.link_state, TrpLinkState::Healthy);

    let trp1 = engine.get_trp(CoresetPoolId::Pool1);
    assert_eq!(trp1.physical_cell_id, 202);
    assert!(!trp1.is_serving_cell);
    assert_eq!(trp1.link_state, TrpLinkState::Healthy);

    // PCI > 1007 must fail per 3GPP TS 38.211
    let err = MtrpEngine::new(1008, 200);
    assert_eq!(err, Err(MtrpError::InvalidPci(1008)));

    let err2 = MtrpEngine::new(100, 1008);
    assert_eq!(err2, Err(MtrpError::InvalidPci(1008)));
}

#[test]
fn test_sdm_spatial_multiplexing_and_sinr() {
    let mut engine = MtrpEngine::new(50, 60).unwrap();
    engine.set_scheme(MtrpScheme::Sdm);
    engine.set_dci_mode(MtrpDciMode::SingleDci);
    engine.set_harq_mode(MtrpHarqMode::JointCodebook);

    engine.update_trp_measurements(CoresetPoolId::Pool0, 18.0, 75.0);
    engine.update_trp_measurements(CoresetPoolId::Pool1, 14.0, 80.0);

    let bundle = engine.schedule_pdsch(1200, 22, 100).unwrap();
    assert_eq!(bundle.scheme, MtrpScheme::Sdm);
    assert_eq!(bundle.legs.len(), 2);

    // Both legs occupy full 100 PRBs and symbols 2..14
    for leg in &bundle.legs {
        assert_eq!(leg.start_symbol, 2);
        assert_eq!(leg.num_symbols, 12);
        assert_eq!(leg.start_prb, 0);
        assert_eq!(leg.num_prbs, 100);
    }

    // In SDM, effective SINR is bounded by the bottleneck layer (14 dB)
    let eff_sinr = bundle.effective_combined_sinr(&engine.trps);
    assert!((eff_sinr - 14.0).abs() < 1e-6);

    // Decoding succeeds at 12 dB requirement, fails at 16 dB
    assert!(bundle.simulate_decoding(&engine.trps, 12.0));
    assert!(!bundle.simulate_decoding(&engine.trps, 16.0));
}

#[test]
fn test_tdm_scheme1b_mini_slot_repetition() {
    let mut engine = MtrpEngine::new(300, 400).unwrap();
    engine.set_scheme(MtrpScheme::TdmScheme1b {
        symbols_per_repetition: 5,
    });

    let bundle = engine.schedule_pdsch(600, 18, 50).unwrap();
    assert_eq!(bundle.legs.len(), 2);

    let leg0 = &bundle.legs[0];
    let leg1 = &bundle.legs[1];

    assert_eq!(leg0.pool_id, CoresetPoolId::Pool0);
    assert_eq!(leg0.start_symbol, 2);
    assert_eq!(leg0.num_symbols, 5);
    assert_eq!(leg0.redundancy_version, 0);

    assert_eq!(leg1.pool_id, CoresetPoolId::Pool1);
    assert_eq!(leg1.start_symbol, 7); // 2 + 5
    assert_eq!(leg1.num_symbols, 5);
    assert_eq!(leg1.redundancy_version, 2); // Non-zero RV for incremental redundancy
}

#[test]
fn test_fdm_scheme2b_interleaved_repetition_mrc_gain() {
    let mut engine = MtrpEngine::new(500, 600).unwrap();
    engine.set_scheme(MtrpScheme::FdmScheme2b);

    // Both TRPs have 10.0 dB SINR
    engine.update_trp_measurements(CoresetPoolId::Pool0, 10.0, 70.0);
    engine.update_trp_measurements(CoresetPoolId::Pool1, 10.0, 70.0);

    let bundle = engine.schedule_pdsch(400, 12, 60).unwrap();
    assert_eq!(bundle.legs.len(), 2);

    // MRC combining: 10 dB + 10 dB = 10 * log10(10 + 10) = ~13.01 dB (+3 dB diversity gain)
    let combined_sinr = bundle.effective_combined_sinr(&engine.trps);
    assert!((combined_sinr - 13.0103).abs() < 0.05);
}

#[test]
fn test_independent_trp_beam_failure_and_resilient_survivor_traffic() {
    let mut engine = MtrpEngine::new(700, 800).unwrap();
    engine.bfi_threshold = 3;

    // Normal state: 2 legs scheduled
    let bundle_initial = engine.schedule_pdsch(500, 15, 40).unwrap();
    assert_eq!(bundle_initial.legs.len(), 4); // TdmScheme1a with 2 reps per TRP = 4 legs

    // Trigger BFI on TRP 0 (Serving cell)
    assert!(
        engine
            .evaluate_bfi(CoresetPoolId::Pool0, DEFAULT_MTRP_Q_OUT_DBM - 5.0, None)
            .is_none()
    );
    assert!(
        engine
            .evaluate_bfi(CoresetPoolId::Pool0, DEFAULT_MTRP_Q_OUT_DBM - 7.0, None)
            .is_none()
    );

    // 3rd instance triggers BFR MAC CE on TRP 0 with candidate beam #28
    let bfr_ce = engine
        .evaluate_bfi(
            CoresetPoolId::Pool0,
            DEFAULT_MTRP_Q_OUT_DBM - 10.0,
            Some(28),
        )
        .expect("BFR MAC CE should be generated");

    assert!(bfr_ce.serving_cell);
    assert_eq!(bfr_ce.failed_pool, CoresetPoolId::Pool0);
    assert!(bfr_ce.candidate_available);
    assert_eq!(bfr_ce.candidate_beam_id, Some(28));
    assert_eq!(engine.stats_bfr_events, 1);

    // Crucial Rel-18 feature: While TRP 0 is failed, TRP 1 is NOT affected!
    // PDSCH scheduling automatically falls back to TRP 1 without dropping packets
    let bundle_fallback = engine.schedule_pdsch(500, 15, 40).unwrap();
    assert_eq!(
        bundle_fallback.scheme,
        MtrpScheme::SingleTrpFallback {
            active_pool: CoresetPoolId::Pool1
        }
    );
    assert_eq!(bundle_fallback.legs.len(), 1);
    assert_eq!(bundle_fallback.legs[0].pool_id, CoresetPoolId::Pool1);
    assert_eq!(bundle_fallback.legs[0].pci, 800);

    // Complete BFR for TRP 0
    engine.complete_bfr(CoresetPoolId::Pool0, 28);
    assert_eq!(engine.get_trp(CoresetPoolId::Pool0).active_tci_state, 28);
    assert!(engine.get_trp(CoresetPoolId::Pool0).is_available());

    // Cooperative transmission automatically resumes
    let bundle_resumed = engine.schedule_pdsch(500, 15, 40).unwrap();
    assert_eq!(bundle_resumed.legs.len(), 4);
}

#[test]
fn test_mtrp_bfr_mac_ce_serialization_roundtrip() {
    let ce1 = MtrpBfrMacCe {
        serving_cell: true,
        failed_pool: CoresetPoolId::Pool1,
        candidate_available: true,
        candidate_beam_id: Some(45),
    };
    let bytes1 = ce1.serialize();
    let decoded1 = MtrpBfrMacCe::deserialize(bytes1);
    assert_eq!(ce1, decoded1);

    // No candidate available
    let ce2 = MtrpBfrMacCe {
        serving_cell: false,
        failed_pool: CoresetPoolId::Pool0,
        candidate_available: false,
        candidate_beam_id: None,
    };
    let bytes2 = ce2.serialize();
    let decoded2 = MtrpBfrMacCe::deserialize(bytes2);
    assert_eq!(ce2, decoded2);
}

#[test]
fn test_harq_telemetry_and_catastrophic_failure() {
    let mut engine = MtrpEngine::new(10, 20).unwrap();

    engine.record_harq_feedback(CoresetPoolId::Pool0, true);
    engine.record_harq_feedback(CoresetPoolId::Pool0, false);
    engine.record_harq_feedback(CoresetPoolId::Pool1, true);

    assert_eq!(engine.stats_pool0_acks, 1);
    assert_eq!(engine.stats_pool0_nacks, 1);
    assert_eq!(engine.stats_pool1_acks, 1);
    assert_eq!(engine.stats_pool1_nacks, 0);

    // Fail both TRPs
    engine.trps[0].link_state = TrpLinkState::BeamFailure {
        candidate_beam: None,
    };
    engine.trps[1].link_state = TrpLinkState::BeamFailure {
        candidate_beam: None,
    };

    let result = engine.schedule_pdsch(200, 10, 25);
    assert_eq!(result, Err(MtrpError::BothTrpsFailed));

    // Exceeding PRBs
    let prb_err = engine.schedule_pdsch(200, 10, 300);
    assert_eq!(
        prb_err,
        Err(MtrpError::InvalidPrbAllocation {
            requested: 300,
            available: 275
        })
    );
}
