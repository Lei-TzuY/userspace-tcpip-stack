//! Integration and unit tests for 3GPP Rel-18/19 5G-Advanced Physical Downlink Control Channel (PDCCH)
//! Engine, CORESET Interleaving, and Dynamic Monitoring Adaptation.

use toy_tcpip::nr_pdcch_engine::*;

#[test]
fn test_coreset_configuration_and_reg_mapping_non_interleaved() {
    // 4 active bits in bitmap -> 4 * 6 = 24 PRBs
    let bitmap = [0x0F, 0x00, 0x00, 0x00, 0x00, 0x00];
    let duration = 2; // 2 symbols

    let coreset = CoresetConfig::new(
        1,
        bitmap,
        duration,
        CceRegMapping::NonInterleaved,
        PrecoderGranularity::SameAsRegBundle,
    )
    .expect("Valid non-interleaved CORESET");

    assert_eq!(coreset.total_prbs(), 24);
    assert_eq!(coreset.total_regs(), 48); // 24 PRBs * 2 symbols
    assert_eq!(coreset.total_cces(), 8);  // 48 REGs / 6 = 8 CCEs

    // CCE 0 -> REGs 0..=5
    let regs_cce0 = coreset.map_cce_to_regs(0).unwrap();
    assert_eq!(regs_cce0, [0, 1, 2, 3, 4, 5]);

    // CCE 1 -> REGs 6..=11
    let regs_cce1 = coreset.map_cce_to_regs(1).unwrap();
    assert_eq!(regs_cce1, [6, 7, 8, 9, 10, 11]);

    // CCE 7 (last CCE) -> REGs 42..=47
    let regs_cce7 = coreset.map_cce_to_regs(7).unwrap();
    assert_eq!(regs_cce7, [42, 43, 44, 45, 46, 47]);

    // Out of bounds CCE
    assert!(coreset.map_cce_to_regs(8).is_err());
}

#[test]
fn test_coreset_cce_to_reg_interleaved_permutation() {
    // 8 active bits -> 48 PRBs, 1 symbol duration -> 48 REGs -> 8 CCEs
    let bitmap = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00];
    let duration = 1;

    let coreset = CoresetConfig::new(
        2,
        bitmap,
        duration,
        CceRegMapping::Interleaved {
            reg_bundle_size: 2, // L = 2
            interleaver_size: 2, // R = 2
            shift_index: 0,
        },
        PrecoderGranularity::SameAsRegBundle,
    )
    .expect("Valid interleaved CORESET");

    assert_eq!(coreset.total_regs(), 48);
    assert_eq!(coreset.total_cces(), 8);

    // Verify all 8 CCEs map to exactly 6 REGs each, and all 48 REGs are covered uniquely
    let mut reg_covered = [false; 48];
    for cce_idx in 0..8 {
        let regs = coreset.map_cce_to_regs(cce_idx).unwrap();
        assert_eq!(regs.len(), 6);
        for &reg in &regs {
            assert!(
                (reg as usize) < 48,
                "REG index {} out of bounds",
                reg
            );
            assert!(
                !reg_covered[reg as usize],
                "REG {} duplicated across CCEs",
                reg
            );
            reg_covered[reg as usize] = true;
        }
    }

    // Every single REG in the CORESET must be mapped (bijective property)
    assert!(reg_covered.iter().all(|&c| c));
}

#[test]
fn test_y_k_pseudo_random_hashing_recursion() {
    let rnti1 = 0x1234;
    let rnti2 = 0x5678;

    let y0_rnti1 = compute_y_k(rnti1, 0);
    let y1_rnti1 = compute_y_k(rnti1, 1);
    let y2_rnti1 = compute_y_k(rnti1, 2);

    assert_eq!(y0_rnti1, (rnti1 as u64) % HASH_MODULO_D);
    assert_eq!(y1_rnti1, (HASH_MULTIPLIER_A0 * y0_rnti1) % HASH_MODULO_D);
    assert_eq!(y2_rnti1, (HASH_MULTIPLIER_A0 * y1_rnti1) % HASH_MODULO_D);

    // Different RNTIs must produce different hashing sequences
    let y1_rnti2 = compute_y_k(rnti2, 1);
    assert_ne!(y1_rnti1, y1_rnti2);
}

#[test]
fn test_candidate_cce_index_common_vs_ue_specific() {
    let bitmap = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]; // 48 PRBs
    let coreset = CoresetConfig::new(
        0,
        bitmap,
        2, // 96 REGs -> 16 CCEs
        CceRegMapping::NonInterleaved,
        PrecoderGranularity::SameAsRegBundle,
    )
    .unwrap();
    assert_eq!(coreset.total_cces(), 16);

    let candidates = AggregationCandidates {
        al1: 4,
        al2: 4,
        al4: 2,
        al8: 1,
        al16: 0,
    };

    // 1. Common Search Space: Y_k = 0
    let css = SearchSpaceConfig {
        search_space_id: 0,
        coreset_id: 0,
        periodicity_slots: 1,
        offset_slots: 0,
        duration_slots: 1,
        monitoring_symbols_mask: 0x0001,
        candidates,
        search_space_type: SearchSpaceType::Common(CommonSearchSpaceType::Type0),
        sssg_id: 0,
    };

    for cand_idx in 0..candidates.al4 {
        let cce = compute_candidate_cce_index(
            &css,
            &coreset,
            AggregationLevel::L4,
            cand_idx,
            0,
            0x1000,
        )
        .unwrap();

        // Must be multiple of L=4
        assert_eq!(cce % 4, 0);
        assert!(cce + 4 <= 16);
    }

    // 2. UE-Specific Search Space: randomized across slots
    let uss = SearchSpaceConfig {
        search_space_id: 1,
        coreset_id: 0,
        periodicity_slots: 1,
        offset_slots: 0,
        duration_slots: 1,
        monitoring_symbols_mask: 0x0001,
        candidates,
        search_space_type: SearchSpaceType::UeSpecific,
        sssg_id: 0,
    };

    let cce_slot0 = compute_candidate_cce_index(
        &uss,
        &coreset,
        AggregationLevel::L2,
        0,
        0,
        0x55AA,
    )
    .unwrap();

    let cce_slot1 = compute_candidate_cce_index(
        &uss,
        &coreset,
        AggregationLevel::L2,
        0,
        1,
        0x55AA,
    )
    .unwrap();

    // Start CCE must be aligned to L=2
    assert_eq!(cce_slot0 % 2, 0);
    assert_eq!(cce_slot1 % 2, 0);
}

#[test]
fn test_rel17_18_search_space_group_switching() {
    let switch_timer_slots = 4;
    let mut sssg_mgr = PdcchMonitoringAdaptation::new(Some(switch_timer_slots));

    // Initially in sparse Group 0
    assert_eq!(sssg_mgr.current_sssg_id, 0);

    // DCI trigger switches to high-traffic Group 1
    sssg_mgr.trigger_switch_to_group1();
    assert_eq!(sssg_mgr.current_sssg_id, 1);
    assert_eq!(sssg_mgr.timer_countdown, 4);

    // Advance 1 slot
    sssg_mgr.advance_slot();
    assert_eq!(sssg_mgr.current_sssg_id, 1);
    assert_eq!(sssg_mgr.timer_countdown, 3);

    // Advance 3 more slots -> countdown hits 0 -> fallback to Group 0
    sssg_mgr.advance_slot();
    sssg_mgr.advance_slot();
    sssg_mgr.advance_slot();
    assert_eq!(sssg_mgr.timer_countdown, 0);
    assert_eq!(sssg_mgr.current_sssg_id, 0);
}

#[test]
fn test_rel17_18_pdcch_skipping() {
    let mut sssg_mgr = PdcchMonitoringAdaptation::new(None);
    assert!(sssg_mgr.is_monitoring_active());

    // Trigger skipping for 3 slots
    sssg_mgr.trigger_skipping(3);
    assert!(!sssg_mgr.is_monitoring_active());

    // Slot 1 elapsed
    sssg_mgr.advance_slot();
    assert!(!sssg_mgr.is_monitoring_active());

    // Slot 2 elapsed
    sssg_mgr.advance_slot();
    assert!(!sssg_mgr.is_monitoring_active());

    // Slot 3 elapsed -> resuming monitoring
    sssg_mgr.advance_slot();
    assert!(sssg_mgr.is_monitoring_active());
}

#[test]
fn test_slot_blind_decoding_and_cce_budget_limits() {
    let bitmap = [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]; // 96 PRBs
    let coreset = CoresetConfig::new(
        1,
        bitmap,
        2, // 192 REGs -> 32 CCEs
        CceRegMapping::NonInterleaved,
        PrecoderGranularity::SameAsRegBundle,
    )
    .unwrap();

    let valid_candidates = AggregationCandidates {
        al1: 8,
        al2: 4,
        al4: 2,
        al8: 1,
        al16: 0,
    }; // Total candidates = 15 <= 36 (for mu=1)

    let ss1 = SearchSpaceConfig {
        search_space_id: 1,
        coreset_id: 1,
        periodicity_slots: 1,
        offset_slots: 0,
        duration_slots: 1,
        monitoring_symbols_mask: 0x0001,
        candidates: valid_candidates,
        search_space_type: SearchSpaceType::UeSpecific,
        sssg_id: 0,
    };

    // Valid budget check for 30 kHz (mu=1, max 36 BDs)
    let (bds, cces) = audit_slot_monitoring_budget(&[ss1.clone()], &coreset, 0, 1).unwrap();
    assert_eq!(bds, 15);
    assert!(cces <= 56);

    // Overloaded candidate budget (> 36 BDs)
    let overloaded_candidates = AggregationCandidates {
        al1: 20,
        al2: 10,
        al4: 8,
        al8: 4,
        al16: 0,
    }; // Total candidates = 42 > 36!

    let ss_overloaded = SearchSpaceConfig {
        search_space_id: 2,
        coreset_id: 1,
        periodicity_slots: 1,
        offset_slots: 0,
        duration_slots: 1,
        monitoring_symbols_mask: 0x0001,
        candidates: overloaded_candidates,
        search_space_type: SearchSpaceType::UeSpecific,
        sssg_id: 0,
    };

    assert!(matches!(
        audit_slot_monitoring_budget(&[ss_overloaded], &coreset, 0, 1),
        Err(PdcchError::BlindDecodingBudgetExceeded { count: 42, limit: 36 })
    ));
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = PdcchMonitoringPdu {
        version: 1,
        slot_index: 42,
        coreset_id: 1,
        search_space_id: 5,
        aggregation_level: 4,
        candidate_index: 1,
        start_cce: 8,
        sssg_id: 1,
        skipping_remaining: 0,
    };

    let bytes = pdu.to_bytes();
    assert_eq!(bytes.len(), PdcchMonitoringPdu::WIRE_SIZE);

    // Roundtrip decoding
    let decoded = PdcchMonitoringPdu::from_bytes(&bytes).expect("Decoding must succeed");
    assert_eq!(decoded, pdu);

    // CRC corruption test
    let mut corrupted = bytes.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(matches!(
        PdcchMonitoringPdu::from_bytes(&corrupted),
        Err(PdcchError::CrcMismatch { .. })
    ));

    // Bad magic test
    let mut bad_magic = bytes.clone();
    bad_magic[0] = 0x00;
    assert!(matches!(
        PdcchMonitoringPdu::from_bytes(&bad_magic),
        Err(PdcchError::InvalidMagic(_))
    ));
}
