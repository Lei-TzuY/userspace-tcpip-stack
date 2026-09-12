// Integration tests for 3GPP Rel-18/19 NR HARQ-ACK Codebook Engine
// Tests: TS 38.213 §9.1 codebook construction, DAI tracking, multi-TRP,
//        sub-slot URLLC, SPS release, MAC CE codec, priority multiplexing.

use toy_tcpip::nr_harq_codebook::*;

// ─── Test 1: Type-1 Semi-Static Codebook Construction ────────────────

#[test]
fn test_type1_semi_static_codebook_construction() {
    // Configure: 2 cells, 2 PDSCH/slot/cell, 1 TB, no sub-slot, 3 DL slots.
    let config = Type1Config {
        num_cells: 2,
        max_pdsch_per_slot_per_cell: 2,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        monitoring_window_slots: 3,
    };

    // Expected codebook size: 2 cells * 3 slots * 1 sub-slot * 2 pdsch * 1 tb = 12
    assert_eq!(config.codebook_size(), 12);

    let mut engine = HarqCodebookEngine::new_type1(config).unwrap();

    // Add 4 occasions across 2 cells.
    let mut occ1 = PdschOccasion::new_dynamic(0, 0, 0, 1);
    occ1.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ1).unwrap();

    let mut occ2 = PdschOccasion::new_dynamic(0, 1, 1, 1);
    occ2.set_ack(0, HarqAckBit::Nack);
    engine.add_occasion(occ2).unwrap();

    let mut occ3 = PdschOccasion::new_dynamic(1, 0, 2, 1);
    occ3.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ3).unwrap();

    let mut occ4 = PdschOccasion::new_dynamic(1, 2, 3, 1);
    occ4.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ4).unwrap();

    let codebook = engine.assemble().unwrap();

    assert_eq!(codebook.codebook_type, CodebookType::Type1SemiStatic);
    assert_eq!(codebook.num_bits, 12);
    assert_eq!(codebook.num_occasions, 4);
    assert!(codebook.contains_dtx); // Many positions have no PDSCH → DTX

    // ACK count: 3 ACKs from our occasions.
    assert_eq!(codebook.ack_count(), 3);

    // PUCCH format should be Format2 (12 bits > 2).
    assert_eq!(codebook.pucch_format, PucchFormat::Format2);

    // Telemetry check.
    let telem = engine.telemetry();
    assert_eq!(telem.codebooks_assembled, 1);
    assert_eq!(telem.type1_count, 1);
}

// ─── Test 2: Type-2 Dynamic Codebook with DAI Tracking ───────────────

#[test]
fn test_type2_dynamic_codebook_with_dai() {
    let config = Type2Config {
        num_cells: 1,
        max_tb_per_pdsch: 2,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        one_shot_enabled: false,
    };

    let mut engine = HarqCodebookEngine::new_type2(config).unwrap();

    // Add 3 PDSCH occasions with 2 TBs each.
    for i in 0..3u8 {
        let mut occ = PdschOccasion::new_dynamic(0, i as u16, i, 2);
        occ.counter_dai = i % DAI_COUNTER_MODULO;
        occ.total_dai = 3;
        occ.set_ack(0, HarqAckBit::Ack);
        occ.set_ack(
            1,
            if i % 2 == 0 {
                HarqAckBit::Ack
            } else {
                HarqAckBit::Nack
            },
        );
        engine.add_occasion(occ).unwrap();
    }

    let codebook = engine.assemble().unwrap();

    assert_eq!(codebook.codebook_type, CodebookType::Type2Dynamic);
    // 3 occasions × 2 TBs = 6 bits.
    assert_eq!(codebook.num_bits, 6);

    // TB0: ACK, ACK, ACK → 3 bits = 1
    // TB1: ACK, NACK, ACK → bits = 1, 0, 1
    // Full: 1, 1, 1, 0, 1, 1 → 5 ACKs, 1 NACK
    assert_eq!(codebook.ack_count(), 5);

    // PUCCH format: 6 bits > 2 → Format2.
    assert_eq!(codebook.pucch_format, PucchFormat::Format2);
}

// ─── Test 3: Multi-TRP Sub-codebook Splitting ────────────────────────

#[test]
fn test_multi_trp_separate_sub_codebooks() {
    let type2_config = Type2Config {
        num_cells: 1,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        one_shot_enabled: false,
    };

    let mtrp_config = MultiTrpConfig {
        separate_sub_codebooks: true,
        max_tb_per_pdsch: 1,
        harq_ack_mode: MultiTrpHarqAckMode::Separate,
    };

    let mut engine = HarqCodebookEngine::new_multi_trp(type2_config, mtrp_config).unwrap();

    // Add 2 TRP0 occasions and 2 TRP1 occasions.
    for i in 0..2u8 {
        let mut occ0 = PdschOccasion::new_dynamic(0, i as u16, i, 1);
        occ0.trp_index = Some(TrpIndex::Trp0);
        occ0.counter_dai = i;
        occ0.set_ack(0, HarqAckBit::Ack);
        engine.add_occasion(occ0).unwrap();

        let mut occ1 = PdschOccasion::new_dynamic(0, i as u16, i + 2, 1);
        occ1.trp_index = Some(TrpIndex::Trp1);
        occ1.counter_dai = i;
        occ1.set_ack(
            0,
            if i == 0 {
                HarqAckBit::Ack
            } else {
                HarqAckBit::Nack
            },
        );
        engine.add_occasion(occ1).unwrap();
    }

    let codebook = engine.assemble().unwrap();

    assert_eq!(codebook.codebook_type, CodebookType::Type3MultiTrp);
    // Separate mode: TRP0 (2 bits) + TRP1 (2 bits) = 4 bits.
    assert_eq!(codebook.num_bits, 4);

    // Sub-codebooks should be present.
    assert!(codebook.trp_sub_codebooks.is_some());
    let subs = codebook.trp_sub_codebooks.as_ref().unwrap();
    assert_eq!(subs[0], vec![1, 1]); // TRP0: ACK, ACK
    assert_eq!(subs[1], vec![1, 0]); // TRP1: ACK, NACK
}

// ─── Test 4: Multi-TRP Joint Mode ───────────────────────────────────

#[test]
fn test_multi_trp_joint_codebook() {
    let type2_config = Type2Config {
        num_cells: 1,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        one_shot_enabled: false,
    };

    let mtrp_config = MultiTrpConfig {
        separate_sub_codebooks: false,
        max_tb_per_pdsch: 1,
        harq_ack_mode: MultiTrpHarqAckMode::Joint,
    };

    let mut engine = HarqCodebookEngine::new_multi_trp(type2_config, mtrp_config).unwrap();

    // TRP0: ACK, ACK, NACK
    // TRP1: ACK, NACK, ACK
    // Joint: ACK&ACK=ACK, ACK&NACK=NACK, NACK&ACK=NACK
    let trp0_acks = [HarqAckBit::Ack, HarqAckBit::Ack, HarqAckBit::Nack];
    let trp1_acks = [HarqAckBit::Ack, HarqAckBit::Nack, HarqAckBit::Ack];

    for i in 0..3u8 {
        let mut occ0 = PdschOccasion::new_dynamic(0, i as u16, i, 1);
        occ0.trp_index = Some(TrpIndex::Trp0);
        occ0.counter_dai = i;
        occ0.set_ack(0, trp0_acks[i as usize]);
        engine.add_occasion(occ0).unwrap();

        let mut occ1 = PdschOccasion::new_dynamic(0, i as u16, i + 3, 1);
        occ1.trp_index = Some(TrpIndex::Trp1);
        occ1.counter_dai = i;
        occ1.set_ack(0, trp1_acks[i as usize]);
        engine.add_occasion(occ1).unwrap();
    }

    let codebook = engine.assemble().unwrap();

    // Joint: bit[0]=1&1=1, bit[1]=1&0=0, bit[2]=0&1=0
    assert_eq!(codebook.bits, vec![1, 0, 0]);
    assert_eq!(codebook.num_bits, 3);
    assert_eq!(codebook.ack_count(), 1);
    assert!(codebook.trp_sub_codebooks.is_none()); // not separate
}

// ─── Test 5: SPS Release HARQ-ACK ───────────────────────────────────

#[test]
fn test_sps_release_harq_ack() {
    let config = Type2Config {
        num_cells: 1,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        one_shot_enabled: false,
    };

    let mut engine = HarqCodebookEngine::new_type2(config).unwrap();

    // Dynamic PDSCH.
    let mut occ1 = PdschOccasion::new_dynamic(0, 0, 0, 1);
    occ1.counter_dai = 0;
    occ1.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ1).unwrap();

    // SPS activation.
    let mut occ2 = PdschOccasion::new_sps(0, 1, 1, 0);
    occ2.counter_dai = 1;
    occ2.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ2).unwrap();

    // SPS release → always ACK.
    let occ3 = PdschOccasion {
        cell_id: 0,
        slot_index: 2,
        sub_slot_index: 0,
        harq_process_id: 1,
        num_tb: 1,
        ack_bits: [HarqAckBit::Ack, HarqAckBit::Dtx],
        scheduling_type: PdschSchedulingType::SpsRelease,
        trp_index: None,
        priority: HarqPriority::Low,
        counter_dai: 2,
        total_dai: 3,
        sps_config_index: Some(0),
    };
    engine.add_occasion(occ3).unwrap();

    let codebook = engine.assemble().unwrap();

    assert_eq!(codebook.num_bits, 3);
    assert_eq!(codebook.bits, vec![1, 1, 1]); // All ACK
    assert!(!codebook.contains_dtx);

    // Telemetry should track SPS release.
    assert_eq!(engine.telemetry().sps_release_acks, 1);
}

// ─── Test 6: MAC CE Serialization/Deserialization ────────────────────

#[test]
fn test_mac_ce_serialization_roundtrip() {
    // 16-bit codebook: 10110010 01101001.
    let codebook = AssembledCodebook {
        bits: vec![1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1],
        num_bits: 16,
        codebook_type: CodebookType::Type2Dynamic,
        pucch_format: PucchFormat::Format2,
        num_occasions: 8,
        contains_dtx: false,
        priority: HarqPriority::Low,
        trp_sub_codebooks: None,
    };

    let mac_ce = HarqAckMacCe::from_codebook(&codebook);
    assert_eq!(mac_ce.lcid, 60);
    assert_eq!(mac_ce.payload.len(), 2);
    assert_eq!(mac_ce.payload[0], 0xB2); // 10110010
    assert_eq!(mac_ce.payload[1], 0x69); // 01101001

    let wire = mac_ce.serialize();
    // Wire format: [LCID, length, byte0, byte1]
    assert_eq!(wire.len(), 4);
    assert_eq!(wire[0], 60);
    assert_eq!(wire[1], 2); // 2 payload bytes

    let (decoded, consumed) = HarqAckMacCe::deserialize(&wire).unwrap();
    assert_eq!(consumed, 4);
    assert_eq!(decoded.payload, mac_ce.payload);
    assert_eq!(decoded.num_ack_bits, 16);
}

// ─── Test 7: Sub-slot URLLC Codebook Assembly ────────────────────────

#[test]
fn test_sub_slot_urllc_codebook() {
    let config = SubSlotConfig::TwoSubSlots;
    assert_eq!(config.sub_slots_per_slot(), 2);

    // Create occasions in sub-slot 0 and sub-slot 1.
    let mut occ_sub0 = PdschOccasion::new_dynamic(0, 0, 0, 1);
    occ_sub0.sub_slot_index = 0;
    occ_sub0.priority = HarqPriority::High;
    occ_sub0.set_ack(0, HarqAckBit::Ack);

    let mut occ_sub1_a = PdschOccasion::new_dynamic(0, 0, 1, 1);
    occ_sub1_a.sub_slot_index = 1;
    occ_sub1_a.priority = HarqPriority::High;
    occ_sub1_a.set_ack(0, HarqAckBit::Nack);

    let mut occ_sub1_b = PdschOccasion::new_dynamic(0, 0, 2, 1);
    occ_sub1_b.sub_slot_index = 1;
    occ_sub1_b.priority = HarqPriority::High;
    occ_sub1_b.set_ack(0, HarqAckBit::Ack);

    let occasions = vec![occ_sub0, occ_sub1_a, occ_sub1_b];
    let codebooks = assemble_sub_slot_codebooks(&occasions, config, 1);

    assert_eq!(codebooks.len(), 2); // One per sub-slot.

    // Sub-slot 0: 1 occasion, 1 bit = ACK.
    assert_eq!(codebooks[0].num_bits, 1);
    assert_eq!(codebooks[0].bits, vec![1]);
    assert_eq!(codebooks[0].priority, HarqPriority::High);

    // Sub-slot 1: 2 occasions, 2 bits = [NACK, ACK].
    assert_eq!(codebooks[1].num_bits, 2);
    assert_eq!(codebooks[1].bits, vec![0, 1]);
}

// ─── Test 8: Priority Multiplexing ───────────────────────────────────

#[test]
fn test_priority_multiplexing() {
    let hp_codebook = AssembledCodebook {
        bits: vec![1, 0],
        num_bits: 2,
        codebook_type: CodebookType::Type2Dynamic,
        pucch_format: PucchFormat::Format1,
        num_occasions: 1,
        contains_dtx: false,
        priority: HarqPriority::High,
        trp_sub_codebooks: None,
    };

    let lp_codebook = AssembledCodebook {
        bits: vec![1, 1, 0, 1],
        num_bits: 4,
        codebook_type: CodebookType::Type2Dynamic,
        pucch_format: PucchFormat::Format2,
        num_occasions: 2,
        contains_dtx: true,
        priority: HarqPriority::Low,
        trp_sub_codebooks: None,
    };

    let combined = multiplex_priority_codebooks(&hp_codebook, &lp_codebook);

    // HP bits first, then LP bits.
    assert_eq!(combined.bits, vec![1, 0, 1, 1, 0, 1]);
    assert_eq!(combined.num_bits, 6);
    assert_eq!(combined.priority, HarqPriority::High);
    assert!(combined.contains_dtx);
    assert_eq!(combined.num_occasions, 3);
    assert_eq!(combined.pucch_format, PucchFormat::Format2);
}

// ─── Test 9: One-Shot Multi-Cell Codebook (Rel-18) ───────────────────

#[test]
fn test_one_shot_multi_cell_codebook() {
    // Cell 0: 2 PDSCHs, Cell 1: 1 PDSCH.
    let mut cell0_occ1 = PdschOccasion::new_dynamic(0, 0, 0, 1);
    cell0_occ1.set_ack(0, HarqAckBit::Ack);
    let mut cell0_occ2 = PdschOccasion::new_dynamic(0, 1, 1, 1);
    cell0_occ2.set_ack(0, HarqAckBit::Nack);
    let mut cell1_occ1 = PdschOccasion::new_dynamic(1, 0, 0, 1);
    cell1_occ1.set_ack(0, HarqAckBit::Ack);

    let occasions_by_cell = vec![vec![cell0_occ1, cell0_occ2], vec![cell1_occ1]];

    let codebook = encode_one_shot_multi_cell(&occasions_by_cell, 1).unwrap();

    // Cell0: ACK, NACK. Cell1: ACK. → [1, 0, 1]
    assert_eq!(codebook.bits, vec![1, 0, 1]);
    assert_eq!(codebook.num_bits, 3);
    assert_eq!(codebook.num_occasions, 3);
}

// ─── Test 10: Error Handling & Edge Cases ────────────────────────────

#[test]
fn test_error_handling_and_edge_cases() {
    // Invalid config: 0 cells.
    let result = HarqCodebookEngine::new_type1(Type1Config {
        num_cells: 0,
        max_pdsch_per_slot_per_cell: 1,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        monitoring_window_slots: 1,
    });
    assert!(result.is_err());

    // Valid engine, but cell ID out of range.
    let config = Type2Config {
        num_cells: 2,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        one_shot_enabled: false,
    };
    let mut engine = HarqCodebookEngine::new_type2(config).unwrap();

    let occ_bad_cell = PdschOccasion::new_dynamic(5, 0, 0, 1);
    assert!(matches!(
        engine.add_occasion(occ_bad_cell),
        Err(HarqCodebookError::CellIdOutOfRange { .. })
    ));

    // Empty codebook assembly.
    assert!(matches!(
        engine.assemble(),
        Err(HarqCodebookError::EmptyCodebook)
    ));

    // Missing TRP index for mTRP engine.
    let mtrp_engine = HarqCodebookEngine::new_multi_trp(
        Type2Config {
            num_cells: 1,
            max_tb_per_pdsch: 1,
            sub_slot_config: SubSlotConfig::NoSubSlot,
            one_shot_enabled: false,
        },
        MultiTrpConfig {
            separate_sub_codebooks: false,
            max_tb_per_pdsch: 1,
            harq_ack_mode: MultiTrpHarqAckMode::Separate,
        },
    );
    let mut mtrp_engine = mtrp_engine.unwrap();
    let occ_no_trp = PdschOccasion::new_dynamic(0, 0, 0, 1);
    assert!(matches!(
        mtrp_engine.add_occasion(occ_no_trp),
        Err(HarqCodebookError::MissingTrpIndex)
    ));

    // Sub-slot out of range.
    let config2 = Type2Config {
        num_cells: 1,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::TwoSubSlots,
        one_shot_enabled: false,
    };
    let mut engine2 = HarqCodebookEngine::new_type2(config2).unwrap();
    let mut occ_bad_ss = PdschOccasion::new_dynamic(0, 0, 0, 1);
    occ_bad_ss.sub_slot_index = 5; // > 2 sub-slots
    assert!(matches!(
        engine2.add_occasion(occ_bad_ss),
        Err(HarqCodebookError::SubSlotOutOfRange { .. })
    ));

    // Telemetry reset.
    engine.reset_telemetry();
    assert_eq!(engine.telemetry().codebooks_assembled, 0);
}

// ─── Test 11: Window Clear & Multi-Assembly ──────────────────────────

#[test]
fn test_window_clear_and_multi_assembly() {
    let config = Type2Config {
        num_cells: 1,
        max_tb_per_pdsch: 1,
        sub_slot_config: SubSlotConfig::NoSubSlot,
        one_shot_enabled: false,
    };

    let mut engine = HarqCodebookEngine::new_type2(config).unwrap();

    // First window.
    let mut occ = PdschOccasion::new_dynamic(0, 0, 0, 1);
    occ.counter_dai = 0;
    occ.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ).unwrap();
    let cb1 = engine.assemble().unwrap();
    assert_eq!(cb1.num_bits, 1);

    // Clear and start second window.
    engine.clear_window();
    assert_eq!(engine.occasion_count(), 0);

    let mut occ2a = PdschOccasion::new_dynamic(0, 0, 0, 1);
    occ2a.counter_dai = 0;
    occ2a.set_ack(0, HarqAckBit::Nack);
    engine.add_occasion(occ2a).unwrap();

    let mut occ2b = PdschOccasion::new_dynamic(0, 1, 1, 1);
    occ2b.counter_dai = 1;
    occ2b.set_ack(0, HarqAckBit::Ack);
    engine.add_occasion(occ2b).unwrap();

    let cb2 = engine.assemble().unwrap();
    assert_eq!(cb2.num_bits, 2);
    assert_eq!(cb2.bits, vec![0, 1]);

    // Telemetry accumulates across windows.
    assert_eq!(engine.telemetry().codebooks_assembled, 2);
}
