//! Integration tests for 3GPP Rel-18/19 5G-Advanced Configured Grant (CG Type 1 & Type 2) & SPS Transmission Engine.
//! Validates:
//! - Type 1 grant RRC configuration and immediate activation.
//! - Type 2 grant dynamic PDCCH DCI CS-RNTI activation and release validation.
//! - DCI format error detection (NDI != 0, RV != 0, non-zero HARQ process ID, invalid FDRA).
//! - 3GPP TS 38.321 §5.8.2 HARQ process ID formula computation.
//! - Repetition K and RV sequence mapping (`Rv0231`, `Rv0303`, `Rv0000`).
//! - Multi-configuration collision arbitration based on priority.
//! - Binary wire framing (`ConfiguredGrantWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_configured_grant::{
    CgError, ConfiguredGrantConfig, ConfiguredGrantManager, ConfiguredGrantStatus,
    ConfiguredGrantType, ConfiguredGrantWirePdu, DciCsRnti, RedundancyVersionSequence, RepetitionK,
    UplinkResourceAllocation, compute_cg_harq_proc_id,
};

// ---------------------------------------------------------------------------
// 1. Type 1 Configured Grant Tests (TS 38.321 §5.8.2)
// ---------------------------------------------------------------------------

#[test]
fn test_type1_configured_grant_immediate_active() {
    let mut mgr = ConfiguredGrantManager::new(20); // 20 slots per frame (e.g. 30 kHz SCS, mu=1)

    let alloc = UplinkResourceAllocation {
        start_prb: 10,
        num_prbs: 50,
        start_symbol: 0,
        num_symbols: 14,
        mcs: 16,
    };

    let config = ConfiguredGrantConfig {
        config_id: 1,
        grant_type: ConfiguredGrantType::Type1,
        periodicity_symbols: 28, // 2 slots (28 symbols)
        nrof_harq_processes: 4,
        harq_proc_id_offset: 0,
        rep_k: RepetitionK::K1,
        rep_k_rv: RedundancyVersionSequence::Rv0231,
        resource_allocation: Some(alloc),
        priority: 10,
    };

    mgr.add_config(config).expect("Failed to add Type 1 config");

    // Must be active immediately
    assert_eq!(mgr.get_status(1), Some(ConfiguredGrantStatus::Active));

    // Frame 0, Slot 0, Symbol 0 -> Aligned with 28-symbol periodicity!
    let occ0 = mgr.evaluate_occasion(0, 0, 0);
    assert!(occ0.is_some());
    let grant0 = occ0.unwrap();
    assert_eq!(grant0.config_id, 1);
    assert_eq!(grant0.harq_proc_id, 0);
    assert_eq!(grant0.rv, 0);

    // Frame 0, Slot 1, Symbol 0 (14 symbols elapsed) -> Not aligned with 28-symbol periodicity
    let occ1 = mgr.evaluate_occasion(0, 1, 0);
    assert!(occ1.is_none());

    // Frame 0, Slot 2, Symbol 0 (28 symbols elapsed) -> Aligned! Next HARQ process = 1
    let occ2 = mgr.evaluate_occasion(0, 2, 0);
    assert!(occ2.is_some());
    let grant2 = occ2.unwrap();
    assert_eq!(grant2.config_id, 1);
    assert_eq!(grant2.harq_proc_id, 1);
}

// ---------------------------------------------------------------------------
// 2. Type 2 Configured Grant Activation & Release Tests
// ---------------------------------------------------------------------------

#[test]
fn test_type2_configured_grant_activation_and_release() {
    let mut mgr = ConfiguredGrantManager::new(10); // 10 slots per frame (15 kHz SCS, mu=0)

    let config = ConfiguredGrantConfig {
        config_id: 2,
        grant_type: ConfiguredGrantType::Type2,
        periodicity_symbols: 14, // 1 slot (14 symbols)
        nrof_harq_processes: 8,
        harq_proc_id_offset: 1,
        rep_k: RepetitionK::K2,
        rep_k_rv: RedundancyVersionSequence::Rv0231,
        resource_allocation: None,
        priority: 5,
    };

    mgr.add_config(config).expect("Failed to add Type 2 config");

    // Initially suspended until DCI arrives
    assert_eq!(mgr.get_status(2), Some(ConfiguredGrantStatus::Suspended));
    assert!(mgr.evaluate_occasion(0, 0, 0).is_none());

    // Valid Activation DCI with CS-RNTI 0x8001
    let act_dci = DciCsRnti {
        cs_rnti: 0x8001,
        ndi: 0,
        rv: 0,
        harq_proc_id: 0,
        fdra: 0x0123,
        mcs: 20,
        start_symbol: 0,
        num_symbols: 14,
        start_prb: 5,
        num_prbs: 25,
    };

    mgr.activate_type2(2, &act_dci)
        .expect("Failed to activate Type 2");
    assert_eq!(mgr.get_status(2), Some(ConfiguredGrantStatus::Active));

    // Now occasion is scheduled
    let occ = mgr.evaluate_occasion(0, 0, 0).expect("Expected occasion");
    assert_eq!(occ.config_id, 2);
    assert_eq!(occ.resource.start_prb, 5);
    assert_eq!(occ.resource.num_prbs, 25);
    assert_eq!(occ.resource.mcs, 20);

    // Valid Release DCI with FDRA 0xFFFF
    let rel_dci = DciCsRnti {
        cs_rnti: 0x8001,
        ndi: 0,
        rv: 0,
        harq_proc_id: 0,
        fdra: 0xFFFF,
        mcs: 0,
        start_symbol: 0,
        num_symbols: 0,
        start_prb: 0,
        num_prbs: 0,
    };

    mgr.release_type2(2, &rel_dci)
        .expect("Failed to release Type 2");
    assert_eq!(mgr.get_status(2), Some(ConfiguredGrantStatus::Suspended));
    assert!(mgr.evaluate_occasion(0, 0, 0).is_none());
}

#[test]
fn test_type2_dci_validation_failures() {
    let mut mgr = ConfiguredGrantManager::new(10);
    let config = ConfiguredGrantConfig {
        config_id: 3,
        grant_type: ConfiguredGrantType::Type2,
        periodicity_symbols: 14,
        nrof_harq_processes: 4,
        harq_proc_id_offset: 0,
        rep_k: RepetitionK::K1,
        rep_k_rv: RedundancyVersionSequence::Rv0000,
        resource_allocation: None,
        priority: 1,
    };
    mgr.add_config(config).unwrap();

    // 1. Invalid CS-RNTI (< 0x8001)
    let bad_rnti_dci = DciCsRnti {
        cs_rnti: 0x1234,
        ndi: 0,
        rv: 0,
        harq_proc_id: 0,
        fdra: 0x1,
        mcs: 10,
        start_symbol: 0,
        num_symbols: 14,
        start_prb: 0,
        num_prbs: 10,
    };
    assert!(matches!(
        mgr.activate_type2(3, &bad_rnti_dci),
        Err(CgError::InvalidCsRnti(_))
    ));

    // 2. NDI != 0
    let mut bad_ndi_dci = bad_rnti_dci;
    bad_ndi_dci.cs_rnti = 0x8001;
    bad_ndi_dci.ndi = 1;
    assert_eq!(
        mgr.activate_type2(3, &bad_ndi_dci),
        Err(CgError::DciNdiNotZero)
    );

    // 3. RV != 0
    let mut bad_rv_dci = bad_rnti_dci;
    bad_rv_dci.cs_rnti = 0x8001;
    bad_rv_dci.rv = 2;
    assert_eq!(
        mgr.activate_type2(3, &bad_rv_dci),
        Err(CgError::DciRvNotZero)
    );

    // 4. HARQ process ID != 0 for activation
    let mut bad_harq_dci = bad_rnti_dci;
    bad_harq_dci.cs_rnti = 0x8001;
    bad_harq_dci.harq_proc_id = 3;
    assert_eq!(
        mgr.activate_type2(3, &bad_harq_dci),
        Err(CgError::DciHarqProcInvalid(3))
    );

    // 5. FDRA != 0xFFFF for release
    let bad_rel_fdra_dci = DciCsRnti {
        cs_rnti: 0x8001,
        ndi: 0,
        rv: 0,
        harq_proc_id: 0,
        fdra: 0x0FFF,
        mcs: 0,
        start_symbol: 0,
        num_symbols: 0,
        start_prb: 0,
        num_prbs: 0,
    };
    assert_eq!(
        mgr.release_type2(3, &bad_rel_fdra_dci),
        Err(CgError::DciFdraInvalid)
    );
}

// ---------------------------------------------------------------------------
// 3. 3GPP TS 38.321 §5.8.2 HARQ Process ID Formula Tests
// ---------------------------------------------------------------------------

#[test]
fn test_harq_process_id_computation_formula() {
    let slots_per_frame = 10;
    let periodicity_symbols = 14; // 1 slot
    let nrof_harq_processes = 8;
    let harq_proc_id_offset = 2;

    // SFN 0, Slot 0, Symbol 0 -> current_symbol = 0 -> (0 / 14) % 8 + 2 = 2
    let hid0 = compute_cg_harq_proc_id(
        0,
        0,
        0,
        slots_per_frame,
        periodicity_symbols,
        nrof_harq_processes,
        harq_proc_id_offset,
    )
    .unwrap();
    assert_eq!(hid0, 2);

    // SFN 0, Slot 1, Symbol 0 -> current_symbol = 14 -> (14 / 14) % 8 + 2 = 3
    let hid1 = compute_cg_harq_proc_id(
        0,
        1,
        0,
        slots_per_frame,
        periodicity_symbols,
        nrof_harq_processes,
        harq_proc_id_offset,
    )
    .unwrap();
    assert_eq!(hid1, 3);

    // SFN 0, Slot 7, Symbol 0 -> (7) % 8 + 2 = 9
    let hid7 = compute_cg_harq_proc_id(
        0,
        7,
        0,
        slots_per_frame,
        periodicity_symbols,
        nrof_harq_processes,
        harq_proc_id_offset,
    )
    .unwrap();
    assert_eq!(hid7, 9);

    // SFN 0, Slot 8, Symbol 0 -> (8) % 8 + 2 = 2 (wrapped!)
    let hid8 = compute_cg_harq_proc_id(
        0,
        8,
        0,
        slots_per_frame,
        periodicity_symbols,
        nrof_harq_processes,
        harq_proc_id_offset,
    )
    .unwrap();
    assert_eq!(hid8, 2);
}

// ---------------------------------------------------------------------------
// 4. Repetition K & Redundancy Version Sequences
// ---------------------------------------------------------------------------

#[test]
fn test_repetition_k_and_rv_sequences() {
    let rv_seq = RedundancyVersionSequence::Rv0231;
    assert_eq!(rv_seq.get_rv(0), 0);
    assert_eq!(rv_seq.get_rv(1), 2);
    assert_eq!(rv_seq.get_rv(2), 3);
    assert_eq!(rv_seq.get_rv(3), 1);
    assert_eq!(rv_seq.get_rv(4), 0); // cycles

    let rv_seq2 = RedundancyVersionSequence::Rv0303;
    assert_eq!(rv_seq2.get_rv(0), 0);
    assert_eq!(rv_seq2.get_rv(1), 3);
    assert_eq!(rv_seq2.get_rv(2), 0);
    assert_eq!(rv_seq2.get_rv(3), 3);

    let rv_seq3 = RedundancyVersionSequence::Rv0000;
    assert_eq!(rv_seq3.get_rv(0), 0);
    assert_eq!(rv_seq3.get_rv(1), 0);
}

// ---------------------------------------------------------------------------
// 5. Multi-Configuration Collision Arbitration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_multi_configuration_collision_arbitration() {
    let mut mgr = ConfiguredGrantManager::new(10);

    let alloc1 = UplinkResourceAllocation {
        start_prb: 0,
        num_prbs: 20,
        start_symbol: 0,
        num_symbols: 14,
        mcs: 10,
    };

    let alloc2 = UplinkResourceAllocation {
        start_prb: 50,
        num_prbs: 30,
        start_symbol: 0,
        num_symbols: 14,
        mcs: 22,
    };

    // Config 1 with low priority (10)
    let config1 = ConfiguredGrantConfig {
        config_id: 1,
        grant_type: ConfiguredGrantType::Type1,
        periodicity_symbols: 14,
        nrof_harq_processes: 4,
        harq_proc_id_offset: 0,
        rep_k: RepetitionK::K1,
        rep_k_rv: RedundancyVersionSequence::Rv0231,
        resource_allocation: Some(alloc1),
        priority: 10,
    };

    // Config 2 with higher priority (2 < 10)
    let config2 = ConfiguredGrantConfig {
        config_id: 2,
        grant_type: ConfiguredGrantType::Type1,
        periodicity_symbols: 14,
        nrof_harq_processes: 4,
        harq_proc_id_offset: 0,
        rep_k: RepetitionK::K1,
        rep_k_rv: RedundancyVersionSequence::Rv0231,
        resource_allocation: Some(alloc2),
        priority: 2,
    };

    mgr.add_config(config1).unwrap();
    mgr.add_config(config2).unwrap();

    // When both collide at Frame 0, Slot 0, Symbol 0: Config 2 must win!
    let occ = mgr.evaluate_occasion(0, 0, 0).expect("Expected occasion");
    assert_eq!(occ.config_id, 2);
    assert_eq!(occ.resource.start_prb, 50);
}

// ---------------------------------------------------------------------------
// 6. Binary Wire Framing Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = ConfiguredGrantWirePdu {
        config_id: 1,
        grant_type: 1,
        sfn: 512,
        slot: 9,
        symbol: 0,
        harq_proc_id: 3,
        rv: 2,
        start_prb: 24,
        num_prbs: 48,
        mcs: 18,
    };

    let bytes = pdu.to_wire_bytes();
    assert_eq!(bytes.len(), 20);

    let decoded = ConfiguredGrantWirePdu::from_wire_bytes(&bytes).unwrap();
    assert_eq!(decoded, pdu);
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = ConfiguredGrantWirePdu {
        config_id: 2,
        grant_type: 2,
        sfn: 100,
        slot: 4,
        symbol: 0,
        harq_proc_id: 1,
        rv: 0,
        start_prb: 10,
        num_prbs: 20,
        mcs: 12,
    };

    let mut bytes = pdu.to_wire_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF; // Invert CRC byte

    assert!(matches!(
        ConfiguredGrantWirePdu::from_wire_bytes(&bytes),
        Err(CgError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = ConfiguredGrantWirePdu {
        config_id: 3,
        grant_type: 1,
        sfn: 1,
        slot: 1,
        symbol: 0,
        harq_proc_id: 0,
        rv: 0,
        start_prb: 0,
        num_prbs: 10,
        mcs: 5,
    };

    let mut bytes = pdu.to_wire_bytes();
    bytes[0] = 0x00;

    assert!(matches!(
        ConfiguredGrantWirePdu::from_wire_bytes(&bytes),
        Err(CgError::InvalidWireMagic(_))
    ));
}
