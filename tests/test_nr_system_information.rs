//! Integration tests for 3GPP Rel-18/19 5G-Advanced System Information (MIB/SIB1/OSI) Broadcast, Scheduling & On-Demand Acquisition Engine.
//! Validates:
//! - MasterInformationBlock (MIB) 10-bit SFN synthesis, CORESET#0 / SearchSpace#0 extraction, and cell barring flags.
//! - SIB1 cell selection S-criterion ($q_{\text{RxLevMin}}$, $q_{\text{QualMin}}$) and PLMN identity verification.
//! - TDD UL-DL pattern slot allocation across numerologies $\mu \in \{0, 1, 2\}$.
//! - SI scheduling window start frame and slot occasion determination per TS 38.331 §5.2.2.3.2.
//! - Modification Period boundaries ($SFN \bmod N_{\text{mod}} = 0$), Paging Short Message notification, and value tag updates.
//! - 3-hour SIB validity timer lifecycle and cache invalidation.
//! - Binary wire framing (`SystemInformationWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_system_information::{
    compute_si_window_occasion, CachedSib, CellSelectionInfo, DmrsTypeAPosition,
    MasterInformationBlock, ModificationPeriodManager, PlmnIdentity, SibType,
    SubcarrierSpacingCommon, SystemInfoError, SystemInformationBlock1, SystemInformationWirePdu,
    TddPeriodicityMs, TddUlDlPattern, SIB_VALIDITY_DURATION_SEC, SI_RNTI,
};

// ---------------------------------------------------------------------------
// 1. MIB Structure & Decoding Tests (TS 38.331 §6.2.2)
// ---------------------------------------------------------------------------

#[test]
fn test_mib_decoding_sfn_combination_and_coreset0() {
    assert_eq!(SI_RNTI, 0xFFFF);

    // 6 MSBs = 42 (0b101010), 4 LSBs = 7 (0b0111) -> (42 << 4) | 7 = 679
    let sfn = MasterInformationBlock::combine_sfn(42, 7).unwrap();
    assert_eq!(sfn, 679);

    // Invalid SFN bits
    assert_eq!(
        MasterInformationBlock::combine_sfn(64, 0),
        Err(SystemInfoError::InvalidSfn(1024))
    );

    let mib = MasterInformationBlock {
        sfn,
        scs_common: SubcarrierSpacingCommon::Scs30or120,
        k_ssb: 4,
        dmrs_type_a_pos: DmrsTypeAPosition::Pos2,
        pdcch_config_sib1: 0x53, // CORESET#0 index 5, SearchSpace#0 index 3
        cell_barred: false,
        intra_freq_reselection_allowed: true,
    };

    assert_eq!(mib.coreset0_index(), 5);
    assert_eq!(mib.search_space0_index(), 3);
    assert!(!mib.cell_barred);
    assert!(mib.intra_freq_reselection_allowed);
}

// ---------------------------------------------------------------------------
// 2. SIB1 Cell Selection S-Criterion Tests (TS 38.331 §6.3.1)
// ---------------------------------------------------------------------------

#[test]
fn test_sib1_cell_selection_s_criterion() {
    let selection_info = CellSelectionInfo {
        q_rx_lev_min_dbm: -120.0,
        q_qual_min_db: Some(-15.0),
    };

    // Both RSRP and RSRQ exceed minimums -> S-criterion satisfied
    assert!(selection_info.evaluate_s_criterion(-105.0, Some(-10.0)));

    // RSRP fails minimum -> S-criterion rejected
    assert!(!selection_info.evaluate_s_criterion(-122.0, Some(-10.0)));

    // RSRQ fails minimum -> S-criterion rejected
    assert!(!selection_info.evaluate_s_criterion(-105.0, Some(-18.0)));

    // No RSRQ required
    let selection_info_no_qual = CellSelectionInfo {
        q_rx_lev_min_dbm: -115.0,
        q_qual_min_db: None,
    };
    assert!(selection_info_no_qual.evaluate_s_criterion(-110.0, None));
    assert!(!selection_info_no_qual.evaluate_s_criterion(-118.0, None));
}

// ---------------------------------------------------------------------------
// 3. TDD Pattern Common Slot Calculation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_tdd_pattern_slots_calculation() {
    let pattern_2p5ms = TddUlDlPattern {
        periodicity: TddPeriodicityMs::Ms2p5,
        nrof_downlink_slots: 3,
        nrof_downlink_symbols: 10,
        nrof_uplink_slots: 1,
        nrof_uplink_symbols: 4,
    };

    // For mu = 1 (30 kHz, 2 slots/ms): 2.5 ms * 2 slots/ms = 5 slots
    assert_eq!(pattern_2p5ms.total_slots_per_period(1), 5);

    // For mu = 0 (15 kHz, 1 slot/ms): 5.0 ms * 1 slot/ms = 5 slots
    let pattern_5ms = TddUlDlPattern {
        periodicity: TddPeriodicityMs::Ms5,
        nrof_downlink_slots: 7,
        nrof_downlink_symbols: 0,
        nrof_uplink_slots: 2,
        nrof_uplink_symbols: 0,
    };
    assert_eq!(pattern_5ms.total_slots_per_period(0), 5);

    // For mu = 2 (60 kHz, 4 slots/ms): 1.25 ms * 4 slots/ms = 5 slots
    let pattern_1p25ms = TddUlDlPattern {
        periodicity: TddPeriodicityMs::Ms1p25,
        nrof_downlink_slots: 3,
        nrof_downlink_symbols: 6,
        nrof_uplink_slots: 1,
        nrof_uplink_symbols: 2,
    };
    assert_eq!(pattern_1p25ms.total_slots_per_period(2), 5);
}

// ---------------------------------------------------------------------------
// 4. SI Scheduling Window & Slot Timing Tests (TS 38.331 §5.2.2.3.2)
// ---------------------------------------------------------------------------

#[test]
fn test_si_window_occasion_calculation() {
    let window_length_slots = 20u16;
    let periodicity_frames = 16u16;
    let mu = 1u8; // 30 kHz -> 20 slots per frame
    let current_sfn = 100u16;

    // Message n = 0: nw = 0 -> start_frame_offset = 0, slot = 0
    let occ0 = compute_si_window_occasion(0, window_length_slots, periodicity_frames, mu, current_sfn).unwrap();
    assert_eq!(occ0.start_slot_in_frame, 0);
    assert_eq!(occ0.window_length_slots, 20);
    assert_eq!(occ0.start_sfn % periodicity_frames, 0);

    // Message n = 1: nw = 20 -> start_frame_offset = 1 frame, slot = 0
    let occ1 = compute_si_window_occasion(1, window_length_slots, periodicity_frames, mu, current_sfn).unwrap();
    assert_eq!(occ1.start_slot_in_frame, 0);
    assert_eq!(occ1.window_length_slots, 20);
    assert_eq!(occ1.start_sfn % periodicity_frames, 1);

    // Invalid window length 0 returns error
    assert_eq!(
        compute_si_window_occasion(0, 0, periodicity_frames, mu, current_sfn),
        Err(SystemInfoError::InvalidSiWindowLength(0))
    );
}

// ---------------------------------------------------------------------------
// 5. Modification Period & Paging Notification Tests (TS 38.331 §5.2.2.2)
// ---------------------------------------------------------------------------

#[test]
fn test_modification_period_and_paging_notification() {
    let mut mod_mgr = ModificationPeriodManager::new(64, 0);

    assert!(mod_mgr.is_modification_boundary(0));
    assert!(mod_mgr.is_modification_boundary(64));
    assert!(mod_mgr.is_modification_boundary(128));
    assert!(!mod_mgr.is_modification_boundary(50));

    // Frame 30: Paging short message received with systemInfoModification
    mod_mgr.notify_si_modification();
    assert!(mod_mgr.modification_pending);

    // Ticking frame 31 does not trigger modification
    let applied_31 = mod_mgr.tick_frame(31);
    assert!(!applied_31);
    assert_eq!(mod_mgr.value_tag, 0);

    // Ticking frame 64 (boundary) applies modification and updates value tag
    let applied_64 = mod_mgr.tick_frame(64);
    assert!(applied_64);
    assert_eq!(mod_mgr.value_tag, 1);
    assert!(!mod_mgr.modification_pending);
}

// ---------------------------------------------------------------------------
// 6. 3-Hour SIB Validity Rule Tests (TS 38.331 §5.2.2.2)
// ---------------------------------------------------------------------------

#[test]
fn test_cached_sib_three_hour_validity() {
    assert_eq!(SIB_VALIDITY_DURATION_SEC, 10800);

    let cached = CachedSib {
        sib_type: SibType::Sib2,
        value_tag: 3,
        received_timestamp_sec: 1000,
    };

    // Valid 1 hour later
    assert!(cached.is_valid(1000 + 3600, 3));

    // Valid 1 second before 3 hours
    assert!(cached.is_valid(1000 + 10799, 3));

    // Expired at exactly 3 hours
    assert!(!cached.is_valid(1000 + 10800, 3));

    // Value tag mismatch immediately invalidates cache
    assert!(!cached.is_valid(1000 + 100, 4));
}

// ---------------------------------------------------------------------------
// 7. Complete SIB1 Container Verification
// ---------------------------------------------------------------------------

#[test]
fn test_sib1_container_configuration() {
    let sib1 = SystemInformationBlock1 {
        cell_selection: CellSelectionInfo {
            q_rx_lev_min_dbm: -124.0,
            q_qual_min_db: Some(-14.0),
        },
        plmn_list: vec![PlmnIdentity {
            mcc: 310,
            mnc: 260,
            mnc_digit_count: 3,
        }],
        cell_identity: 0x000F_FFFF_1234, // 36 bits
        tracking_area_code: 0x123456,    // 24 bits
        tdd_pattern: Some(TddUlDlPattern {
            periodicity: TddPeriodicityMs::Ms2p5,
            nrof_downlink_slots: 3,
            nrof_downlink_symbols: 10,
            nrof_uplink_slots: 1,
            nrof_uplink_symbols: 4,
        }),
        si_window_length_slots: 20,
        si_messages: vec![],
    };

    assert_eq!(sib1.plmn_list[0].mcc, 310);
    assert_eq!(sib1.plmn_list[0].mnc, 260);
    assert_eq!(sib1.tracking_area_code, 0x123456);
}

// ---------------------------------------------------------------------------
// 8. Binary Wire Framing (SystemInformationWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = SystemInformationWirePdu {
        sfn: 512,
        cell_identity: 0x000F_EDCB_A987,
        tracking_area_code: 0x654321,
        mcc: 460,
        mnc: 01,
        q_rx_lev_min_dbm: -122.5,
        si_window_length_slots: 40,
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert_eq!(wire_bytes.len(), 30);

    let decoded = SystemInformationWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded.sfn, pdu.sfn);
    assert_eq!(decoded.cell_identity, pdu.cell_identity);
    assert_eq!(decoded.tracking_area_code, pdu.tracking_area_code);
    assert_eq!(decoded.mcc, pdu.mcc);
    assert_eq!(decoded.mnc, pdu.mnc);
    assert!((decoded.q_rx_lev_min_dbm - pdu.q_rx_lev_min_dbm).abs() < 1e-4);
    assert_eq!(decoded.si_window_length_slots, pdu.si_window_length_slots);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = SystemInformationWirePdu {
        sfn: 0,
        cell_identity: 0,
        tracking_area_code: 0,
        mcc: 0,
        mnc: 0,
        q_rx_lev_min_dbm: 0.0,
        si_window_length_slots: 0,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0xAA;

    assert!(matches!(
        SystemInformationWirePdu::from_wire_bytes(&wire_bytes),
        Err(SystemInfoError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = SystemInformationWirePdu {
        sfn: 100,
        cell_identity: 1234,
        tracking_area_code: 5678,
        mcc: 310,
        mnc: 410,
        q_rx_lev_min_dbm: -118.0,
        si_window_length_slots: 20,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[15] ^= 0x55; // Corrupt payload byte

    assert!(matches!(
        SystemInformationWirePdu::from_wire_bytes(&wire_bytes),
        Err(SystemInfoError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = SystemInformationWirePdu {
        sfn: 1,
        cell_identity: 0,
        tracking_area_code: 0,
        mcc: 0,
        mnc: 0,
        q_rx_lev_min_dbm: 0.0,
        si_window_length_slots: 0,
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..20];

    assert!(matches!(
        SystemInformationWirePdu::from_wire_bytes(truncated),
        Err(SystemInfoError::WirePayloadTooShort { .. })
    ));
}
