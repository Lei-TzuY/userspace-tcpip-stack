//! Integration tests for 3GPP Rel-18/19 5G-Advanced Paging Occasion (PO/PF) Calculation, DCI Format 1_0 Short Message & Subgrouping Engine.
//! Validates:
//! - Paging configuration validity checking ($T, N, N_s, \text{PF\_offset}$).
//! - Exact Paging Frame (PF) validation: $(SFN + \text{PF\_offset}) \bmod T = (T / N) \cdot (UE\_ID \bmod N)$.
//! - Paging Occasion (PO) index determination: $i_s = \lfloor UE\_ID / N \rfloor \bmod N_s$.
//! - Next PF/PO prediction engine handling 1024-frame SFN wrap-around.
//! - Rel-18 Paging Subgrouping: $\text{subgroupId} = \lfloor UE\_ID / (N \cdot N_s) \rfloor \bmod N_{\text{subgroups}}$.
//! - DCI Format 1_0 Short Message encoder/decoder (P-RNTI `0xFFFE`, SI Modification, ETWS/CMAS, StopPagingMonitoring).
//! - RRC PagingRecord processing and UE identity matching (5G-S-TMSI / Full I-RNTI).
//! - Binary wire framing (`PagingWirePdu`) with magic `0x50414745` ("PAGE") and CRC-16 CCITT validation.

use toy_tcpip::nr_paging_engine::{
    check_paging_records, compute_paging_subgroup_id, compute_po_index, is_paging_frame,
    next_paging_frame, NumberOfPagingOccasions, PagingCause, PagingConfig, PagingDrxCycle,
    PagingError, PagingRecord, PagingWirePdu, ShortMessage, UePagingIdentity, P_RNTI,
    SHORT_MSG_ETWS_CMAS_IND, SHORT_MSG_STOP_PAGING_MON, SHORT_MSG_SYS_INFO_MOD,
};

// ---------------------------------------------------------------------------
// 1. Paging Configuration & Parameter Validation Tests (TS 38.304 §7.1)
// ---------------------------------------------------------------------------

#[test]
fn test_paging_config_validation() {
    assert_eq!(P_RNTI, 0xFFFE);

    // Valid configuration: T=64, N=32 (divides 64), Ns=2, offset=0
    let config = PagingConfig::new(
        PagingDrxCycle::Rf64,
        32,
        NumberOfPagingOccasions::Two,
        0,
    )
    .unwrap();
    assert_eq!(config.drx_cycle.frames(), 64);
    assert_eq!(config.n, 32);
    assert_eq!(config.ns as u8, 2);

    // Invalid N: 20 does not divide 64
    assert!(matches!(
        PagingConfig::new(PagingDrxCycle::Rf64, 20, NumberOfPagingOccasions::One, 0),
        Err(PagingError::InvalidNParameter { n: 20, t: 64 })
    ));

    // Invalid PF offset: offset 64 >= T (64)
    assert!(matches!(
        PagingConfig::new(PagingDrxCycle::Rf64, 32, NumberOfPagingOccasions::One, 64),
        Err(PagingError::InvalidPfOffset { offset: 64, t: 64 })
    ));
}

// ---------------------------------------------------------------------------
// 2. Exact Paging Frame (PF) & PO Index Calculation Tests (TS 38.304 §7.1)
// ---------------------------------------------------------------------------

#[test]
fn test_is_paging_frame_and_po_index_calculation() {
    let config = PagingConfig::new(
        PagingDrxCycle::Rf64,
        32,
        NumberOfPagingOccasions::Two,
        0,
    )
    .unwrap();

    // 5G-S-TMSI = 0x0001_0000_0087 (ue_id = 135)
    let ue_identity = UePagingIdentity::Ng5gSTmsi(135);
    let ue_id = ue_identity.ue_id();
    assert_eq!(ue_id, 135);

    // T = 64, N = 32 -> T/N = 2
    // ue_id % N = 135 % 32 = 7
    // Target mod = (64/32) * 7 = 14
    // PFs should be SFNs where SFN % 64 == 14: SFN = 14, 78, 142, etc.
    assert!(is_paging_frame(14, &config, ue_id));
    assert!(is_paging_frame(78, &config, ue_id));
    assert!(is_paging_frame(142, &config, ue_id));

    // Non-PF frames
    assert!(!is_paging_frame(15, &config, ue_id));
    assert!(!is_paging_frame(0, &config, ue_id));

    // PO index: is = (ue_id / N) % Ns = (135 / 32) % 2 = 4 % 2 = 0
    let po_idx = compute_po_index(&config, ue_id);
    assert_eq!(po_idx, 0);

    // Another UE: ue_id = 135 + 32 = 167
    // (167 / 32) % 2 = 5 % 2 = 1
    let po_idx_2 = compute_po_index(&config, 167);
    assert_eq!(po_idx_2, 1);
}

#[test]
fn test_paging_frame_with_offset() {
    // Config with PF offset = 5
    let config = PagingConfig::new(
        PagingDrxCycle::Rf64,
        32,
        NumberOfPagingOccasions::One,
        5,
    )
    .unwrap();

    let ue_id = 7; // (7 % 32) * 2 = 14
    // (SFN + 5) % 64 == 14 -> SFN % 64 == 9
    assert!(is_paging_frame(9, &config, ue_id));
    assert!(is_paging_frame(73, &config, ue_id));
    assert!(!is_paging_frame(14, &config, ue_id));
}

// ---------------------------------------------------------------------------
// 3. Next PF/PO Prediction & 1024 SFN Wraparound Tests
// ---------------------------------------------------------------------------

#[test]
fn test_next_paging_frame_search_and_wraparound() {
    let config = PagingConfig::new(
        PagingDrxCycle::Rf128,
        64,
        NumberOfPagingOccasions::Two,
        0,
    )
    .unwrap();

    let ue_id = 10; // (10 % 64) * (128/64) = 20 -> SFN % 128 == 20
    // SFN targets: 20, 148, 276, 404, 532, 660, 788, 916

    // Search starting at current SFN = 500
    let (next_sfn, po_idx) = next_paging_frame(500, &config, ue_id);
    assert_eq!(next_sfn, 532);
    assert_eq!(po_idx, compute_po_index(&config, ue_id));

    // Search starting at current SFN = 920 -> wraps around to 20!
    let (wrapped_sfn, _) = next_paging_frame(920, &config, ue_id);
    assert_eq!(wrapped_sfn, 20);
}

// ---------------------------------------------------------------------------
// 4. Rel-18 Paging Subgrouping Tests (TS 38.304 §7.4)
// ---------------------------------------------------------------------------

#[test]
fn test_rel18_paging_subgrouping() {
    let config = PagingConfig::new(
        PagingDrxCycle::Rf64,
        32,
        NumberOfPagingOccasions::Two,
        0,
    )
    .unwrap();

    // Denominator = N * Ns = 32 * 2 = 64
    let n_subgroups = 4u8;

    // UE 1: ue_id = 100 -> (100 / 64) % 4 = 1 % 4 = 1
    let sg1 = compute_paging_subgroup_id(&config, 100, n_subgroups).unwrap();
    assert_eq!(sg1, 1);

    // UE 2: ue_id = 200 -> (200 / 64) % 4 = 3 % 4 = 3
    let sg2 = compute_paging_subgroup_id(&config, 200, n_subgroups).unwrap();
    assert_eq!(sg2, 3);

    // Invalid subgroup count (not power of 2 or > 8)
    assert!(matches!(
        compute_paging_subgroup_id(&config, 100, 5),
        Err(PagingError::InvalidSubgroupCount(5))
    ));
}

// ---------------------------------------------------------------------------
// 5. DCI Format 1_0 Short Message Tests (TS 38.212 §7.3.1.2.1)
// ---------------------------------------------------------------------------

#[test]
fn test_dci_format_1_0_short_message_encoding() {
    let msg = ShortMessage {
        system_info_modification: true,
        etws_cmas_indication: false,
        stop_paging_monitoring: true,
    };

    let byte = msg.to_byte();
    assert_eq!(byte, SHORT_MSG_SYS_INFO_MOD | SHORT_MSG_STOP_PAGING_MON);

    let decoded = ShortMessage::from_byte(byte);
    assert!(decoded.system_info_modification);
    assert!(!decoded.etws_cmas_indication);
    assert!(decoded.stop_paging_monitoring);

    // All flags active
    let all_active = ShortMessage {
        system_info_modification: true,
        etws_cmas_indication: true,
        stop_paging_monitoring: true,
    };
    assert_eq!(
        all_active.to_byte(),
        SHORT_MSG_SYS_INFO_MOD | SHORT_MSG_ETWS_CMAS_IND | SHORT_MSG_STOP_PAGING_MON
    );
}

// ---------------------------------------------------------------------------
// 6. RRC Paging Record & Filtering Tests (TS 38.331 §6.2.2)
// ---------------------------------------------------------------------------

#[test]
fn test_rrc_paging_record_matching() {
    let my_id = UePagingIdentity::Ng5gSTmsi(0x1122_3344_5566);
    let other_id = UePagingIdentity::Ng5gSTmsi(0x9988_7766_5544);
    let inactive_id = UePagingIdentity::FullIRnti(0xAABB_CCDD_EE);

    let records = vec![
        PagingRecord {
            ue_identity: other_id,
            paging_cause: PagingCause::Data,
        },
        PagingRecord {
            ue_identity: my_id,
            paging_cause: PagingCause::Voice,
        },
        PagingRecord {
            ue_identity: inactive_id,
            paging_cause: PagingCause::Signaling,
        },
    ];

    // Matched my identity
    let match_result = check_paging_records(&records, my_id);
    assert_eq!(match_result, Some(PagingCause::Voice));

    // Unknown identity
    let unknown_id = UePagingIdentity::Ng5gSTmsi(0x0000_1111_2222);
    assert_eq!(check_paging_records(&records, unknown_id), None);
}

// ---------------------------------------------------------------------------
// 7. Binary Wire Framing (PagingWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = PagingWirePdu {
        sfn: 512,
        po_index: 2,
        ue_identity_raw: 0x0001_2345_6789_ABCD,
        short_message: 0x05,
        subgroup_id: 3,
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert_eq!(wire_bytes.len(), 19);

    let decoded = PagingWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded.sfn, pdu.sfn);
    assert_eq!(decoded.po_index, pdu.po_index);
    assert_eq!(decoded.ue_identity_raw, pdu.ue_identity_raw);
    assert_eq!(decoded.short_message, pdu.short_message);
    assert_eq!(decoded.subgroup_id, pdu.subgroup_id);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = PagingWirePdu {
        sfn: 0,
        po_index: 0,
        ue_identity_raw: 0,
        short_message: 0,
        subgroup_id: 0,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0x00;

    assert!(matches!(
        PagingWirePdu::from_wire_bytes(&wire_bytes),
        Err(PagingError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = PagingWirePdu {
        sfn: 256,
        po_index: 1,
        ue_identity_raw: 0x1234,
        short_message: 1,
        subgroup_id: 2,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[8] ^= 0xFF; // Corrupt payload byte

    assert!(matches!(
        PagingWirePdu::from_wire_bytes(&wire_bytes),
        Err(PagingError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = PagingWirePdu {
        sfn: 10,
        po_index: 0,
        ue_identity_raw: 0,
        short_message: 0,
        subgroup_id: 0,
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..10];

    assert!(matches!(
        PagingWirePdu::from_wire_bytes(truncated),
        Err(PagingError::WirePayloadTooShort { .. })
    ));
}
