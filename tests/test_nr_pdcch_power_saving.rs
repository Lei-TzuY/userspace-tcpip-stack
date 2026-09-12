//! Integration tests for 3GPP Rel-18/19 5G-Advanced PDCCH Power Saving Engine:
//! Search Space Set Group Switching (SSGS) & PDCCH Monitoring Skipping.
//!
//! Validates:
//! - Default Group 0 sparse monitoring and baseline power saving.
//! - DCI-driven explicit group switching with $P_{\text{switch}}$ latency.
//! - `searchSpaceSwitchTimer` autonomous fallback from Group 1 to Group 0.
//! - Timer restart upon subsequent DCI reception in Group 1.
//! - PDCCH monitoring skipping for $K_{\text{skip}}$ slots while preserving CSS monitoring.
//! - Telemetry of blind decode candidate reduction and power saving percentage.
//! - Binary wire framing (`NrSsgsWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_pdcch_power_saving::{
    NrSsgsWirePdu, PdcchPowerSavingConfig, PdcchPowerSavingEngine, PdcchPowerSavingError,
    SearchSpaceConfig, SearchSpaceGroup, SearchSpaceType,
};

fn create_test_engine(switch_timer: u16, p_switch: u8, p_skip: u8) -> PdcchPowerSavingEngine {
    let config = PdcchPowerSavingConfig {
        switch_timer_slots: Some(switch_timer),
        p_switch_slots: p_switch,
        p_skip_slots: p_skip,
        skipping_durations: vec![1, 2, 4, 8],
    };

    let mut engine = PdcchPowerSavingEngine::new(config);

    // CSS: Common Search Space (Type0 CSS for SIB1/Paging) - 8 candidates, period 1
    engine
        .add_search_space(SearchSpaceConfig {
            id: 0,
            ss_type: SearchSpaceType::Common,
            group_memberships: vec![],
            periodicity_slots: 1,
            offset_slots: 0,
            num_candidates: 8,
        })
        .unwrap();

    // Group 0 USS: Sparse monitoring - 12 candidates, period 2 (monitored every 2nd slot)
    engine
        .add_search_space(SearchSpaceConfig {
            id: 1,
            ss_type: SearchSpaceType::UeSpecific,
            group_memberships: vec![SearchSpaceGroup::Group0],
            periodicity_slots: 2,
            offset_slots: 0,
            num_candidates: 12,
        })
        .unwrap();

    // Group 1 USS: Dense monitoring - 36 candidates, period 1 (monitored every slot)
    engine
        .add_search_space(SearchSpaceConfig {
            id: 2,
            ss_type: SearchSpaceType::UeSpecific,
            group_memberships: vec![SearchSpaceGroup::Group1],
            periodicity_slots: 1,
            offset_slots: 0,
            num_candidates: 36,
        })
        .unwrap();

    engine
}

// ---------------------------------------------------------------------------
// 1. Default Group 0 Sparse Monitoring Tests
// ---------------------------------------------------------------------------

#[test]
fn test_default_group0_sparse_monitoring() {
    let mut engine = create_test_engine(5, 1, 1);

    // Initial state: must be Group 0
    assert_eq!(engine.active_group(), SearchSpaceGroup::Group0);
    assert_eq!(engine.remaining_timer(), None);
    assert_eq!(engine.remaining_skipping_slots(), 0);

    // Slot 0: Aligned with both SS 0 (CSS) and SS 1 (Group 0 USS, period 2)
    let dec0 = engine.advance_slot(0);
    assert_eq!(dec0.active_group, SearchSpaceGroup::Group0);
    assert_eq!(dec0.monitored_search_spaces, vec![0, 1]);
    assert_eq!(dec0.total_candidates, 8 + 12); // 20
    assert_eq!(dec0.max_possible_candidates, 8 + 12 + 36); // 56
    assert!(dec0.power_saving_percentage > 60); // 36 / 56 ~ 64% power saving

    // Slot 1: SS 1 is not aligned (period 2, offset 0). Only SS 0 (CSS) is monitored!
    let dec1 = engine.advance_slot(1);
    assert_eq!(dec1.monitored_search_spaces, vec![0]);
    assert_eq!(dec1.total_candidates, 8);
    assert_eq!(dec1.max_possible_candidates, 8 + 36); // 44
    assert!(dec1.power_saving_percentage > 80); // 36 / 44 ~ 81% power saving
}

// ---------------------------------------------------------------------------
// 2. DCI Explicit Group Switching & Pswitch Delay
// ---------------------------------------------------------------------------

#[test]
fn test_dci_explicit_group_switching_with_delay() {
    let mut engine = create_test_engine(5, 2, 1); // P_switch = 2 slots delay

    // At slot 10, UE receives DCI commanding switch to Group 1
    engine.handle_dci(Some(SearchSpaceGroup::Group1), None).unwrap();

    // Slot 10: Delay remaining = 2 -> not switched yet
    let dec10 = engine.advance_slot(10);
    assert_eq!(dec10.active_group, SearchSpaceGroup::Group0);

    // Slot 11: Delay remaining = 1 -> not switched yet
    let dec11 = engine.advance_slot(11);
    assert_eq!(dec11.active_group, SearchSpaceGroup::Group0);

    // Slot 12: Delay elapsed -> applied! Now in Group 1
    let dec12 = engine.advance_slot(12);
    assert_eq!(dec12.active_group, SearchSpaceGroup::Group1);
    assert!(dec12.monitored_search_spaces.contains(&2)); // Dense USS 2 is monitored
    assert_eq!(engine.remaining_timer(), Some(4)); // Timer started at 5 and counted down 1 slot during slot 12
}

// ---------------------------------------------------------------------------
// 3. Autonomous Fallback Timer Tests (TS 38.213 §10.4)
// ---------------------------------------------------------------------------

#[test]
fn test_search_space_switch_timer_autonomous_fallback() {
    let mut engine = create_test_engine(3, 0, 0); // Timer = 3 slots, 0 delay for immediate switch

    // Switch to Group 1 immediately
    engine.handle_dci(Some(SearchSpaceGroup::Group1), None).unwrap();
    assert_eq!(engine.active_group(), SearchSpaceGroup::Group1);
    assert_eq!(engine.remaining_timer(), Some(3));

    // Slot 1: Timer counts down from 3 to 2
    let dec1 = engine.advance_slot(1);
    assert_eq!(dec1.active_group, SearchSpaceGroup::Group1);
    assert_eq!(engine.remaining_timer(), Some(2));

    // Slot 2: Timer counts down from 2 to 1
    let dec2 = engine.advance_slot(2);
    assert_eq!(dec2.active_group, SearchSpaceGroup::Group1);
    assert_eq!(engine.remaining_timer(), Some(1));

    // Slot 3: Timer expires (1 -> 0)! Autonomously falls back to Group 0!
    let dec3 = engine.advance_slot(3);
    assert_eq!(dec3.active_group, SearchSpaceGroup::Group0);
    assert_eq!(engine.remaining_timer(), None);

    // Slot 4: Remains in Group 0
    let dec4 = engine.advance_slot(4);
    assert_eq!(dec4.active_group, SearchSpaceGroup::Group0);
}

#[test]
fn test_timer_restart_on_subsequent_dci_in_group1() {
    let mut engine = create_test_engine(4, 0, 0);

    // Switch to Group 1
    engine.handle_dci(Some(SearchSpaceGroup::Group1), None).unwrap();
    assert_eq!(engine.remaining_timer(), Some(4));

    // Slot 1: Decrements to 3
    engine.advance_slot(1);
    assert_eq!(engine.remaining_timer(), Some(3));

    // Slot 2: Decrements to 2
    engine.advance_slot(2);
    assert_eq!(engine.remaining_timer(), Some(2));

    // DCI arrives without group switch -> restarts timer back to 4!
    engine.handle_dci(None, None).unwrap();
    assert_eq!(engine.remaining_timer(), Some(4));

    // Slot 3: Decrements from 4 to 3 (prevented premature fallback)
    let dec3 = engine.advance_slot(3);
    assert_eq!(dec3.active_group, SearchSpaceGroup::Group1);
    assert_eq!(engine.remaining_timer(), Some(3));
}

// ---------------------------------------------------------------------------
// 4. PDCCH Monitoring Skipping Tests (TS 38.213 §10.4)
// ---------------------------------------------------------------------------

#[test]
fn test_pdcch_skipping_uss_while_preserving_css() {
    let mut engine = create_test_engine(10, 0, 1); // P_skip = 1 slot delay

    // Switch to Group 1 for dense monitoring
    engine.handle_dci(Some(SearchSpaceGroup::Group1), None).unwrap();
    assert_eq!(engine.active_group(), SearchSpaceGroup::Group1);

    // DCI arrives commanding skipping duration index 2 (corresponds to 4 slots)
    engine.handle_dci(None, Some(2)).unwrap();

    // Slot 10: Delay = 1 slot -> skipping not started yet
    let dec10 = engine.advance_slot(10);
    assert!(!dec10.is_skipping_uss);
    assert_eq!(dec10.monitored_search_spaces, vec![0, 2]); // CSS (0) + Dense USS (2)

    // Slot 11: Skipping starts! (4 slots total)
    let dec11 = engine.advance_slot(11);
    assert!(dec11.is_skipping_uss);
    assert_eq!(dec11.monitored_search_spaces, vec![0]); // ONLY CSS is monitored!
    assert_eq!(dec11.total_candidates, 8); // Only 8 CSS candidates
    assert!(dec11.power_saving_percentage > 80);

    // Slots 12, 13, 14: Continue skipping USS
    let dec12 = engine.advance_slot(12);
    assert!(dec12.is_skipping_uss);
    let dec13 = engine.advance_slot(13);
    assert!(dec13.is_skipping_uss);
    let dec14 = engine.advance_slot(14);
    assert!(dec14.is_skipping_uss);

    // Slot 15: Skipping duration elapsed -> Normal USS monitoring resumes!
    let dec15 = engine.advance_slot(15);
    assert!(!dec15.is_skipping_uss);
    assert_eq!(dec15.monitored_search_spaces, vec![0, 2]);
}

// ---------------------------------------------------------------------------
// 5. Binary Wire Framing Tests (`NrSsgsWirePdu`)
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = NrSsgsWirePdu {
        sfn: 128,
        slot: 15,
        active_group: 1,
        skip_remaining_slots: 3,
        switch_timer_val: 7,
        total_candidates: 44,
        max_candidates: 56,
    };

    let bytes = pdu.to_wire_bytes();
    assert_eq!(bytes.len(), 18);

    let decoded = NrSsgsWirePdu::from_wire_bytes(&bytes).unwrap();
    assert_eq!(decoded, pdu);
}

#[test]
fn test_wire_pdu_crc_mismatch() {
    let pdu = NrSsgsWirePdu {
        sfn: 256,
        slot: 2,
        active_group: 0,
        skip_remaining_slots: 0,
        switch_timer_val: 0,
        total_candidates: 8,
        max_candidates: 44,
    };

    let mut bytes = pdu.to_wire_bytes();
    let len = bytes.len();
    bytes[len - 1] ^= 0x55; // Corrupt CRC

    assert!(matches!(
        NrSsgsWirePdu::from_wire_bytes(&bytes),
        Err(PdcchPowerSavingError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_invalid_magic() {
    let pdu = NrSsgsWirePdu {
        sfn: 1,
        slot: 1,
        active_group: 0,
        skip_remaining_slots: 0,
        switch_timer_val: 0,
        total_candidates: 8,
        max_candidates: 8,
    };

    let mut bytes = pdu.to_wire_bytes();
    bytes[0] = 0x00;

    assert!(matches!(
        NrSsgsWirePdu::from_wire_bytes(&bytes),
        Err(PdcchPowerSavingError::InvalidWireMagic(_))
    ));
}
